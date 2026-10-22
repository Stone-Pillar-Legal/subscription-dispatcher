"""Durable single-host supervisor metadata, with no stored matter documents.

An exclusive process lock prevents competing supervisors and permits deterministic
crash recovery. An interrupted run is never automatically retried: inference or a
remote write may have occurred. Queued jobs survive restart. SharePoint task and
policy references are resolved by trusted deployment adapters, not browser code.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid


class JobError(Exception):
    pass


class Busy(JobError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


@dataclass(frozen=True)
class Submission:
    agent: str
    matter: str
    task_item: str
    task_sha256: str
    policy_sha256: str

    def payload(self):
        values = vars(self)
        for key, value in values.items():
            if type(value) is not str or not value or len(value) > 512 or any(ord(c) < 32 for c in value):
                raise JobError('Invalid submission reference')
            if key.endswith('sha256') and (len(value) != 64 or any(c not in '0123456789abcdef' for c in value)):
                raise JobError('Expected SHA-256 reference')
        return canonical(values)


class JobStore:
    """Trusted service only. Principal must come from authenticated HTTP context."""
    def __init__(self, directory, *, clock=time.time):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink() or self.directory.stat().st_mode & 0o077:
            raise JobError('Job directory must be private and not a symlink')
        self.path = self.directory / 'jobs.sqlite3'
        if self.path.is_symlink():
            raise JobError('Symlink database refused')
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        if self.path.stat().st_mode & 0o077:
            raise JobError('Job database must be private')
        self.clock = clock
        with self.connection() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, principal TEXT NOT NULL,
                    request_key TEXT NOT NULL, digest TEXT NOT NULL, spec TEXT NOT NULL,
                    state TEXT NOT NULL, cancel INTEGER NOT NULL DEFAULT 0,
                    publication TEXT NOT NULL DEFAULT 'not_started',
                    receipt TEXT, created REAL NOT NULL, updated REAL NOT NULL,
                    UNIQUE(principal, request_key));
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    job TEXT NOT NULL, event TEXT NOT NULL, recorded REAL NOT NULL);
            ''')

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA synchronous=FULL')
        try:
            yield db
        finally:
            db.close()

    @contextmanager
    def transaction(self):
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                yield db
                db.execute('COMMIT')
            except BaseException:
                db.execute('ROLLBACK')
                raise

    def event(self, db, job, event):
        db.execute('INSERT INTO events(job,event,recorded) VALUES(?,?,?)',
                   (job, event, self.clock()))

    def submit(self, principal, request_key, submission):
        for value in (principal, request_key):
            if type(value) is not str or not value or len(value) > 512:
                raise JobError('Invalid identity or request key')
        spec = submission.payload()
        digest = hashlib.sha256(spec.encode()).hexdigest()
        with self.transaction() as db:
            old = db.execute('SELECT id,digest FROM jobs WHERE principal=? AND request_key=?',
                             (principal, request_key)).fetchone()
            if old:
                if old['digest'] != digest:
                    raise JobError('Request key already binds different work')
                return old['id']
            ident = str(uuid.uuid4())
            db.execute('INSERT INTO jobs(id,principal,request_key,digest,spec,state,created,updated) VALUES(?,?,?,?,?,?,?,?)',
                       (ident, principal, request_key, digest, spec, 'queued', self.clock(), self.clock()))
            self.event(db, ident, 'queued')
            return ident

    def get(self, principal, ident):
        with self.connection() as db:
            row = db.execute('SELECT * FROM jobs WHERE id=? AND principal=?', (ident, principal)).fetchone()
            if row is None:
                raise JobError('Job not found')
            value = dict(row)
            value['spec'] = json.loads(value['spec'])
            value['receipt'] = json.loads(value['receipt']) if value['receipt'] else None
            return value

    def cancel(self, principal, ident):
        with self.transaction() as db:
            row = db.execute('SELECT state FROM jobs WHERE id=? AND principal=?', (ident, principal)).fetchone()
            if not row:
                raise JobError('Job not found')
            if row['state'] == 'queued':
                db.execute("UPDATE jobs SET state='cancelled',cancel=1,updated=? WHERE id=?", (self.clock(), ident))
                self.event(db, ident, 'cancelled-before-start')
            elif row['state'] == 'running':
                db.execute('UPDATE jobs SET cancel=1,updated=? WHERE id=?', (self.clock(), ident))
                self.event(db, ident, 'stop-requested')

    @contextmanager
    def supervisor(self):
        """Hold for the complete recovery/claim/run/finalize cycle, never per RPC."""
        fd = os.open(self.directory / 'supervisor.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Busy('Another supervisor is active') from None
            yield
        finally:
            os.close(fd)

    def recover(self):
        # Internal supervisor call; exclusive file lock required.
        with self.transaction() as db:
            rows = db.execute("SELECT id FROM jobs WHERE state='running'").fetchall()
            for row in rows:
                db.execute("UPDATE jobs SET state='interrupted',updated=? WHERE id=?", (self.clock(), row['id']))
                self.event(db, row['id'], 'interrupted-outcome-requires-reconciliation')

    def claim(self):
        with self.transaction() as db:
            row = db.execute("SELECT id,principal FROM jobs WHERE state='queued' ORDER BY created,id LIMIT 1").fetchone()
            if not row:
                return None
            db.execute("UPDATE jobs SET state='running',updated=? WHERE id=?", (self.clock(), row['id']))
            self.event(db, row['id'], 'running')
        return self.get(row['principal'], row['id'])

    def admit_publication(self, job):
        """Linearizes publication admission against cancellation before network I/O.

        A later cancellation is a stop request, not a claim to retract admitted I/O.
        Unknown admitted outcomes remain reconciliation-required after a restart.
        """
        with self.transaction() as db:
            row = db.execute('SELECT state,cancel,publication FROM jobs WHERE id=? AND principal=?',
                             (job['id'], job['principal'])).fetchone()
            if not row or row['state'] != 'running' or row['publication'] != 'not_started':
                raise JobError('Publication cannot be admitted')
            if row['cancel']:
                return False
            db.execute("UPDATE jobs SET publication='admitted',updated=? WHERE id=?",
                       (self.clock(), job['id']))
            self.event(db, job['id'], 'publication-admitted')
            return True

    def finish(self, job, state, receipt=None):
        if state not in ('completed', 'failed', 'cancelled', 'interrupted'):
            raise JobError('Invalid terminal state')
        with self.transaction() as db:
            current = db.execute('SELECT state,cancel FROM jobs WHERE id=?', (job['id'],)).fetchone()
            if not current or current['state'] != 'running':
                raise JobError('Job is not running')
            # A stop cannot undo an admitted remote write. Retain its receipt.
            if current['cancel'] and state != 'interrupted':
                state = 'cancelled'
            db.execute('UPDATE jobs SET state=?,receipt=?,updated=? WHERE id=?',
                (state, canonical(receipt) if receipt is not None else None, self.clock(), job['id']))
            if receipt is not None:
                db.execute("UPDATE jobs SET publication='verified' WHERE id=?", (job['id'],))
            self.event(db, job['id'], state)


class Supervisor:
    """Connects durable metadata to the scoped Runner via trusted adapters.

    resolve(job) -> (runner, Run, task_text, policy_bytes); must compile that
    exact private policy and verify caller authority. publish(job, completed_response) -> a verified
    SharePoint receipt with item_id and sha256. No result body is stored here.
    No automatic retry of model execution or publication on any failure.
    """
    def __init__(self, store, resolve, publish):
        self.store, self.resolve, self.publish = store, resolve, publish

    def once(self):
        with self.store.supervisor():
            self.store.recover()
            job = self.store.claim()
            if job is None:
                return None
            def stopped():
                return bool(self.store.get(job['principal'], job['id'])['cancel'])
            try:
                runner, run, task, policy_bytes = self.resolve(job)
                spec = job['spec']
                if (run.principal, run.agent, run.matter) != (job['principal'], spec['agent'], spec['matter']):
                    raise JobError('Resolved run identity mismatch')
                if type(policy_bytes) is not bytes or hashlib.sha256(policy_bytes).hexdigest() != spec['policy_sha256']:
                    raise JobError('Resolved policy changed')
                if hashlib.sha256(task.encode()).hexdigest() != spec['task_sha256']:
                    raise JobError('Resolved task changed')
                result = runner.run(run, task, cancelled=stopped)
                if not self.store.admit_publication(job):
                    self.store.finish(job, 'cancelled')
                else:
                    receipt = self.publish(job, result)
                    if (type(receipt) is not dict or set(receipt) != {'item_id','sha256'}
                            or type(receipt['item_id']) is not str or not receipt['item_id'] or len(receipt['item_id']) > 512
                            or type(receipt['sha256']) is not str or len(receipt['sha256']) != 64
                            or any(c not in '0123456789abcdef' for c in receipt['sha256'])):
                        raise JobError('Invalid publication receipt')
                    if receipt['sha256'] != hashlib.sha256(canonical(result).encode()).hexdigest():
                        raise JobError('Publication content hash mismatch')
                    self.store.finish(job, 'completed', receipt)
            except Exception:
                # Model/tool/publication failure may have had effects. Never imply
                # rollback or auto-resubmit. No raw exceptions or client text logged.
                self.store.finish(job, 'interrupted')
            return job['id']
