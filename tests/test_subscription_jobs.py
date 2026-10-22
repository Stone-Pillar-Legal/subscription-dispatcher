import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from types import SimpleNamespace

from subscription_dispatcher.jobs import Busy, JobError, JobStore, Submission, Supervisor, canonical

TASK = 'Synthetic task'
HASH = hashlib.sha256(TASK.encode()).hexdigest()
POLICY = b'synthetic private policy'
SPEC = Submission('agent', 'matter', 'task-item', HASH, hashlib.sha256(POLICY).hexdigest())


class JobsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'private'
        self.store = JobStore(self.path)

    def resolve(self, job):
        run = SimpleNamespace(principal=job['principal'], agent=job['spec']['agent'], matter=job['spec']['matter'])
        runner = SimpleNamespace(run=lambda run, task, cancelled: {'status':'completed','output':[]})
        return runner, run, TASK, POLICY

    def publish(self, job, response):
        return {'item_id':'synthetic-output', 'sha256':hashlib.sha256(canonical(response).encode()).hexdigest()}

    def test_restart_keeps_queue_and_completed_receipt(self):
        ident = self.store.submit('owner', 'request', SPEC)
        reopened = JobStore(self.path)
        self.assertEqual(reopened.get('owner', ident)['state'], 'queued')
        Supervisor(reopened, self.resolve, self.publish).once()
        again = JobStore(self.path)
        self.assertEqual(again.get('owner', ident)['state'], 'completed')
        self.assertEqual(again.get('owner', ident)['receipt']['item_id'], 'synthetic-output')
        self.assertIsNone(Supervisor(again, self.resolve, self.publish).once())
        self.assertNotIn(TASK.encode(), self.path.joinpath('jobs.sqlite3').read_bytes())

    def test_request_idempotency_is_identity_scoped_and_content_bound(self):
        ident = self.store.submit('owner', 'request', SPEC)
        self.assertEqual(ident, self.store.submit('owner', 'request', SPEC))
        with self.assertRaises(JobError):
            self.store.submit('owner', 'request', replace(SPEC, agent='other'))
        other = self.store.submit('other-owner', 'request', SPEC)
        self.assertNotEqual(other, ident)
        with self.assertRaises(JobError): self.store.get('other-owner', ident)
        with self.assertRaises(JobError): self.store.cancel('other-owner', ident)

    def test_concurrent_submission_enqueues_once(self):
        ids = []
        def submit(): ids.append(JobStore(self.path).submit('owner','same',SPEC))
        threads = [threading.Thread(target=submit) for _ in range(8)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(len(ids), 8)
        self.assertEqual(len(set(ids)), 1)

    def test_active_supervisor_cannot_be_mistaken_for_crash(self):
        with self.store.supervisor():
            with self.assertRaises(Busy):
                Supervisor(JobStore(self.path), self.resolve, self.publish).once()

    def test_cancel_queued_never_resolves_or_runs(self):
        ident = self.store.submit('owner', 'request', SPEC)
        self.store.cancel('owner', ident)
        def forbidden(*args): self.fail('Cancelled work executed')
        self.assertIsNone(Supervisor(self.store, forbidden, forbidden).once())
        self.assertEqual(self.store.get('owner', ident)['state'], 'cancelled')

    def test_cancel_during_publication_preserves_receipt_without_false_success(self):
        ident = self.store.submit('owner', 'request', SPEC)
        def publish(job, result):
            self.store.cancel('owner', ident)
            return self.publish(job, result)
        Supervisor(self.store, self.resolve, publish).once()
        value = self.store.get('owner', ident)
        self.assertEqual(value['state'], 'cancelled')
        self.assertEqual(value['receipt']['item_id'], 'synthetic-output')

    def test_changed_task_or_identity_never_runs_or_publishes(self):
        for mismatch in ('task', 'identity', 'policy'):
            with self.subTest(mismatch=mismatch):
                ident = self.store.submit('owner', mismatch, SPEC)
                def resolve(job):
                    runner, run, task, policy = self.resolve(job)
                    runner.run = lambda *a, **kw: self.fail('Unverified work ran')
                    if mismatch == 'task': task += 'modified'
                    elif mismatch == 'identity': run.principal = 'another-owner'
                    else: policy += b'modified'
                    return runner, run, task, policy
                def forbidden(*args): self.fail('Unverified output published')
                Supervisor(self.store, resolve, forbidden).once()
                self.assertEqual(self.store.get('owner', ident)['state'], 'interrupted')

    def test_ambiguous_publish_is_not_retried(self):
        ident = self.store.submit('owner', 'request', SPEC)
        writes = []
        def publish(*args):
            writes.append('may-have-written')
            raise TimeoutError('sensitive-provider-response')
        worker = Supervisor(self.store, self.resolve, publish)
        worker.once()
        worker.once()
        self.assertEqual(writes, ['may-have-written'])
        self.assertEqual(self.store.get('owner', ident)['state'], 'interrupted')
        self.assertNotIn(b'sensitive-provider-response', self.path.joinpath('jobs.sqlite3').read_bytes())

    def test_actual_process_crash_never_reexecutes_running_job(self):
        ident = self.store.submit('owner', 'request', SPEC)
        code = '''
import os, sys
from subscription_dispatcher.jobs import JobStore
s = JobStore(sys.argv[1])
with s.supervisor():
 s.recover()
 assert s.claim()
 os._exit(73)
'''
        result = subprocess.run([sys.executable, '-c', code, str(self.path)], timeout=10,
                                cwd=Path(__file__).resolve().parents[1])
        self.assertEqual(result.returncode, 73)
        def forbidden(*args): self.fail('Crashed job reran')
        reopened = JobStore(self.path)
        self.assertIsNone(Supervisor(reopened, forbidden, forbidden).once())
        self.assertEqual(reopened.get('owner', ident)['state'], 'interrupted')
        self.assertEqual(reopened.submit('owner', 'request', SPEC), ident)

    def test_bad_receipt_is_not_completed(self):
        ident = self.store.submit('owner','request',SPEC)
        Supervisor(self.store, self.resolve, lambda *a: {'text':'not a receipt'}).once()
        self.assertEqual(self.store.get('owner', ident)['state'], 'interrupted')

    def test_public_directory_and_symlink_database_refused(self):
        unsafe = Path(self.temp.name) / 'unsafe'
        unsafe.mkdir(mode=0o755)
        with self.assertRaises(JobError): JobStore(unsafe)
        other = Path(self.temp.name) / 'other'
        other.mkdir(mode=0o700)
        (other/'jobs.sqlite3').symlink_to(self.store.path)
        with self.assertRaises(JobError): JobStore(other)

    def test_wrong_publication_hash_is_not_success(self):
        ident = self.store.submit('owner','request',SPEC)
        Supervisor(self.store, self.resolve, lambda *a: {'item_id':'output','sha256':'b'*64}).once()
        self.assertEqual(self.store.get('owner', ident)['state'], 'interrupted')

    def test_cancel_wins_atomic_publication_admission(self):
        ident = self.store.submit('owner', 'request', SPEC)
        admit = self.store.admit_publication
        def cancelling_admission(job):
            self.store.cancel('owner', ident)
            return admit(job)
        self.store.admit_publication = cancelling_admission
        def forbidden(*args): self.fail('Publication started after cancellation won')
        Supervisor(self.store, self.resolve, forbidden).once()
        job = self.store.get('owner', ident)
        self.assertEqual(job['state'], 'cancelled')
        self.assertEqual(job['publication'], 'not_started')

    def test_cancel_cannot_erase_unknown_publication(self):
        ident = self.store.submit('owner', 'request', SPEC)
        def ambiguous(job, result):
            self.assertEqual(self.store.get('owner', ident)['publication'], 'admitted')
            self.store.cancel('owner', ident)
            raise TimeoutError('remote write may have succeeded')
        Supervisor(self.store, self.resolve, ambiguous).once()
        job = self.store.get('owner', ident)
        self.assertEqual(job['state'], 'interrupted')
        self.assertEqual(job['publication'], 'admitted')
        self.assertEqual(job['cancel'], 1)
        self.assertIsNone(job['receipt'])

    def test_supervisor_runs_real_scoped_loop_and_publishes_verified_bytes(self):
        from subscription_dispatcher.policy import Kernel
        from subscription_dispatcher.runner import Run, Runner
        from tests.test_subscription_runner import Model, call
        ident = self.store.submit('owner', 'request', SPEC)
        writes = []
        kernel = Kernel(read=lambda *args: b'approved synthetic input',
            create=lambda *args: writes.append(args) or 'draft-output')
        model = Model([
            [call('read', {'resource':'approved-input'})],
            [call('create', {'resource':'approved-output','content':'draft','idempotency_key':'draft'}, 'call2')],
            [dict(type='message', role='assistant', content=[])]])
        def resolve(job):
            grant = kernel.issue(run_id=job['id'], principal=job['principal'],
                agent=job['spec']['agent'], matter=job['spec']['matter'],
                site_id='site', drive_id='drive', read_items=['approved-input'],
                output_folders=['approved-output'], read_only=False)
            run = Run(grant.grant_id, job['principal'], SPEC.agent, SPEC.matter,
                      'catalog-model', 'synthetic private instructions', False)
            return Runner(model, kernel), run, TASK, POLICY
        published = {}
        def publish(job, result):
            content = canonical(result).encode()
            published[job['id']] = content
            readback = published[job['id']]
            self.assertEqual(readback, content)
            return {'item_id':'receipt-item', 'sha256':hashlib.sha256(readback).hexdigest()}
        Supervisor(self.store, resolve, publish).once()
        self.assertEqual(self.store.get('owner',ident)['state'], 'completed')
        self.assertEqual(len(writes),1)
        self.assertEqual(writes[0][:3], ('site','drive','approved-output'))
        self.assertEqual(len(model.requests),3)
        self.assertIn(ident,published)
