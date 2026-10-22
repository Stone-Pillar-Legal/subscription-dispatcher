"""In-process authorization kernel; no provider, credentials, or network implementation.

The trusted supervisor alone constructs this kernel and issues/cancels grants. Request
identity must come from authenticated host context, not model-supplied identity claims.
Storage adapters are trusted: read must honour its byte limit, and create must use
create-only/no-overwrite semantics with the supplied server operation ID. Never expose
those adapters or issue()/cancel() as model tools.

A per-grant lock serializes authorization, storage calls and cancellation. Cancellation
waits for an in-flight call; once it returns no later call can start. It cannot undo a
remote request already sent. Expiry is checked at call admission, not a remote lease.
Adapters must not reenter this kernel. Idempotency is in-memory: unknown writes are
never retried here. Restart/multiple workers require a durable shared grant/idempotency
store and reconciliation before reusing any run; this module does not provide them.
"""
from dataclasses import dataclass, field
import hashlib
import math
import secrets
import threading
import time
from typing import Callable


class Denied(Exception):
    """Request is outside current grant authority."""


class OutcomeUnknown(Exception):
    """A create may have happened; reconcile externally, never blindly retry."""


@dataclass(frozen=True)
class Grant:
    grant_id: str
    run_id: str
    principal: str
    agent: str
    matter: str
    site_id: str
    drive_id: str
    read_items: frozenset[str]
    output_folders: frozenset[str]
    read_only: bool
    expires_at: float


@dataclass(frozen=True)
class Created:
    operation_id: str
    item_id: str
    sha256: str


@dataclass(frozen=True)
class _Write:
    folder: str
    sha256: str
    content: bytes = field(repr=False)
    operation_id: str
    result: Created | None = None


@dataclass
class _State:
    grant: Grant
    lock: object = field(default_factory=threading.Lock)
    cancelled: bool = False
    writes: dict = field(default_factory=dict)


def _id(value):
    # Opaque IDs, never interpreted as paths or URLs by this kernel.
    if type(value) is not str or not value or len(value) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Denied('Invalid identifier')
    return value


def _ids(values):
    if type(values) not in (set, frozenset, tuple, list) or len(values) > 4096:
        raise Denied('Invalid resource inventory')
    return frozenset(_id(value) for value in values)


class Kernel:
    """Server-owned grants and injected read/create-only storage capabilities.

    read(site_id, drive_id, item_id, max_bytes) -> bytes
    create(site_id, drive_id, folder_id, operation_id, content, sha256) -> item_id

    execute accepts only opaque resource IDs, never caller-selected site/drive/path.
    Each write key is scoped to its grant and permanently binds folder plus bytes.
    """
    def __init__(self, *, read: Callable, create: Callable, clock=time.monotonic,
                 max_bytes=16 * 1024 * 1024, max_writes=1024):
        if not callable(read) or not callable(create) or not callable(clock):
            raise ValueError('Storage and clock callbacks required')
        if type(max_bytes) is not int or max_bytes <= 0 or type(max_writes) is not int or max_writes <= 0:
            raise ValueError('Positive integer limits required')
        self._read, self._create, self._clock = read, create, clock
        self._max_bytes, self._max_writes = max_bytes, max_writes
        self._states = {}
        self._runs = set()
        self._lock = threading.Lock()

    def _now(self):
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise Denied('Invalid clock')
        return now

    def issue(self, *, run_id, principal, agent, matter, site_id, drive_id,
              read_items=(), output_folders=(), read_only=True, ttl=300):
        """Trusted server API; never an agent/caller-selectable policy operation."""
        for value in (run_id, principal, agent, matter, site_id, drive_id):
            _id(value)
        if type(read_only) is not bool or type(ttl) not in (int, float) or not math.isfinite(ttl) or ttl <= 0:
            raise Denied('Invalid grant lifetime or mode')
        reads, folders = _ids(read_items), _ids(output_folders)
        if read_only and folders:
            raise Denied('Read-only grant cannot authorize output folders')
        expiry = self._now() + ttl
        if not math.isfinite(expiry):
            raise Denied('Invalid grant expiry')
        with self._lock:
            if run_id in self._runs:
                raise Denied('Run already granted; policy replacement forbidden')
            grant = Grant(secrets.token_urlsafe(32), run_id, principal, agent, matter,
                          site_id, drive_id, reads, folders, read_only, expiry)
            self._states[grant.grant_id] = _State(grant)
            self._runs.add(run_id)
            return grant

    def _state(self, grant_id):
        _id(grant_id)
        with self._lock:
            state = self._states.get(grant_id)
        if state is None:
            raise Denied('Unknown grant')
        return state

    def cancel(self, grant_id):
        """Trusted supervisor API. Returns after previously admitted calls finish."""
        state = self._state(grant_id)
        with state.lock:
            state.cancelled = True

    def execute(self, grant_id, *, principal, agent, matter, operation, resource,
                content=None, idempotency_key=None):
        state = self._state(grant_id)
        for value in (principal, agent, matter, resource):
            _id(value)
        with state.lock:
            grant = state.grant
            if (principal, agent, matter) != (grant.principal, grant.agent, grant.matter):
                raise Denied('Grant identity mismatch')
            if state.cancelled or self._now() >= grant.expires_at:
                raise Denied('Grant cancelled or expired')
            if type(operation) is str and operation == 'read':
                if content is not None or idempotency_key is not None or resource not in grant.read_items:
                    raise Denied('Read not authorized')
                data = self._read(grant.site_id, grant.drive_id, resource, self._max_bytes)
                if type(data) is not bytes or len(data) > self._max_bytes:
                    raise Denied('Invalid or oversized storage read')
                return data
            if type(operation) is not str or operation != 'create':
                raise Denied('Operation not authorized')
            if grant.read_only or resource not in grant.output_folders:
                raise Denied('Create not authorized')
            _id(idempotency_key)
            if type(content) is not bytes or len(content) > self._max_bytes:
                raise Denied('Create requires bounded immutable bytes')
            digest = hashlib.sha256(content).hexdigest()
            previous = state.writes.get(idempotency_key)
            if previous is not None:
                if (previous.folder, previous.sha256, previous.content) != (resource, digest, content):
                    raise Denied('Idempotency key already bound to different output')
                if previous.result is None:
                    raise OutcomeUnknown('Prior create outcome unknown; no retry issued')
                return previous.result
            if any(row.result is None for row in state.writes.values()):
                raise OutcomeUnknown('An unresolved create freezes new writes for this grant')
            if self._now() >= grant.expires_at:
                raise Denied('Grant expired before create')
            if len(state.writes) >= self._max_writes:
                raise Denied('Write inventory limit reached')
            write = _Write(resource, digest, content, secrets.token_urlsafe(32))
            # Record before handing off. Any exception, including interruption or a
            # malformed response, leaves an unknown record that blocks duplication.
            state.writes[idempotency_key] = write
            try:
                item = self._create(grant.site_id, grant.drive_id, resource,
                                    write.operation_id, content, digest)
                _id(item)
            except BaseException as exc:
                raise OutcomeUnknown('Create outcome unknown; no retry will be issued') from exc
            result = Created(write.operation_id, item, digest)
            state.writes[idempotency_key] = _Write(resource, digest, content, write.operation_id, result)
            return result
