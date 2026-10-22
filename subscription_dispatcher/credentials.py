"""Load one explicitly configured, protected SIWC validator record.

This is NOT an OAuth validator: format/issuer assertions are trusted only because
an independently trusted OAuth validator authors this private file. No discovery,
network, token refresh, signature verification or credential writing occurs here.
The containing directory and file must be private to the current uid. Ancestors
are traversed without links and must be owned by root/current uid and not writable
by others (root-owned sticky temporary directories are permitted). The caller must
protect the validator and its uid; these checks cannot defeat a malicious process
with that same identity. No credential values are included in errors or reprs.
"""
import json
import math
import os
import stat
import time

from .plan_transport import PlanError, PlanSession

MAX_CREDENTIAL_BYTES = 64 * 1024
_REQUIRED = frozenset(('format', 'issuer', 'subject', 'client_id',
    'ext_agent_host_id', 'access_token', 'refresh_token', 'id_token',
    'scopes', 'expires_at', 'validated_at'))


class CredentialError(PlanError):
    """Sanitized protected-record refusal."""


def _fail():
    raise CredentialError('Protected SIWC credential record is invalid or unavailable')


def _identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink)


def _file_state(s):
    return _identity(s) + (s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _directory(s, private=False):
    if not stat.S_ISDIR(s.st_mode):
        _fail()
    if private:
        if s.st_uid != os.getuid() or s.st_mode & 0o077:
            _fail()
    elif (s.st_uid not in (0, os.getuid()) or
          (s.st_mode & 0o022 and not (s.st_uid == 0 and s.st_mode & stat.S_ISVTX))):
        _fail()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _constant(value):
    _fail()


def _session(data, now):
    if type(data) is not dict or not _REQUIRED <= data.keys() or data.keys() - (_REQUIRED | {'email'}):
        _fail()
    if data['format'] != 'siwc-validated-v1' or data['issuer'] != 'https://auth.openai.com':
        _fail()
    for key in ('subject', 'client_id', 'ext_agent_host_id', 'access_token', 'refresh_token', 'id_token'):
        value = data[key]
        if type(value) is not str or not value or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
            _fail()
    if 'email' in data and (type(data['email']) is not str or not data['email'] or
                           any(ord(c) < 32 or ord(c) == 127 for c in data['email'])):
        _fail()
    scopes = data['scopes']
    if (type(scopes) is not list or not scopes or
            any(type(s) is not str or not s or any(c.isspace() for c in s) for s in scopes) or
            len(set(scopes)) != len(scopes)):
        _fail()
    for value in (now, data['validated_at'], data['expires_at']):
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            _fail()
    if data['validated_at'] > now or data['validated_at'] >= data['expires_at']:
        _fail()
    session = PlanSession(access_token=data['access_token'], client_id=data['client_id'],
                          subject=data['subject'], scopes=frozenset(scopes),
                          expires_at=data['expires_at'])
    session.validate(now)
    return session


def load_credentials(path, *, now=None):
    """Return PlanSession from an explicit absolute canonical path.

    No environment/home expansion or symlink resolution is performed. ``now`` is
    injectable for tests; by default expiry is evaluated against time.time().
    The returned session intentionally contains no refresh token or ID token.
    """
    descriptors = []
    try:
        path = os.fspath(path)
        if (type(path) is not str or not path.startswith('/') or '\x00' in path or
                any(p in ('', '.', '..') for p in path.split('/')[1:])):
            _fail()
        parts = path.split('/')[1:]
        if len(parts) < 2:
            _fail()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent = os.open('/', flags)
        descriptors.append(parent)
        root_state = os.fstat(parent)
        _directory(root_state)
        links = []
        for index, name in enumerate(parts[:-1]):
            child = os.open(name, flags, dir_fd=parent)
            descriptors.append(child)
            state = os.fstat(child)
            _directory(state, private=index == len(parts) - 2)
            links.append((parent, name, child, _identity(state)))
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=parent)
        descriptors.append(fd)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_uid != os.getuid() or before.st_mode & 0o077 or
                before.st_size > MAX_CREDENTIAL_BYTES):
            _fail()
        chunks, size = [], 0
        while size <= MAX_CREDENTIAL_BYTES:
            chunk = os.read(fd, min(8192, MAX_CREDENTIAL_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > MAX_CREDENTIAL_BYTES or _file_state(before) != _file_state(os.fstat(fd)):
            _fail()
        data = json.loads(b''.join(chunks).decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=_constant)
        session = _session(data, time.time() if now is None else now)
        if _file_state(before) != _file_state(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)):
            _fail()
        if _identity(root_state) != _identity(os.stat('/', follow_symlinks=False)):
            _fail()
        for ancestor, name, child, expected in links:
            if (expected != _identity(os.fstat(child)) or
                    expected != _identity(os.stat(name, dir_fd=ancestor, follow_symlinks=False))):
                _fail()
        return session
    except (OSError, ValueError, TypeError, RecursionError, OverflowError, PlanError):
        raise CredentialError('Protected SIWC credential record is invalid or unavailable') from None
    finally:
        for fd in reversed(descriptors):
            os.close(fd)
