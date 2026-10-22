"""Private create-only credential persistence; no OAuth validation or networking.

Input is bounded JSON on stdin; output contains only status/path. All filesystem
operations are relative to pinned no-follow directory descriptors. Root/current
uid ancestors may be searchable, but not group/other writable except root-owned
sticky temporary directories. The final directory must be current-uid private.
Same-uid hostile processes remain outside this boundary. Incomplete temporary
files are retained on failure for inspection; never clean up through changed paths.
"""
import json
import os
import re
import secrets
import stat
import sys

LIMIT = 65536


def pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def invalid(_):
    raise ValueError()


def identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode)


def file_state(s):
    return identity(s) + (s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def private_file(s):
    if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077 or s.st_nlink != 1 or s.st_size > LIMIT:
        raise ValueError()


def save(directory, record):
    """Return published/reconciled, durability-unconfirmed, or refused.

    An identical retry verifies the existing protected bytes and fsyncs both file
    and directory. A different record is never replaced. Unconfirmed publication
    is not a success and must be reconciled before the caller uses the record.
    """
    fds = []
    published = False
    target = None
    try:
        if type(directory) is not str or not directory.startswith('/') or any(x in ('', '.', '..') for x in directory.split('/')[1:]):
            raise ValueError()
        if type(record) is not dict or record.get('format') != 'siwc-validated-v1' or not re.fullmatch(r'oaiapp_[A-Za-z0-9_-]+', record.get('client_id', '')):
            raise ValueError()
        data = json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
        if len(data) > LIMIT:
            raise ValueError()
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        root = os.open('/', flags)
        fds.append(root)
        parent = root
        chain = []
        parts = directory.split('/')[1:]
        for i, component in enumerate(parts):
            child = os.open(component, flags, dir_fd=parent)
            fds.append(child)
            s = os.fstat(child)
            if s.st_uid not in (0, os.getuid()) or (s.st_mode & 0o022 and not (s.st_uid == 0 and s.st_mode & stat.S_ISVTX)):
                raise ValueError()
            if i == len(parts)-1 and (s.st_uid != os.getuid() or s.st_mode & 0o077):
                raise ValueError()
            chain.append((parent, component, child, identity(s)))
            parent = child
        def check():
            for ancestor, component, child, expected in chain:
                if identity(os.fstat(child)) != expected or identity(os.stat(component, dir_fd=ancestor, follow_symlinks=False)) != expected:
                    raise ValueError()
        name = record['client_id'] + '.json'
        target = directory + '/' + name
        check()
        temporary = '.pending-' + secrets.token_hex(24)
        # Check existing records first; do not create another temporary on retry.
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            fd = None
        if fd is not None:
            fds.append(fd)
            before = os.fstat(fd)
            private_file(before)
            content = bytearray()
            while len(content) <= LIMIT:
                chunk = os.read(fd, min(8192, LIMIT+1-len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            if bytes(content) != data or file_state(os.fstat(fd)) != file_state(before):
                raise ValueError()
            published = True
            os.fsync(fd)
            os.fsync(parent)
            check()
            if file_state(os.stat(name, dir_fd=parent, follow_symlinks=False)) != file_state(before):
                raise ValueError()
            return {'status': 'reconciled', 'path': target}
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        fds.append(fd)
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise ValueError()
            view = view[count:]
        os.fsync(fd)
        private_file(os.fstat(fd))
        check()
        os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        published = True
        os.unlink(temporary, dir_fd=parent)
        os.fsync(fd)
        os.fsync(parent)
        check()
        final = os.stat(name, dir_fd=parent, follow_symlinks=False)
        private_file(final)
        if file_state(final) != file_state(os.fstat(fd)):
            raise ValueError()
        return {'status': 'published', 'path': target}
    except Exception:
        return ({'status': 'published-but-durability-unconfirmed', 'path': target}
                if published else {'status': 'refused'})
    finally:
        for fd in reversed(fds):
            os.close(fd)


def main():
    try:
        raw = sys.stdin.buffer.read(LIMIT+1)
        if len(raw) > LIMIT:
            raise ValueError()
        request = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=invalid)
        if type(request) is not dict or set(request) != {'directory', 'record'}:
            raise ValueError()
        result = save(request['directory'], request['record'])
    except Exception:
        result = {'status': 'refused'}
    print(json.dumps(result))


if __name__ == '__main__':
    main()
