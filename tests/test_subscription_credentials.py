import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from subscription_dispatcher.credentials import (
    CredentialError, MAX_CREDENTIAL_BYTES, load_credentials)
from subscription_dispatcher.plan_transport import PlanSession


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # Resolve only the synthetic fixture root (macOS /var is a symlink).
        self.root = Path(self.temp.name).resolve()
        self.private = self.root / 'credentials'
        self.private.mkdir(mode=0o700)
        self.path = self.private / 'session.json'
        self.record = dict(format='siwc-validated-v1', issuer='https://auth.openai.com',
            subject='synthetic-user', client_id='oaiapp_synthetic',
            ext_agent_host_id='urn:uuid:synthetic-host', access_token='synthetic-bearer',
            refresh_token='synthetic-refresh', id_token='synthetic-id-token',
            scopes=['resource.invoke', 'chatgpt.tokens.use.direct'],
            expires_at=1000, validated_at=50)
        self.write()

    def write(self, data=None, raw=None):
        self.path.write_bytes(raw if raw is not None else json.dumps(self.record if data is None else data).encode())
        self.path.chmod(0o600)

    def reject(self):
        with self.assertRaises(CredentialError) as caught:
            load_credentials(self.path, now=100)
        for secret in ('synthetic-bearer', 'synthetic-refresh', 'synthetic-id-token'):
            self.assertNotIn(secret, str(caught.exception))

    def test_valid_record_returns_existing_session_without_extra_tokens(self):
        session = load_credentials(self.path, now=100)
        self.assertIsInstance(session, PlanSession)
        self.assertEqual(session.access_token, self.record['access_token'])
        self.assertEqual(session.scopes, frozenset(self.record['scopes']))
        self.assertNotIn('synthetic-bearer', repr(session))
        self.assertFalse(hasattr(session, 'refresh_token'))
        self.assertFalse(hasattr(session, 'id_token'))

    def test_optional_email(self):
        self.record['email'] = 'fixture@example.invalid'
        self.write()
        self.assertEqual(load_credentials(self.path, now=100).subject, 'synthetic-user')

    def test_missing_each_required_field(self):
        for key in self.record:
            with self.subTest(key=key):
                self.write({k:v for k,v in self.record.items() if k != key})
                self.reject()

    def test_invalid_values(self):
        for key, value in [('issuer','https://other.invalid'), ('format','raw-oauth'),
                ('subject',{}), ('access_token','sk-synthetic'), ('refresh_token',''),
                ('id_token',None), ('client_id','dynamic_agent_client'),
                ('ext_agent_host_id',''), ('scopes',[]), ('scopes','resource.invoke'),
                ('scopes',['resource.invoke']*2), ('scopes',[{}]),
                ('expires_at',130), ('expires_at',True), ('validated_at',101),
                ('validated_at',-1), ('validated_at','50'), ('email',4)]:
            with self.subTest(key=key, value=value):
                self.write(dict(self.record, **{key:value}))
                self.reject()

    def test_malformed_duplicate_constants_and_bounds(self):
        for raw in (b'{', b'\xff', b'[]', b'{"format":1,"format":2}',
                    b'{"expires_at":NaN}', b'{"expires_at":Infinity}',
                    b'{"expires_at":-Infinity}', b' '*(MAX_CREDENTIAL_BYTES+1)):
            with self.subTest(size=len(raw)):
                self.write(raw=raw)
                self.reject()

    def test_unknown_field_refused(self):
        self.write(dict(self.record, unexpected=True))
        self.reject()

    def test_file_and_directory_permissions(self):
        for target in (self.path, self.private):
            old = target.stat().st_mode & 0o777
            for mode in (0o644, 0o750, 0o770):
                with self.subTest(target=target.name, mode=mode):
                    target.chmod(mode)
                    self.reject()
            target.chmod(old)

    def test_owner_refused(self):
        with patch('subscription_dispatcher.credentials.os.getuid', return_value=os.getuid()+1):
            self.reject()

    def test_hardlink_refused_and_sibling_unchanged(self):
        sibling = self.private / 'second'
        os.link(self.path, sibling)
        before = sibling.read_bytes()
        self.reject()
        self.assertEqual(sibling.read_bytes(), before)

    def test_symlink_leaf(self):
        actual = self.private / 'actual'
        self.path.rename(actual)
        self.path.symlink_to(actual)
        self.reject()

    def test_symlink_parent_and_ancestor(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.private, target_is_directory=True)
        with self.assertRaises(CredentialError):
            load_credentials(alias / self.path.name, now=100)
        outer = self.root / 'outer'
        outer.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(CredentialError):
            load_credentials(outer / 'credentials' / self.path.name, now=100)

    def test_noncanonical_and_missing_paths(self):
        for path in ('relative.json', str(self.private)+'/../credentials/session.json',
                     str(self.private)+'//session.json', str(self.path)+'/',
                     self.private/'missing', self.private):
            with self.subTest(path=str(path)), self.assertRaises(CredentialError):
                load_credentials(path, now=100)

    def test_fifo_nonblocking_refusal(self):
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        self.reject()

    def test_expiry_checked_with_clock(self):
        with patch('subscription_dispatcher.credentials.time.time', return_value=990):
            with self.assertRaises(CredentialError):
                load_credentials(self.path)

    def test_replacement_during_read_refused(self):
        original = os.read
        replaced = False
        def read(fd, count):
            nonlocal replaced
            result = original(fd, count)
            if not replaced:
                replaced = True
                self.path.rename(self.private / 'retained')
                self.write()
            return result
        with patch('subscription_dispatcher.credentials.os.read', side_effect=read):
            self.reject()

    def test_parent_replacement_during_read_refused(self):
        original = os.read
        replaced = False
        def read(fd, count):
            nonlocal replaced
            result = original(fd, count)
            if not replaced:
                replaced = True
                self.private.rename(self.root / 'retained')
                self.private.mkdir(mode=0o700)
                self.write()
            return result
        with patch('subscription_dispatcher.credentials.os.read', side_effect=read):
            self.reject()

    def test_nonprivate_file_rejected_before_read(self):
        self.path.chmod(0o644)
        with patch('subscription_dispatcher.credentials.os.read') as read:
            self.reject()
            read.assert_not_called()


if __name__ == '__main__':
    unittest.main()
