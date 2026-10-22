"""Synthetic authorization/storage tests; no provider, credentials or remote I/O."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
import hashlib
import threading
import unittest
from unittest.mock import Mock

from subscription_dispatcher.policy import Kernel, Denied, OutcomeUnknown


class DispatcherPolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.read = Mock(return_value=b'synthetic input')
        self.create = Mock(return_value='created-item')
        self.kernel = Kernel(read=self.read, create=self.create, clock=lambda: self.now,
                             max_bytes=64, max_writes=3)
        self.grant = self.issue()

    def issue(self, **changes):
        args = dict(run_id='run-1', principal='principal-1', agent='writer', matter='matter-1',
                    site_id='server-site', drive_id='server-drive', read_items=['input-1'],
                    output_folders=['output-1', 'output-2'], read_only=False, ttl=10)
        args.update(changes)
        return self.kernel.issue(**args)

    def execute(self, **changes):
        args = dict(principal='principal-1', agent='writer', matter='matter-1',
                    operation='create', resource='output-1', content=b'output', idempotency_key='request-1')
        args.update(changes)
        return self.kernel.execute(self.grant.grant_id, **args)

    def test_exact_storage_coordinates_and_immutable_results(self):
        result = self.execute()
        self.create.assert_called_once_with('server-site', 'server-drive', 'output-1',
            result.operation_id, b'output', hashlib.sha256(b'output').hexdigest())
        with self.assertRaises(FrozenInstanceError):
            result.item_id = 'forged'
        self.assertEqual(self.execute(operation='read', resource='input-1', content=None,
                                      idempotency_key=None), b'synthetic input')
        self.read.assert_called_once_with('server-site', 'server-drive', 'input-1', 64)

    def test_identity_and_resource_rejections_never_call_storage(self):
        for changes in ({'principal': 'other'}, {'agent': 'other'}, {'matter': 'other'},
                        {'resource': 'unapproved-folder'}, {'resource': '../output-1'},
                        {'resource': 'https://example.test/output-1'}):
            with self.subTest(changes=changes), self.assertRaises(Denied):
                self.execute(**changes)
        for resource in ('output-1', 'input-2', '../input-1'):
            with self.assertRaises(Denied):
                self.execute(operation='read', resource=resource, content=None, idempotency_key=None)
        self.read.assert_not_called(); self.create.assert_not_called()

    def test_unknown_operations_and_extra_coordinates_refused(self):
        for operation in ('delete', 'overwrite', 'update', 'patch', 'issue', 'cancel', 'policy', None, 1):
            with self.subTest(operation=operation), self.assertRaises(Denied):
                self.execute(operation=operation)
        for key in ('site_id', 'drive_id', 'path', 'filename'):
            with self.subTest(key=key), self.assertRaises(TypeError):
                self.execute(**{key: 'caller-selected'})
        self.create.assert_not_called()

    def test_server_grant_is_frozen_and_defensive_inventory_copy(self):
        items = ['input-1']; folders = ['output-1']
        grant = self.issue(run_id='run-2', read_items=items, output_folders=folders)
        items.append('secret'); folders.append('forbidden')
        self.assertEqual(grant.read_items, frozenset({'input-1'}))
        with self.assertRaises(FrozenInstanceError):
            grant.agent = 'different'
        forged = replace(self.grant, output_folders=frozenset({'forbidden'}))
        with self.assertRaises(Denied):
            self.kernel.execute(forged.grant_id, principal='principal-1', agent='writer', matter='matter-1',
                                operation='create', resource='forbidden', content=b'x', idempotency_key='x')
        with self.assertRaises(Denied):
            self.issue()  # No replacement/extension of the same run.
        self.create.assert_not_called()

    def test_readonly_grants_cannot_authorize_or_perform_writes(self):
        with self.assertRaises(Denied):
            self.issue(run_id='reader', read_only=True)
        self.grant = self.issue(run_id='reader', read_only=True, output_folders=())
        with self.assertRaises(Denied):
            self.execute()
        self.assertEqual(self.execute(operation='read', resource='input-1', content=None,
                                      idempotency_key=None), b'synthetic input')
        self.create.assert_not_called()

    def test_expiry_cancel_and_replay_remain_authorized_operations(self):
        self.execute()
        self.now = self.grant.expires_at
        with self.assertRaises(Denied):
            self.execute()  # Even cached replies require current authority.
        self.grant = self.issue(run_id='cancelled')
        self.kernel.cancel(self.grant.grant_id)
        self.kernel.cancel(self.grant.grant_id)
        with self.assertRaises(Denied):
            self.execute()
        self.assertEqual(self.create.call_count, 1)

    def test_write_idempotency_binds_folder_and_exact_bytes(self):
        first = self.execute()
        self.assertEqual(first, self.execute())
        for change in ({'content': b'different'}, {'resource': 'output-2'}):
            with self.assertRaises(Denied):
                self.execute(**change)
        self.assertEqual(self.create.call_count, 1)

    def test_unknown_outcome_blocks_retries_even_with_new_keys(self):
        remote = []
        def lost(*args):
            remote.append(args)
            raise TimeoutError('response lost after remote create')
        self.create.side_effect = lost
        for key in ('request-1', 'request-1', 'different-key'):
            with self.assertRaises(OutcomeUnknown):
                self.execute(idempotency_key=key)
        self.assertEqual(len(remote), 1)
        with self.assertRaises(Denied):
            self.execute(content=b'changed')

    def test_all_create_failures_remain_unknown_including_bad_receipt(self):
        for failure in (OSError('before or after send unknown'), KeyboardInterrupt(), None):
            with self.subTest(failure=type(failure).__name__):
                self.grant = self.issue(run_id=str(type(failure)))
                self.create.reset_mock()
                self.create.side_effect = failure
                self.create.return_value = None
                with self.assertRaises(OutcomeUnknown): self.execute()
                with self.assertRaises(OutcomeUnknown): self.execute()
                self.assertEqual(self.create.call_count, 1)

    def test_concurrent_same_key_calls_create_once(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.execute(), range(20)))
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(self.create.call_count, 1)

    def test_cancellation_serializes_with_inflight_call(self):
        entered, release, cancelling, finished = (threading.Event() for _ in range(4))
        def blocked(*args):
            entered.set()
            if not release.wait(3): raise TimeoutError('test barrier')
            return 'created-item'
        self.create.side_effect = blocked
        def cancel():
            cancelling.set()
            self.kernel.cancel(self.grant.grant_id)
            finished.set()
        with ThreadPoolExecutor(max_workers=2) as pool:
            call = pool.submit(self.execute)
            self.assertTrue(entered.wait(3))
            cancellation = pool.submit(cancel)
            try:
                self.assertTrue(cancelling.wait(3))
                self.assertFalse(finished.wait(.05))
            finally:
                release.set()
            call.result(timeout=3); cancellation.result(timeout=3)
        with self.assertRaises(Denied): self.execute(idempotency_key='new')
        self.assertEqual(self.create.call_count, 1)

    def test_limits_and_read_results(self):
        for content in (bytearray(b'x'), 'x', b'x' * 65):
            with self.assertRaises(Denied): self.execute(content=content)
        for result in (b'x' * 65, 'not bytes'):
            self.read.return_value = result
            with self.assertRaises(Denied):
                self.execute(operation='read', resource='input-1', content=None, idempotency_key=None)
        for i in range(3): self.execute(idempotency_key=str(i), content=b'')
        with self.assertRaises(Denied): self.execute(idempotency_key='fourth')
        self.assertEqual(self.create.call_count, 3)

    def test_unknown_grant_and_invalid_lifetimes(self):
        with self.assertRaises(Denied): self.kernel.cancel('unknown')
        for ttl in (0, -1, float('nan'), float('inf'), True):
            with self.assertRaises(Denied): self.issue(run_id='bad', ttl=ttl)
        self.now = float('nan')
        with self.assertRaises(Denied): self.execute()
        self.create.assert_not_called()


if __name__ == '__main__':
    unittest.main()
