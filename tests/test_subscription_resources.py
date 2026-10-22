import dataclasses
from concurrent.futures import ThreadPoolExecutor
import tempfile
import threading
import unittest

from subscription_dispatcher.jobs import JobStore
from subscription_dispatcher.resources import Binding, ResourceError, ResourceRegistry


class ResourceRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = JobStore(self.temp.name)
        self.registry = ResourceRegistry(self.store)
        self.args = dict(principal='owner', matter='matter', provider='provider',
                         resource_id='resource', root_id='root', site_id='site')

    def register(self, **changes):
        return self.registry.register(**(self.args | changes))

    def test_exact_registration_restart_and_immutable_value(self):
        first = self.register()
        self.assertIsInstance(first, Binding)
        self.assertEqual(first, self.register())
        other = ResourceRegistry(JobStore(self.temp.name))
        self.assertEqual(first, other.register(**self.args))
        self.assertEqual(first, other.get(first.id, 'owner', 'matter'))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.root_id = 'changed'
        self.assertEqual(set(dataclasses.asdict(first)), {'id', *self.args})

    def test_every_binding_change_denied(self):
        first = self.register()
        for field in ('principal', 'matter', 'resource_id', 'root_id', 'site_id'):
            with self.subTest(field=field), self.assertRaises(ResourceError):
                self.register(**{field: 'different'})
        self.assertEqual(first, self.registry.get(first.id, 'owner', 'matter'))
        # Different providers have separate namespaces, as specified.
        self.assertNotEqual(first.id, self.register(provider='other-provider').id)

    def test_cross_owner_matter_and_missing_access(self):
        first = self.register()
        for ident, owner, matter in ((first.id,'other','matter'),
                                     (first.id,'owner','other'), ('missing','owner','matter')):
            with self.assertRaises(ResourceError):
                self.registry.get(ident, owner, matter)
        with self.assertRaises(ResourceError): self.registry.retire(first.id, 'other')
        with self.assertRaises(ResourceError): self.registry.retire('missing', 'owner')
        self.assertEqual(first, self.registry.get(first.id, 'owner', 'matter'))

    def test_retirement_permanent_across_restart(self):
        first = self.register()
        self.registry.retire(first.id, 'owner')
        self.registry = ResourceRegistry(JobStore(self.temp.name))
        self.registry.retire(first.id, 'owner')  # idempotent owner retirement
        with self.assertRaises(ResourceError): self.registry.get(first.id, 'owner', 'matter')
        for changes in ({}, {'principal':'other'}, {'matter':'other'},
                        {'resource_id':'replacement'}, {'root_id':'replacement'}, {'site_id':'other'}):
            with self.subTest(changes=changes), self.assertRaises(ResourceError):
                self.register(**changes)

    def test_invalid_identifiers_all_entry_points(self):
        for bad in ('', ' ', ' padded', 'x y', 'x\n', 'x\x00', 'x\x7f', 'x\u200b',
                    'x'*513, 'é'*257, '\ud800', None, 1, b'bytes'):
            for field in self.args:
                with self.subTest(field=field, bad=repr(bad)), self.assertRaises(ResourceError):
                    self.register(**{field:bad})
            with self.assertRaises(ResourceError): self.registry.get(bad, 'owner', 'matter')
            with self.assertRaises(ResourceError): self.registry.get('id', bad, 'matter')
            with self.assertRaises(ResourceError): self.registry.get('id', 'owner', bad)
            with self.assertRaises(ResourceError): self.registry.retire(bad, 'owner')
            with self.assertRaises(ResourceError): self.registry.retire('id', bad)
        self.register(root_id='x'*512)

    def race(self, argument_sets):
        barrier = threading.Barrier(len(argument_sets))
        def work(args):
            registry = ResourceRegistry(JobStore(self.temp.name))
            barrier.wait(timeout=10)
            try:
                return registry.register(**args)
            except ResourceError:
                return None
        with ThreadPoolExecutor(max_workers=len(argument_sets)) as pool:
            return list(pool.map(work, argument_sets))

    def test_concurrent_identical_registration_one_identity(self):
        results = self.race([self.args.copy() for _ in range(8)])
        self.assertTrue(all(isinstance(x, Binding) for x in results))
        self.assertEqual(len({x.id for x in results}), 1)

    def test_concurrent_resource_reassignment_has_one_winner(self):
        results = self.race([self.args | {'principal':f'owner-{i}', 'matter':f'matter-{i}'}
                             for i in range(8)])
        self.assertEqual(sum(x is not None for x in results), 1)

    def test_concurrent_matter_rebinding_has_one_winner(self):
        results = self.race([self.args | {'resource_id':f'resource-{i}'} for i in range(8)])
        self.assertEqual(sum(x is not None for x in results), 1)

    def test_register_racing_retire_cannot_reactivate(self):
        first = self.register()
        barrier = threading.Barrier(2)
        def register():
            barrier.wait(timeout=10)
            try: return self.register()
            except ResourceError: return None
        def retire():
            barrier.wait(timeout=10)
            self.registry.retire(first.id, 'owner')
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(register), pool.submit(retire)]
            for future in futures: future.result()
        with self.assertRaises(ResourceError): self.register()
        with self.assertRaises(ResourceError): self.registry.get(first.id, 'owner', 'matter')


if __name__ == '__main__':
    unittest.main()
