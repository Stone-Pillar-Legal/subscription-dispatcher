import json
import unittest
from subscription_dispatcher.policy import Kernel
from subscription_dispatcher.runner import Run, Runner, RunError


def call(name, args, ident='call1', namespace='matter'):
    return dict(type='function_call', namespace=namespace, name=name,
                arguments=json.dumps(args), call_id=ident)


class Model:
    def __init__(self, outputs):
        self.outputs = iter(outputs)
        self.requests = []
    def complete(self, **kwargs):
        self.requests.append(kwargs)
        return dict(status='completed', output=next(self.outputs))


class RunnerTests(unittest.TestCase):
    def setup_run(self, outputs, read_only=False):
        self.reads, self.writes = [], []
        def read(*args):
            self.reads.append(args)
            return b'synthetic evidence'
        def create(*args):
            self.writes.append(args)
            return 'created-item'
        kernel = Kernel(read=read, create=create)
        grant = kernel.issue(run_id='run', principal='owner', agent='agent',
            matter='matter', site_id='site', drive_id='drive', read_items=['input'],
            output_folders=[] if read_only else ['output'], read_only=read_only)
        run = Run(grant.grant_id, 'owner', 'agent', 'matter', 'catalog-model', 'test', read_only)
        model = Model(outputs)
        return Runner(model, kernel), run, model

    def test_complete_read_then_create_flow(self):
        runner, run, model = self.setup_run([
            [call('read', {'resource':'input'})],
            [call('create', {'resource':'output','content':'synthetic result','idempotency_key':'one'}, 'call2')],
            [dict(type='message', role='assistant', content=[])]])
        self.assertEqual(runner.run(run, 'synthetic task')['status'], 'completed')
        self.assertEqual(len(self.reads), 1)
        self.assertEqual(len(self.writes), 1)
        self.assertEqual(self.writes[0][:3], ('site','drive','output'))
        self.assertEqual(len(model.requests), 3)

    def test_cross_matter_and_identity_override_rejected(self):
        for args in ({'resource':'other-matter'}, {'resource':'input','principal':'admin'},
                     {'resource':'input','drive_id':'another-drive'}):
            runner, run, _ = self.setup_run([[call('read', args)]])
            with self.assertRaises(RunError): runner.run(run, 'test')
            self.assertEqual(self.reads, [])
            self.assertEqual(self.writes, [])

    def test_unadvertised_write_read_only_still_denied(self):
        runner, run, _ = self.setup_run([[call('create', dict(resource='output', content='x', idempotency_key='a'))]], True)
        with self.assertRaises(RunError): runner.run(run, 'test')
        self.assertEqual(self.writes, [])

    def test_shell_and_raw_connector_calls_cannot_execute(self):
        for name, namespace in [('exec','shell'), ('upload_file','sharepoint'), ('delete','matter')]:
            runner, run, _ = self.setup_run([[call(name, {}, namespace=namespace)]])
            with self.assertRaises(RunError): runner.run(run, 'test')
            self.assertEqual(self.writes, [])

    def test_cancel_before_model_call(self):
        runner, run, model = self.setup_run([])
        with self.assertRaises(RunError): runner.run(run, 'test', cancelled=lambda:True)
        self.assertEqual(model.requests, [])

    def test_cancel_during_final_inference_is_not_success(self):
        runner, run, model = self.setup_run([])
        stopped = [False]
        def complete(**kwargs):
            stopped[0] = True
            return dict(status='completed', output=[])
        model.complete = complete
        with self.assertRaises(RunError):
            runner.run(run, 'test', cancelled=lambda:stopped[0])
