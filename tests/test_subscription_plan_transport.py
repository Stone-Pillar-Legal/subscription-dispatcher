import io
import json
import unittest
from email.message import Message
from subscription_dispatcher.plan_transport import (
    PlanError, PlanSession, PlanTransport, completed_response)


def event(kind, **extra):
    return ('data: ' + json.dumps(dict(type=kind, **extra)) + '\n\n').encode()


class Reply(io.BytesIO):
    headers = Message()
    headers['Content-Type'] = 'text/event-stream'


class Opener:
    def __init__(self, body):
        self.body, self.requests = body, []
    def open(self, req, timeout):
        self.requests.append(req)
        if isinstance(self.body, Exception):
            raise self.body
        return Reply(self.body)


class PlanTests(unittest.TestCase):
    def session(self, **overrides):
        fields = dict(access_token='synthetic-oauth', client_id='oaiapp_test',
                      subject='synthetic', scopes=frozenset(('resource.invoke',
                      'chatgpt.tokens.use.direct')), expires_at=1000)
        fields.update(overrides)
        return PlanSession(**fields)

    def test_expired_api_key_and_missing_scope_rejected_before_network(self):
        for kwargs in (dict(access_token='sk-test'), dict(scopes=frozenset()),
                       dict(expires_at=101), dict(client_id='dynamic_agent_client'),
                       dict(expires_at=float('nan')), dict(expires_at=float('inf')),
                       dict(expires_at='1000')):
            with self.subTest(kwargs=kwargs):
                opener = Opener(b'')
                t = PlanTransport(lambda: self.session(**kwargs), clock=lambda:100,
                                  opener=opener)
                with self.assertRaises(PlanError):
                    t.complete(model='catalog-model', instructions='', history=[], tools=[])
                self.assertEqual(opener.requests, [])

    def test_complete_subscription_request_has_fixed_endpoint_and_no_fallback(self):
        opener = Opener(event('response.completed', response=dict(status='completed', output=[])))
        t = PlanTransport(self.session, clock=lambda:100, opener=opener)
        self.assertEqual(t.complete(model='catalog-model', instructions='test', history=[], tools=[])['status'], 'completed')
        req = opener.requests[0]
        self.assertEqual(req.full_url, 'https://api.openai.com/v1/responses')
        self.assertEqual(json.loads(req.data)['store'], False)
        self.assertEqual(json.loads(req.data)['stream'], True)
        self.assertEqual(len(opener.requests), 1)

    def test_no_shell_connectors_or_hosted_tools(self):
        t = PlanTransport(self.session, clock=lambda:100, opener=Opener(b''))
        for tool in ({'type':'mcp'}, {'type':'web_search'}, {'type':'namespace','name':'shell','tools':[]}):
            with self.assertRaises(PlanError):
                t.complete(model='test', instructions='', history=[], tools=[tool])

    def test_failed_incomplete_and_truncated_are_not_success(self):
        for body in (b'', event('response.output_text.delta', delta='Looks successful'),
                     event('response.failed'), event('response.incomplete'),
                     b'data: {broken}\n\n', event('response.completed', response={})):
            with self.subTest(body=body), self.assertRaises(PlanError):
                completed_response(io.BytesIO(body))

    def test_network_failure_does_not_retry_or_reveal_secrets(self):
        opener = Opener(RuntimeError('secret-token'))
        t = PlanTransport(self.session, clock=lambda:100, opener=opener)
        with self.assertRaises(PlanError) as cm:
            t.complete(model='test', instructions='', history=[], tools=[])
        self.assertNotIn('secret-token', str(cm.exception))
        self.assertEqual(len(opener.requests), 1)

    def test_failure_after_completion_rejected(self):
        body = event('response.completed', response=dict(status='completed', output=[])) + event('response.failed')
        with self.assertRaises(PlanError):
            completed_response(io.BytesIO(body))

    def test_done_requires_prior_completion(self):
        body = event('response.completed', response=dict(status='completed', output=[])) + b'data: [DONE]\n\n'
        self.assertEqual(completed_response(io.BytesIO(body))['status'], 'completed')
        with self.assertRaises(PlanError):
            completed_response(io.BytesIO(b'data: [DONE]\n\n'))

    def test_session_repr_does_not_disclose_bearer(self):
        self.assertNotIn('synthetic-oauth', repr(self.session()))
