"""Explicit ChatGPT-plan transport; never reads API keys or ambient credentials.

The authentication service must supply a validated SIWC registration. This module
is not an OAuth authenticator and must not be exposed directly to browser input.
"""
from dataclasses import dataclass, field
import json
import math
import urllib.request
import urllib.error

ENDPOINT = 'https://api.openai.com/v1/responses'
REQUIRED_SCOPES = frozenset(('chatgpt.tokens.use.direct', 'resource.invoke'))
MAX_EVENT_BYTES = 4 * 1024 * 1024
MAX_STREAM_BYTES = 32 * 1024 * 1024


class PlanError(Exception):
    """Sanitized failure; caller must stop, never switch billing providers."""


@dataclass(frozen=True)
class PlanSession:
    # Only constructed by a trusted OAuth validator, never from dashboard JSON.
    access_token: str = field(repr=False)
    client_id: str
    subject: str
    scopes: frozenset
    expires_at: float

    def validate(self, now):
        if (type(now) not in (int, float) or not math.isfinite(now)
                or type(self.expires_at) not in (int, float)
                or not math.isfinite(self.expires_at)):
            raise PlanError('Invalid authorization lifetime')
        if (not isinstance(self.access_token, str) or not self.access_token
                or self.access_token.startswith('sk-')
                or any(c.isspace() for c in self.access_token)
                or not isinstance(self.client_id, str)
                or not self.client_id.startswith('oaiapp_')
                or not self.subject or not REQUIRED_SCOPES.issubset(self.scopes)
                or self.expires_at <= now + 30):
            raise PlanError('ChatGPT plan authorization is missing or expired')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def completed_response(lines):
    """Parse bounded SSE. Partial output is never treated as completed output."""
    data, total, event_size = [], 0, 0
    completed = None
    for raw in lines:
        total += len(raw)
        event_size += len(raw)
        if total > MAX_STREAM_BYTES or event_size > MAX_EVENT_BYTES:
            raise PlanError('Model stream exceeds limit')
        try:
            line = raw.decode('utf-8').rstrip('\r\n')
        except (UnicodeError, AttributeError):
            raise PlanError('Unreadable model stream') from None
        if not line:
            if data:
                payload = '\n'.join(data)
                if payload == '[DONE]':
                    data = []
                    break
                try:
                    event = json.loads(payload)
                    kind = event['type']
                except (ValueError, KeyError, TypeError):
                    raise PlanError('Unreadable model event') from None
                if kind in ('error', 'response.failed', 'response.incomplete'):
                    raise PlanError('ChatGPT plan request failed or was incomplete')
                if kind == 'response.completed':
                    if completed is not None:
                        raise PlanError('Duplicate completion event')
                    completed = event.get('response')
                    if (not isinstance(completed, dict)
                            or completed.get('status') != 'completed'
                            or not isinstance(completed.get('output'), list)):
                        raise PlanError('Invalid completed response')
            data, event_size = [], 0
        elif line.startswith('data:'):
            data.append(line[5:].lstrip(' '))
    if completed is None or data:
        raise PlanError('Stream ended without a complete response')
    return completed


class PlanTransport:
    def __init__(self, session_provider, *, clock, opener=None):
        self.session_provider = session_provider
        self.clock = clock
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect())

    def complete(self, *, model, instructions, history, tools):
        session = self.session_provider()
        if not isinstance(session, PlanSession):
            raise PlanError('Validated ChatGPT session required')
        session.validate(self.clock())
        # Model and tools are server selected, not arbitrary browser payloads.
        if not isinstance(model, str) or not model or not isinstance(history, list):
            raise PlanError('Invalid model request')
        for tool in tools:
            if (tool.get('type') != 'namespace'
                    or tool.get('name') != 'matter'
                    or not isinstance(tool.get('tools'), list)
                    or any(t.get('type') != 'function' for t in tool['tools'])):
                raise PlanError('Only broker function tools are permitted')
        payload = dict(model=model, instructions=instructions, input=history,
                       tools=tools, store=False, stream=True)
        req = urllib.request.Request(ENDPOINT, data=json.dumps(payload).encode(),
            headers={'Authorization': 'Bearer ' + session.access_token,
                     'Content-Type': 'application/json', 'Accept': 'text/event-stream'},
            method='POST')
        try:
            with self.opener.open(req, timeout=60) as response:
                if response.headers.get_content_type() != 'text/event-stream':
                    raise PlanError('Expected a streaming model response')
                return completed_response(response)
        except PlanError:
            raise
        except Exception:
            # No retries, fallback providers, response bodies or credentials logged.
            raise PlanError('ChatGPT plan request unavailable; no fallback attempted') from None
