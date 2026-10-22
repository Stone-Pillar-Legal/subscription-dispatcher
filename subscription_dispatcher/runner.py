"""Bounded function-call loop. No shell, subprocess, MCP or connector inheritance.

Trusted callers construct Run objects from authenticated identity and private policy.
The model can ask for a resource operation but cannot select its grant or identity.
This is a library, not yet a public HTTP dispatcher or durable job service.
"""
from dataclasses import dataclass
import json
from .policy import Denied, OutcomeUnknown


class RunError(Exception):
    pass


@dataclass(frozen=True)
class Run:
    grant_id: str
    principal: str
    agent: str
    matter: str
    model: str
    instructions: str
    read_only: bool


def tool_schema(read_only):
    def function(name, properties):
        return dict(type='function', name=name, strict=True,
                    description='Use only resources authorized for this run.',
                    parameters=dict(type='object', properties=properties,
                                    required=list(properties), additionalProperties=False))
    functions = [function('read', {'resource': {'type': 'string'}})]
    if not read_only:
        functions.append(function('create', {
            'resource': {'type':'string'}, 'content': {'type':'string'},
            'idempotency_key': {'type':'string'}}))
    return [dict(type='namespace', name='matter', description='Scoped matter storage', tools=functions)]


def strict_object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RunError('Duplicate tool argument')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (TypeError, ValueError):
        raise RunError('Invalid tool arguments') from None
    if not isinstance(value, dict):
        raise RunError('Tool arguments must be an object')
    return value


class Runner:
    def __init__(self, transport, kernel, *, max_rounds=12, max_context_bytes=2*1024*1024):
        self.transport, self.kernel = transport, kernel
        self.max_rounds, self.max_context_bytes = max_rounds, max_context_bytes

    def run(self, run, task, *, cancelled=lambda:False):
        history = [dict(role='user', content=task)]
        calls_seen = set()
        for _ in range(self.max_rounds):
            if cancelled():
                self.kernel.cancel(run.grant_id)
                raise RunError('Run cancelled')
            if len(json.dumps(history).encode()) > self.max_context_bytes:
                raise RunError('Run context exceeds limit')
            response = self.transport.complete(model=run.model,
                instructions=run.instructions, history=history,
                tools=tool_schema(run.read_only))
            if cancelled():
                self.kernel.cancel(run.grant_id)
                raise RunError('Run cancelled')
            outputs = response['output']
            calls = []
            for item in outputs:
                kind = item.get('type')
                if kind == 'function_call':
                    calls.append(item)
                elif kind not in ('message', 'reasoning'):
                    raise RunError('Unsupported model output type')
            history.extend(outputs)
            if not calls:
                return response
            for call in calls:
                if cancelled():
                    self.kernel.cancel(run.grant_id)
                    raise RunError('Run cancelled')
                name = call.get('name')
                call_id = call.get('call_id')
                if (call.get('namespace') != 'matter' or name not in ('read', 'create')
                        or not isinstance(call_id, str) or not call_id or call_id in calls_seen):
                    raise RunError('Unrecognized or repeated tool call')
                calls_seen.add(call_id)
                args = strict_object(call.get('arguments'))
                expected = {'resource'} if name == 'read' else {'resource','content','idempotency_key'}
                if set(args) != expected or any(type(v) is not str for v in args.values()):
                    raise RunError('Unexpected tool arguments')
                if name == 'create' and run.read_only:
                    raise RunError('Write requested by read-only role')
                try:
                    value = self.kernel.execute(run.grant_id,
                        principal=run.principal, agent=run.agent, matter=run.matter,
                        operation=name, resource=args['resource'],
                        content=args['content'].encode() if name == 'create' else None,
                        idempotency_key=args.get('idempotency_key'))
                    if name == 'read':
                        result = {'text': value.decode('utf-8')}
                    else:
                        result = {'item_id': value.item_id, 'sha256': value.sha256}
                except (Denied, OutcomeUnknown, UnicodeError):
                    # Stop; do not ask the model to improvise around authorization.
                    raise RunError('Storage operation denied or unresolved') from None
                history.append(dict(type='function_call_output', call_id=call_id,
                                    output=json.dumps(result)))
        raise RunError('Maximum model rounds reached')
