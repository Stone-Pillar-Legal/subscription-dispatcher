"""Permanent resource ownership metadata for trusted server code only.

Not a model tool or authenticator. Callers supply authenticated principals and
canonical provider/resource identifiers, never credentials. Retirement reserves
both identities forever. A returned Binding is a point-in-time lookup, not a
lease against concurrent retirement or authorization for remote I/O.
"""
from dataclasses import dataclass
import unicodedata
import uuid


class ResourceError(Exception):
    """Invalid, unavailable, or permanently conflicting resource binding."""


def _identifier(value):
    if (type(value) is not str or not value or len(value) > 512
            or any(c.isspace() or unicodedata.category(c).startswith('C') for c in value)
            or len(value.encode('utf-8')) > 512):
        raise ResourceError('Invalid resource identity')
    return value


@dataclass(frozen=True, slots=True)
class Binding:
    id: str
    principal: str
    matter: str
    provider: str
    resource_id: str
    root_id: str
    site_id: str


_FIELDS = ('principal', 'matter', 'provider', 'resource_id', 'root_id', 'site_id')


class ResourceRegistry:
    """Uses the injected private store's SQLite transaction/connection API.

    Exact strings are identities; provider-specific canonicalization belongs to
    the trusted registry caller. No deletion, reassignment, or reactivation API.
    """
    def __init__(self, store):
        self.store = store
        with store.transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS resource_bindings (
                id TEXT PRIMARY KEY, principal TEXT NOT NULL, matter TEXT NOT NULL,
                provider TEXT NOT NULL, resource_id TEXT NOT NULL,
                root_id TEXT NOT NULL, site_id TEXT NOT NULL,
                retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0,1)),
                UNIQUE(provider,resource_id), UNIQUE(principal,matter,provider))""")

    @staticmethod
    def _binding(row):
        return Binding(**{key: row[key] for key in ('id',) + _FIELDS})

    def register(self, principal, matter, provider, resource_id, root_id, site_id):
        values = tuple(map(_identifier, (principal, matter, provider, resource_id, root_id, site_id)))
        # BEGIN IMMEDIATE serializes competing checks and insertion, including
        # registries in other processes. Unique constraints retain tombstones.
        with self.store.transaction() as db:
            rows = db.execute("""SELECT * FROM resource_bindings
                WHERE (provider=? AND resource_id=?)
                   OR (principal=? AND matter=? AND provider=?)""",
                (provider, resource_id, principal, matter, provider)).fetchall()
            if rows:
                if (len(rows) == 1 and not rows[0]['retired']
                        and tuple(rows[0][key] for key in _FIELDS) == values):
                    return self._binding(rows[0])
                raise ResourceError('Resource binding is unavailable or permanently reserved')
            binding = Binding(str(uuid.uuid4()), *values)
            db.execute("""INSERT INTO resource_bindings
                (id,principal,matter,provider,resource_id,root_id,site_id)
                VALUES (?,?,?,?,?,?,?)""", (binding.id,) + values)
            return binding

    def get(self, binding_id, principal, matter):
        values = tuple(map(_identifier, (binding_id, principal, matter)))
        with self.store.connection() as db:
            row = db.execute("""SELECT * FROM resource_bindings
                WHERE id=? AND principal=? AND matter=? AND retired=0""", values).fetchone()
            if row is None:
                raise ResourceError('Active resource binding not found')
            return self._binding(row)

    def retire(self, binding_id, principal):
        values = tuple(map(_identifier, (binding_id, principal)))
        with self.store.transaction() as db:
            row = db.execute('SELECT id FROM resource_bindings WHERE id=? AND principal=?', values).fetchone()
            if row is None:
                raise ResourceError('Resource binding not found')
            db.execute('UPDATE resource_bindings SET retired=1 WHERE id=? AND principal=?', values)
