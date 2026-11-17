"""PostgreSQL document store (JSONB) behind every Night Shift ledger.

One table per ledger -- incidents, approvals, contracts, changes, voice calls --
each ``(id text primary key, doc jsonb)``. The helpers here are the only SQL in
the code base; everything atomic that consent depends on (an approval used
exactly once, a contract use consumed exactly once) is a single conditional
``UPDATE ... RETURNING`` so two workers can never both win.
"""

from __future__ import annotations

import json
import os
import re
import threading
from typing import Any

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

_IDENT = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_lock = threading.Lock()
_pool: ConnectionPool | None = None
_ready: set[str] = set()
_ensure_lock = threading.RLock()


def dsn() -> str:
    return os.environ.get(
        "DATABASE_URL", "postgresql://beacon:beacon@localhost:5432/beacon"
    )


def table(name: str) -> str:
    """Validate a ledger name; it is interpolated as an identifier."""
    if not _IDENT.match(name):
        raise ValueError(f"invalid table name: {name!r}")
    return name


def pool() -> ConnectionPool:
    global _pool
    with _lock:
        if _pool is None:
            _pool = ConnectionPool(
                dsn(), min_size=1, max_size=8, kwargs={"autocommit": True}, open=True
            )
        return _pool


def reset() -> None:
    """Close the pool (tests, or after DATABASE_URL changes)."""
    global _pool
    with _lock:
        if _pool is not None:
            _pool.close()
        _pool = None
        _ready.clear()


def _ensure(name: str) -> str:
    name = table(name)
    if name not in _ready:
        import psycopg.errors as pge

        with _ensure_lock:
            if name in _ready:
                return name
            _create(name, pge)
    return name


def _create(name: str, pge: Any) -> None:

    # Two processes/threads creating the same table at the same instant can raise UniqueViolation or
    # DuplicateTable from the catalog even with IF NOT EXISTS; the table exists afterwards, so retry once.
    for attempt in (1, 2):
        try:
            with pool().connection() as conn:
                conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (name,))
                conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {name} ("
                    "id text PRIMARY KEY, doc jsonb NOT NULL, "
                    "created_at timestamptz NOT NULL DEFAULT now())"
                )
                conn.execute(
                    f"CREATE INDEX IF NOT EXISTS {name}_doc_gin ON {name} "
                    "USING gin (doc jsonb_path_ops)"
                )
            break
        except (pge.UniqueViolation, pge.DuplicateTable, pge.DuplicateObject):
            if attempt == 2:
                raise
    _ready.add(name)


def _plain(value: Any) -> Any:
    """JSON-normalise (datetimes, Decimals, sets become strings/lists)."""
    return json.loads(json.dumps(value, default=str))


def put(name: str, key: str, doc: dict[str, Any]) -> None:
    t = _ensure(name)
    with pool().connection() as conn:
        conn.execute(
            f"INSERT INTO {t} (id, doc) VALUES (%s, %s) "
            "ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc",
            (key, Jsonb(_plain(doc))),
        )


def insert(name: str, key: str, doc: dict[str, Any]) -> bool:
    """Insert only if absent; False when the key already exists."""
    t = _ensure(name)
    with pool().connection() as conn:
        cur = conn.execute(
            f"INSERT INTO {t} (id, doc) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING",
            (key, Jsonb(_plain(doc))),
        )
        return cur.rowcount == 1


def get(name: str, key: str) -> dict[str, Any] | None:
    t = _ensure(name)
    with pool().connection() as conn:
        row = conn.execute(f"SELECT doc FROM {t} WHERE id = %s", (key,)).fetchone()
    return dict(row[0]) if row else None


def patch(
    name: str,
    key: str,
    fields: dict[str, Any],
    *,
    where: str = "",
    params: tuple[Any, ...] = (),
) -> bool:
    """Merge top-level *fields* into the document; optional SQL guard on ``doc``.

    Returns whether a row changed, which is how conditional writes report that
    their condition did not hold.
    """
    t = _ensure(name)
    guard = f" AND ({where})" if where else ""
    with pool().connection() as conn:
        cur = conn.execute(
            f"UPDATE {t} SET doc = doc || %s WHERE id = %s{guard}",
            (Jsonb(_plain(fields)), key, *params),
        )
        return cur.rowcount == 1


def append(name: str, key: str, field: str, entry: Any) -> bool:
    """Append one element to the JSON array at top-level *field*."""
    t = _ensure(name)
    with pool().connection() as conn:
        cur = conn.execute(
            f"UPDATE {t} SET doc = jsonb_set(doc, %s, "
            "COALESCE(doc -> %s, '[]'::jsonb) || %s) WHERE id = %s",
            ([field], field, Jsonb([_plain(entry)]), key),
        )
        return cur.rowcount == 1


def add_numbers(name: str, key: str, field: str, amounts: dict[str, int]) -> None:
    """Atomically add integers into the JSON object at top-level *field*."""
    t = _ensure(name)
    with pool().connection() as conn, conn.transaction():
        row = conn.execute(
            f"SELECT doc -> %s FROM {t} WHERE id = %s FOR UPDATE", (field, key)
        ).fetchone()
        if row is None:
            return
        current = dict(row[0] or {})
        for k, v in amounts.items():
            current[k] = int(current.get(k, 0) or 0) + int(v)
        conn.execute(
            f"UPDATE {t} SET doc = jsonb_set(doc, %s, %s) WHERE id = %s",
            ([field], Jsonb(current), key),
        )


def scan(
    name: str, where: str = "", params: tuple[Any, ...] = ()
) -> list[dict[str, Any]]:
    t = _ensure(name)
    sql = f"SELECT doc FROM {t}" + (f" WHERE {where}" if where else "")
    with pool().connection() as conn:
        return [dict(r[0]) for r in conn.execute(sql, params).fetchall()]


def delete(name: str, key: str) -> None:
    t = _ensure(name)
    with pool().connection() as conn:
        conn.execute(f"DELETE FROM {t} WHERE id = %s", (key,))


def ping(timeout: float = 1.0) -> bool:
    try:
        with pool().connection(timeout=timeout) as conn:
            conn.execute("SELECT 1")
        return True
    except Exception:
        return False
