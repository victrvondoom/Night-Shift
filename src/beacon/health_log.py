"""Last-interaction bookkeeping for ``/api/system/integrations`` (persisted, secret-free)."""

from __future__ import annotations

import os
from typing import Any

from beacon import db
from beacon.evidence.contracts import iso, now_utc


def _t() -> str:
    return os.environ.get("NS_HEALTH_TABLE", "ns_integration_health")


def record(name: str, ok: bool, category: str = "", detail: str = "") -> None:
    cur = db.get(_t(), name) or {"name": name, "ok_count": 0, "fail_count": 0}
    now = iso(now_utc())
    if ok:
        cur.update(last_success_at=now, ok_count=int(cur["ok_count"]) + 1, last_error_category="", last_detail=detail[:200])
    else:
        cur.update(last_error_at=now, fail_count=int(cur["fail_count"]) + 1, last_error_category=category, last_detail=detail[:200])
    db.put(_t(), name, cur)


def get(name: str) -> dict[str, Any]:
    return db.get(_t(), name) or {}


def count(key: str) -> None:
    cur = db.get(_t(), key) or {"name": key, "n": 0}
    cur["n"] = int(cur.get("n", 0)) + 1
    db.put(_t(), key, cur)
