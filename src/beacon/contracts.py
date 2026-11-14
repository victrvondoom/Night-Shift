"""Sleep Contracts: standing approvals granted by voice.

A contract lets Night Shift run one allowlisted action for one alarm on exactly
the resources named in ``params``, a limited number of times, until it
expires.  The engineer's own words are stored as evidence.  Matching is by
alarm name, action and the params hash; the golden-snapshot check for the
params stays with the caller (``handler``) so this module stays generic.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from beacon import db
from beacon.approvals import params_hash
from beacon.store import _deserialize_item

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(tz=UTC)


def put(
    *,
    alarm_name: str,
    action: str,
    params: dict[str, Any],
    days: int,
    max_uses: int,
    transcript_quote: str,
    granted_by: str,
    incident_id: str,
    table_name: str,
    attestation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = _now()
    expires = now + timedelta(days=days)
    record: dict[str, Any] = {
        "contract_id": str(uuid.uuid4()),
        "alarm_name": alarm_name,
        "action": action,
        "params": params,
        "params_hash": params_hash(action, params),
        "granted_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "expires_at_epoch": int(expires.timestamp()),
        "days": days,
        "max_uses": max_uses,
        "uses": 0,
        "status": "active",
        "transcript_quote": transcript_quote,
        "attestation": dict(attestation or {}),
        "granted_by": granted_by,
        "incident_id": incident_id,
        "last_used_at": None,
    }
    db.put(table_name, str(record["contract_id"]), record)
    logger.info(
        "contract %s granted for %s / %s (%d days, %d uses)",
        record["contract_id"],
        alarm_name,
        action,
        days,
        max_uses,
    )
    return record


def _scan(table_name: str, client: Any = None) -> list[dict[str, Any]]:
    return [_deserialize_item(r) for r in db.scan(table_name)]


def _is_live(record: dict[str, Any]) -> bool:
    return (
        record.get("status") == "active"
        and str(record.get("expires_at", "")) > _now().isoformat()
        and int(record.get("uses", 0)) < int(record.get("max_uses", 0))
    )


def list_active(*, table_name: str) -> list[dict[str, Any]]:
    rows = [r for r in _scan(table_name) if _is_live(r)]
    return sorted(rows, key=lambda r: str(r.get("granted_at", "")))


def match(
    alarm_name: str,
    action: str,
    params: dict[str, Any],
    *,
    table_name: str,
) -> dict[str, Any] | None:
    """The live contract covering exactly this alarm + action + params, if any."""
    wanted = params_hash(action, params)
    for record in list_active(table_name=table_name):
        if (
            record.get("alarm_name") == alarm_name
            and record.get("action") == action
            and record.get("params_hash") == wanted
        ):
            return record
    return None


def use(contract_id: str, *, table_name: str) -> bool:
    """Atomically consume one use; False if exhausted, expired or revoked."""
    now = _now().isoformat()
    t = db.table(table_name)
    db.get(t, contract_id)  # ensures the table exists
    with db.pool().connection() as conn:
        cur = conn.execute(
            f"UPDATE {t} SET doc = doc || jsonb_build_object("
            "'uses', (doc->>'uses')::int + 1, 'last_used_at', %s::text) "
            "WHERE id = %s AND (doc->>'uses')::int < (doc->>'max_uses')::int "
            "AND doc->>'expires_at' > %s AND doc->>'status' = 'active'",
            (now, contract_id, now),
        )
        return cur.rowcount == 1


def revoke(contract_id: str, *, table_name: str) -> None:
    db.patch(
        table_name, contract_id, {"status": "revoked", "revoked_at": _now().isoformat()}
    )
