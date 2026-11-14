"""Approval ledger (``beacon-approvals-<stack>``).

Two kinds of rows share the table:

* **proposals** (``proposal#<incident>#<fix_id>``): what Night Shift offered to do,
  with the dry-run result and blast radius; valid for five minutes.
* **approvals** (uuid): the engineer's consent, carrying the verbatim
  transcript, the channel and the exact action + params it covers; valid
  for fifteen minutes and usable exactly once.

The Temporal ``require_approval`` activity refuses to execute without a
valid approval row, so approval is a record, not a prompt.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from beacon import db
from beacon.store import _deserialize_item

logger = logging.getLogger(__name__)

PROPOSAL_TTL_SECONDS = 300
APPROVAL_TTL_SECONDS = 900
_ROW_TTL_DAYS = 30


def _now() -> datetime:
    return datetime.now(tz=UTC)


def params_hash(action: str, params: dict[str, Any]) -> str:
    """Stable identity of (action, params) so contracts and approvals can match."""
    canonical = json.dumps(
        {"action": action, "params": params}, sort_keys=True, default=str
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _proposal_key(incident_id: str, fix_id: int) -> str:
    return f"proposal#{incident_id}#{fix_id}"


def _put(table_name: str, record: dict[str, Any]) -> None:
    db.put(table_name, str(record["approval_id"]), record)


def _get_raw(table_name: str, approval_id: str) -> dict[str, Any] | None:
    raw = db.get(table_name, approval_id)
    return _deserialize_item(raw) if raw else None


def create_proposal(
    incident_id: str,
    fix_id: int,
    action: str,
    params: dict[str, Any],
    *,
    blast_radius: str,
    dry_run: dict[str, Any],
    table_name: str,
    ttl_seconds: int = PROPOSAL_TTL_SECONDS,
) -> dict[str, Any]:
    now = _now()
    record: dict[str, Any] = {
        "approval_id": _proposal_key(incident_id, fix_id),
        "kind": "proposal",
        "incident_id": incident_id,
        "fix_id": fix_id,
        "action": action,
        "params": params,
        "params_hash": params_hash(action, params),
        "blast_radius": blast_radius,
        "dry_run": dry_run,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
        "ttl": int((now + timedelta(days=_ROW_TTL_DAYS)).timestamp()),
    }
    _put(table_name, record)
    return record


def withdraw_proposal(
    incident_id: str,
    fix_id: int,
    *,
    reason: str,
    table_name: str,
) -> bool:
    """Expire a proposal now (barge-in withdrew it); False if there was none."""
    key = _proposal_key(incident_id, fix_id)
    if get_proposal(incident_id, fix_id, table_name=table_name) is None:
        return False
    db.patch(
        table_name,
        key,
        {"expires_at": _now().isoformat(), "withdrawn_reason": reason[:200]},
    )
    return True


def consume_proposal(incident_id: str, fix_id: int, *, table_name: str) -> bool:
    """Atomically claim a live proposal for one approval; False if already claimed.

    A proposal can be approved once. Saying or typing the phrase again while it
    is still inside its five-minute window must not apply the change twice.
    """
    return db.patch(
        table_name,
        _proposal_key(incident_id, fix_id),
        {"consumed_at": _now().isoformat()},
        where="doc->>'consumed_at' IS NULL AND doc->>'expires_at' > %s",
        params=(_now().isoformat(),),
    )


def get_proposal_raw(
    incident_id: str,
    fix_id: int,
    *,
    table_name: str,
) -> dict[str, Any] | None:
    """The proposal row whether or not it is still live (to explain a refusal)."""
    return _get_raw(table_name, _proposal_key(incident_id, fix_id))


def get_proposal(
    incident_id: str,
    fix_id: int,
    *,
    table_name: str,
) -> dict[str, Any] | None:
    """Return the proposal if it exists and has not expired."""
    record = _get_raw(table_name, _proposal_key(incident_id, fix_id))
    if record is None:
        return None
    if str(record.get("expires_at", "")) <= _now().isoformat():
        return None
    return record


def create(
    incident_id: str,
    action: str,
    params: dict[str, Any],
    *,
    source: str,
    channel: str,
    transcript_quote: str,
    table_name: str,
    ttl_seconds: int = APPROVAL_TTL_SECONDS,
    fix_id: int | None = None,
    contract_id: str | None = None,
    attestation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record consent for exactly one (action, params) on one incident."""
    now = _now()
    record: dict[str, Any] = {
        "approval_id": str(uuid.uuid4()),
        "kind": "approval",
        "incident_id": incident_id,
        "fix_id": fix_id,
        "action": action,
        "params": params,
        "params_hash": params_hash(action, params),
        "source": source,
        "channel": channel,
        "transcript_quote": transcript_quote,
        "attestation": dict(attestation or {}),
        "contract_id": contract_id,
        "granted_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
        "used_at": None,
        "ttl": int((now + timedelta(days=_ROW_TTL_DAYS)).timestamp()),
    }
    _put(table_name, record)
    logger.info(
        "approval %s created for %s (%s via %s)",
        record["approval_id"],
        action,
        source,
        channel,
    )
    return record


def get(approval_id: str, *, table_name: str) -> dict[str, Any] | None:
    return _get_raw(table_name, approval_id)


def is_valid(record: dict[str, Any], action: str, params: dict[str, Any]) -> str | None:
    """Return None when the approval covers this action/params now, else why not."""
    if record.get("kind") != "approval":
        return "not an approval record"
    if record.get("used_at"):
        return "approval already used"
    if str(record.get("expires_at", "")) <= _now().isoformat():
        return "approval expired"
    if record.get("action") != action:
        return "approval is for a different action"
    if record.get("params_hash") != params_hash(action, params):
        return "approval is for different params"
    return None


def mark_used(approval_id: str, *, table_name: str) -> bool:
    """Atomically stamp ``used_at``; False if it was already used.

    One conditional UPDATE: of two workers racing on the same approval exactly
    one sees a changed row, so an approval can never execute twice.
    """
    return db.patch(
        table_name,
        approval_id,
        {"used_at": _now().isoformat()},
        where="doc->>'used_at' IS NULL AND doc->>'kind' = 'approval'",
    )


def invalidate_for_fix(
    incident_id: str, fix_id: int, *, reason: str, table_name: str
) -> int:
    """Expire every unused approval for one proposal (cancellation); count them."""
    now = _now().isoformat()
    n = 0
    for row in list_for_incident(incident_id, table_name=table_name):
        if (
            row.get("kind") == "approval"
            and row.get("fix_id") == fix_id
            and not row.get("used_at")
            and db.patch(
                table_name,
                str(row["approval_id"]),
                {"expires_at": now, "invalidated_reason": reason[:200]},
                where="doc->>'used_at' IS NULL",
            )
        ):
            n += 1
    return n


def list_for_incident(incident_id: str, *, table_name: str) -> list[dict[str, Any]]:
    """Every approval row for one incident, oldest first."""
    rows = [
        _deserialize_item(r)
        for r in db.scan(table_name, "doc->>'incident_id' = %s", (incident_id,))
    ]
    rows.sort(key=lambda r: str(r.get("granted_at") or r.get("created_at") or ""))
    return rows


def scan(table_name: str) -> list[dict[str, Any]]:
    return [_deserialize_item(r) for r in db.scan(table_name)]


def record_execution(
    approval_id: str, result: dict[str, Any], *, table_name: str
) -> None:
    """Store the execute outcome on the approval so retries replay it."""
    db.patch(
        table_name,
        approval_id,
        {
            "execute_result": result,
            "executed_at": str(result.get("executed_at") or _now().isoformat()),
        },
    )
