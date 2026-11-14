from __future__ import annotations

import contextlib
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from beacon import db

if TYPE_CHECKING:
    from beacon.config import NightShiftConfig
    from beacon.events import TriggerInfo

logger = logging.getLogger(__name__)

_TTL_DAYS = 30
_TERMINAL_STATUSES = ("resolved", "escalated", "closed")


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _resolve_table(config: NightShiftConfig | None, table_name: str | None) -> str:
    """Return the explicit ledger name, else the one from config."""
    if table_name:
        return table_name
    if config is not None and config.incidents_table_name:
        return config.incidents_table_name
    raise ValueError("An incidents table name is required (table_name or config)")


def put_incident(
    analysis: str,
    trigger: TriggerInfo,
    config: NightShiftConfig | None = None,
    *,
    table_name: str | None = None,
    rca_json: dict[str, Any] | None = None,
    timeline: list[dict[str, Any]] | None = None,
    diagnostics: dict[str, Any] | None = None,
    changes: list[dict[str, Any]] | None = None,
    status: str = "awaiting_engineer",
    woken: bool = True,
) -> str:
    """Store a new incident document and return its generated UUID."""
    table = _resolve_table(config, table_name)
    incident_id = str(uuid.uuid4())
    now = _now()
    item: dict[str, Any] = {
        "incident_id": incident_id,
        "rca": analysis,
        "trigger_type": trigger.trigger_type.value,
        "timestamp": now.isoformat(),
        "ttl": int((now + timedelta(days=_TTL_DAYS)).timestamp()),
        "prefetch_status": "pending",
        "status": status,
        "woken": woken,
        "timeline": timeline or [],
    }
    if trigger.alarm_name:
        item["alarm_name"] = trigger.alarm_name
    if trigger.alarm_reason:
        item["alarm_reason"] = trigger.alarm_reason
    if trigger.labels:
        item["alert_labels"] = dict(trigger.labels)
    if trigger.annotations:
        item["alert_annotations"] = dict(trigger.annotations)
    if config is not None and config.log_group_patterns:
        item["log_groups"] = list(config.log_group_patterns)
    if rca_json is not None:
        item["rca_json"] = rca_json
    if diagnostics is not None:
        item["diagnostics"] = diagnostics
    if changes is not None:
        item["changes"] = changes
    db.put(table, incident_id, item)
    logger.info("Stored incident %s", incident_id)
    return incident_id


def get_incident(
    incident_id: str,
    config: NightShiftConfig | None = None,
    *,
    table_name: str | None = None,
) -> dict[str, Any]:
    """Read an incident by ID; an empty dict if it does not exist."""
    return _deserialize_item(db.get(_resolve_table(config, table_name), incident_id))


def append_timeline(
    incident_id: str,
    event: str,
    *,
    table_name: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one ``{t, event, detail?}`` entry to the incident timeline."""
    entry: dict[str, Any] = {"t": _now().isoformat(), "event": event}
    if detail:
        entry["detail"] = detail
    db.append(table_name, incident_id, "timeline", entry)
    return entry


def update_status(
    incident_id: str,
    status: str,
    *,
    table_name: str,
    extra: dict[str, Any] | None = None,
) -> None:
    """Set the lifecycle ``status`` plus any extra top-level attributes."""
    db.patch(table_name, incident_id, {"status": status, **(extra or {})})


def add_usage(incident_id: str, usage: dict[str, int], *, table_name: str) -> None:
    """Atomically add token counts to ``usage.<key>`` on the incident."""
    parts = {k: int(v) for k, v in usage.items() if v}
    if parts:
        db.add_numbers(table_name, incident_id, "usage", parts)


def find_open_incident(
    alarm_name: str, *, table_name: str, within_minutes: int = 10
) -> dict[str, Any] | None:
    """Return the newest non-terminal incident for *alarm_name* in the window.

    Deduplicates Alertmanager re-notifications so one outage is one incident.
    """
    since = (_now() - timedelta(minutes=within_minutes)).isoformat()
    rows = db.scan(
        table_name,
        "doc->>'alarm_name' = %s AND doc->>'timestamp' >= %s "
        "AND NOT (COALESCE(doc->>'status','') = ANY(%s))",
        (alarm_name, since, list(_TERMINAL_STATUSES)),
    )
    items = [_deserialize_item(r) for r in rows]
    if not items:
        return None
    return max(items, key=lambda item: str(item.get("timestamp", "")))


def scan_incidents(table_name: str) -> list[dict[str, Any]]:
    return [_deserialize_item(r) for r in db.scan(table_name)]


def update_cached_data(
    incident_id: str,
    cached_data: dict[str, Any],
    config: NightShiftConfig | None = None,
    *,
    status: str = "complete",
    table_name: str | None = None,
) -> None:
    """Write pre-fetched investigation data to an incident record."""
    db.patch(
        _resolve_table(config, table_name),
        incident_id,
        {"cached_data": cached_data, "prefetch_status": status},
    )
    logger.info("Updated cached data for incident %s (status=%s)", incident_id, status)


def _deserialize_item(item: dict[str, Any] | None) -> dict[str, Any]:
    """A stored document as callers expect it (``ttl`` stays a string)."""
    result = dict(item or {})
    if "ttl" in result:
        result["ttl"] = str(result["ttl"])
    if isinstance(result.get("cached_data"), str):
        with contextlib.suppress(json.JSONDecodeError, TypeError):
            result["cached_data"] = json.loads(result["cached_data"])
    return result
