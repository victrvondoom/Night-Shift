"""Provider payload -> ``NightShiftEvent`` (original ids and timestamps preserved)."""

from __future__ import annotations

import json
import re
from typing import Any

from beacon import changes
from beacon.evidence.contracts import (
    EventType,
    NightShiftEvent,
    Resource,
    SourceMode,
    iso,
    now_utc,
    parse_ts,
    stable_id,
)

MODE_KEY = "nightshift.io/source-mode"
RUN_KEY = "nightshift.io/run-id"
_DB_ERR = re.compile(
    r"(database|db|redis|postgres).{0,40}(unreachable|refused|timed out|timeout)|"
    r"connection (refused|timed out)",
    re.I,
)


def _mode(raw: Any) -> SourceMode:
    return SourceMode.DEMO_SIMULATOR if raw == SourceMode.DEMO_SIMULATOR else SourceMode.LIVE


def _target_app(name: str) -> str:
    """demo-db-ingress -> demo-db (the workload a policy protects) by convention."""
    return re.sub(r"-(ingress|egress|netpol|policy|allow.*)$", "", name)


def from_audit(item: dict[str, Any], *, cluster: str = "") -> NightShiftEvent | None:
    row = changes.from_audit_event(item)
    if row is None:
        return None
    ref = item.get("objectRef") or {}
    audit_id = str(item.get("auditID") or "")
    if not audit_id:
        return None
    is_netpol = ref.get("resource") == "networkpolicies"
    name = str(ref.get("name") or "")
    ns = str(ref.get("namespace") or "")
    verb = str(item.get("verb") or "")
    mode = _mode((item.get("annotations") or {}).get(MODE_KEY))
    return NightShiftEvent(
        event_id=stable_id("evt", "kubernetes", audit_id),
        source="kubernetes",
        source_event_id=audit_id,
        # Night Shift's own remediation write is evidence of the fix, never a new "change" to correlate
        event_type=(
            EventType.REMEDIATION
            if row.get("by_beacon")
            else EventType.NETPOL_CHANGE if is_netpol else EventType.OTHER_CHANGE
        ),
        observed_at=row["event_time"],
        received_at=iso(now_utc()),
        resource=Resource(
            cluster=cluster,
            namespace=ns,
            kind="NetworkPolicy" if is_netpol else str(ref.get("resource") or ""),
            name=name,
            target_app=_target_app(name) if is_netpol else "",
        ),
        severity="warning" if is_netpol and verb in ("patch", "update", "delete") else "info",
        summary=f"{verb} {ref.get('resource')} {ns}/{name} by {row['actor_short']}",
        payload_reference=f"audit:{audit_id}",
        source_mode=mode,
        run_id=str((item.get("annotations") or {}).get(RUN_KEY) or ""),
    )


def from_alert(alert: dict[str, Any]) -> NightShiftEvent | None:
    labels = {str(k): str(v) for k, v in (alert.get("labels") or {}).items()}
    notes = {str(k): str(v) for k, v in (alert.get("annotations") or {}).items()}
    starts = alert.get("startsAt")
    fp = str(alert.get("fingerprint") or "")
    if not (starts and fp):
        return None
    name = labels.get("alertname", "unknown")
    return NightShiftEvent(
        event_id=stable_id("evt", "prometheus", f"{fp}-{starts}"),
        source="prometheus",
        source_event_id=f"{fp}-{starts}",
        event_type=EventType.ALERT_FIRING,
        observed_at=iso(parse_ts(starts)),
        received_at=iso(now_utc()),
        resource=Resource(
            namespace=labels.get("namespace", ""),
            kind="Alert",
            name=name,
            target_app=labels.get("target_app") or notes.get("beacon_target_app", ""),
        ),
        severity="critical" if labels.get("severity") == "page" else "warning",
        summary=f"{name}: {notes.get('summary') or notes.get('description') or 'firing'}",
        payload_reference=f"alert:{fp}",
        source_mode=_mode(notes.get(MODE_KEY)),
        run_id=notes.get(RUN_KEY, ""),
        attributes={
            **{k: v for k, v in labels.items() if k in ("alertname", "namespace", "service", "severity", "job", "deployment")},
            **{k: v for k, v in notes.items() if k in ("beacon_health_url", "summary", "description")},
        },
    )


def _log_target(line: str) -> str:
    """'database unreachable at demo-db:6379' -> demo-db"""
    m = re.search(r"\bat ([a-z0-9][a-z0-9.-]*)(?::\d+)?", line)
    return m.group(1) if m else ""


def from_app_log(rec: dict[str, Any]) -> NightShiftEvent | None:
    """One application log line: ``{id, ts, namespace, app, line, target_app?, source_mode?}``."""
    line = str(rec.get("line") or "")
    sid = str(rec.get("id") or "")
    if not (sid and rec.get("ts") and _DB_ERR.search(line)):
        return None
    return NightShiftEvent(
        event_id=stable_id("evt", "application", sid),
        source="application",
        source_event_id=sid,
        event_type=EventType.APP_ERROR,
        observed_at=iso(parse_ts(rec["ts"])),
        received_at=iso(now_utc()),
        resource=Resource(
            namespace=str(rec.get("namespace") or ""),
            kind="Log",
            name=str(rec.get("app") or ""),
            target_app=str(rec.get("target_app") or _log_target(line)),
        ),
        severity="critical",
        summary=line[:240],
        payload_reference=f"log:{sid}",
        source_mode=_mode(rec.get("source_mode")),
        run_id=str(rec.get("run_id") or ""),
    )


def from_github(kind: str, payload: dict[str, Any], delivery: str) -> NightShiftEvent | None:
    row = changes.from_github_event(kind, payload)
    if row is None or not delivery:
        return None
    return NightShiftEvent(
        event_id=stable_id("evt", "github", delivery),
        source="github",
        source_event_id=delivery,
        event_type=EventType.DEPLOYMENT,
        observed_at=row["event_time"],
        received_at=iso(now_utc()),
        resource=Resource(kind="Deployment", name=",".join(row["resource_ids"])),
        summary=f"{row['event_name']} by {row['actor_short']}",
        payload_reference=f"github:{delivery}",
    )


def redact_payload(obj: Any) -> str:
    """Safe retained reference body: drop auth-ish keys, cap size."""
    def scrub(v: Any) -> Any:
        if isinstance(v, dict):
            return {
                k: ("[redacted]" if re.search(r"token|secret|authorization|password", k, re.I) else scrub(x))
                for k, x in v.items()
            }
        if isinstance(v, list):
            return [scrub(x) for x in v[:50]]
        return v

    return json.dumps(scrub(obj), default=str)[:8000]
