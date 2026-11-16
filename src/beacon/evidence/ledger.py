"""Persistence for events, correlations, research, analyses and provenance.

Everything lives in the existing PostgreSQL JSON-document ledger (``beacon.db``),
so there is no second datastore.  Writes are idempotent on stable ids.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from beacon import db
from beacon.evidence.contracts import (
    Correlation,
    ModelAnalysis,
    NightShiftEvent,
    ResearchItem,
    iso,
    now_utc,
)

logger = logging.getLogger(__name__)


def _t(env: str, default: str) -> str:
    return os.environ.get(env, default)


def events_table() -> str:
    return _t("NS_EVENTS_TABLE", "ns_events")


def corr_table() -> str:
    return _t("NS_CORRELATIONS_TABLE", "ns_correlations")


def research_table() -> str:
    return _t("NS_RESEARCH_TABLE", "ns_research")


def analysis_table() -> str:
    return _t("NS_ANALYSES_TABLE", "ns_analyses")


def trace_table() -> str:
    return _t("NS_TRACE_TABLE", "ns_trace")


def incidents_table() -> str:
    return _t("INCIDENTS_TABLE_NAME", "incidents")


def payload_table() -> str:
    return _t("NS_PAYLOADS_TABLE", "ns_payloads")


# --- trace / provenance ----------------------------------------------------


def trace(incident_id: str, stage: str, ref: str, detail: dict[str, Any] | None = None) -> None:
    """Append one provenance stage: source -> NATS -> Pathway -> ... -> report."""
    if not incident_id:
        return
    key = f"{incident_id}#{stage}#{ref}"
    db.insert(
        trace_table(),
        key,
        {
            "incident_id": incident_id,
            "stage": stage,
            "ref": ref,
            "detail": detail or {},
            "at": iso(now_utc()),
        },
    )


def provenance(incident_id: str) -> list[dict[str, Any]]:
    rows = db.scan(trace_table(), "doc->>'incident_id' = %s", (incident_id,))
    return sorted(rows, key=lambda r: str(r.get("at")))


# --- events ----------------------------------------------------------------


def record_event(ev: NightShiftEvent, payload_body: str = "") -> bool:
    """Idempotent on ``event_id``; False when this delivery was a duplicate."""
    fresh = db.insert(events_table(), ev.event_id, ev.model_dump(mode="json"))
    if fresh and payload_body:
        db.put(payload_table(), ev.payload_reference, {"body": payload_body, "event_id": ev.event_id})
    return fresh


def get_event(event_id: str) -> dict[str, Any] | None:
    return db.get(events_table(), event_id)


def events_for(incident_id: str) -> list[dict[str, Any]]:
    rows = db.scan(events_table(), "doc->>'incident_id' = %s", (incident_id,))
    return sorted(rows, key=lambda r: (str(r["observed_at"]), str(r["event_id"])))


def unassigned_events(namespace: str = "") -> list[dict[str, Any]]:
    rows = db.scan(events_table(), "COALESCE(doc->>'incident_id','') = ''")
    if namespace:
        rows = [r for r in rows if r["resource"]["namespace"] == namespace]
    return sorted(rows, key=lambda r: str(r["observed_at"]))


def recent_events(limit: int = 50) -> list[dict[str, Any]]:
    rows = db.scan(events_table())
    return sorted(rows, key=lambda r: str(r["received_at"]), reverse=True)[:limit]


def attach_remediation_event(ev: NightShiftEvent) -> None:
    """Attach Night Shift's own remediation write to the newest open incident in that namespace."""
    rows = [
        r
        for r in db.scan(incidents_table(), "doc ? 'correlation_ids' AND doc->>'status' IN ('remediating','awaiting_engineer')")
        if (r.get("alert_labels") or {}).get("namespace", ev.resource.namespace) == ev.resource.namespace
    ]
    if not rows:
        return
    target = max(rows, key=lambda r: str(r.get("detected_at")))
    db.patch(events_table(), ev.event_id, {"incident_id": target["incident_id"]})
    trace(target["incident_id"], "remediation_event", ev.event_id, {"source": ev.source})


# --- correlations + incident -------------------------------------------------


def record_correlation(corr: Correlation, *, nats_subject: str = "beacon.correlations") -> bool:
    """Persist a Pathway correlation, claim its events and open/refresh the incident."""
    existing = db.get(corr_table(), corr.correlation_id)
    if existing:  # monotonic: an out-of-order or duplicated delivery can never shrink the evidence set
        union = list(dict.fromkeys([*corr.included_event_ids, *existing.get("included_event_ids", [])]))
        corr = corr.model_copy(update={"included_event_ids": union, "symptom_types": sorted(set(corr.symptom_types) | set(existing.get("symptom_types", [])))})
    row = corr.model_dump(mode="json")
    changed = existing is None or existing.get("included_event_ids") != row["included_event_ids"]
    db.put(corr_table(), corr.correlation_id, row)
    for eid in corr.included_event_ids:
        db.patch(events_table(), eid, {"incident_id": corr.incident_id})
    _ensure_incident(corr)
    if changed:
        trace(
            corr.incident_id,
            "pathway_correlation",
            f"{corr.correlation_id}:{len(corr.included_event_ids)}",
            {"rule": corr.rule, "events": corr.included_event_ids, "subject": nats_subject},
        )
        for eid in corr.included_event_ids:
            ev = get_event(eid) or {}
            trace(corr.incident_id, "persisted_evidence", eid, {"source": ev.get("source")})
    return changed


def correlations_for(incident_id: str) -> list[dict[str, Any]]:
    rows = db.scan(corr_table(), "doc->>'incident_id' = %s", (incident_id,))
    return sorted(rows, key=lambda r: str(r["processed_at"]))


def _ensure_incident(corr: Correlation) -> None:
    evs = [get_event(e) or {} for e in corr.included_event_ids]
    alert = next((e for e in evs if e.get("event_type") == "alert_firing"), None)
    change = get_event(corr.change_event_id) or {}
    mode = "DEMO_SIMULATOR" if any(e.get("source_mode") == "DEMO_SIMULATOR" for e in evs + [change]) else "LIVE"
    attrs = dict((alert or {}).get("attributes") or {})
    doc = db.get(incidents_table(), corr.incident_id)
    detected = min([e["observed_at"] for e in evs + [change] if e.get("observed_at")] or [iso(now_utc())])
    base: dict[str, Any] = {
        "incident_id": corr.incident_id,
        "source_mode": mode,
        "correlation_ids": [corr.correlation_id],
        "detected_at": detected,
        "affected_service": attrs.get("service") or corr.target_app,
        "severity": "critical" if alert else "warning",
    }
    if alert:
        base.update(
            alarm_name=attrs.get("alertname", ""),
            alarm_reason=attrs.get("description") or attrs.get("summary") or "",
            alert_labels={k: attrs[k] for k in ("alertname", "namespace", "service", "severity") if k in attrs},
            alert_annotations={k: attrs[k] for k in ("beacon_health_url",) if k in attrs},
        )
    if doc is None:
        now = iso(now_utc())
        db.put(
            incidents_table(),
            corr.incident_id,
            {
                **base,
                "rca": "",
                "trigger_type": "alarm",
                "timestamp": now,
                "prefetch_status": "skipped",
                "status": "awaiting_engineer",
                "woken": True,
                "timeline": [{"t": now, "event": "incident_opened", "detail": {"correlation_id": corr.correlation_id, "rule": corr.rule}}],
            },
        )
        trace(corr.incident_id, "incident_opened", corr.correlation_id)
    else:
        db.patch(incidents_table(), corr.incident_id, {k: v for k, v in base.items() if k not in ("detected_at",) and v != ""})


# --- research / analyses ----------------------------------------------------


def record_research(items: list[ResearchItem]) -> None:
    for it in items:
        db.put(research_table(), it.evidence_id, it.model_dump(mode="json"))
        trace(it.incident_id, "tavily_source", it.evidence_id, {"url": it.url, "query_id": it.query_id})


def research_for(incident_id: str) -> list[dict[str, Any]]:
    rows = db.scan(research_table(), "doc->>'incident_id' = %s", (incident_id,))
    return sorted(rows, key=lambda r: (str(r["retrieved_at"]), str(r["evidence_id"])))


def record_analysis(a: ModelAnalysis) -> None:
    db.put(analysis_table(), a.analysis_id, a.model_dump(mode="json"))
    trace(a.incident_id, "bifrost_request", a.bifrost_request_id or a.analysis_id, {"origin": a.origin, "status": a.status})


def analyses_for(incident_id: str) -> list[dict[str, Any]]:
    rows = db.scan(analysis_table(), "doc->>'incident_id' = %s", (incident_id,))
    return sorted(rows, key=lambda r: str(r["created_at"]))
