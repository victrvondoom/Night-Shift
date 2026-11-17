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
    ResearchBrief,
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


def queries_table() -> str:
    return _t("NS_QUERIES_TABLE", "ns_queries")


def budget_table() -> str:
    return _t("NS_BUDGET_TABLE", "ns_research_budget")


def runs_table() -> str:
    return _t("NS_RUNS_TABLE", "ns_research_runs")


def snapshots_table() -> str:
    return _t("NS_SNAPSHOTS_TABLE", "ns_snapshots")


def budget_limits() -> tuple[int, float]:
    """(max external operations, max credits) per incident; every search, extract AND retry is one operation."""
    return int(os.environ.get("TAVILY_MAX_QUERIES_PER_INCIDENT", "8")), float(os.environ.get("TAVILY_MAX_CREDITS_PER_INCIDENT", "16"))


def reserve(incident_id: str, op: str, est_credits: float) -> dict[str, Any] | None:
    """Atomically reserve one external operation. Returns the budget row, or None when the budget is exhausted.

    One conditional UPDATE decides, so N concurrent callers can never overspend. The reservation is made
    BEFORE the request and is never refunded: failures, zero-result searches and retries all consume budget.
    """
    max_ops, max_credits = budget_limits()
    t = db._ensure(budget_table())
    fresh = {"incident_id": incident_id, "operations_used": 0, "credits_reserved": 0.0, "credits_reported": 0.0, "max_operations": max_ops, "max_credits": max_credits, "created_at": iso(now_utc())}
    from psycopg.types.json import Jsonb

    with db.pool().connection() as conn:
        conn.execute(f"INSERT INTO {t} (id, doc) VALUES (%s, %s) ON CONFLICT (id) DO NOTHING", (incident_id, Jsonb(fresh)))
        row = conn.execute(
            f"UPDATE {t} SET doc = jsonb_set(jsonb_set(doc, '{{operations_used}}', to_jsonb((doc->>'operations_used')::int + 1)), "
            "'{credits_reserved}', to_jsonb((doc->>'credits_reserved')::numeric + %s)) "
            "WHERE id = %s AND (doc->>'operations_used')::int < %s AND (doc->>'credits_reserved')::numeric + %s <= %s RETURNING doc",
            (est_credits, incident_id, max_ops, est_credits, max_credits),
        ).fetchone()
    return dict(row[0]) if row else None


def settle(incident_id: str, est_credits: float, actual_credits: float | None) -> None:
    """Replace the estimate with the provider-reported credits when the provider reported them."""
    if actual_credits is None:
        return
    t = db._ensure(budget_table())
    with db.pool().connection() as conn:
        conn.execute(
            f"UPDATE {t} SET doc = jsonb_set(jsonb_set(doc, '{{credits_reserved}}', to_jsonb((doc->>'credits_reserved')::numeric + %s)), "
            "'{credits_reported}', to_jsonb((doc->>'credits_reported')::numeric + %s)) WHERE id = %s",
            (actual_credits - est_credits, actual_credits, incident_id),
        )


def budget_for(incident_id: str) -> dict[str, Any]:
    max_ops, max_credits = budget_limits()
    row = db.get(budget_table(), incident_id) or {}
    used = int(row.get("operations_used", 0))
    return {
        "operations_used": used,
        "max_operations": max_ops,
        "operations_remaining": max(0, max_ops - used),
        "credits_reserved": float(row.get("credits_reserved", 0)),
        "credits_reported": float(row.get("credits_reported", 0)),
        "max_credits": max_credits,
        "exhausted": used >= max_ops or float(row.get("credits_reserved", 0)) >= max_credits,
    }


def record_attempt(incident_id: str, attempt_id: str, **fields: Any) -> None:
    """One row per external attempt (search/extract, success or failure, original or retry)."""
    db.put(queries_table(), attempt_id, {"incident_id": incident_id, "attempt_id": attempt_id, "sent_at": iso(now_utc()), **fields})


def queries_for(incident_id: str) -> list[dict[str, Any]]:
    rows = db.scan(queries_table(), "doc->>'incident_id' = %s", (incident_id,))
    return sorted(rows, key=lambda r: str(r.get("sent_at")))


def acquire_run(incident_id: str, kind: str, ttl_s: int = 180) -> str | None:
    """Single in-flight research run per incident (concurrent follow-ups are refused, not interleaved)."""
    from datetime import timedelta

    key = f"{incident_id}#lock"
    now = now_utc()
    doc = {"incident_id": incident_id, "lock": True, "kind": kind, "started_at": iso(now), "expires_at": iso(now + timedelta(seconds=ttl_s))}
    if db.insert(runs_table(), key, doc):
        return key
    t = db._ensure(runs_table())
    from psycopg.types.json import Jsonb

    with db.pool().connection() as conn:
        got = conn.execute(f"UPDATE {t} SET doc = %s WHERE id = %s AND doc->>'expires_at' < %s", (Jsonb(doc), key, iso(now))).rowcount
    return key if got == 1 else None


def release_run(key: str) -> None:
    db.delete(runs_table(), key)


def record_run(incident_id: str, run_id: str, **fields: Any) -> None:
    db.put(runs_table(), run_id, {"incident_id": incident_id, "run_id": run_id, "recorded_at": iso(now_utc()), **fields})


def runs_for(incident_id: str) -> list[dict[str, Any]]:
    rows = [r for r in db.scan(runs_table(), "doc->>'incident_id' = %s", (incident_id,)) if not r.get("lock")]
    return sorted(rows, key=lambda r: str(r.get("recorded_at")))


def active_run(incident_id: str) -> dict[str, Any] | None:
    row = db.get(runs_table(), f"{incident_id}#lock")
    return row if row and str(row.get("expires_at", "")) > iso(now_utc()) else None


def record_snapshot(snap: dict[str, Any]) -> bool:
    """Immutable: insert-only. A snapshot is never updated, so a brief always points at exactly what it saw."""
    return db.insert(snapshots_table(), snap["snapshot_id"], snap)


def get_snapshot(snapshot_id: str) -> dict[str, Any] | None:
    return db.get(snapshots_table(), snapshot_id)


def briefs_table() -> str:
    return _t("NS_BRIEFS_TABLE", "ns_briefs")


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
    if ev.run_id:
        rows = [r for r in rows if r.get("run_id") == ev.run_id] or rows
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
    if corr.strength == "CHANGE_ONLY_NO_SYMPTOM":
        return changed  # a policy edit with no symptom is recorded as a correlation, but is not an incident
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
        "run_id": corr.run_id,
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


def record_brief(br: ResearchBrief) -> None:
    db.put(briefs_table(), br.brief_id, br.model_dump(mode="json"))
    trace(br.incident_id, "bifrost_request", br.bifrost_request_id or br.brief_id, {"purpose": "external_research_synthesis", "origin": br.origin, "status": br.status})


def briefs_for(incident_id: str) -> list[dict[str, Any]]:
    rows = db.scan(briefs_table(), "doc->>'incident_id' = %s", (incident_id,))
    return sorted(rows, key=lambda r: str(r["created_at"]))
