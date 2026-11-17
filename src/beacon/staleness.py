"""Deterministic stale-answer detection: an explanation is bound to an immutable evidence snapshot.

No model decides staleness.  A snapshot records every relevant evidence item with a content hash; new
state is compared to it by transparent rules.  Not every incoming event invalidates every answer.

Rules (each reason carries its rule name):
  NEW_RELEVANT_EVENT   a change/symptom event of this incident that the answer never saw
  NEW_SOURCE           a retrieved source the answer never saw that SUPPORTS / CONTRADICTS / adds CONTEXT
  UPDATED_SOURCE       a source the answer saw whose content hash changed (material change)
Ignored (reported, never silent): unrelated event types, duplicate content, UNVERIFIED / INSUFFICIENT_EVIDENCE
sources, STALE (old) sources, remediation events.  A source with an unknown publication date is NOT invalidating
by itself and is flagged in the reason detail.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from beacon.evidence.contracts import iso, now_utc, stable_id

RELEVANT_EVENT_TYPES = {"networkpolicy_change", "alert_firing", "db_connection_error"}
NON_INVALIDATING = {"UNVERIFIED": "unverified_source_not_relevant", "INSUFFICIENT_EVIDENCE": "insufficient_content_not_relevant", "STALE": "old_source_does_not_invalidate"}


def event_hash(e: dict[str, Any]) -> str:
    return hashlib.sha256("|".join(str(e.get(k, "")) for k in ("event_type", "source", "source_event_id", "observed_at", "summary")).encode()).hexdigest()


def evidence_set_hash(items: list[dict[str, Any]]) -> str:
    return hashlib.sha256(json.dumps(sorted((i["id"], i["content_hash"]) for i in items)).encode()).hexdigest()[:16]


def build_snapshot(incident_id: str, *, run_id: str, brief_version: int, events: list[dict[str, Any]], sources: list[dict[str, Any]], provider: str | None, model: str | None, purpose: str = "research_brief") -> dict[str, Any]:
    items: list[dict[str, Any]] = [
        {"id": e["event_id"], "kind": "event", "content_hash": event_hash(e), "observed_at": e["observed_at"]}
        for e in events
        if e["event_type"] in RELEVANT_EVENT_TYPES
    ] + [
        {"id": s["evidence_id"], "kind": "source", "content_hash": s.get("content_hash", ""), "hash_basis": s.get("hash_basis", "snippet"), "published_date": s.get("published_date"), "date_status": s.get("date_status", "UNKNOWN"), "classification": s.get("classification")}
        for s in sources
    ]
    ehash = evidence_set_hash(items)
    return {
        "snapshot_id": stable_id("snap", incident_id, str(brief_version), ehash),
        "incident_id": incident_id,
        "run_id": run_id,
        "brief_version": brief_version,
        "purpose": purpose,
        "evidence": items,
        "evidence_set_hash": ehash,
        "provider": provider,
        "model": model,
        "created_at": iso(now_utc()),
    }


def evaluate(snapshot: dict[str, Any] | None, events: list[dict[str, Any]], sources: list[dict[str, Any]]) -> dict[str, Any]:
    if snapshot is None:
        return {"status": "NO_SNAPSHOT", "reasons": [], "ignored": [], "invalidated_at": None}
    seen = {i["id"]: i for i in snapshot["evidence"]}
    seen_hashes = {i["content_hash"] for i in snapshot["evidence"] if i.get("content_hash")}
    reasons: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    for e in events:
        if e["event_id"] in seen:
            continue
        if e["event_type"] not in RELEVANT_EVENT_TYPES:
            ignored.append({"evidence_id": e["event_id"], "kind": "event", "reason": "unrelated_event_type", "detail": e["event_type"]})
        elif event_hash(e) in seen_hashes:
            ignored.append({"evidence_id": e["event_id"], "kind": "event", "reason": "duplicate_content", "detail": "identical to evidence in the snapshot"})
        else:
            reasons.append({"rule": "NEW_RELEVANT_EVENT", "evidence_id": e["event_id"], "kind": "event", "detail": f"{e['event_type']} observed {e['observed_at']} was not considered", "at": e.get("received_at")})
    for s in sources:
        sid, h = s["evidence_id"], s.get("content_hash", "")
        if sid in seen:
            if seen[sid].get("hash_basis", "snippet") != s.get("hash_basis", "snippet"):
                if h != seen[sid].get("content_hash"):
                    ignored.append({"evidence_id": sid, "kind": "source", "reason": "enrichment_by_extraction", "detail": "the same source now carries its extracted full text; not a content change"})
                continue
            if h and seen[sid].get("content_hash") and h != seen[sid]["content_hash"]:
                reasons.append({"rule": "UPDATED_SOURCE", "evidence_id": sid, "kind": "source", "detail": f"content of {s.get('domain') or s.get('url')} changed since the snapshot", "at": s.get("retrieved_at")})
            continue
        cls = s.get("classification")
        if cls in NON_INVALIDATING:
            ignored.append({"evidence_id": sid, "kind": "source", "reason": NON_INVALIDATING[cls], "detail": cls})
        elif h and h in seen_hashes:
            ignored.append({"evidence_id": sid, "kind": "source", "reason": "duplicate_content", "detail": "same content as a source already in the snapshot"})
        else:
            note = " (publication date unknown)" if s.get("date_status", "UNKNOWN") != "KNOWN" else ""
            reasons.append({"rule": "NEW_SOURCE", "evidence_id": sid, "kind": "source", "detail": f"{cls} source {s.get('domain') or s.get('url')} was retrieved after the snapshot{note}", "at": s.get("retrieved_at")})
    times = [r["at"] for r in reasons if r.get("at")]
    return {
        "status": "STALE" if reasons else "FRESH",
        "snapshot_id": snapshot["snapshot_id"],
        "brief_version": snapshot["brief_version"],
        "reasons": reasons,
        "ignored": ignored,
        "invalidated_at": min(times) if times else None,
        "evaluated_at": iso(now_utc()),
        "summary": f"{len(reasons)} change(s) since version {snapshot['brief_version']} invalidate it" if reasons else "nothing relevant has changed since this version",
    }
