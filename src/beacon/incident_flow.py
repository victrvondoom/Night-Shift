"""Incident workspace logic: the view model, proposal, typed approval, cancellation, report.

Everything here delegates to existing guarded machinery: ``diagnose`` (deterministic fix choice
from live drift vs the golden snapshot), ``approvals`` (single-use, hash-bound), OPA via
``remediate``, Temporal/inline via ``workflows``.  The LLM never picks a command.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from datetime import datetime
from typing import Any

from beacon import approvals, store, workflows
from beacon.evidence import ledger
from beacon.evidence.contracts import iso, now_utc, parse_ts
from beacon.remediation import registry

logger = logging.getLogger(__name__)
REQUIRED_CHECKS = {
    "kubernetes_state": ("postcondition",),
    "monitoring": ("alarm_ok_after_fix", "metric_zero"),
    "application_health": ("app_health",),
}


def _incidents() -> str:
    return os.environ.get("INCIDENTS_TABLE_NAME", "incidents")


def _approvals() -> str:
    return os.environ.get("APPROVALS_TABLE_NAME", "approvals")


def _apply_enabled() -> bool:
    return os.environ.get("APPLY_ENABLED", "true").lower() != "false"


# ---------------------------------------------------------------------------- verification


def verification_view(timeline: list[dict[str, Any]]) -> dict[str, Any]:
    """Latest verification attempt grouped into the three independent categories."""
    attempts = [e for e in timeline if e.get("event") == "verify_attempt"]
    if not attempts:
        return {"attempts": 0, "categories": {}, "all_passed": False}
    last = attempts[-1]
    checks = {c["name"]: c for c in (last.get("detail") or {}).get("checks", [])}
    cats: dict[str, Any] = {}
    for cat, names in REQUIRED_CHECKS.items():
        got = [checks[n] for n in names if n in checks]
        cats[cat] = {
            "status": "PASS" if got and len(got) == len(names) and all(c["ok"] for c in got) else ("FAIL" if got else "MISSING"),
            "checks": [{"name": c["name"], "ok": c["ok"], "detail": c.get("detail", ""), "checked_at": c.get("checked_at") or last.get("t")} for c in got],
        }
    return {
        "attempts": len(attempts),
        "last_attempt_at": last.get("t"),
        "categories": cats,
        "all_passed": all(v["status"] == "PASS" for v in cats.values()),
    }


def lifecycle(inc: dict[str, Any], has_corr: bool, analyses: list[dict[str, Any]], verification: dict[str, Any]) -> str:
    """Derived from persisted records.  VERIFIED needs status=resolved AND all three check groups passing."""
    status = inc.get("status")
    events0 = [e.get("event") for e in inc.get("timeline") or []]
    if status == "resolved" and verification.get("all_passed"):
        return "VERIFIED"
    if "execute_failed" in events0 and "executed" not in events0 and status != "escalated":
        return "EXECUTION_FAILED"
    if ("proposal_cancelled" in events0 or "proposal_withdrawn" in events0) and "approved" not in events0:
        return "CANCELLED"
    if status == "resolved":
        return "VERIFICATION_FAILED"  # resolved flag without the independent checks is never shown as VERIFIED
    if status == "escalated":
        return "ESCALATED"
    events = {e.get("event") for e in inc.get("timeline") or []}
    if status == "remediating" or "executing" in events:
        return "VERIFYING" if "executed" in events else "EXECUTING"
    if "approved" in events:
        return "APPROVED"
    if inc.get("proposals"):
        return "PROPOSED"
    if analyses:
        return "ANALYZED"
    return "CORRELATED" if has_corr else "DETECTED"


def view(incident_id: str) -> dict[str, Any] | None:
    inc = store.get_incident(incident_id, table_name=_incidents())
    if not inc:
        return None
    events = ledger.events_for(incident_id)
    corrs = ledger.correlations_for(incident_id)
    research = ledger.research_for(incident_id)
    analyses = ledger.analyses_for(incident_id)
    current_ids = {e["event_id"] for e in events} | {r["evidence_id"] for r in research}
    from beacon import analysis as analysis_mod
    from beacon import research as research_mod

    for a in analyses:
        a["staleness"] = analysis_mod.staleness(a, current_ids)
    for r in research:
        r["age_days"] = research_mod.age_days(r.get("updated_date") or r.get("published_date"))
        r["date_known"] = bool(r.get("updated_date") or r.get("published_date"))
    from beacon import staleness as staleness_mod

    briefs = ledger.briefs_for(incident_id)
    for i, br in enumerate(briefs):
        ev = staleness_mod.evaluate(ledger.get_snapshot(br.get("snapshot_id", "")), events, research)
        br["staleness"] = {**ev, "status": "SUPERSEDED" if i < len(briefs) - 1 else ev["status"]}
    budget = ledger.budget_for(incident_id)
    runs = ledger.runs_for(incident_id)
    active = ledger.active_run(incident_id)
    last = runs[-1] if runs else None
    r_status = "RESEARCHING" if active else (last["status"] if last else "NOT_STARTED")
    if not active and last and last["status"] in ("COMPLETED", "PARTIAL") and budget["exhausted"]:
        r_status = "BUDGET_EXHAUSTED" if last["status"] == "PARTIAL" else r_status
    research_state = {"status": r_status, "budget": budget, "attempts": ledger.queries_for(incident_id), "runs": runs[-10:], "active": bool(active), "brief_status": (briefs[-1]["staleness"]["status"] if briefs else "NEVER_RESEARCHED")}
    timeline = inc.get("timeline") or []
    ver = verification_view(timeline)
    proposals = []
    for p in inc.get("proposals") or []:
        raw = approvals.get_proposal_raw(incident_id, int(p["fix_id"]), table_name=_approvals()) or {}
        live = approvals.get_proposal(incident_id, int(p["fix_id"]), table_name=_approvals())
        state = (
            "CANCELLED" if raw.get("withdrawn_reason") else "APPROVED" if raw.get("consumed_at") else "EXPIRED" if live is None else "PENDING_APPROVAL"
        )
        proposals.append({**p, "proposal_id": raw.get("approval_id"), "params_hash": raw.get("params_hash"), "state": state, "supporting_evidence_ids": raw.get("supporting_evidence_ids", []), "required_approver": "engineer with console passcode (typed confirmation)", "approval": raw.get("approval_summary")})
    detected = inc.get("detected_at")
    return {
        "incident_id": incident_id,
        "source_mode": inc.get("source_mode", "LIVE"),
        "severity": inc.get("severity"),
        "affected_service": inc.get("affected_service"),
        "alarm_name": inc.get("alarm_name"),
        "lifecycle": lifecycle(inc, bool(corrs), analyses, ver),
        "status": inc.get("status"),
        "detected_at": detected,
        "seconds_since_detection": int((now_utc() - parse_ts(detected)).total_seconds()) if detected else None,
        "events": events,
        "correlations": corrs,
        "research": research,
        "analyses": analyses,
        "research_briefs": briefs,
        "research_state": research_state,
        "analysis_stale": bool(analyses and analyses[-1]["staleness"]["stale"]),
        "proposals": proposals,
        "execution": [e for e in timeline if e.get("event") in ("approved", "executing", "executed", "execute_failed", "verify_attempt", "resolved", "escalated", "proposal_cancelled", "proposal_withdrawn")],
        "verification": ver,
        "provenance": ledger.provenance(incident_id),
        "digest": hashlib.sha256(json.dumps([len(events), len(corrs), len(research), len(analyses), len(briefs), len(timeline), r_status, budget["operations_used"], len(research_state["attempts"]), inc.get("status")], default=str).encode()).hexdigest()[:12],
    }


# ---------------------------------------------------------------------------- proposal


def propose(incident_id: str) -> dict[str, Any]:
    inc = store.get_incident(incident_id, table_name=_incidents())
    if not inc:
        return {"error": "incident not found"}
    # deterministic: live drift vs golden snapshot, executed on the WORKER (the API process holds no cluster credentials)
    diag = workflows.run_step("diagnose", {"step": "diagnose", "incident_id": incident_id})
    if not diag.get("ok"):
        return {"error": str(diag.get("error") or "diagnostics unavailable")}
    action, params = diag.get("suggested_action"), diag.get("action_params")
    if not action or not isinstance(params, dict):
        return {"error": "no safe fix: live state shows no drift from the golden snapshot (the change may already be reverted)"}
    params = registry.validate_params(str(action), params)
    existing = [p for p in inc.get("proposals") or [] if isinstance(p, dict)]
    fix_id = len(existing) + 1
    dry = workflows.run_step("dryrun", {"step": "dryrun", "action": action, "params": params, "incident_id": incident_id})
    spec = registry.get_action(str(action))
    blast = str(dry.get("blast_radius") or (spec.blast_radius(params) if spec else ""))
    dry_run = {"ok": bool(dry.get("ok")), "code": dry.get("code"), "detail": dry.get("detail") or dry.get("error"), "role": dry.get("role", "")}
    support = [e["event_id"] for e in ledger.events_for(incident_id)]
    proposal = approvals.create_proposal(incident_id, fix_id, str(action), params, blast_radius=blast, dry_run=dry_run, table_name=_approvals())
    from beacon import db

    db.patch(_approvals(), proposal["approval_id"], {"supporting_evidence_ids": support})
    summary = {
        "fix_id": fix_id,
        "action": action,
        "params": params,
        "target": f"{params.get('namespace')}/{params.get('name')}",
        "blast_radius": blast,
        "reason": "deterministic: the golden-snapshot ingress rule is missing from the live NetworkPolicy",
        "dry_run": dry_run,
        "expires_at": proposal["expires_at"],
        "expected_effect": f"{params.get('protocol')}/{params.get('port')} from app={params.get('from_app')} is admitted again into {params.get('namespace')}/{params.get('name')}",
        "confirmation_phrase": registry.confirmation_phrase(fix_id),
    }
    store.update_status(incident_id, str(inc.get("status") or "awaiting_engineer"), table_name=_incidents(), extra={"proposals": [*existing, summary]})
    store.append_timeline(incident_id, "fix_proposed", table_name=_incidents(), detail={"fix_id": fix_id, "action": action, "dry_run": dry_run, "blast_radius": blast})
    ledger.trace(incident_id, "proposal", proposal["approval_id"], {"dry_run_ok": dry_run["ok"]})
    return summary


# ---------------------------------------------------------------------------- approval


def approve(incident_id: str, fix_id: int, *, typed_phrase: str, params_hash: str, user: str, idempotency_key: str, authenticated: bool, auth_method: str = "", session: str = "") -> tuple[int, dict[str, Any]]:
    """Typed, authenticated approval bound to (incident, proposal, action+params hash, expiry, user, idempotency key)."""
    if not authenticated:
        return 401, {"approved": False, "error": "approval requires the console passcode"}
    if not _apply_enabled():
        return 409, {"approved": False, "error": "remediation is disabled (APPLY_ENABLED=false)"}
    if not idempotency_key:
        return 400, {"approved": False, "error": "idempotency_key is required"}
    raw = approvals.get_proposal_raw(incident_id, fix_id, table_name=_approvals())
    if raw is None:
        return 404, {"approved": False, "error": "no such proposal"}
    if raw.get("consumed_at"):
        if raw.get("idempotency_key") == idempotency_key:
            return 200, {"approved": True, "replay": True, "approval_id": raw.get("approval_id_issued"), "message": "this approval was already recorded; nothing was applied twice"}
        return 409, {"approved": False, "error": "proposal already approved with a different request; nothing more was applied"}
    proposal = approvals.get_proposal(incident_id, fix_id, table_name=_approvals())
    if proposal is None:
        why = "was cancelled" if raw.get("withdrawn_reason") else "expired"
        return 410, {"approved": False, "error": f"proposal {why}; nothing was applied. Propose again."}
    if params_hash != proposal.get("params_hash"):
        return 409, {"approved": False, "error": "the proposal changed since you reviewed it (params hash mismatch); review and approve again"}
    if not (proposal.get("dry_run") or {}).get("ok"):
        return 409, {"approved": False, "error": "this proposal failed its dry run and cannot be approved"}
    if " ".join(typed_phrase.lower().split()) != registry.confirmation_phrase(fix_id):
        return 422, {"approved": False, "error": f"type exactly '{registry.confirmation_phrase(fix_id)}' to approve"}
    if not approvals.consume_proposal(incident_id, fix_id, table_name=_approvals()):
        return 409, {"approved": False, "error": "proposal was just approved by another request"}
    record = approvals.create(
        incident_id,
        str(proposal["action"]),
        dict(proposal["params"]),
        source="console",
        channel="typed_console",
        transcript_quote=typed_phrase.strip(),
        fix_id=fix_id,
        table_name=_approvals(),
        attestation={"evidence": "typed_console", "user": user, "auth_method": auth_method, "session": session, "verified_human_identity": False, "idempotency_key": idempotency_key, "proposal_id": proposal["approval_id"], "params_hash": params_hash, "proposal_expires_at": proposal["expires_at"]},
    )
    from beacon import consent, db

    consent_rec = {"incident_id": incident_id, "proposal_id": proposal["approval_id"], "approval_id": record["approval_id"], "action": proposal["action"], "params_hash": params_hash, "principal": user, "auth_method": auth_method, "session": session, "typed_phrase": typed_phrase.strip(), "proposal_expires_at": proposal["expires_at"], "granted_at": record["granted_at"], "idempotency_key": idempotency_key}
    signature = consent.sign(consent_rec)
    db.patch(_approvals(), record["approval_id"], {"consent": consent_rec, "consent_signature": signature})
    db.patch(_approvals(), proposal["approval_id"], {"idempotency_key": idempotency_key, "approval_id_issued": record["approval_id"], "approval_summary": {"user": user, "auth_method": auth_method, "verified_human_identity": False, "approved_at": record["granted_at"], "evidence": "typed_console", "approval_id": record["approval_id"]}})
    store.append_timeline(incident_id, "approved", table_name=_incidents(), detail={"fix_id": fix_id, "channel": "typed_console", "user": user, "auth_method": auth_method, "approval_id": record["approval_id"], "transcript_quote": typed_phrase.strip()})
    ledger.trace(incident_id, "approval", record["approval_id"], {"user": user})
    payload = {"approval_id": record["approval_id"], "incident_id": incident_id, "action": proposal["action"], "params": proposal["params"]}

    def run() -> None:
        try:
            exec_id = workflows.start_remediation(payload)
            store.update_status(incident_id, store.get_incident(incident_id, table_name=_incidents()).get("status", "remediating"), table_name=_incidents(), extra={"execution_arn": exec_id})
            ledger.trace(incident_id, "temporal_execution", exec_id, {"mode": os.environ.get("REMEDIATION_MODE", "temporal")})
        except Exception:
            logger.exception("remediation start failed")
            store.append_timeline(incident_id, "execute_failed", table_name=_incidents(), detail={"detail": "could not start remediation"})

    if os.environ.get("REMEDIATION_MODE", "temporal") == "inline":
        threading.Thread(target=run, daemon=True, name=f"remediate-{incident_id}").start()
    else:
        run()
    return 202, {"approved": True, "approval_id": record["approval_id"], "message": "approved; execution and independent verification are running"}


def cancel(incident_id: str, fix_id: int, *, user: str) -> tuple[int, dict[str, Any]]:
    raw = approvals.get_proposal_raw(incident_id, fix_id, table_name=_approvals())
    if raw is None:
        return 404, {"error": "no such proposal"}
    if raw.get("consumed_at"):
        n = approvals.invalidate_for_fix(incident_id, fix_id, reason="cancelled by " + user, table_name=_approvals())
        if not n:
            return 409, {"error": "approval already used; execution cannot be cancelled from here"}
    approvals.withdraw_proposal(incident_id, fix_id, reason="cancelled by " + user, table_name=_approvals())
    approvals.invalidate_for_fix(incident_id, fix_id, reason="cancelled by " + user, table_name=_approvals())
    store.append_timeline(incident_id, "proposal_cancelled", table_name=_incidents(), detail={"fix_id": fix_id, "by": user})
    return 200, {"cancelled": True}


# ---------------------------------------------------------------------------- report


def report(incident_id: str) -> dict[str, Any] | None:
    """The postmortem, assembled ONLY from persisted records (no model writes any of it)."""
    from beacon import consent

    v = view(incident_id)
    if v is None:
        return None
    inc = store.get_incident(incident_id, table_name=_incidents())
    corr = v["correlations"][-1] if v["correlations"] else None
    analysis = next((a for a in reversed(v["analyses"]) if a.get("structured")), None)
    brief = v["research_briefs"][-1] if v.get("research_briefs") else None
    prop = v["proposals"][-1] if v["proposals"] else None
    tl = inc.get("timeline") or []
    approved = next((e for e in tl if e["event"] == "approved"), None)
    resolved = next((e for e in reversed(tl) if e["event"] in ("resolved", "escalated")), None)
    changes = [e for e in v["events"] if e["event_type"] == "networkpolicy_change"]
    symptoms = [e for e in v["events"] if e["event_type"] in ("alert_firing", "db_connection_error")]
    approval_rec = None
    if approved:
        rows = [r for r in approvals.list_for_incident(incident_id, table_name=_approvals()) if r.get("kind") == "approval"]
        approval_rec = rows[-1] if rows else None
    consent_ok = bool(approval_rec and approval_rec.get("consent") and consent.verify(approval_rec["consent"], approval_rec.get("consent_signature")))
    executions = [e for e in tl if e["event"] == "executed"]
    errors = [{"t": e["t"], "event": e["event"], "detail": e.get("detail")} for e in tl if e["event"] in ("execute_failed", "escalated", "proposal_cancelled", "proposal_withdrawn")]
    errors += [{"t": e["t"], "event": "verify_attempt_failed", "detail": [c["name"] for c in (e.get("detail") or {}).get("checks", []) if not c["ok"]]} for e in tl if e["event"] == "verify_attempt" and not (e.get("detail") or {}).get("ok")]
    duration = None
    if resolved and v.get("detected_at"):
        duration = int((parse_ts(resolved["t"]) - parse_ts(v["detected_at"])).total_seconds())
    unknown = list((analysis or {}).get("structured", {}).get("what_is_unknown", [])) + list((brief or {}).get("missing_evidence") or [])
    unknown.append("The approver is the local passcode holder (LOCAL_PASSCODE); no named individual was verified.")
    r = {
        "report_version": "nightshift.report.v2",
        "generated_at": iso(now_utc()),
        "generated_from": "persisted ledger records only (events, correlations, research attempts/sources/briefs, analyses, approvals, consent, timeline)",
        "incident_id": incident_id,
        "source_mode": v["source_mode"],
        "final_state": v["lifecycle"],
        "detected_at": v.get("detected_at"),
        "duration_seconds_detection_to_final": duration,
        "detection_events": [{k: e[k] for k in ("event_id", "source", "source_event_id", "event_type", "observed_at", "source_mode")} for e in changes + symptoms[:50]],
        "correlation": corr and {k: corr[k] for k in ("correlation_id", "rule", "strength", "included_event_ids", "window_start", "window_end", "window_seconds", "run_id", "missing_evidence", "explanation", "engine")} | {"status": "CORRELATION (not a confirmed root cause)"},
        "research": {
            "queries": [{k: a.get(k) for k in ("op", "query", "outcome", "http_status", "request_id", "credits_reported", "retry", "sent_at")} for a in ledger.queries_for(incident_id)],
            "sources": [{k: s.get(k) for k in ("evidence_id", "url", "domain", "title", "published_date", "date_status", "retrieved_at", "classification", "content_hash", "request_id")} for s in v["research"]],
            "budget": ledger.budget_for(incident_id),
            "brief": brief and {k: brief.get(k) for k in ("version", "snapshot_id", "origin", "evidence_strength", "incident_summary", "likely_explanation", "bifrost_request_id", "bifrost_trace_id", "provider", "model", "created_at")},
            "brief_status": v["research_state"]["brief_status"],
        },
        "analysis": analysis and {k: analysis.get(k) for k in ("analysis_id", "origin", "bifrost_request_id", "provider", "model", "evidence_set_hash")},
        "proposal": prop and {k: prop.get(k) for k in ("fix_id", "proposal_id", "action", "params", "target", "blast_radius", "dry_run", "expires_at", "state")},
        "policy_decision": {"engine": "OPA", "dry_run_phase": "ALLOW" if prop and prop["dry_run"].get("ok") else "NOT_ALLOWED_OR_NOT_RUN", "execute_phase": "ALLOW (execution was performed)" if executions else "NOT_EVALUATED_OR_DENIED"},
        "approval": approved and {"approver": (approved.get("detail") or {}).get("user"), "auth_method": (approved.get("detail") or {}).get("auth_method"), "verified_human_identity": False, "typed_phrase": (approved.get("detail") or {}).get("transcript_quote"), "approval_id": (approved.get("detail") or {}).get("approval_id"), "approved_at": approved["t"], "consent_signature": approval_rec and approval_rec.get("consent_signature"), "consent_signature_valid": consent_ok},
        "execution": {"count": len(executions), "events": [e for e in tl if e["event"] in ("executing", "executed", "execute_failed")], "workflow": inc.get("execution_arn")},
        "kubernetes_changes": [{"event_id": e["event_id"], "observed_at": e["observed_at"], "summary": e["summary"]} for e in v["events"] if e["event_type"] == "remediation_applied"] or ([{"action": prop["action"], "params": prop["params"], "note": "no audit event for the remediation has been ingested"}] if executions and prop else []),
        "verification": v["verification"],
        "errors_and_interruptions": errors,
        "remaining_uncertainty": unknown,
        "provenance": v["provenance"],
        "events": [{k: e[k] for k in ("event_id", "source", "source_event_id", "event_type", "observed_at", "source_mode")} for e in v["events"]],
    }
    return r


def report_markdown(r: dict[str, Any]) -> str:
    c, ap, pr, ex = r["correlation"], r["approval"], r["proposal"], r["execution"]
    L = [
        f"# Incident report {r['incident_id']}",
        f"Final state: **{r['final_state']}** · source mode: **{r['source_mode']}** · generated {r['generated_at']} from persisted records",
        f"Detected {r['detected_at']} · detection→final {r['duration_seconds_detection_to_final']} s",
        "",
        "## Detection and correlation",
        *[f"- {e['observed_at']} {e['source']}/{e['event_type']} `{e['source_event_id']}` ({e['source_mode']})" for e in r["detection_events"][:12]],
        f"- Rule `{c and c['rule']}` window {c and c['window_seconds']} s, strength {c and c['strength']}: {c and c['status']}" if c else "- no correlation",
        *[f"- Missing evidence: {m}" for m in (c or {}).get("missing_evidence", [])],
        "",
        "## Research",
        f"- {len(r['research']['queries'])} external attempt(s), {len(r['research']['sources'])} source(s); budget {r['research']['budget']['operations_used']}/{r['research']['budget']['max_operations']} operations",
        *[f"- source {s['domain']} {s['url']} ({s['classification']}, published {s['published_date'] or 'unknown'}, fetched {s['retrieved_at']})" for s in r["research"]["sources"][:10]],
        f"- Brief: {r['research']['brief']}" if r["research"]["brief"] else "- no research brief",
        "",
        "## Remediation",
        f"- Proposal: {pr['action']} {pr['params']} on {pr['target']}; blast radius: {pr['blast_radius']}" if pr else "- no proposal",
        f"- Policy: {r['policy_decision']}",
        f"- Approval: {ap}" if ap else "- no approval",
        f"- Execution count: **{ex['count']}** (workflow {ex['workflow']})",
        *[f"- Kubernetes change: {k}" for k in r["kubernetes_changes"]],
        "",
        "## Independent verification",
    ]
    for cat, info in r["verification"].get("categories", {}).items():
        L.append(f"- {cat}: **{info['status']}**")
        L += [f"  - {k['name']}: {'ok' if k['ok'] else 'FAILED'} @ {k['checked_at']} — {k['detail']}" for k in info["checks"]]
    L += ["", "## Errors and interruptions", *[f"- {e['t']} {e['event']} {e['detail']}" for e in r["errors_and_interruptions"]], "", "## Remaining uncertainty", *[f"- {u}" for u in r["remaining_uncertainty"]], "", "## Provenance", *[f"- {p['at']} {p['stage']} {p['ref']}" for p in r["provenance"]]]
    return "\n".join(L)


__all__ = ["approve", "cancel", "datetime", "lifecycle", "propose", "report", "report_markdown", "verification_view", "view"]
