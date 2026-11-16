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
    if status == "resolved" and verification.get("all_passed"):
        return "VERIFIED"
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
        "proposals": proposals,
        "execution": [e for e in timeline if e.get("event") in ("approved", "executing", "executed", "execute_failed", "verify_attempt", "resolved", "escalated", "proposal_cancelled")],
        "verification": ver,
        "provenance": ledger.provenance(incident_id),
        "digest": hashlib.sha256(json.dumps([len(events), len(corrs), len(research), len(analyses), len(timeline), inc.get("status")], default=str).encode()).hexdigest()[:12],
    }


# ---------------------------------------------------------------------------- proposal


def propose(incident_id: str) -> dict[str, Any]:
    from beacon import diagnose
    from beacon.remediation import actions_netpol

    inc = store.get_incident(incident_id, table_name=_incidents())
    if not inc:
        return {"error": "incident not found"}
    golden = actions_netpol.load_golden_snapshot() or {}
    diag = diagnose.run(golden)  # deterministic: live drift vs golden snapshot
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


def approve(incident_id: str, fix_id: int, *, typed_phrase: str, params_hash: str, user: str, idempotency_key: str, authenticated: bool) -> tuple[int, dict[str, Any]]:
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
        attestation={"evidence": "typed_console", "user": user, "idempotency_key": idempotency_key, "proposal_id": proposal["approval_id"], "params_hash": params_hash, "proposal_expires_at": proposal["expires_at"]},
    )
    from beacon import db

    db.patch(_approvals(), proposal["approval_id"], {"idempotency_key": idempotency_key, "approval_id_issued": record["approval_id"], "approval_summary": {"user": user, "approved_at": record["granted_at"], "evidence": "typed_console", "approval_id": record["approval_id"]}})
    store.append_timeline(incident_id, "approved", table_name=_incidents(), detail={"fix_id": fix_id, "channel": "typed_console", "user": user, "approval_id": record["approval_id"], "transcript_quote": typed_phrase.strip()})
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
    v = view(incident_id)
    if v is None:
        return None
    corr = v["correlations"][-1] if v["correlations"] else None
    analysis = next((a for a in reversed(v["analyses"]) if a.get("structured")), None)
    prop = v["proposals"][-1] if v["proposals"] else None
    approved = next((e for e in v["execution"] if e["event"] == "approved"), None)
    executed = next((e for e in v["execution"] if e["event"] in ("executed", "execute_failed")), None)
    changes = [e for e in v["events"] if e["event_type"] == "networkpolicy_change"]
    symptoms = [e for e in v["events"] if e["event_type"] in ("alert_firing", "db_connection_error")]
    qa = {
        "what_changed": changes[0]["summary"] if changes else "no change event recorded",
        "resource_affected": corr["resource"] if corr else None,
        "symptoms_that_followed": [f"{e['source']}: {e['summary']}" for e in symptoms][:6],
        "supporting_event_ids": corr["included_event_ids"] if corr else [],
        "known_vs_hypothesis": {
            "confirmed": [c["text"] for c in (analysis or {}).get("structured", {}).get("what_is_confirmed", [])] if analysis else ["events were recorded with source timestamps"],
            "hypothesis": (analysis or {}).get("structured", {}).get("root_cause_hypothesis") if analysis else "root cause not analysed",
            "unknown": (analysis or {}).get("structured", {}).get("what_is_unknown", []) if analysis else [],
        },
        "smallest_safe_remediation": f"{prop['action']} {prop['params']}" if prop else None,
        "exact_change": prop["blast_radius"] if prop else None,
        "approved_by": (approved or {}).get("detail", {}).get("user") if approved else None,
        "executed": bool(executed and executed["event"] == "executed"),
        "recovery_independently_verified": v["lifecycle"] == "VERIFIED",
    }
    return {
        "report_version": "nightshift.report.v1",
        "generated_at": iso(now_utc()),
        "generated_from": "persisted ledger records (events, correlations, research, analyses, approvals, timeline)",
        "incident_id": incident_id,
        "source_mode": v["source_mode"],
        "lifecycle": v["lifecycle"],
        "answers": qa,
        "analysis_origin": (analysis or {}).get("origin"),
        "analysis_gateway": {k: (analysis or {}).get(k) for k in ("bifrost_request_id", "provider", "model", "latency_ms", "usage", "cost")} if analysis else None,
        "verification": v["verification"],
        "provenance": v["provenance"],
        "events": [{k: e[k] for k in ("event_id", "source", "source_event_id", "event_type", "observed_at", "source_mode")} for e in v["events"]],
    }


def report_markdown(r: dict[str, Any]) -> str:
    a = r["answers"]
    lines = [
        f"# Incident report {r['incident_id']}",
        f"Lifecycle: **{r['lifecycle']}** · source mode: **{r['source_mode']}** · generated {r['generated_at']}",
        "",
        "## What happened",
        f"- What changed: {a['what_changed']}",
        f"- Affected resource: {a['resource_affected']}",
        "- Symptoms that followed:",
        *[f"  - {s}" for s in a["symptoms_that_followed"]],
        f"- Supporting event ids: {', '.join(a['supporting_event_ids'])}",
        "",
        "## Known vs hypothesis",
        *[f"- Confirmed: {c}" for c in a["known_vs_hypothesis"]["confirmed"]],
        f"- Hypothesis: {a['known_vs_hypothesis']['hypothesis']}",
        *[f"- Unknown: {u}" for u in a["known_vs_hypothesis"]["unknown"]],
        "",
        "## Remediation",
        f"- Smallest safe remediation: {a['smallest_safe_remediation']}",
        f"- Exact change: {a['exact_change']}",
        f"- Approved by: {a['approved_by']}",
        f"- Executed: {a['executed']}",
        f"- Recovery independently verified: {a['recovery_independently_verified']}",
        "",
        "## Verification",
    ]
    for cat, info in r["verification"].get("categories", {}).items():
        lines.append(f"- {cat}: **{info['status']}**")
        lines += [f"  - {c['name']}: {'ok' if c['ok'] else 'FAILED'} @ {c['checked_at']} — {c['detail']}" for c in info["checks"]]
    lines += ["", "## Provenance", *[f"- {p['at']} {p['stage']} {p['ref']}" for p in r["provenance"]]]
    return "\n".join(lines)


__all__ = ["approve", "cancel", "datetime", "lifecycle", "propose", "report", "report_markdown", "verification_view", "view"]
