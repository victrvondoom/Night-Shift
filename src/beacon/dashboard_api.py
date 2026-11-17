"""Read-only dashboard API (FastAPI router mounted at ``/api``).

Public reads for the console.  Every response goes through :func:`redact`
so tokens and keys never reach a browser.  The only
mutation is revoking a Sleep Contract, which needs the passcode.
"""

from __future__ import annotations

import json
import logging
import os
import re
import statistics
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from importlib import metadata
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import Response

from beacon import contracts, prom, reports, store
from beacon.remediation import registry

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

SERVICE = "beacon-dashboard"
# Bearer tokens and OmniDimension keys must never reach a browser, whatever row they
# were accidentally written into.
_TOKEN_RE = re.compile(r"\b(bn-[A-Za-z0-9]{8,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9._-]+)")
_PRIVATE_FIELDS = ("conversation", "rca", "cached_data")

SAFETY_RULES = [
    "Only allowlisted actions can run; params must match the schema exactly.",
    "NetworkPolicy restores must exist in the golden snapshot taken on a healthy cluster.",  # noqa: E501
    "Every action passes OPA policy and a Kubernetes server-side dry run before execution.",  # noqa: E501
    "A voice request is never consent: approval needs the exact phrase from a verified channel.",  # noqa: E501
    "One approval executes exactly once (a single conditional UPDATE on the approval row).",  # noqa: E501
    "Verification needs the alert cleared after the fix, its expression clean, the post-condition and a passing health check.",  # noqa: E501
    "Sleep Contracts are scoped to alert + action + exact resources, expire, and count uses.",  # noqa: E501
    "APPLY_ENABLED=false stops every write path: triage contract branch, approvals, execute.",  # noqa: E501
]


def _control(cid: str, title: str, rule: str, file: str, test: str) -> dict[str, str]:
    return {"id": cid, "title": title, "rule": rule, "file": file, "test": test}


# The same rules as controls the console can walk through: the plain-language
# rule, the file that enforces it, and the test that proves it.
SAFETY_CONTROLS: list[dict[str, str]] = [
    _control(
        "allowlist",
        "Only allowlisted actions",
        SAFETY_RULES[0],
        "src/beacon/remediation/registry.py",
        "tests/test_registry.py::test_registry_has_exactly_the_allowlisted_actions",
    ),
    _control(
        "golden",
        "Restores must match the golden snapshot",
        SAFETY_RULES[1],
        "src/beacon/remediation/actions_netpol.py",
        "tests/test_k8s_remediation.py::test_dryrun_rejects_rule_outside_golden_snapshot",
    ),
    _control(
        "dry-run",
        "Policy check and server-side dry run",
        SAFETY_RULES[2],
        "src/beacon/remediate.py",
        "tests/test_policy.py::test_protected_namespace_is_denied",
    ),
    _control(
        "transcript",
        "A voice request is not consent",
        SAFETY_RULES[3],
        "src/beacon/voice_tools.py",
        "tests/test_consent.py::test_omnidim_approve_is_held_and_nothing_executes",
    ),
    _control(
        "once",
        "One approval executes exactly once",
        SAFETY_RULES[4],
        "src/beacon/approvals.py",
        "tests/test_idempotency.py::test_approval_is_consumed_exactly_once_under_race",
    ),
    _control(
        "verify",
        "Four-part verification",
        SAFETY_RULES[5],
        "src/beacon/remediation/verify.py",
        "tests/test_verify.py::test_alert_that_cleared_before_the_fix_does_not_pass",
    ),
    _control(
        "contracts",
        "Sleep Contracts are scoped and expire",
        SAFETY_RULES[6],
        "src/beacon/contracts.py",
        "tests/test_contracts.py::test_match_is_scoped_to_alarm_action_and_exact_params",
    ),
    _control(
        "kill-switch",
        "Kill switch",
        SAFETY_RULES[7],
        "src/beacon/remediate.py",
        "tests/test_idempotency.py::test_execute_honours_the_kill_switch",
    ),
    _control(
        "two-roles",
        "Two identities, one direction",
        "The API you talk to runs as a read-only service account; only the worker, "
        "whose Role can patch NetworkPolicies and Deployments in the allowed "
        "namespaces, can change anything.",
        "deploy/k8s/beacon/rbac.yaml",
        "tests/test_manifests.py::test_api_service_account_has_no_write_verbs",
    ),
]

router = APIRouter()


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _json(status: int, body: dict[str, Any]) -> Response:
    return Response(
        status_code=status,
        media_type="application/json",
        content=json.dumps(redact(body), default=str),
    )


def _passcode_ok(request: Request) -> bool:
    from beacon import auth

    return auth.principal(request) is not None


# A bare 12-digit number that is not part of a UUID or hex id (cloud account ids
# in archived incidents and anything shaped like one).
_ACCOUNT_RE = re.compile(r"(?<![0-9A-Fa-f-])\d{12}(?![0-9A-Fa-f-])")


def _redact_str(value: str) -> str:
    return _ACCOUNT_RE.sub("************", _TOKEN_RE.sub("[redacted]", value))


def redact(value: Any) -> Any:
    """Strip anything token-shaped from a response, recursively."""
    if isinstance(value, str):
        return _redact_str(value)
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    return value


def _public(incident: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in incident.items() if k not in _PRIVATE_FIELDS}


_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_CACHE_SECONDS = 2.0


def _scan_incidents(table: str) -> list[dict[str, Any]]:
    rows = store.scan_incidents(table)
    rows.sort(key=lambda r: str(r.get("timestamp", "")), reverse=True)
    return rows


def _all_incidents() -> list[dict[str, Any]]:
    """Incident list with a per-container cache: many viewers poll every 3 s."""
    table = _env("INCIDENTS_TABLE_NAME", "incidents")
    now = time.monotonic()
    hit = _cache.get(table)
    if hit and now - hit[0] < _CACHE_SECONDS:
        return hit[1]
    rows = _scan_incidents(table)
    _cache[table] = (now, rows)
    return rows


def _minutes(start: Any, end: Any) -> float | None:
    try:
        a = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        b = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
    except ValueError:
        return None
    return round((b - a).total_seconds() / 60, 1)


# Token price (USD per 1M tokens; 0 for a local model) and a fixed conversion, so the
# tally shows an honest order of magnitude, not a bill.  Both are env-tunable.
def _price(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def cost_inr(usage: dict[str, Any] | None) -> float:
    """Rupees for one incident's model usage (input, output, embedding tokens)."""
    if not usage:
        return 0.0
    usd = (
        float(usage.get("input_tokens", 0)) / 1e6 * _price("PRICE_INPUT_PER_M", 0.06)
        + float(usage.get("output_tokens", 0))
        / 1e6
        * _price("PRICE_OUTPUT_PER_M", 0.24)
        + float(usage.get("embedding_tokens", 0))
        / 1e6
        * _price("PRICE_EMBED_PER_M", 0.02)
    )
    return round(usd * _price("USD_INR", 84.0), 4)


def _is_night_ist(iso: str) -> bool:
    """22:00-07:00 IST: the hours a page costs sleep."""
    try:
        when = datetime.fromisoformat(str(iso).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return False
    minutes = when.hour * 60 + when.minute + 330  # UTC -> IST
    hour = (minutes // 60) % 24
    return hour >= 22 or hour < 7


def _parse(iso: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(iso).replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        return None


def _night_of(iso: Any) -> str | None:
    """Label the night an incident belongs to: IST date, with the day turning
    over at noon so 23:30 and 03:00 the next morning are the same night."""
    when = _parse(iso)
    if when is None:
        return None
    return (when + timedelta(hours=5, minutes=30) - timedelta(hours=12)).strftime(
        "%Y-%m-%d"
    )


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = (len(ordered) - 1) * pct
    lo, hi = int(idx), min(int(idx) + 1, len(ordered) - 1)
    return round(ordered[lo] + (ordered[hi] - ordered[lo]) * (idx - lo), 2)


def _seconds_to_first_proposal(row: dict[str, Any]) -> float | None:
    """Alarm to the first dry-run fix on the table, from the timeline."""
    start = _parse(row.get("timestamp"))
    if start is None:
        return None
    for ev in row.get("timeline") or []:
        if ev.get("event") == "fix_proposed":
            at = _parse(ev.get("t"))
            if at is not None:
                return max(0.0, round((at - start).total_seconds(), 1))
    return None


def _version() -> str:
    explicit = _env("BEACON_VERSION")
    if explicit:
        return explicit
    try:
        return metadata.version("beacon")
    except metadata.PackageNotFoundError:
        return "dev"


def build_analytics(
    rows: list[dict[str, Any]], live_contracts: list[dict[str, Any]]
) -> dict[str, Any]:
    """Operations analytics from the incident rows and the live contracts.

    Pure, so the console can mirror it client-side in replay mode and the
    tests can pin the numbers without a table.
    """
    nights: dict[str, dict[str, Any]] = {}
    per_incident: list[dict[str, Any]] = []
    ttr_all: list[float] = []
    proposal_secs: list[float] = []
    cumulative = 0.0
    for row in sorted(rows, key=lambda r: str(r.get("timestamp", ""))):
        night = _night_of(row.get("timestamp")) or "unknown"
        bucket = nights.setdefault(
            night,
            {
                "night": night,
                "incidents": 0,
                "resolved": 0,
                "escalated": 0,
                "woken": 0,
                "under_contract": 0,
                "cost_inr": 0.0,
                "_ttr": [],
            },
        )
        status = str(row.get("status", ""))
        ttr = (
            _minutes(row.get("timestamp"), row.get("resolved_at"))
            if status == "resolved" and row.get("resolved_at")
            else None
        )
        cost = cost_inr(row.get("usage"))
        cumulative = round(cumulative + cost, 4)
        under_contract = row.get("handled_by") == "contract"
        woken = bool(row.get("woken", True))
        bucket["incidents"] += 1
        bucket["resolved"] += status == "resolved"
        bucket["escalated"] += status == "escalated"
        bucket["woken"] += woken
        bucket["under_contract"] += under_contract
        bucket["cost_inr"] = round(bucket["cost_inr"] + cost, 4)
        if ttr is not None:
            bucket["_ttr"].append(ttr)
            ttr_all.append(ttr)
        first = _seconds_to_first_proposal(row)
        if first is not None:
            proposal_secs.append(first)
        per_incident.append(
            {
                "incident_id": row.get("incident_id"),
                "alarm_name": row.get("alarm_name"),
                "timestamp": row.get("timestamp"),
                "night": night,
                "status": status,
                "woken": woken,
                "under_contract": under_contract,
                "minutes_to_recovery": ttr,
                "seconds_to_first_proposal": first,
                "cost_inr": cost,
                "cost_inr_cumulative": cumulative,
            }
        )
    night_rows = []
    for bucket in nights.values():
        ttrs = bucket.pop("_ttr")
        bucket["median_minutes_to_recovery"] = _percentile(ttrs, 0.5)
        bucket["p90_minutes_to_recovery"] = _percentile(ttrs, 0.9)
        night_rows.append(bucket)
    night_rows.sort(key=lambda b: b["night"])
    alarms = Counter(str(r.get("alarm_name") or "unknown") for r in rows)
    outcomes = Counter(str(r.get("status", "")) for r in rows)
    now = datetime.now(tz=UTC)
    contract_rows = []
    for c in live_contracts:
        expires = _parse(c.get("expires_at"))
        contract_rows.append(
            {
                "contract_id": c.get("contract_id"),
                "alarm_name": c.get("alarm_name"),
                "action": c.get("action"),
                "uses": int(c.get("uses") or 0),
                "max_uses": int(c.get("max_uses") or 0),
                "uses_left": max(
                    0, int(c.get("max_uses") or 0) - int(c.get("uses") or 0)
                ),
                "expires_at": c.get("expires_at"),
                "hours_left": round((expires - now).total_seconds() / 3600, 1)
                if expires
                else None,
            }
        )
    return {
        "generated_at": now.isoformat(),
        "nights": night_rows,
        "incidents": per_incident,
        "recovery": {
            "count": len(ttr_all),
            "p50_minutes": _percentile(ttr_all, 0.5),
            "p90_minutes": _percentile(ttr_all, 0.9),
            "max_minutes": max(ttr_all) if ttr_all else None,
        },
        "first_proposal": {
            "count": len(proposal_secs),
            "mean_seconds": round(statistics.fmean(proposal_secs), 1)
            if proposal_secs
            else None,
        },
        "outcomes": {
            "resolved": outcomes.get("resolved", 0),
            "escalated": outcomes.get("escalated", 0),
            "in_progress": sum(
                v for k, v in outcomes.items() if k not in ("resolved", "escalated")
            ),
        },
        "humans": {
            "woken": sum(1 for r in rows if r.get("woken", True)),
            "under_contract": sum(1 for r in rows if r.get("handled_by") == "contract"),
        },
        "cost": {
            "total_inr": cumulative,
            "per_incident_inr": round(cumulative / len(rows), 4) if rows else 0.0,
        },
        "top_alarms": [
            {"alarm_name": name, "count": n} for name, n in alarms.most_common(5)
        ],
        "contracts": contract_rows,
    }


def _alarm_metric_series(alarm_name: str, minutes: int = 30) -> list[dict[str, Any]]:
    """The alert expression's own series (what Verify looks at), oldest first.

    The rule's comparison is stripped so the raw value is charted rather than
    only the moments it was breaching.
    """
    rule = prom.alert_rule(alarm_name)
    if not rule:
        return []
    expr = re.sub(r"\s*(==|!=|>=|<=|>|<)\s*[-+0-9.e]+\s*$", "", str(rule["query"]))
    end = time.time()
    series = prom.query_range(expr, start=end - minutes * 60, end=end, step=15)
    if not series:
        return []
    return [
        {"t": datetime.fromtimestamp(float(t), tz=UTC).isoformat(), "v": float(v)}
        for t, v in series[0].get("values") or []
    ]


def _apply_flags() -> dict[str, bool | None]:
    """APPLY_ENABLED on the write paths (one setting for API and worker)."""
    on = _env("APPLY_ENABLED", "true").lower() != "false"
    return {"triage": on, "voice": on, "remediate": on}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "service": SERVICE,
        "version": _version(),
        "region": _env("CLUSTER_NAME", "local"),
        "stack": _env("BEACON_NAMESPACE", "beacon"),
    }


@router.get("/incidents")
def incidents() -> Response:
    rows = [_public(r) for r in _all_incidents()[:50]]
    return _json(200, {"incidents": rows})


@router.get("/incidents/{incident_id}")
def incident(incident_id: str) -> Response:
    row = store.get_incident(
        incident_id, table_name=_env("INCIDENTS_TABLE_NAME", "incidents")
    )
    if not row:
        return _json(404, {"error": "not found"})
    return _json(200, {"incident": _public(row)})


@router.get("/incidents/{incident_id}/execution")
def execution(incident_id: str) -> Response:
    row = store.get_incident(
        incident_id, table_name=_env("INCIDENTS_TABLE_NAME", "incidents")
    )
    if not row:
        return _json(404, {"error": "not found"})
    arn = str(row.get("execution_arn") or "")
    status = None
    if arn:
        try:
            from beacon import workflows

            status = workflows.describe(arn).get("status")
        except Exception as exc:
            logger.warning("workflow status unavailable: %s", exc)
    # The loop's own steps, as the worker wrote them to the incident timeline.
    steps = (
        "executing",
        "executed",
        "execute_failed",
        "verify_attempt",
        "resolved",
        "escalated",
    )
    events = [
        {"t": e.get("t"), "type": "ActivityCompleted", "state": e.get("event")}
        for e in row.get("timeline") or []
        if e.get("event") in steps
    ]
    return _json(200, {"execution_arn": arn, "status": status, "events": events})


@router.get("/incidents/{incident_id}/metric")
def incident_metric(incident_id: str) -> Response:
    row = store.get_incident(
        incident_id, table_name=_env("INCIDENTS_TABLE_NAME", "incidents")
    )
    if not row:
        return _json(404, {"error": "not found"})
    alarm_name = str(row.get("alarm_name") or "")
    points: list[dict[str, Any]] = []
    if alarm_name:
        try:
            points = _alarm_metric_series(alarm_name)
        except Exception as exc:
            logger.warning("metric series unavailable: %s", exc)
    return _json(
        200,
        {
            "alarm_name": alarm_name,
            "metric": {"namespace": "prometheus", "metric_name": alarm_name},
            "points": points,
            "executed_at": row.get("executed_at"),
            "resolved_at": row.get("resolved_at"),
        },
    )


@router.get("/tally")
def tally() -> Response:
    rows = _all_incidents()
    resolved = [r for r in rows if r.get("status") == "resolved"]
    durations = [
        m
        for m in (_minutes(r.get("timestamp"), r.get("resolved_at")) for r in resolved)
        if m is not None
    ]
    costs = [cost_inr(r.get("usage")) for r in rows]
    night_not_woken = [
        r
        for r in rows
        if r.get("woken") is False and _is_night_ist(str(r.get("timestamp", "")))
    ]
    # each night incident handled without a page protects ~1 h of sleep
    # (the time an engineer typically stays up after a 3 AM page)
    per_page = float(os.environ.get("SLEEP_HOURS_PER_PAGE", "1.0"))
    return _json(
        200,
        {
            "incidents_handled": len(rows),
            "resolved": len(resolved),
            "escalated": sum(1 for r in rows if r.get("status") == "escalated"),
            "humans_woken": sum(1 for r in rows if r.get("woken", True)),
            "handled_by_contract": sum(
                1 for r in rows if r.get("handled_by") == "contract"
            ),
            "median_minutes_to_recovery": statistics.median(durations)
            if durations
            else None,
            "cost_inr_total": round(sum(costs), 4),
            "cost_inr_per_incident": round(sum(costs) / len(rows), 4) if rows else 0.0,
            "night_incidents_not_woken": len(night_not_woken),
            "sleep_protected_hours": round(len(night_not_woken) * per_page, 1),
        },
    )


@router.get("/analytics")
def analytics() -> Response:
    live = contracts.list_active(table_name=_env("CONTRACTS_TABLE_NAME", "contracts"))
    return _json(200, build_analytics(_all_incidents(), live))


def _all_approvals() -> list[dict[str, Any]]:
    from beacon import approvals

    return [
        r
        for r in approvals.scan(_env("APPROVALS_TABLE_NAME", "approvals"))
        if r.get("kind") in (None, "approval")
    ]


def _all_contracts() -> list[dict[str, Any]]:
    return contracts._scan(_env("CONTRACTS_TABLE_NAME", "contracts"))


@router.get("/incidents/{incident_id}/postmortem")
def postmortem(incident_id: str) -> Response:
    """A deterministic Markdown postmortem for one incident (no model call)."""
    row = store.get_incident(
        incident_id, table_name=_env("INCIDENTS_TABLE_NAME", "incidents")
    )
    if not row:
        return _json(404, {"error": "not found"})
    md = reports.postmortem(row, contracts=_all_contracts(), approvals=_all_approvals())
    return Response(
        status_code=200,
        media_type="text/markdown; charset=utf-8",
        content=str(redact(md)),
    )


@router.get("/audit")
def audit(request: Request) -> Response:
    """Every consent record with the words that granted it; ``?format=csv``."""
    rows = reports.audit(
        approvals=_all_approvals(),
        contracts=_all_contracts(),
        incidents=_all_incidents(),
    )
    if request.query_params.get("format", "json") == "csv":
        return Response(
            status_code=200,
            media_type="text/csv; charset=utf-8",
            content=str(redact(reports.audit_csv(rows))),
        )
    return _json(200, {"rows": rows, "count": len(rows)})


@router.get("/report/latest")
def report_latest(request: Request) -> Response:
    """The morning report for the night that just ended (or ``?night=YYYY-MM-DD``)."""
    night = request.query_params.get("night")
    live = contracts.list_active(table_name=_env("CONTRACTS_TABLE_NAME", "contracts"))
    return _json(
        200, reports.morning_report(_all_incidents(), contracts=live, night_of=night)
    )


@router.get("/contracts")
def list_contracts() -> Response:
    rows = contracts.list_active(table_name=_env("CONTRACTS_TABLE_NAME", "contracts"))
    out = [
        {
            "contract_id": r["contract_id"],
            "alarm_name": r.get("alarm_name"),
            "action": r.get("action"),
            "scope": r.get("params"),
            "uses": r.get("uses"),
            "max_uses": r.get("max_uses"),
            "granted_at": r.get("granted_at"),
            "expires_at": r.get("expires_at"),
            "transcript_quote": r.get("transcript_quote"),
            "granted_by": r.get("granted_by"),
            "incident_id": r.get("incident_id"),
        }
        for r in rows
    ]
    return _json(200, {"contracts": out})


@router.delete("/contracts/{contract_id}")
def revoke_contract(contract_id: str, request: Request) -> Response:
    if not _passcode_ok(request):
        return _json(401, {"error": "passcode required"})
    contracts.revoke(contract_id, table_name=_env("CONTRACTS_TABLE_NAME", "contracts"))
    return _json(200, {"ok": True, "contract_id": contract_id})


@router.get("/safety")
def safety() -> Response:
    allowlist = [
        {
            "id": spec.id,
            "description": spec.description,
            "params": {k: t.__name__ for k, t in spec.params_schema.items()},
            "iam_actions": list(spec.rbac_rules),
            "inverse": spec.inverse,
            "undo_of": next(
                (o.id for o in registry.REGISTRY.values() if o.inverse == spec.id),
                None,
            ),
        }
        for spec in registry.REGISTRY.values()
    ]
    return _json(
        200,
        {
            "allowlist": allowlist,
            "apply_enabled": _apply_flags(),
            "rules": SAFETY_RULES,
            "controls": SAFETY_CONTROLS,
        },
    )
