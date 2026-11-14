"""Change ledger: who changed what, just before the alert.

Two feeds write rows, both arriving over NATS JetStream (``beacon.changes``):

* **Kubernetes audit events** -- the API server's audit webhook posts every
  write (create/update/patch/delete) with the user, verb and object;
* **GitHub events** -- ``deployment``, ``deployment_status`` and ``push``
  webhooks, so a rollout is tied to the commit and the person behind it.

Triage reads the window before the alert and ranks a change that names a
resource diagnostics found broken above everything else.
"""

from __future__ import annotations

import logging
import os
import time
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from beacon import db

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

_TTL_DAYS = 30
_WRITE_VERBS = ("delete", "deletecollection", "patch", "update", "create")
# service accounts whose routine writes are noise, not causes
_NOISE_USERS = (
    "system:kube-controller-manager",
    "system:kube-scheduler",
    "system:apiserver",
    "system:node:",
    "system:serviceaccount:kube-system:",
)


def _table() -> str:
    return os.environ.get("CHANGES_TABLE_NAME", "changes")


def _remediator() -> str:
    return os.environ.get(
        "BEACON_K8S_IDENTITY", "system:serviceaccount:beacon:beacon-remediator"
    )


def short_actor(user: str) -> str:
    """``system:serviceaccount:ns:name`` -> ``sa/ns/name``; people stay as they are."""
    if user == _remediator():
        return "beacon remediation"
    if user.startswith("system:serviceaccount:"):
        return "sa/" + "/".join(user.split(":")[2:])
    return user


def from_audit_event(event: dict[str, Any]) -> dict[str, Any] | None:
    """One ledger row from a Kubernetes ``audit.k8s.io/v1`` event, or None."""
    verb = str(event.get("verb") or "")
    ref = event.get("objectRef") or {}
    user = str((event.get("user") or {}).get("username") or "unknown")
    if verb not in _WRITE_VERBS or event.get("stage") not in (None, "ResponseComplete"):
        return None
    if not ref.get("resource") or any(user.startswith(n) for n in _NOISE_USERS):
        return None
    if ref.get("resource") in ("events", "leases", "tokenreviews", "endpoints"):
        return None
    code = int((event.get("responseStatus") or {}).get("code") or 0)
    if "All" in ((event.get("requestURI") or "").partition("dryRun=")[2][:3]):
        return None  # a dry run changed nothing
    when = _norm(event.get("stageTimestamp") or event.get("requestReceivedTimestamp"))
    target = "/".join(p for p in (ref.get("namespace"), ref.get("name")) if p)
    return {
        "sk": f"{when}#{event.get('auditID') or time.time_ns()}",
        "event_name": f"{verb} {ref.get('resource')}",
        "event_source": "kubernetes-audit",
        "event_time": when,
        "actor": user,
        "actor_short": short_actor(user),
        "by_beacon": user == _remediator(),
        "user_agent": str(event.get("userAgent") or "")[:200],
        "source_ip": ",".join(event.get("sourceIPs") or []),
        "resource_ids": [target] if target else [],
        "error_code": "" if code < 400 else str(code),
        "ttl": int(time.time()) + _TTL_DAYS * 86400,
    }


def from_github_event(kind: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    """One ledger row from a GitHub ``deployment`` / ``deployment_status`` / ``push``."""
    repo = str((payload.get("repository") or {}).get("full_name") or "")
    actor = str((payload.get("sender") or {}).get("login") or "unknown")
    if kind == "deployment":
        dep = payload.get("deployment") or {}
        when, what = (
            dep.get("created_at"),
            f"{dep.get('environment')}@{str(dep.get('sha'))[:7]}",
        )
    elif kind == "deployment_status":
        st, dep = (
            payload.get("deployment_status") or {},
            payload.get("deployment") or {},
        )
        when = st.get("created_at")
        what = f"{dep.get('environment')}@{str(dep.get('sha'))[:7]}:{st.get('state')}"
    elif kind == "push":
        when = (payload.get("head_commit") or {}).get("timestamp")
        what = f"{payload.get('ref')}@{str(payload.get('after'))[:7]}"
    else:
        return None
    if not when:
        return None
    when = _norm(when)
    return {
        "sk": f"{when}#gh-{kind}-{payload.get('after') or (payload.get('deployment') or {}).get('id')}",
        "event_name": f"github {kind}",
        "event_source": "github",
        "event_time": when,
        "actor": actor,
        "actor_short": actor,
        "by_beacon": False,
        "user_agent": "",
        "source_ip": "",
        "resource_ids": [r for r in (repo, what) if r],
        "error_code": "",
        "ttl": int(time.time()) + _TTL_DAYS * 86400,
    }


def record(row: dict[str, Any]) -> bool:
    """Write one row (idempotent on its sort key); False if it was a duplicate."""
    fresh = db.insert(_table(), str(row["sk"]), row)
    if fresh:
        logger.info(
            "ledger: %s on %s by %s",
            row["event_name"],
            row["resource_ids"],
            row["actor_short"],
        )
    return fresh


# ---------------------------------------------------------------------------
# Query side (triage + voice agent)
# ---------------------------------------------------------------------------

_DESTRUCTIVE_PREFIXES = ("delete", "patch", "update", "github deployment", "create")


def _rank(event_name: str) -> int:
    for i, prefix in enumerate(_DESTRUCTIVE_PREFIXES):
        if event_name.startswith(prefix):
            return i
    return len(_DESTRUCTIVE_PREFIXES)


def recent(
    minutes: int = 60,
    *,
    before: datetime | None = None,
    table_name: str | None = None,
    affected_ids: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """Changes in ``[before - minutes, before]``, most relevant first.

    A change that names one of ``affected_ids`` (the resources diagnostics found
    broken) outranks everything else, so an unrelated deploy never hides the
    patch that took the rule away. Then most destructive, then time.
    """
    affected = {str(i) for i in affected_ids if i}
    end = before or datetime.now(tz=UTC)
    start = end - timedelta(minutes=minutes)
    rows = db.scan(
        table_name or _table(),
        "doc->>'event_time' >= %s AND doc->>'event_time' <= %s",
        (_z(start), _z(end) + "~"),
    )
    for row in rows:
        row.pop("ttl", None)
        row["source"] = "ledger"
    # newest first, then (stable) by relevance and destructiveness: of two patches
    # to the broken resource, the one closest to the alert is the likely cause
    rows.sort(key=lambda r: str(r.get("event_time", "")), reverse=True)
    rows.sort(
        key=lambda r: (
            0 if affected & {str(i) for i in r.get("resource_ids", [])} else 1,
            _rank(str(r.get("event_name", ""))),
        )
    )
    return rows


def _norm(value: Any) -> str:
    try:
        return _z(datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except ValueError:
        return _z(datetime.now(tz=UTC))


def _z(value: datetime) -> str:
    """Kubernetes-style UTC timestamp so string comparison orders correctly."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _seconds_between(a: str, b: datetime) -> str:
    try:
        delta = (b - datetime.fromisoformat(a.replace("Z", "+00:00"))).total_seconds()
    except ValueError:
        return ""
    return (
        f"{int(delta)} s before the alert"
        if delta >= 0
        else f"{int(-delta)} s after the alert"
    )


def format_changes(
    rows: list[dict[str, Any]], *, alarm_at: datetime | None = None
) -> str:
    """Prompt-friendly lines for the ``[changes]`` section."""
    if not rows:
        return "No cluster or deployment changes recorded in the window."
    lines = [
        f"{len(rows)} change(s) recorded before the alert (most destructive first):"
    ]
    for row in rows[:20]:
        ids = ",".join(str(i) for i in row.get("resource_ids", [])) or "-"
        actor = str(row.get("actor_short", "unknown"))
        tag = " [beacon remediation]" if row.get("by_beacon") else ""
        when = str(row.get("event_time", ""))
        rel = f" ({_seconds_between(when, alarm_at)})" if alarm_at else ""
        lines.append(f"- {when}{rel}: {row.get('event_name')} on {ids} by {actor}{tag}")
    return "\n".join(lines)
