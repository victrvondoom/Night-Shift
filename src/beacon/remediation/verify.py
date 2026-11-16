"""Verification: "recovered" is a claim Night Shift must prove, not a boolean read.

Four independent checks, all required:

1. the alert that paged is no longer firing in Prometheus **and** it was still
   firing when the fix was executed (an alert that cleared on its own before the
   fix, or a stale reading, cannot pass);
2. the alert's own PromQL expression evaluates to nothing right now;
3. the action's post-condition holds against the Kubernetes API (for example
   the rule is present, the rollout is complete);
4. the application's own health endpoint answers 200 from inside the cluster.

None of them is "the patch call returned 200".
"""

from __future__ import annotations

import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from beacon import prom

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)
# how long before the fix an alert may have stopped firing and still count as
# "cleared by the fix" (one evaluation + one scrape of slack)
_SLACK_SECONDS = 45


@dataclass(slots=True)
class VerifyCheck:
    name: str
    ok: bool
    detail: str = ""
    metric: dict[str, Any] = field(default_factory=dict)
    checked_at: str = field(default_factory=lambda: datetime.now(tz=UTC).isoformat())


@dataclass(slots=True)
class VerifyResult:
    ok: bool
    checks: list[VerifyCheck]

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "checks": [asdict(c) for c in self.checks]}


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


def verify_alarm(
    alarm_name: str, *, after: datetime, labels: dict[str, str] | None = None
) -> VerifyCheck:
    """Not firing now, and it stopped firing at or after the fix."""
    name = "alarm_ok_after_fix"
    sel = prom.selector(alarm_name, labels)
    rule = prom.alert_rule(alarm_name)
    if rule is None:
        return VerifyCheck(name, False, f"alert rule {alarm_name} not found")
    metric = {"alertname": alarm_name, "expr": rule.get("query", ""), "selector": sel}
    if prom.query(sel):
        return VerifyCheck(name, False, "alert is still firing", metric)
    now = time.time()
    fix_at = after.timestamp()
    series = prom.query_range(sel, start=fix_at - 900, end=now, step=5)
    samples = [float(v[0]) for s in series for v in s.get("values") or []]
    if not samples:
        return VerifyCheck(
            name, False, "alert was not firing in the 15 minutes before the fix", metric
        )
    last = max(samples)
    if last < fix_at - _SLACK_SECONDS:
        return VerifyCheck(
            name,
            False,
            f"alert stopped firing at {_iso(last)}, before the fix at {_iso(fix_at)}",
            metric,
        )
    return VerifyCheck(
        name, True, f"alert last fired {_iso(last)} (fix at {_iso(fix_at)})", metric
    )


def verify_metric(metric: dict[str, Any]) -> VerifyCheck:
    """The alert's own expression returns no series right now."""
    expr = str(metric.get("expr") or "")
    if not expr:
        return VerifyCheck("metric_zero", False, "alert has no expression to check")
    result = prom.query(expr)
    if result:
        value = result[0].get("value", [0, "?"])[1]
        return VerifyCheck(
            "metric_zero", False, f"`{expr}` still breaching (value {value})", metric
        )
    return VerifyCheck("metric_zero", True, f"`{expr}` returns no series", metric)


def health_url_allowed(url: str) -> bool:
    """Only cluster-local hosts (or an explicit allowlist) may be probed."""
    host = urllib.parse.urlparse(url).hostname or ""
    if urllib.parse.urlparse(url).scheme not in ("http", "https") or not host:
        return False
    allowed = [
        h.strip()
        for h in os.environ.get(
            "HEALTH_CHECK_ALLOW", ".svc,.svc.cluster.local,localhost,127.0.0.1"
        ).split(",")
        if h.strip()
    ]
    return any(host == a or (a.startswith(".") and host.endswith(a)) for a in allowed)


def verify_health(url: str) -> VerifyCheck:
    """A real request to the application's health endpoint must answer 200."""
    name = "app_health"
    if not url:
        return VerifyCheck(name, False, "alert has no beacon_health_url annotation")
    if not health_url_allowed(url):
        return VerifyCheck(name, False, f"{url} is not an allowed health target")
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310
            status = int(resp.status)
    except urllib.error.HTTPError as exc:
        status = exc.code
    except Exception as exc:
        return VerifyCheck(name, False, f"GET {url} failed: {exc}")
    return VerifyCheck(name, status == 200, f"GET {url} -> {status}")


def verify_all(
    alarm_name: str,
    *,
    after: datetime,
    postcondition: Callable[[], bool],
    labels: dict[str, str] | None = None,
    health_url: str = "",
) -> VerifyResult:
    """Run the four checks; all must pass. A check that raises is a failed check."""
    try:
        alarm_check = verify_alarm(alarm_name, after=after, labels=labels)
    except Exception as exc:
        logger.exception("alert check raised")
        alarm_check = VerifyCheck("alarm_ok_after_fix", False, f"prometheus: {exc}")
    try:
        metric_check = verify_metric(alarm_check.metric)
    except Exception as exc:
        logger.exception("metric check raised")
        metric_check = VerifyCheck("metric_zero", False, f"prometheus: {exc}")
    try:
        post_ok = bool(postcondition())
        post_detail = (
            "post-condition holds" if post_ok else "post-condition does not hold"
        )
    except Exception as exc:  # the check itself failing is a failed check
        logger.exception("postcondition raised")
        post_ok, post_detail = False, f"post-condition check failed: {exc}"
    checks = [
        alarm_check,
        metric_check,
        VerifyCheck("postcondition", post_ok, post_detail),
        verify_health(health_url),
    ]
    return VerifyResult(ok=all(c.ok for c in checks), checks=checks)
