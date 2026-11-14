"""Prometheus HTTP API: instant/range queries, alert state and rule lookup."""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

_TIMEOUT = 10


def url() -> str:
    return os.environ.get("PROMETHEUS_URL", "http://localhost:9090").rstrip("/")


def _get(path: str, **params: Any) -> Any:
    qs = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    req = urllib.request.Request(f"{url()}{path}?{qs}")  # noqa: S310
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
        body = json.loads(resp.read().decode())
    if body.get("status") != "success":
        raise RuntimeError(f"prometheus: {body.get('error') or body}")
    return body["data"]


def query(expr: str, *, at: float | None = None) -> list[dict[str, Any]]:
    """Instant vector for *expr*: ``[{"metric": {...}, "value": [ts, "v"]}]``."""
    return list(_get("/api/v1/query", query=expr, time=at).get("result") or [])


def query_range(
    expr: str, *, start: float, end: float, step: int = 15
) -> list[dict[str, Any]]:
    return list(
        _get("/api/v1/query_range", query=expr, start=start, end=end, step=step).get(
            "result"
        )
        or []
    )


def alert_rule(alertname: str) -> dict[str, Any] | None:
    """The alerting rule called *alertname* (its ``query`` is the PromQL expr)."""
    for group in _get("/api/v1/rules", type="alert").get("groups") or []:
        for rule in group.get("rules") or []:
            if rule.get("name") == alertname:
                return dict(rule)
    return None


def selector(alertname: str, labels: dict[str, str] | None = None) -> str:
    """``ALERTS`` selector for one alert instance (alertname + stable labels)."""
    parts = {"alertname": alertname}
    for key in ("namespace", "service", "job", "deployment"):
        if labels and labels.get(key):
            parts[key] = labels[key]
    inner = ",".join(f'{k}="{v}"' for k, v in sorted(parts.items()))
    return f'ALERTS{{{inner},alertstate="firing"}}'
