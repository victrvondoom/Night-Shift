"""Read-only investigation tools: Prometheus, Loki and Kubernetes object state.

Used by the pre-fetch planner and the evidence tool. Nothing here writes, and
the Kubernetes lookups are limited to a fixed set of kinds.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

from beacon import k8s, logs, prom
from beacon.remediation import actions_deploy

logger = logging.getLogger(__name__)


def query_metrics(promql: str, period_minutes: int = 60) -> dict[str, Any]:
    """A PromQL range query over the last *period_minutes* (~40 points)."""
    end = time.time()
    try:
        series = prom.query_range(
            promql,
            start=end - period_minutes * 60,
            end=end,
            step=max(period_minutes * 60 // 40, 15),
        )
    except Exception as exc:
        logger.warning("metric query failed: %s", exc)
        return {"promql": promql, "error": "Failed to retrieve metric data"}
    return {
        "promql": promql,
        "period_minutes": period_minutes,
        "series": [
            {
                "labels": s.get("metric", {}),
                "datapoints": [
                    {
                        "timestamp": datetime.fromtimestamp(
                            float(t), tz=UTC
                        ).isoformat(),
                        "value": float(v),
                    }
                    for t, v in s.get("values") or []
                ],
            }
            for s in series[:10]
        ],
    }


def query_logs(
    selector: str, filter_pattern: str = "", lookback_minutes: int = 60, limit: int = 50
) -> dict[str, Any]:
    """Search Loki: a stream selector plus an optional line filter."""
    query = selector
    if filter_pattern:
        escaped = filter_pattern.replace("\\", "\\\\").replace('"', '\\"')
        query = f'{selector} |= "{escaped}"'
    try:
        rows = logs.query_range(query, lookback_minutes, limit=limit)
    except Exception as exc:
        logger.warning("log query failed: %s", exc)
        return {
            "selector": selector,
            "filter_pattern": filter_pattern,
            "error": "Failed to retrieve log data",
        }
    return {
        "selector": selector,
        "filter_pattern": filter_pattern,
        "lookback_minutes": lookback_minutes,
        "event_count": len(rows),
        "sample_lines": [logs.format_log_line(ts, line) for ts, line in rows],
    }


def check_resource_status(kind: str, namespace: str, name: str) -> dict[str, Any]:
    """Current state of one ``deployment``, ``networkpolicy`` or ``pods`` selector."""
    kind = kind.lower()
    base = {"kind": kind, "namespace": namespace, "name": name}
    try:
        if kind == "deployment":
            return {
                **base,
                **actions_deploy.describe({"namespace": namespace, "name": name}),
            }
        if kind == "networkpolicy":
            obj = k8s.raw(
                k8s.net().read_namespaced_network_policy(
                    name, namespace, _preload_content=False
                )
            )
            return {**base, "status": "present", "spec": obj.get("spec")}
        if kind == "pods":
            listing = k8s.raw(
                k8s.core().list_namespaced_pod(
                    namespace, label_selector=f"app={name}", _preload_content=False
                )
            )
            return {
                **base,
                "pods": [
                    {
                        "name": p["metadata"]["name"],
                        "phase": (p.get("status") or {}).get("phase"),
                        "containers": [
                            {
                                "name": c.get("name"),
                                "ready": c.get("ready"),
                                "restarts": c.get("restartCount"),
                                "state": next(iter(c.get("state") or {}), None),
                                "reason": next(
                                    iter((c.get("state") or {}).values()), {}
                                ).get("reason"),
                            }
                            for c in (p.get("status") or {}).get("containerStatuses")
                            or []
                        ],
                    }
                    for p in listing.get("items") or []
                ],
            }
    except Exception as exc:
        logger.warning("status check %s %s/%s failed: %s", kind, namespace, name, exc)
        return {**base, "status": "unknown", "error": str(exc)[:200]}
    return {**base, "status": "unknown", "error": f"unsupported kind: {kind}"}


def recent_events(namespace: str, limit: int = 30) -> list[dict[str, Any]]:
    """The newest Kubernetes Events in a namespace (rollout and pod failures)."""
    listing = k8s.raw(
        k8s.core().list_namespaced_event(namespace, _preload_content=False)
    )
    items = sorted(
        listing.get("items") or [],
        key=lambda e: str(e.get("lastTimestamp") or e.get("eventTime") or ""),
    )[-limit:]
    return [
        {
            "time": e.get("lastTimestamp") or e.get("eventTime"),
            "type": e.get("type"),
            "reason": e.get("reason"),
            "object": f"{(e.get('involvedObject') or {}).get('kind')}/"
            f"{(e.get('involvedObject') or {}).get('name')}",
            "message": str(e.get("message") or "")[:300],
        }
        for e in items
    ]
