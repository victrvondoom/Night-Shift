"""Application logs from Grafana Loki."""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import Any

_TIMEOUT = 15


def loki_url() -> str:
    return os.environ.get("LOKI_URL", "http://localhost:3100").rstrip("/")


def format_log_line(timestamp_ms: int, message: str) -> str:
    """Format one log entry as an ``ISO-timestamp message`` line."""
    dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=UTC)
    return f"{dt.isoformat()} {message.rstrip(chr(10))}"


def resolve_log_groups(patterns: list[str]) -> list[str]:
    """LogQL stream selectors to query (deduplicated, order kept)."""
    return list(dict.fromkeys(p for p in patterns if p))


def query_range(
    query: str, lookback_minutes: int, *, limit: int = 5000
) -> list[tuple[int, str]]:
    """``(timestamp_ms, line)`` pairs for a LogQL query, oldest first."""
    end_ns = time.time_ns()
    start_ns = end_ns - lookback_minutes * 60 * 1_000_000_000
    qs = urllib.parse.urlencode(
        {
            "query": query,
            "start": start_ns,
            "end": end_ns,
            "limit": limit,
            "direction": "forward",
        }
    )
    req = urllib.request.Request(f"{loki_url()}/loki/api/v1/query_range?{qs}")  # noqa: S310
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
        data: Any = json.loads(resp.read().decode())
    rows: list[tuple[int, str]] = []
    for stream in (data.get("data") or {}).get("result") or []:
        for ts, line in stream.get("values") or []:
            rows.append((int(ts) // 1_000_000, str(line)))
    rows.sort(key=lambda r: r[0])
    return rows


def fetch_logs(selector: str, lookback_minutes: int) -> str:
    """Every line a selector matched in the window, one per line."""
    return "\n".join(
        format_log_line(ts, line)
        for ts, line in query_range(selector, lookback_minutes)
    )
