"""OmniDimension voice: the one module that talks to ``omnidim.io`` (server side only).

Contract (https://docs.omnidim.io/docs/api-reference/sessions/createSession):

    POST https://omnidim.io/api/v1/sessions/create   Authorization: Bearer <OMNIDIM_API_KEY>
    {"agent_id": <int>, "type": "voice", "custom_variables": {...}, "metadata": {...}}
    -> 201 {"session_id", "token", "expires_at", "ws_url", ...}

Only ``ws_url`` / ``expires_at`` / ``session_id`` ever leave the server, exactly as returned:
the URL is single use, valid 15 minutes, and is never built, edited, cached or stored here.
The API key never reaches the browser.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

from beacon import secrets

logger = logging.getLogger(__name__)
_TIMEOUT = 15


class OmniDimError(RuntimeError):
    def __init__(self, message: str, status: int = 502, category: str = "provider_error") -> None:
        super().__init__(message)
        self.status = status
        self.category = category


def base_url() -> str:
    return os.environ.get("OMNIDIM_API_BASE", "https://omnidim.io").rstrip("/")


def api_key() -> str:
    return secrets.get("OMNIDIM_API_KEY")


def agent_id() -> str:
    return os.environ.get("OMNIDIM_AGENT_ID", "")


def configured() -> bool:
    return bool(api_key() and agent_id().isdigit())


def create_session(custom_variables: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    """Create one short-lived voice session; returns the browser-safe subset."""
    if not configured():
        raise OmniDimError("OmniDimension is not configured", 503, "not_configured")
    body = json.dumps({"agent_id": int(agent_id()), "type": "voice", "custom_variables": custom_variables, "metadata": metadata}).encode()
    req = urllib.request.Request(  # noqa: S310
        f"{base_url()}/api/v1/sessions/create",
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {api_key()}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        category = {401: "auth", 402: "insufficient_balance", 404: "agent_not_found", 429: "rate_limited_or_concurrency"}.get(exc.code, "provider_error")
        _record(False, category)
        raise OmniDimError(f"OmniDimension returned HTTP {exc.code}", exc.code, category) from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        _record(False, "unavailable")
        raise OmniDimError(f"OmniDimension unreachable: {type(exc).__name__}", 502, "unavailable") from exc
    ws_url = data.get("ws_url")
    if not isinstance(ws_url, str) or not ws_url.startswith("wss://"):
        _record(False, "invalid_response")
        raise OmniDimError("OmniDimension response had no ws_url", 502, "invalid_response")
    _record(True)
    return {"ws_url": ws_url, "expires_at": data.get("expires_at"), "session_id": data.get("session_id")}


def _record(ok: bool, category: str = "") -> None:
    try:
        from beacon import health_log

        health_log.record("omnidimension", ok, category)
    except Exception:
        logger.debug("health_log failed", exc_info=True)
