"""The single model gateway client: every incident-analysis request goes through Bifrost.

Bifrost is an OpenAI-compatible gateway (``POST {BIFROST_URL}/v1/chat/completions``).
Night Shift's trace enrichment uses Bifrost's *native, documented* log-metadata
headers (``x-bf-lh-*``) so a request in Bifrost's logs can be tied back to
``incident -> evidence set -> request -> decision``.  Nothing here invents usage,
cost or latency: fields are copied from the gateway response when present.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class GatewayError(Exception):
    def __init__(self, category: str, detail: str = "") -> None:
        super().__init__(f"{category}: {detail}")
        self.category = category  # not_configured|unavailable|timeout|rate_limited|auth|provider_error|invalid_response
        self.detail = detail


@dataclass
class GatewayResult:
    content: str
    request_id: str | None = None
    provider: str | None = None
    model: str | None = None
    latency_ms: int | None = None
    usage: dict[str, int] | None = None
    cost: float | None = None
    attempts: int | None = None
    fallback_used: bool | None = None
    trace_id: str | None = None
    upstream_latency_ms: float | None = None
    fallback_index: int | None = None
    raw_meta: dict[str, Any] = field(default_factory=dict)


def base_url() -> str:
    return (os.environ.get("BIFROST_URL") or os.environ.get("BIFROST_BASE_URL", "")).rstrip("/")


def configured() -> bool:
    return bool(base_url())


def model() -> str:
    return os.environ.get("BIFROST_MODEL", "")


def fallbacks() -> list[str]:
    return [m.strip() for m in os.environ.get("BIFROST_FALLBACK_MODELS", "").split(",") if m.strip()]


def trace_headers(meta: dict[str, str]) -> dict[str, str]:
    """Incident Trace Enrichment: Bifrost log-metadata headers (``x-bf-lh-<key>``)."""
    return {f"x-bf-lh-{k.replace('_', '-')}": str(v)[:200] for k, v in meta.items() if v}


def headers(meta: dict[str, str], request_id: str = "") -> dict[str, str]:
    h = {"content-type": "application/json", **trace_headers(meta)}
    if request_id:
        h["x-request-id"] = request_id  # Bifrost echoes it as X-Bifrost-Request-Id (verified against a real gateway)
    vk = os.environ.get("BIFROST_VIRTUAL_KEY", "")
    if vk:
        h["x-bf-vk"] = vk
    key = os.environ.get("BIFROST_API_KEY", "")
    if key:
        h["authorization"] = f"Bearer {key}"
    return h


def _timeout() -> float:
    return float(os.environ.get("BIFROST_TIMEOUT_SECONDS", "60"))


def _fnum(v: str | None) -> float | None:
    try:
        return float(v) if v not in (None, "") else None
    except ValueError:
        return None


def _record(ok: bool, category: str = "", detail: str = "") -> None:
    if category == "not_configured":
        return  # refused before sending: not an interaction, so never evidence of failure
    try:
        from beacon import health_log

        health_log.record("bifrost:model_invocation", ok, category, detail)
    except Exception:  # health bookkeeping must never break a request
        logger.debug("health_log failed", exc_info=True)


def chat(messages: list[dict[str, str]], *, meta: dict[str, str], request_id: str = "", json_mode: bool = True, timeout: float | None = None) -> GatewayResult:
    """One chat completion through Bifrost.  Raises ``GatewayError`` with a category."""
    if not configured() or not model():
        _record(False, "not_configured", "BIFROST_URL/BIFROST_MODEL not set")
        raise GatewayError("not_configured", "BIFROST_URL and BIFROST_MODEL are required")
    body: dict[str, Any] = {"model": model(), "messages": messages, "temperature": 0.1}
    if fallbacks():
        body["fallbacks"] = fallbacks()
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    t0 = time.perf_counter()
    try:
        resp = httpx.post(f"{base_url()}/v1/chat/completions", json=body, headers=headers(meta, request_id), timeout=timeout or _timeout())
    except httpx.TimeoutException as exc:
        _record(False, "timeout", str(exc))
        raise GatewayError("timeout", str(exc)) from exc
    except httpx.HTTPError as exc:
        _record(False, "unavailable", type(exc).__name__)
        raise GatewayError("unavailable", type(exc).__name__) from exc
    elapsed = int((time.perf_counter() - t0) * 1000)
    if resp.status_code == 429:
        _record(False, "rate_limited", "HTTP 429")
        raise GatewayError("rate_limited", "HTTP 429")
    if resp.status_code in (401, 403):
        _record(False, "auth", f"HTTP {resp.status_code}")
        raise GatewayError("auth", f"HTTP {resp.status_code}")
    if resp.status_code >= 400:
        _record(False, "provider_error", f"HTTP {resp.status_code}")
        raise GatewayError("provider_error", f"HTTP {resp.status_code}: {resp.text[:200]}")
    try:
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
    except Exception as exc:
        _record(False, "invalid_response", "no choices[0].message.content")
        raise GatewayError("invalid_response", "unexpected gateway payload") from exc
    extra = data.get("extra_fields") or {}
    h = resp.headers
    usage = data.get("usage")
    fb_idx = h.get("x-bifrost-fallback-index")
    # Identity/routing facts come from Bifrost's own response headers; the body "id" is the
    # *upstream provider's* completion id and is not a Bifrost request id.
    result = GatewayResult(
        content=content or "",
        request_id=h.get("x-bifrost-request-id") or None,
        trace_id=h.get("x-bifrost-trace-id") or None,
        provider=h.get("x-bifrost-provider") or extra.get("provider") or None,
        model=h.get("x-bifrost-resolved-model") or data.get("model") or None,
        latency_ms=int(v) if (v := _fnum(h.get("x-bifrost-latency-ms"))) is not None else (int(extra["latency"]) if isinstance(extra.get("latency"), (int, float)) else None),
        upstream_latency_ms=_fnum(h.get("x-bifrost-upstream-latency-ms")),
        usage={k: int(v) for k, v in usage.items() if isinstance(v, (int, float))} if isinstance(usage, dict) else None,
        cost=float(extra["cost"]) if isinstance(extra.get("cost"), (int, float)) else None,
        attempts=None,
        fallback_index=int(fb_idx) if fb_idx and fb_idx.isdigit() else None,
        fallback_used=(int(fb_idx) > 0) if fb_idx and fb_idx.isdigit() else (h.get("x-bifrost-routing-info-is-fallback", "").lower() == "true" if "x-bifrost-routing-info-is-fallback" in h else None),
        raw_meta={"observed_wall_ms": elapsed, "upstream_completion_id": data.get("id")},
    )
    _record(True)
    return result


def completion(**kwargs: Any) -> Any:
    """Drop-in for ``litellm.completion`` used by the legacy triage / typed-voice paths.

    With ``BIFROST_URL`` set the call is sent to Bifrost's OpenAI-compatible endpoint;
    otherwise it falls back to the configured provider and the bypass is recorded so
    ``/api/system/integrations`` shows it (it is never silent).
    """
    import litellm

    meta = {"purpose": kwargs.pop("nightshift_purpose", "legacy_llm_call"), "workflow_stage": "legacy"}
    if configured() and model():
        kwargs = {**kwargs, "model": f"openai/{model()}", "api_base": f"{base_url()}/v1", "api_key": os.environ.get("BIFROST_VIRTUAL_KEY") or "bifrost", "extra_headers": headers(meta)}
        _record_route("bifrost")
    else:
        _record_route("BYPASS_NO_GATEWAY")
        logger.warning("LLM call without Bifrost (BIFROST_URL unset): model=%s", kwargs.get("model"))
    return litellm.completion(**kwargs)


def _record_route(route: str) -> None:
    try:
        from beacon import health_log

        health_log.count(f"llm_route:{route}")
    except Exception:
        logger.debug("route count failed", exc_info=True)


def probe() -> tuple[bool, str]:
    """Cheap reachability check (no model call, no cost)."""
    if not configured():
        return False, "not configured"
    try:
        r = httpx.get(f"{base_url()}/health", timeout=3)
        return r.status_code < 500, f"GET /health -> {r.status_code}"
    except httpx.HTTPError as exc:
        return False, type(exc).__name__


def loads_json(text: str) -> dict[str, Any]:
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        t = t[t.find("{") :]
    return dict(json.loads(t))
