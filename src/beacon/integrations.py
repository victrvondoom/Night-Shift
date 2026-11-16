"""Honest integration health.  A state is CONNECTED only after a real probe or a real success.

States: CONNECTED | DEGRADED | FAILED | NOT_CONFIGURED | CONFIGURED_UNVERIFIED | DEMO_ADAPTER
No expensive probes: Tavily is never searched and OmniDimension never opens a session just to
look healthy; they report CONFIGURED_UNVERIFIED until a real interaction has succeeded.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from beacon import db, health_log, omnidim, research
from beacon.llm import gateway


def _row(name: str, state: str, mode: str, detail: str, *, config: dict[str, bool] | None = None, activity: int | None = None) -> dict[str, Any]:
    h = health_log.get(name)
    return {
        "integration": name,
        "state": state,
        "mode": mode,
        "last_success_at": h.get("last_success_at"),
        "last_error_category": h.get("last_error_category") or None,
        "last_error_at": h.get("last_error_at"),
        "detail": detail,
        "configuration_present": config or {},
        "observed_activity": activity if activity is not None else (int(h.get("ok_count", 0)) + int(h.get("fail_count", 0)) or None),
    }


def _by_history(name: str, configured: bool, mode: str, config: dict[str, bool], *, probe: tuple[bool, str] | None = None) -> dict[str, Any]:
    h = health_log.get(name)
    if not configured:
        return _row(name, "NOT_CONFIGURED", mode, "required configuration is missing", config=config)
    if probe is not None and not probe[0]:
        return _row(name, "FAILED", mode, probe[1], config=config)
    if h.get("last_error_at") and (not h.get("last_success_at") or h["last_error_at"] > h["last_success_at"]):
        return _row(name, "DEGRADED" if h.get("last_success_at") else "FAILED", mode, f"last interaction failed: {h.get('last_error_category')}", config=config)
    if h.get("last_success_at"):
        return _row(name, "CONNECTED", mode, "last interaction succeeded" + (f"; {probe[1]}" if probe else ""), config=config)
    if probe is not None:
        return _row(name, "CONNECTED", mode, probe[1] + " (no model/search call made yet)", config=config)
    return _row(name, "CONFIGURED_UNVERIFIED", mode, "configured; no successful interaction yet", config=config)


def _http(url: str) -> tuple[bool, str]:
    try:
        r = httpx.get(url, timeout=2)
        return r.status_code < 500, f"GET {url.split('?')[0]} -> {r.status_code}"
    except httpx.HTTPError as exc:
        return False, f"{type(exc).__name__}"


def snapshot() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    out.append(_row("postgresql", "CONNECTED" if db.ping() else "FAILED", "LIVE", "SELECT 1" if db.ping() else "unreachable"))
    nats_url = os.environ.get("NATS_URL", "")
    nats_ok = False
    if nats_url:
        import asyncio

        from beacon import eventbus

        async def ping() -> bool:
            nc, _ = await eventbus.connect()
            await nc.close()
            return True

        try:
            nats_ok = asyncio.run(asyncio.wait_for(ping(), 3))
        except Exception:
            nats_ok = False
    out.append(_row("nats", "CONNECTED" if nats_ok else ("FAILED" if nats_url else "NOT_CONFIGURED"), "LIVE", "JetStream stream BEACON reachable" if nats_ok else "unreachable or unset", config={"NATS_URL": bool(nats_url)}))
    corr_url = os.environ.get("CORRELATOR_URL", "")
    if not corr_url:
        out.append(_row("pathway", "NOT_CONFIGURED", "LIVE", "CORRELATOR_URL not set", config={"CORRELATOR_URL": False}))
    else:
        try:
            r = httpx.get(corr_url.rstrip("/") + "/healthz", timeout=2).json()
            row = _row("pathway", "CONNECTED", "LIVE", f"pathway {r.get('pathway_version')} · rule {r.get('rule')} · last event {r.get('last_event_at')}", config={"CORRELATOR_URL": True}, activity=int(r.get("events_seen", 0)))
            row["last_success_at"] = r.get("last_correlation_at")
            out.append(row)
        except Exception:
            out.append(_row("pathway", "FAILED", "LIVE", "correlator /healthz unreachable", config={"CORRELATOR_URL": True}))
    opa = os.environ.get("OPA_URL", "")
    out.append(_row("opa", "CONNECTED" if opa and _http(opa.rstrip("/") + "/health")[0] else ("FAILED" if opa else "NOT_CONFIGURED"), "LIVE", "policy engine /health", config={"OPA_URL": bool(opa)}))
    sim = os.environ.get("SIMULATOR_URL", "")
    if sim:
        ok, d = _http(sim.rstrip("/") + "/sim/info")
        out.append(_row("kubernetes", "DEMO_ADAPTER" if ok else "FAILED", "DEMO_SIMULATOR", "in-memory simulator; no real cluster is read or changed. " + d, config={"SIMULATOR_URL": True}))
    else:
        out.append(_row("kubernetes", "CONFIGURED_UNVERIFIED" if os.environ.get("KUBECONFIG") else "NOT_CONFIGURED", "LIVE", "no live probe is run from the API (the API holds no cluster credentials)", config={"KUBECONFIG": bool(os.environ.get("KUBECONFIG"))}))
    prom = os.environ.get("PROMETHEUS_URL", "")
    p_ok = bool(prom) and _http(prom.rstrip("/") + "/api/v1/rules?type=alert")[0]
    out.append(_row("prometheus", ("DEMO_ADAPTER" if sim else "CONNECTED") if p_ok else ("FAILED" if prom else "NOT_CONFIGURED"), "DEMO_SIMULATOR" if sim else "LIVE", "rules API reachable" if p_ok else "unreachable or unset", config={"PROMETHEUS_URL": bool(prom)}))
    mode = os.environ.get("REMEDIATION_MODE", "temporal")
    out.append(_row("temporal", "DEMO_ADAPTER" if mode == "inline" else "CONFIGURED_UNVERIFIED", "INLINE" if mode == "inline" else "LIVE", "REMEDIATION_MODE=inline: the same remediation steps run in the worker process, no Temporal server" if mode == "inline" else "workflow server not probed from the API", config={"TEMPORAL_ADDRESS": bool(os.environ.get("TEMPORAL_ADDRESS"))}))
    b = gateway.probe() if gateway.configured() else None
    out.append(_by_history("bifrost", gateway.configured() and bool(gateway.model()), "LIVE", {"BIFROST_URL": gateway.configured(), "BIFROST_MODEL": bool(gateway.model()), "BIFROST_VIRTUAL_KEY": bool(os.environ.get("BIFROST_VIRTUAL_KEY"))}, probe=b))
    out.append(_by_history("tavily", research.configured(), "LIVE", {"TAVILY_API_KEY": research.configured()}))
    out.append(_by_history("omnidimension", omnidim.configured(), "LIVE", {"OMNIDIM_API_KEY": bool(omnidim.api_key()), "OMNIDIM_AGENT_ID": bool(omnidim.agent_id())}))
    bypass = health_log.get("llm_route:BYPASS_NO_GATEWAY").get("n", 0)
    out.append({"integration": "llm_gateway_routing", "state": "DEGRADED" if bypass else "CONNECTED", "mode": "LIVE", "detail": f"{bypass} legacy LLM call(s) ran without Bifrost (BIFROST_URL unset)" if bypass else "no un-gatewayed LLM calls observed", "last_success_at": None, "last_error_category": "bypass" if bypass else None, "configuration_present": {}, "observed_activity": int(health_log.get("llm_route:bifrost").get("n", 0)) or None, "last_error_at": None})
    return out
