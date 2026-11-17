"""Capability-level, evidence-based integration health.

Rules (tested in tests/test_integration_health.py):

* ``CONNECTED`` needs an *observed successful interaction* with the intended service for the
  integration's primary capability (a real request that succeeded, or a real probe that answered).
  Configuration alone is never evidence.
* ``FAILED``  -> a real attempt failed and has never succeeded.
* ``DEGRADED`` -> it has succeeded before but the latest attempt (or a required dependency) failed.
* ``NOT_CONFIGURED`` / ``CONFIGURED_UNVERIFIED`` / ``DEMO_ADAPTER`` / ``DISABLED`` as named.

Counts and timestamps come from the persisted interaction log (``beacon.health_log``), which is
written only where a real interaction happens.  Nothing here makes a model call, a Tavily search or
a voice session just to look healthy.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from beacon import db, health_log, omnidim, research
from beacon.llm import gateway

STATES = ("CONNECTED", "DEGRADED", "FAILED", "NOT_CONFIGURED", "CONFIGURED_UNVERIFIED", "DEMO_ADAPTER", "DISABLED")


def history_state(h: dict[str, Any]) -> str | None:
    """State implied by interaction history alone; None when there has been no interaction."""
    ok, err = h.get("last_success_at"), h.get("last_error_at")
    if not ok and not err:
        return None
    if ok and (not err or ok >= err):
        return "CONNECTED"
    return "DEGRADED" if ok else "FAILED"


def cap(name: str, state: str, detail: str, key: str = "") -> dict[str, Any]:
    h = health_log.get(key) if key else {}
    return {
        "capability": name,
        "state": state,
        "detail": detail,
        "last_success_at": h.get("last_success_at"),
        "last_failure_at": h.get("last_error_at"),
        "last_error_category": h.get("last_error_category") or None,
        "success_count": int(h.get("ok_count", 0)),
        "failure_count": int(h.get("fail_count", 0)),
    }


def observed(name: str, key: str, configured: bool, absent: str = "required configuration is missing", pending: str = "configured; no interaction attempted yet") -> dict[str, Any]:
    """A capability whose truth comes only from observed interactions."""
    if not configured:
        return cap(name, "NOT_CONFIGURED", absent, key)
    h = health_log.get(key)
    st = history_state(h)
    if st is None:
        return cap(name, "CONFIGURED_UNVERIFIED", pending, key)
    detail = "last interaction succeeded" if st == "CONNECTED" else f"last interaction failed: {h.get('last_error_category')}"
    return cap(name, st, detail, key)


def roll_up(name: str, mode: str, caps: list[dict[str, Any]], primary: str, detail: str = "", config: dict[str, bool] | None = None) -> dict[str, Any]:
    """Integration state = state of its primary capability; DEGRADED if another capability that has history is failing."""
    by = {c["capability"]: c for c in caps}
    state = by[primary]["state"]
    if state == "CONNECTED" and any(c["state"] in ("FAILED", "DEGRADED") for c in caps if c["capability"] != primary):
        state = "DEGRADED"
    p = by[primary]
    return {
        "integration": name,
        "state": state,
        "mode": mode,
        "detail": detail or p["detail"],
        "last_success_at": p["last_success_at"],
        "last_failure_at": p["last_failure_at"],
        "last_error_category": p["last_error_category"],
        "success_count": p["success_count"],
        "failure_count": p["failure_count"],
        "observed_activity": (p["success_count"] + p["failure_count"]) or None,
        "configuration_present": config or {},
        "capabilities": caps,
    }


def _probe(url: str) -> tuple[bool, str]:
    try:
        r = httpx.get(url, timeout=2)
        return r.status_code < 500, f"GET {url.split('?')[0]} -> {r.status_code}"
    except httpx.HTTPError as exc:
        return False, type(exc).__name__


def _probed(key: str, url: str, name: str) -> dict[str, Any]:
    """A real (cheap) health probe; its result is recorded as an interaction."""
    ok, d = _probe(url)
    health_log.record(key, ok, "unreachable" if not ok else "", d)
    return cap(name, "CONNECTED" if ok else "FAILED", d, key)


def _count(table: str) -> int:
    try:
        return len(db.scan(table))
    except Exception:
        return 0


def mode_info() -> dict[str, str]:
    rem = os.environ.get("REMEDIATION_MODE", "temporal")
    return {
        "execution_mode": "INLINE_DEMO_ADAPTER" if rem == "inline" else "TEMPORAL",
        "cluster_mode": "DEMO_SIMULATOR" if os.environ.get("SIMULATOR_URL") else "LIVE_CLUSTER",
    }


def snapshot() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    sim = os.environ.get("SIMULATOR_URL", "")
    cluster_mode = "DEMO_SIMULATOR" if sim else "LIVE"

    pg = db.ping()
    out.append(roll_up("postgresql", "LIVE", [cap("ledger_query", "CONNECTED" if pg else "FAILED", "SELECT 1" if pg else "unreachable")], "ledger_query"))

    # --- NATS
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
    nats_cap = cap("jetstream_connect", "CONNECTED" if nats_ok else ("FAILED" if nats_url else "NOT_CONFIGURED"), "stream BEACON reachable" if nats_ok else "unreachable or NATS_URL unset")
    out.append(roll_up("nats", "LIVE", [nats_cap], "jetstream_connect", config={"NATS_URL": bool(nats_url)}))

    # --- Pathway
    corr_url = os.environ.get("CORRELATOR_URL", "")
    caps: list[dict[str, Any]] = []
    if not corr_url:
        caps = [cap("process_started", "NOT_CONFIGURED", "CORRELATOR_URL not set")]
        primary = "process_started"
    else:
        try:
            r = httpx.get(corr_url.rstrip("/") + "/healthz", timeout=2).json()
            caps.append(cap("process_started", "CONNECTED", f"pathway {r.get('pathway_version')} up {r.get('uptime_s')}s, rule {r.get('rule')}"))
            seen, emitted = int(r.get("events_seen", 0)), int(r.get("correlations_emitted", 0))
            c = cap("nats_source_consumed", "CONNECTED" if seen else "CONFIGURED_UNVERIFIED", f"{seen} event rows consumed since start" if seen else "process up; no events consumed since start")
            c["last_success_at"] = r.get("last_event_at")
            c["success_count"] = seen
            caps.append(c)
            c = cap("correlation_emitted", "CONNECTED" if emitted else "CONFIGURED_UNVERIFIED", f"{emitted} correlation rows emitted since start" if emitted else "no correlation emitted since start")
            c["last_success_at"] = r.get("last_correlation_at")
            c["success_count"] = emitted
            caps.append(c)
            n = _count(os.environ.get("NS_CORRELATIONS_TABLE", "ns_correlations"))
            caps.append(cap("correlation_persisted", "CONNECTED" if n else "CONFIGURED_UNVERIFIED", f"{n} correlation record(s) in the ledger"))
        except Exception:
            caps.append(cap("process_started", "FAILED", "correlator /healthz unreachable"))
        primary = "correlation_persisted" if len(caps) > 1 else "process_started"
        if len(caps) > 1 and caps[0]["state"] == "CONNECTED" and caps[-1]["state"] != "CONNECTED":
            primary = "process_started"
    out.append(roll_up("pathway", "LIVE", caps, primary, config={"CORRELATOR_URL": bool(corr_url)}))

    # --- OPA
    opa = os.environ.get("OPA_URL", "")
    opa_cap = _probed("opa:health", opa.rstrip("/") + "/health", "policy_engine_health") if opa else cap("policy_engine_health", "NOT_CONFIGURED", "OPA_URL not set")
    out.append(roll_up("opa", "LIVE", [opa_cap], "policy_engine_health", config={"OPA_URL": bool(opa)}))

    # --- Kubernetes / Prometheus
    if sim:
        c = _probed("kubernetes:simulator", sim.rstrip("/") + "/sim/info", "simulator_reachable")
        c["state"] = "DEMO_ADAPTER" if c["state"] == "CONNECTED" else "FAILED"
        c["detail"] = "in-memory DEMO_SIMULATOR; no real cluster is read or changed. " + c["detail"]
        out.append(roll_up("kubernetes", "DEMO_SIMULATOR", [c], "simulator_reachable", config={"SIMULATOR_URL": True}))
    elif os.environ.get("K8S_FLAVOUR") == "k3s":
        # reachability + version only; the API process holds NO cluster credentials (the worker does)
        url = os.environ.get("K8S_API_URL", "https://127.0.0.1:6443").rstrip("/") + "/version"
        try:
            ver = httpx.get(url, timeout=3, verify=False).json().get("gitVersion", "?")  # noqa: S501  (no credentials are sent)
            c = cap("control_plane_reachable", "CONNECTED", f"real kube-apiserver {ver} (k3s); the worker authenticates as the restricted beacon-remediator ServiceAccount")
        except Exception as exc:
            c = cap("control_plane_reachable", "FAILED", type(exc).__name__)
        dp = cap("data_plane", "DEMO_ADAPTER", "EMULATED_DATAPLANE: no kubelet/CNI in this VM; NetworkPolicy is enforced by beacon.sandbox.dataplane reading the real API")
        out.append(roll_up("kubernetes", "REAL_CONTROL_PLANE+EMULATED_DATAPLANE", [c, dp], "control_plane_reachable", config={"K8S_API_URL": True}))
    else:
        kc = bool(os.environ.get("KUBECONFIG") or os.environ.get("KUBERNETES_SERVICE_HOST"))
        out.append(roll_up("kubernetes", "LIVE", [cap("cluster_api", "CONFIGURED_UNVERIFIED" if kc else "NOT_CONFIGURED", "the API process holds no cluster credentials; cluster access is verified by the worker's dry-run/verify steps" if kc else "no kubeconfig / in-cluster environment")], "cluster_api", config={"KUBECONFIG": kc}))
    prom = os.environ.get("PROMETHEUS_URL", "")
    if prom:
        c = _probed("prometheus:rules", prom.rstrip("/") + "/api/v1/rules?type=alert", "rules_api")
        if sim and c["state"] == "CONNECTED":
            c["state"], c["detail"] = "DEMO_ADAPTER", "simulator Prometheus API. " + c["detail"]
    else:
        c = cap("rules_api", "NOT_CONFIGURED", "PROMETHEUS_URL not set")
    out.append(roll_up("prometheus", "LIVE" if os.environ.get("K8S_FLAVOUR") == "k3s" else cluster_mode, [c], "rules_api", config={"PROMETHEUS_URL": bool(prom)}))

    # --- remediation execution engine
    mi = mode_info()
    if mi["execution_mode"] == "INLINE_DEMO_ADAPTER":
        t = cap("workflow_engine", "DEMO_ADAPTER", "REMEDIATION_MODE=inline: same remediation steps run in the worker process; this is NOT Temporal")
    else:
        t = observed("workflow_engine", "temporal:workflow", bool(os.environ.get("TEMPORAL_ADDRESS")), "TEMPORAL_ADDRESS not set", "configured; no workflow run observed yet")
    out.append(roll_up("temporal", mi["execution_mode"], [t], "workflow_engine", config={"TEMPORAL_ADDRESS": bool(os.environ.get("TEMPORAL_ADDRESS"))}))

    # --- Bifrost: separate capabilities
    cfg_url, cfg_model = gateway.configured(), bool(gateway.model())
    b_caps = [
        cap("endpoint_configured", "CONNECTED" if cfg_url else "NOT_CONFIGURED", "BIFROST_URL present" if cfg_url else "BIFROST_URL not set"),
        cap("model_route_configured", "CONNECTED" if cfg_model else "NOT_CONFIGURED", "BIFROST_MODEL present" if cfg_model else "BIFROST_MODEL not set"),
    ]
    b_caps[0]["state"] = "CONFIGURED_UNVERIFIED" if cfg_url else "NOT_CONFIGURED"  # presence is not connectivity
    b_caps[1]["state"] = "CONFIGURED_UNVERIFIED" if cfg_model else "NOT_CONFIGURED"
    b_caps.append(_probed("bifrost:gateway_reachable", gateway.base_url() + "/health", "gateway_reachable") if cfg_url else cap("gateway_reachable", "NOT_CONFIGURED", "BIFROST_URL not set"))
    b_caps.append(observed("model_invocation", "bifrost:model_invocation", cfg_url and cfg_model, "needs BIFROST_URL and BIFROST_MODEL", "no model request attempted yet"))
    fb = bool(gateway.fallbacks())
    b_caps.append(cap("fallback_verified", "NOT_CONFIGURED" if not fb else "CONFIGURED_UNVERIFIED", "no fallback model configured" if not fb else "fallback configured; never observed to trigger"))
    b_caps.append(cap("metadata_propagation_verified", "CONFIGURED_UNVERIFIED" if cfg_url else "NOT_CONFIGURED", "x-bf-lh-* headers are sent; gateway-side retention is verified only by `make live-provider-check` against a real gateway"))
    bypass = int(health_log.get("llm_route:BYPASS_NO_GATEWAY").get("n", 0))
    routed = int(health_log.get("llm_route:bifrost").get("n", 0))
    r = cap("legacy_call_sites_routed", "NOT_CONFIGURED" if not cfg_url else ("CONNECTED" if routed and not bypass else "CONFIGURED_UNVERIFIED"), f"{routed} legacy LLM call(s) routed via Bifrost, {bypass} without a gateway")
    if bypass:
        r["state"] = "DEGRADED"
    r["success_count"], r["failure_count"] = routed, bypass
    b_caps.append(r)
    out.append(roll_up("bifrost", "LIVE", b_caps, "model_invocation", config={"BIFROST_URL": cfg_url, "BIFROST_MODEL": cfg_model, "BIFROST_VIRTUAL_KEY": bool(os.environ.get("BIFROST_VIRTUAL_KEY"))}))

    # --- Tavily
    tv = research.configured()
    t_caps = [
        cap("api_configured", "CONFIGURED_UNVERIFIED" if tv else "NOT_CONFIGURED", "TAVILY_API_KEY present" if tv else "TAVILY_API_KEY not set"),
        observed("search", "tavily:search", tv),
        observed("extract", "tavily:extract", tv, pending="no extract attempted yet (only done for a materially useful source)"),
        cap("results_persisted", "CONNECTED" if _count(os.environ.get("NS_RESEARCH_TABLE", "ns_research")) else ("CONFIGURED_UNVERIFIED" if tv else "NOT_CONFIGURED"), f"{_count(os.environ.get('NS_RESEARCH_TABLE', 'ns_research'))} source record(s) in the ledger"),
    ]
    if t_caps[2]["state"] == "CONFIGURED_UNVERIFIED":
        t_caps[2]["state"] = "CONFIGURED_UNVERIFIED"
    out.append(roll_up("tavily", "LIVE", t_caps, "search", config={"TAVILY_API_KEY": tv}))

    # --- OmniDimension
    ok_cfg, ok_agent = bool(omnidim.api_key()), omnidim.agent_id().isdigit()
    o_caps = [
        cap("api_configured", "CONFIGURED_UNVERIFIED" if ok_cfg else "NOT_CONFIGURED", "OMNIDIM_API_KEY present" if ok_cfg else "OMNIDIM_API_KEY not set"),
        cap("agent_configured", "CONFIGURED_UNVERIFIED" if ok_agent else "NOT_CONFIGURED", "OMNIDIM_AGENT_ID is an integer" if ok_agent else "OMNIDIM_AGENT_ID missing or not an integer"),
        observed("session_creation", "omnidimension:session_creation", ok_cfg and ok_agent, "needs OMNIDIM_API_KEY and OMNIDIM_AGENT_ID"),
        observed("browser_connected", "omnidimension:browser_connected", ok_cfg and ok_agent, "needs OMNIDIM_API_KEY and OMNIDIM_AGENT_ID", "no browser session reported active yet"),
        observed("transcript_received", "omnidimension:transcript", ok_cfg and ok_agent, "needs OMNIDIM_API_KEY and OMNIDIM_AGENT_ID", "no final transcript turn reported yet"),
    ]
    out.append(roll_up("omnidimension", "LIVE", o_caps, "session_creation", config={"OMNIDIM_API_KEY": ok_cfg, "OMNIDIM_AGENT_ID": ok_agent}))
    return out
