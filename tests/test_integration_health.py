"""Integration health is evidence-based: configuration alone is never CONNECTED."""

import time
import uuid

import pytest

from beacon import health_log, integrations


@pytest.fixture()
def hl(monkeypatch):
    monkeypatch.setenv("NS_HEALTH_TABLE", f"t_health_{uuid.uuid4().hex[:8]}")
    for v in ("BIFROST_URL", "BIFROST_MODEL", "TAVILY_API_KEY", "OMNIDIM_API_KEY", "OMNIDIM_AGENT_ID", "SIMULATOR_URL"):
        monkeypatch.delenv(v, raising=False)
    return monkeypatch


def row(name):
    return next(r for r in integrations.snapshot() if r["integration"] == name)


def cap(r, name):
    return next(c for c in r["capabilities"] if c["capability"] == name)


@pytest.mark.parametrize("name", ["bifrost", "tavily", "omnidimension"])
def test_unconfigured_is_not_configured_never_connected(hl, name):
    assert row(name)["state"] == "NOT_CONFIGURED"


def test_configuration_alone_is_unverified(hl):
    hl.setenv("TAVILY_API_KEY", "k")
    hl.setenv("OMNIDIM_API_KEY", "k")
    hl.setenv("OMNIDIM_AGENT_ID", "1")
    hl.setenv("BIFROST_URL", "http://127.0.0.1:9")  # nothing listens: probe fails
    hl.setenv("BIFROST_MODEL", "x/y")
    for n in ("tavily", "omnidimension", "bifrost"):
        r = row(n)
        assert r["state"] == "CONFIGURED_UNVERIFIED", (n, r["state"])
    assert cap(row("bifrost"), "gateway_reachable")["state"] == "FAILED"  # a real failed probe is reported


def test_state_follows_observed_interactions(hl):
    hl.setenv("TAVILY_API_KEY", "k")
    health_log.record("tavily:search", True)
    r = row("tavily")
    assert r["state"] == "CONNECTED" and r["success_count"] == 1 and r["last_success_at"]
    time.sleep(0.01)
    health_log.record("tavily:search", False, "rate_limited")
    r = row("tavily")
    assert r["state"] == "DEGRADED" and r["last_error_category"] == "rate_limited" and r["failure_count"] == 1


def test_only_failures_is_failed(hl):
    hl.setenv("OMNIDIM_API_KEY", "k")
    hl.setenv("OMNIDIM_AGENT_ID", "7")
    health_log.record("omnidimension:session_creation", False, "auth")
    assert row("omnidimension")["state"] == "FAILED"


def test_legacy_bypass_cannot_make_bifrost_connected(hl):
    health_log.count("llm_route:BYPASS_NO_GATEWAY")
    r = row("bifrost")
    assert r["state"] == "NOT_CONFIGURED"
    assert cap(r, "legacy_call_sites_routed")["state"] == "NOT_CONFIGURED" or cap(r, "legacy_call_sites_routed")["state"] == "DEGRADED"
    assert "llm_gateway_routing" not in [x["integration"] for x in integrations.snapshot()]


def test_bifrost_metadata_propagation_is_never_claimed_verified(hl):
    hl.setenv("BIFROST_URL", "http://127.0.0.1:9")
    hl.setenv("BIFROST_MODEL", "x/y")
    assert cap(row("bifrost"), "metadata_propagation_verified")["state"] == "CONFIGURED_UNVERIFIED"


def test_inline_execution_is_never_reported_as_temporal(hl, monkeypatch):
    monkeypatch.setenv("REMEDIATION_MODE", "inline")
    r = row("temporal")
    assert r["state"] == "DEMO_ADAPTER" and r["mode"] == "INLINE_DEMO_ADAPTER"
    monkeypatch.setenv("REMEDIATION_MODE", "temporal")
    monkeypatch.delenv("TEMPORAL_ADDRESS", raising=False)
    assert row("temporal")["state"] == "NOT_CONFIGURED"
