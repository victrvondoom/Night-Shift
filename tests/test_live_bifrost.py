"""LIVE GATEWAY tests: Night Shift -> a real Bifrost gateway process.

These need a running Bifrost (BIFROST_LIVE_URL, default http://127.0.0.1:8088) and, for the fault
injection cases, the local fake upstream (tests/fixtures/fake_llm_upstream.py on :9300/:9301, wired in
deploy/bifrost/config.local.json).  The *gateway* is real; the upstream "model" is a local fake, so
these prove gateway integration (routing, request-id echo, metadata retention, fallback, error
mapping), NOT the quality of a real LLM.  They skip when the gateway is not running.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid

import httpx
import pytest

from beacon import analysis
from beacon.evidence import ledger, normalize
from beacon.evidence.contracts import Correlation, iso, now_utc

GW = os.environ.get("BIFROST_LIVE_URL", "http://127.0.0.1:8088")
APP_DIR = os.environ.get("BIFROST_APP_DIR", "/var/tmp/bifrost-app")


def _up(url: str) -> bool:
    try:
        return httpx.get(url, timeout=1.5).status_code < 500
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(not _up(GW + "/health"), reason="no real Bifrost gateway running (see docs/HACKATHON.md: live gateway)")
FAKE = _up("http://127.0.0.1:9300/")


def mode(m: str) -> None:
    for p in (9300, 9301):
        httpx.post(f"http://127.0.0.1:{p}/__mode", json={"mode": m}, timeout=2)


@pytest.fixture()
def live(tables, monkeypatch):
    sfx = uuid.uuid4().hex[:8]
    for n in ("NS_EVENTS_TABLE", "NS_CORRELATIONS_TABLE", "NS_RESEARCH_TABLE", "NS_ANALYSES_TABLE", "NS_TRACE_TABLE", "NS_PAYLOADS_TABLE", "NS_HEALTH_TABLE", "NS_QUERIES_TABLE", "NS_BRIEFS_TABLE", "NS_BUDGET_TABLE", "NS_RUNS_TABLE", "NS_SNAPSHOTS_TABLE"):
        monkeypatch.setenv(n, f"t_{n.lower()}_{sfx}")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("BIFROST_URL", GW)
    monkeypatch.setenv("BIFROST_MODEL", "openai/gpt-4o-mini")
    monkeypatch.delenv("BIFROST_FALLBACK_MODELS", raising=False)
    if FAKE:
        mode("ok")
    yield monkeypatch
    if FAKE:
        mode("ok")


def _seed(iid="INC-LIVE"):
    ev = normalize.from_audit({"auditID": f"a-{uuid.uuid4().hex[:6]}", "stage": "ResponseComplete", "verb": "patch", "user": {"username": "alice"}, "objectRef": {"resource": "networkpolicies", "namespace": "demo", "name": "demo-db-ingress"}, "responseStatus": {"code": 200}, "stageTimestamp": "2026-11-16T10:00:00.000000Z", "requestURI": "/x"})
    ledger.record_event(ev)
    c = Correlation(correlation_id="cor-live", incident_id=iid, rule="r", change_event_id=ev.event_id, included_event_ids=[ev.event_id], symptom_types=[], namespace="demo", resource="demo/demo-db-ingress", target_app="demo-db", window_start=iso(now_utc()), window_end=iso(now_utc()), window_seconds=600, strength="PARTIAL", explanation="x", processed_at=iso(now_utc()))
    ledger.record_correlation(c)
    return ev


def _bifrost_log(request_id: str) -> dict | None:
    import time

    con = sqlite3.connect(f"file:{APP_DIR}/logs.db?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    for _ in range(40):  # Bifrost writes its log row asynchronously, after the response
        row = con.execute("select id, provider, model, status, fallback_index, metadata from logs where id = ?", (request_id,)).fetchone()
        if row:
            return dict(row)
        time.sleep(0.25)
    return None


def test_real_gateway_request_is_routed_correlated_and_logged_with_incident_metadata(live):
    ev = _seed()
    a = analysis.analyze("INC-LIVE")
    assert a.origin == "BIFROST_MODEL" and a.status in ("OK", "DOWNGRADED")
    assert a.bifrost_request_id == a.analysis_id  # Bifrost echoed our x-request-id
    assert a.bifrost_trace_id and a.provider == "openai" and a.usage and a.latency_ms is not None
    assert a.structured and set(a.structured.supporting_event_ids) <= {ev.event_id}
    row = _bifrost_log(a.analysis_id)  # Bifrost's OWN log store holds the request under our id
    assert row and row["status"] == "success" and row["provider"] == "openai"
    meta = json.loads(row["metadata"])
    assert meta["incident-id"] == "INC-LIVE" and meta["evidence-set"] == a.evidence_set_hash and meta["workflow-stage"] == "analysis"
    assert "authorization" not in json.dumps(meta).lower() and "payload" not in meta  # no secrets / raw evidence in labels


@pytest.mark.skipif(not FAKE, reason="fault injection needs the local fake upstream")
def test_fallback_to_second_provider_is_observed_not_assumed(live):
    live.setenv("BIFROST_FALLBACK_MODELS", "groq/llama-3.3-70b-versatile")
    _seed()
    mode("primary_down")
    a = analysis.analyze("INC-LIVE")
    assert a.origin == "BIFROST_MODEL" and a.provider == "groq" and a.fallback_used is True and a.fallback_index == 1
    # Bifrost logs the primary attempt under our id (status error) and the fallback as a CHILD row
    # (new id, parent_request_id = our id, fallback_index 1) -- with the incident metadata preserved.
    parent = _bifrost_log(a.analysis_id)
    assert parent and parent["status"] == "error" and parent["fallback_index"] == 0
    con = sqlite3.connect(f"file:{APP_DIR}/logs.db?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    child = None
    for _ in range(40):
        child = con.execute("select provider, status, fallback_index, metadata from logs where parent_request_id = ?", (a.analysis_id,)).fetchone()
        if child:
            break
        import time

        time.sleep(0.25)
    assert child and child["provider"] == "groq" and child["status"] == "success" and child["fallback_index"] == 1
    assert json.loads(child["metadata"])["incident-id"] == "INC-LIVE"


@pytest.mark.skipif(not FAKE, reason="fault injection needs the local fake upstream")
def test_all_providers_down_is_gateway_error_with_rules_only(live):
    live.setenv("BIFROST_FALLBACK_MODELS", "groq/llama-3.3-70b-versatile")
    _seed()
    mode("500")
    a = analysis.analyze("INC-LIVE")
    assert a.origin == "RULES_ONLY" and a.status == "GATEWAY_ERROR" and a.error_category == "provider_error" and a.structured


@pytest.mark.skipif(not FAKE, reason="fault injection needs the local fake upstream")
def test_upstream_rate_limit_is_categorised(live):
    _seed()
    mode("429")
    a = analysis.analyze("INC-LIVE")
    assert a.status == "GATEWAY_ERROR" and a.error_category in ("rate_limited", "provider_error") and a.origin == "RULES_ONLY"


@pytest.mark.skipif(not FAKE, reason="fault injection needs the local fake upstream")
def test_client_timeout_is_categorised(live):
    live.setenv("BIFROST_TIMEOUT_SECONDS", "2")
    _seed()
    mode("hang")
    a = analysis.analyze("INC-LIVE")
    assert a.status == "GATEWAY_ERROR" and a.error_category == "timeout"


@pytest.mark.skipif(not FAKE, reason="fault injection needs the local fake upstream")
def test_garbage_model_output_cannot_produce_an_analysis(live):
    _seed()
    mode("garbage")
    a = analysis.analyze("INC-LIVE")
    assert a.origin == "RULES_ONLY" and a.status == "DOWNGRADED" and a.error_category == "invalid_output"


def test_gateway_unreachable_after_real_health_probe(live):
    live.setenv("BIFROST_URL", "http://127.0.0.1:9")
    _seed()
    a = analysis.analyze("INC-LIVE")
    assert a.status == "GATEWAY_ERROR" and a.error_category == "unavailable"

