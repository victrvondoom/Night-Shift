"""LIVE-PROVIDER tests (explicit opt-in): real Tavily, a real model through Bifrost, a real OmniDimension session.

These never run against fakes: each test SKIPS with the exact missing prerequisite when its credentials are absent, so a
skip is reported as NOT_CONFIGURED and is never counted as a pass. Credentials are read from the environment (or .env) and
are never printed or stored.

  Tavily:        TAVILY_API_KEY
  Real model:    BIFROST_URL + BIFROST_MODEL + LIVE_REAL_MODEL=1   (you assert the upstream is a real provider, not the local fake)
  OmniDimension: OMNIDIM_API_KEY + OMNIDIM_AGENT_ID + LIVE_OMNIDIM_SESSION=1   (creates one unconnected session)
"""

from __future__ import annotations

import os
import uuid

import pytest

from beacon import analysis, omnidim, research
from beacon.evidence import ledger
from tests.test_research_engine import NS_TABLES, seed


def _env(*names):
    return all(os.environ.get(n) for n in names)


@pytest.fixture()
def live_tables(tables, monkeypatch):
    sfx = uuid.uuid4().hex[:8]
    for n in NS_TABLES:
        monkeypatch.setenv(n, f"t_live_{n.lower()}_{sfx}")
    monkeypatch.setenv("TAVILY_MAX_QUERIES_PER_INCIDENT", "8")
    monkeypatch.setenv("TAVILY_MAX_CREDITS_PER_INCIDENT", "12")


@pytest.mark.skipif(not _env("TAVILY_API_KEY") or "127.0.0.1" in os.environ.get("TAVILY_API_URL", ""), reason="NOT_CONFIGURED: set TAVILY_API_KEY (and do not point TAVILY_API_URL at a fake)")
def test_live_tavily_search_extract_and_persistence(live_tables):
    seed()
    s = research.execute("INC-T1")
    assert s["status"] in ("COMPLETED", "PARTIAL"), s
    items = ledger.research_for("INC-T1")
    assert items, "a real search returned no sources"
    att = ledger.queries_for("INC-T1")
    assert any(a["op"] == "search" and a["outcome"] == "ok" and a["request_id"] and a["http_status"] == 200 for a in att)
    assert any(a["credits_reported"] for a in att), "Tavily reported no usage credits"
    assert any(i["extraction_status"] == "OK" for i in items) or any(a["op"] == "extract" and a["outcome"] == "ok" for a in att)
    assert all(i["url"].startswith("https://") and i["retrieved_at"] and i["content_hash"] for i in items)
    assert all(i["published_date"] is None or i["date_status"] == "KNOWN" for i in items)  # dates preserved or honestly unknown


@pytest.mark.skipif(not (_env("TAVILY_API_KEY", "BIFROST_URL", "BIFROST_MODEL") and os.environ.get("LIVE_REAL_MODEL") == "1"), reason="NOT_CONFIGURED: needs TAVILY_API_KEY, BIFROST_URL, BIFROST_MODEL and LIVE_REAL_MODEL=1 (a real provider behind Bifrost)")
def test_live_real_model_brief_has_valid_citations(live_tables):
    seed()
    assert research.execute("INC-T1")["status"] in ("COMPLETED", "PARTIAL")
    br = analysis.synthesize_research("INC-T1")
    assert br.origin == "BIFROST_MODEL", (br.status, br.error_category)
    assert br.bifrost_request_id and br.provider and br.model  # real gateway metadata
    ids = {i["evidence_id"] for i in ledger.research_for("INC-T1")}
    cited = [f for f in br.structured_findings if f.kind == "SOURCE_ESTABLISHED"]
    assert cited and all(set(f.evidence_ids) <= ids and f.evidence_ids for f in cited)
    assert ledger.get_snapshot(br.snapshot_id)


@pytest.mark.skipif(not (_env("OMNIDIM_API_KEY", "OMNIDIM_AGENT_ID") and os.environ.get("LIVE_OMNIDIM_SESSION") == "1"), reason="NOT_CONFIGURED: needs OMNIDIM_API_KEY, OMNIDIM_AGENT_ID and LIVE_OMNIDIM_SESSION=1 (creates one unconnected session)")
def test_live_omnidimension_session_creation():
    s = omnidim.create_session({"incident_brief": "live provider check"}, {"purpose": "live_test"})
    assert s["ws_url"].startswith("wss://") and s["expires_at"] and "token" not in s  # the url is single-use: asserted present, never printed
