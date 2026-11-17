"""Phase III through the real HTTP API: the full lifecycle the UI drives (provider contract fakes)."""

from __future__ import annotations

import json
import threading

from beacon import db
from beacon.evidence import ledger, normalize
from tests.conftest import PASS
from tests.fixtures import fake_tavily
from tests.test_research_engine import eng, good_payload, model, seed  # noqa: F401

B = "/api/ns/incidents/INC-T1"


def view(client):
    return client.get(B, headers=PASS).json()


def test_requires_auth_and_reports_not_configured(client, eng):  # noqa: F811
    seed()
    assert client.post(f"{B}/research", json={}).status_code == 401
    assert client.post(f"{B}/research/synthesize").status_code == 401
    eng.delenv("TAVILY_API_KEY")
    r = client.post(f"{B}/research", json={}, headers=PASS)
    assert r.status_code == 503 and r.json()["state"] == "NOT_CONFIGURED" and fake_tavily.State.seen == []


def test_no_correlation_no_research(client, eng):  # noqa: F811
    assert client.post("/api/ns/incidents/INC-NOPE/research", json={}, headers=PASS).status_code == 409


def test_full_lifecycle_through_the_api(client, eng):  # noqa: F811
    seed()
    v0 = view(client)
    assert v0["research_state"]["status"] == "NOT_STARTED" and v0["research_state"]["brief_status"] == "NEVER_RESEARCHED"
    r = client.post(f"{B}/research", json={}, headers=PASS)
    assert r.status_code == 200 and r.json()["status"] == "COMPLETED"
    v1 = view(client)
    rs = v1["research_state"]
    assert rs["status"] == "COMPLETED" and rs["budget"]["operations_used"] == len(rs["attempts"]) and rs["budget"]["credits_reported"] > 0
    assert v1["research"] and all("age_days" in s and "date_known" in s for s in v1["research"])
    # explanation v1
    src = v1["research"][0]["evidence_id"]
    f = model(good_payload(src))
    eng.setenv("BIFROST_URL", f.url); eng.setenv("BIFROST_MODEL", "openai/x")
    br = client.post(f"{B}/research/synthesize", headers=PASS).json()
    assert br["version"] == 1 and br["origin"] == "BIFROST_MODEL"
    v2 = view(client)
    assert v2["research_briefs"][0]["staleness"]["status"] == "FRESH" and v2["research_state"]["brief_status"] == "FRESH"
    # the stored follow-up suggestion is tampered with: the server must sanitise AGAIN before running anything
    row = db.get(ledger.briefs_table(), br["brief_id"])
    db.patch(ledger.briefs_table(), br["brief_id"], {"follow_up_queries": ["Kubernetes NetworkPolicy egress semantics", "why did orders-db-ingress break", "https://evil.example/x"]})
    calls = len(fake_tavily.State.seen)
    fu = client.post(f"{B}/research", json={"followups": True}, headers=PASS)
    assert fu.status_code == 200 and row
    sent = [json.dumps(x["body"]).lower() for x in fake_tavily.State.seen[calls:]]
    assert any("egress semantics" in s for s in sent) and not any("orders-db" in s or "evil" in s for s in sent)
    # a follow-up added a source after v1's snapshot -> v1 is stale, with the exact trigger and time
    v3 = view(client)
    st = v3["research_briefs"][0]["staleness"]
    assert st["status"] == "STALE" and st["reasons"][0]["rule"] == "NEW_SOURCE" and st["invalidated_at"] and st["summary"]
    assert v3["research_state"]["brief_status"] == "STALE"
    # refreshed research -> v2; v1 is retained and marked SUPERSEDED, never overwritten
    br2 = client.post(f"{B}/research/synthesize", headers=PASS).json()
    v4 = view(client)
    assert br2["version"] == 2 and br2["previous_brief_id"] == br["brief_id"]
    assert [b["staleness"]["status"] for b in v4["research_briefs"]] == ["SUPERSEDED", "FRESH"]
    assert v4["research_briefs"][0]["brief_id"] == br["brief_id"]  # still accessible
    assert v4["research_briefs"][0]["snapshot_id"] != v4["research_briefs"][1]["snapshot_id"]


def test_new_relevant_event_marks_the_current_version_stale_but_unrelated_events_do_not(client, eng):  # noqa: F811
    ch, sym = seed()
    client.post(f"{B}/research", json={}, headers=PASS)
    src = view(client)["research"][0]["evidence_id"]
    f = model(good_payload(src))
    eng.setenv("BIFROST_URL", f.url); eng.setenv("BIFROST_MODEL", "openai/x")
    client.post(f"{B}/research/synthesize", headers=PASS)
    # an unrelated event type claimed by the incident
    other = normalize.from_audit({"auditID": "x1", "stage": "ResponseComplete", "verb": "patch", "user": {"username": "system:serviceaccount:beacon:beacon-remediator"}, "objectRef": {"resource": "networkpolicies", "namespace": "payments-prod", "name": "p"}, "responseStatus": {"code": 200}, "stageTimestamp": "2026-11-16T11:00:00.000000Z", "requestURI": "/x"})
    ledger.record_event(other)
    db.patch(ledger.events_table(), other.event_id, {"incident_id": "INC-T1"})
    assert view(client)["research_state"]["brief_status"] == "FRESH"
    late = normalize.from_app_log({"id": "late-9", "ts": "2026-11-16T11:05:00Z", "namespace": "payments-prod", "app": "api", "line": "database unreachable at orders-db:6379"})
    ledger.record_event(late)
    db.patch(ledger.events_table(), late.event_id, {"incident_id": "INC-T1"})
    st = view(client)["research_briefs"][-1]["staleness"]
    assert st["status"] == "STALE" and st["reasons"][0]["rule"] == "NEW_RELEVANT_EVENT"
    assert any(i["reason"] == "unrelated_event_type" for i in st["ignored"])


def test_followups_need_an_explicit_request_and_a_brief(client, eng):  # noqa: F811
    seed()
    client.post(f"{B}/research", json={}, headers=PASS)
    assert client.post(f"{B}/research", json={"followups": True}, headers=PASS).status_code == 409  # no brief yet
    n = len(fake_tavily.State.seen)
    src = view(client)["research"][0]["evidence_id"]
    f = model(good_payload(src))
    eng.setenv("BIFROST_URL", f.url); eng.setenv("BIFROST_MODEL", "openai/x")
    client.post(f"{B}/research/synthesize", headers=PASS)
    assert len(fake_tavily.State.seen) == n  # proposing follow-ups ran NOTHING


def test_concurrent_followups_one_wins_one_is_refused(client, eng):  # noqa: F811
    seed()
    client.post(f"{B}/research", json={}, headers=PASS)
    src = view(client)["research"][0]["evidence_id"]
    f = model(good_payload(src))
    eng.setenv("BIFROST_URL", f.url); eng.setenv("BIFROST_MODEL", "openai/x")
    br = client.post(f"{B}/research/synthesize", headers=PASS).json()
    db.patch(ledger.briefs_table(), br["brief_id"], {"follow_up_queries": ["Kubernetes NetworkPolicy egress semantics", "Kubernetes NetworkPolicy ipBlock behavior"]})
    fake_tavily.State.delay = 0.7
    codes: list[int] = []
    ts = [threading.Thread(target=lambda: codes.append(client.post(f"{B}/research", json={"followups": True}, headers=PASS).status_code)) for _ in range(2)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(codes) == [200, 409]


def test_budget_exhausted_is_reported_not_retried(client, eng):  # noqa: F811
    seed()
    eng.setenv("TAVILY_MAX_QUERIES_PER_INCIDENT", "2")
    client.post(f"{B}/research", json={}, headers=PASS)
    n = len(fake_tavily.State.seen)
    r = client.post(f"{B}/research", json={}, headers=PASS)
    assert r.json()["status"] == "BUDGET_EXHAUSTED" and len(fake_tavily.State.seen) == n
    assert view(client)["research_state"]["budget"]["exhausted"] is True


def test_provider_failure_is_a_failed_run_in_the_ui_state(client, eng):  # noqa: F811
    seed()
    fake_tavily.State.mode = "401"
    r = client.post(f"{B}/research", json={}, headers=PASS)
    assert r.status_code == 502 and r.json()["status"] == "FAILED"
    st = view(client)["research_state"]
    assert st["status"] == "FAILED" and st["runs"][-1]["failures"][0]["category"] == "auth"
    assert "tvly-test-key" not in json.dumps(view(client)) + r.text  # no credential in any response
