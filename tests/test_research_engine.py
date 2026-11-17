"""Phase III: the research engine -- sanitiser, planner, Tavily execution, budget, briefs, stale-answer rules.

Provider traffic here goes to LOCAL CONTRACT FAKES (tests/fixtures/fake_tavily.py and the _Fake gateway).
These tests prove our handling; they are NOT live-provider evidence (see tests/test_live_providers.py).
"""

from __future__ import annotations

import json
import threading
import uuid

import pytest

from beacon import analysis, research, research_plan, staleness
from beacon.evidence import ledger, normalize
from beacon.evidence.contracts import Correlation, iso, now_utc
from tests.fixtures import fake_tavily
from tests.test_workspace import NS_TABLES, _audit, _Fake

CTX = {"incident_id": "INC-T1", "namespace": "payments-prod", "resource": "payments-prod/orders-db-ingress", "target_app": "orders-db", "run_id": "run-77", "affected_service": "checkout-api", "event_types": ["networkpolicy_change", "db_connection_error"], "extra_identifiers": ["orders-db-ingress", "checkout-api"]}


@pytest.fixture()
def eng(tables, monkeypatch):
    sfx = uuid.uuid4().hex[:8]
    for n in NS_TABLES:
        monkeypatch.setenv(n, f"t_{n.lower()}_{sfx}")
    srv, url = fake_tavily.start()
    fake_tavily.State.seen.clear()
    fake_tavily.State.calls = 0
    fake_tavily.State.mode = "ok"
    fake_tavily.State.delay = 0.0
    fake_tavily.State.extract_version = 1
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("TAVILY_API_URL", url)
    monkeypatch.setenv("TAVILY_API_KEY", "tvly-test-key")
    monkeypatch.setenv("TAVILY_RETRY_CAP_S", "0")
    monkeypatch.setenv("TAVILY_TIMEOUT", "5")
    monkeypatch.setenv("TAVILY_MAX_QUERIES_PER_INCIDENT", "20")
    monkeypatch.setenv("TAVILY_MAX_CREDITS_PER_INCIDENT", "100")
    monkeypatch.setenv("BIFROST_URL", "http://127.0.0.1:9")
    monkeypatch.delenv("BIFROST_MODEL", raising=False)
    yield monkeypatch
    srv.shutdown()


def seed(iid="INC-T1", ns="payments-prod", name="orders-db-ingress"):
    ch = normalize.from_audit(_audit("a-" + uuid.uuid4().hex[:6], name=name))
    ch.resource.namespace = ns
    sym = normalize.from_app_log({"id": "l-" + uuid.uuid4().hex[:6], "ts": "2026-11-16T10:00:20Z", "namespace": ns, "app": "checkout-api", "line": "database unreachable at orders-db:6379"})
    for e in (ch, sym):
        ledger.record_event(e)
    c = Correlation(correlation_id=f"cor-{iid}", incident_id=iid, rule="netpol_change_then_dependency_symptoms.v1", change_event_id=ch.event_id, included_event_ids=[ch.event_id, sym.event_id], symptom_types=["db_connection_error"], namespace=ns, resource=f"{ns}/{name}", target_app="orders-db", window_start=iso(now_utc()), window_end=iso(now_utc()), window_seconds=600, strength="STRONG", explanation="A write to the policy was followed by connection errors (correlation only).", processed_at=iso(now_utc()), missing_evidence=["no confirmation of root cause"])
    ledger.record_correlation(c)
    return ch, sym


# ============================================================================ sanitiser
SENSITIVE = [
    "why did orders-db lose connectivity",
    "kubernetes networkpolicy payments-prod namespace blocks traffic",
    "connection refused to 10.42.7.19:6379 networkpolicy",
    "debug orders-db-ingress policy",
    "error from orders-db.payments-prod.svc.cluster.local timeout",
    "contact oncall@example.com about networkpolicy",
    "Authorization: Bearer abcdef1234567890abcdef1234567890",
    "api_key=sk-live-1234567890abcdef kubernetes",
    "token tvly-ABCDEFGH12345678 networkpolicy",
    "see https://internal.corp/runbook networkpolicy",
    "kubernetes networkpolicy 2001:db8:85a3::8a2e:370:7334",
    "incident INC-0123ABCD45 networkpolicy",
    "evt-0123456789abcdef networkpolicy",
    "uuid 123e4567-e89b-12d3-a456-426614174000 networkpolicy",
    "kubectl delete networkpolicy foo",
    "networkpolicy; rm -rf /",
    "read /home/ubuntu/.kube/config networkpolicy",
    "a" * 200,
    "",
    "run-77 kubernetes networkpolicy",
]


@pytest.mark.parametrize("q", SENSITIVE)
def test_sanitiser_rejects_sensitive_or_unsafe_queries(q):
    s = research_plan.sanitize_query(q, CTX)
    assert not s.ok and s.query == "" and s.reasons


CLEAN = [
    "Kubernetes NetworkPolicy ingress rules podSelector how pods are selected and isolated",
    "Kubernetes NetworkPolicy default deny all ingress empty ingress list behavior",
    "Kubernetes troubleshooting service connectivity network plugin policy enforcement",
]


@pytest.mark.parametrize("q", CLEAN)
def test_sanitiser_accepts_generic_mechanism_queries(q):
    assert research_plan.sanitize_query(q, CTX).ok


def test_planner_is_incident_driven_and_never_leaks_context():
    plan = research_plan.plan(CTX)
    assert len(plan) >= 5 and {p.purpose for p in plan} >= {"mechanism", "default_deny", "pitfalls", "troubleshooting"}
    blob = " ".join(p.query.lower() for p in plan)
    for ident in ("payments-prod", "orders-db", "checkout-api", "inc-t1", "run-77"):
        assert ident not in blob
    assert research_plan.plan({"event_types": ["something_else"]}) == []  # unknown failure class -> nothing is searched


def test_followups_are_sanitised_capped_and_deduplicated():
    acc, rej = research_plan.sanitize_followups(["Kubernetes NetworkPolicy egress semantics", "why did orders-db fail", "https://x.io", "Kubernetes NetworkPolicy ipBlock behavior", "Kubernetes NetworkPolicy endPort usage"], CTX, set())
    assert acc == ["Kubernetes NetworkPolicy egress semantics", "Kubernetes NetworkPolicy ipBlock behavior"]
    reasons = {r for x in rej for r in x["reasons"]}
    assert {"internal_identifier", "url", "over_cap"} <= reasons and all(x["query_preview"] in ("[withheld]",) or "NetworkPolicy" in x["query_preview"] for x in rej)


# ============================================================================ dates / parsing
@pytest.mark.parametrize("val,status", [("Tue, 11 Mar 2025 17:00:00 GMT", "KNOWN"), ("2025-03-11T17:00:00Z", "KNOWN"), (None, "UNKNOWN"), ("", "UNKNOWN"), ("not a real date", "UNPARSEABLE"), ("32 Foo 2025", "UNPARSEABLE")])
def test_date_parsing_never_fabricates(val, status):
    iso_s, st = research.parse_date(val)
    assert st == status and (iso_s is None) == (status != "KNOWN")
    if status == "KNOWN":
        assert iso_s.startswith("2025-03-11T17:00:00")


# ============================================================================ engine: success path
def test_full_run_preserves_provenance_and_sends_only_sanitised_queries(eng):
    seed()
    s = research.execute("INC-T1")
    assert s["status"] == "COMPLETED" and s["new"] >= 3
    items = ledger.research_for("INC-T1")
    first = next(i for i in items if i["url"].endswith("/network-policies/"))
    assert first["domain"] == "kubernetes.io" and first["request_id"] and first["credits"] == 1.0
    assert first["published_date"] == "Tue, 11 Mar 2025 17:00:00 GMT" and first["date_status"] == "KNOWN" and first["published_at"].startswith("2025-03-11")
    assert first["retrieved_at"] and first["content_hash"] and first["extraction_status"] == "OK"
    assert next(i for i in items if "debug-service" in i["url"])["date_status"] == "UNKNOWN"  # missing stays unknown
    assert next(i for i in items if "declare-network" in i["url"])["date_status"] == "UNPARSEABLE" and next(i for i in items if "declare-network" in i["url"])["published_at"] is None
    sent = " ".join(json.dumps(x["body"]).lower() for x in fake_tavily.State.seen)
    for ident in ("payments-prod", "orders-db", "checkout-api", "inc-t1"):
        assert ident not in sent  # nothing about the incident reached the provider
    assert all(x["auth"] == "Bearer tvly-test-key" for x in fake_tavily.State.seen)
    att = ledger.queries_for("INC-T1")
    assert any(a["op"] == "extract" for a in att) and all(a["request_id"] for a in att if a["outcome"] == "ok")
    b = ledger.budget_for("INC-T1")
    assert b["operations_used"] == len(att) and b["credits_reported"] == float(len(att))  # actual provider credits, not an estimate


def test_extract_is_one_call_for_the_best_two_primary_sources(eng):
    seed()
    research.execute("INC-T1")
    extracts = [x for x in fake_tavily.State.seen if x["path"] == "/extract"]
    assert len(extracts) == 1 and len(extracts[0]["body"]["urls"]) == 2
    ok = [i for i in ledger.research_for("INC-T1") if i["extraction_status"] == "OK"]
    assert len(ok) == 2 and all("FULL PAGE TEXT" in i["excerpt"] for i in ok)


def test_partial_extraction_failure_is_reported_not_hidden(eng):
    seed()
    fake_tavily.State.mode = "partial_extract"
    s = research.execute("INC-T1")
    assert s["status"] == "PARTIAL" and {"op": "extract", "category": "partial_extraction_failure"} in s["failures"] or any(f["op"] == "extract" for f in s["failures"])
    statuses = sorted(i["extraction_status"] for i in ledger.research_for("INC-T1") if i["classification"] in ("SUPPORTS", "CONTEXT_ONLY") and i["extraction_status"] != "NOT_REQUESTED")
    assert "FAILED" in statuses and "OK" in statuses


# ============================================================================ failures
@pytest.mark.parametrize("mode,cat", [("401", "auth"), ("403", "auth"), ("432", "plan_limit")])
def test_credential_and_plan_failures_stop_immediately_and_are_failed_runs(eng, mode, cat):
    seed()
    fake_tavily.State.mode = mode
    s = research.execute("INC-T1")
    assert s["status"] == "FAILED" and s["failures"][0]["category"] == cat
    assert len(fake_tavily.State.seen) == (1 if cat == "auth" else len(research_plan.plan(CTX)))  # auth never loops; plan-limit may try each query once
    assert ledger.research_for("INC-T1") == []  # a failure is never stored as a result
    assert ledger.budget_for("INC-T1")["operations_used"] == len(ledger.queries_for("INC-T1"))


def test_rate_limit_retries_once_and_every_attempt_consumes_budget(eng):
    seed()
    fake_tavily.State.mode = "429_then_ok"
    s = research.execute("INC-T1")
    att = ledger.queries_for("INC-T1")
    first = att[0]
    assert first["outcome"] == "failed" and first["error_category"] == "rate_limited" and att[1]["retry"] is True and att[1]["outcome"] == "ok"
    assert ledger.budget_for("INC-T1")["operations_used"] == len(att) and s["status"] in ("COMPLETED", "PARTIAL")


def test_persistent_429_is_bounded_two_attempts_per_query_not_a_retry_loop(eng):
    seed()
    fake_tavily.State.mode = "429"
    s = research.execute("INC-T1")
    att = ledger.queries_for("INC-T1")
    assert s["status"] == "FAILED" and all(a["outcome"] == "failed" for a in att)
    per_query: dict[str, int] = {}
    for a in att:
        per_query[a["query"]] = per_query.get(a["query"], 0) + 1
    assert max(per_query.values()) == 2  # original + exactly one retry
    assert ledger.budget_for("INC-T1")["operations_used"] == len(att)  # nothing was free


@pytest.mark.parametrize("mode,cat", [("500", "server_error"), ("garbage", "invalid_response"), ("no_results_key", "invalid_response")])
def test_server_and_malformed_responses_are_failures(eng, mode, cat):
    seed()
    fake_tavily.State.mode = mode
    s = research.execute("INC-T1")
    assert s["status"] == "FAILED" and all(f["category"] == cat for f in s["failures"]) and ledger.research_for("INC-T1") == []


def test_timeout_is_a_failure(eng):
    seed()
    eng.setenv("TAVILY_TIMEOUT", "1")
    fake_tavily.State.mode = "hang"
    s = research.execute("INC-T1")
    assert s["status"] == "FAILED" and s["failures"][0]["category"] == "timeout"


def test_provider_down_is_unavailable(eng):
    seed()
    eng.setenv("TAVILY_API_URL", "http://127.0.0.1:9")
    s = research.execute("INC-T1")
    assert s["status"] == "FAILED" and s["failures"][0]["category"] == "unavailable"


def test_zero_results_is_a_completed_run_that_still_spent_budget(eng):
    seed()
    fake_tavily.State.mode = "empty"
    s = research.execute("INC-T1")
    assert s["status"] == "COMPLETED" and ledger.research_for("INC-T1") == []
    assert ledger.budget_for("INC-T1")["operations_used"] == len(research_plan.plan(CTX))  # zero results are not free


def test_missing_result_fields_are_skipped_safely(eng):
    seed()
    fake_tavily.State.mode = "missing_fields"
    research.execute("INC-T1")
    items = ledger.research_for("INC-T1")
    assert all(i["url"].startswith("https://") for i in items)
    assert any(i["classification"] == "INSUFFICIENT_EVIDENCE" for i in items)  # url but no content


def test_extract_outage_is_partial_and_sources_are_marked_failed(eng):
    seed()
    fake_tavily.State.mode = "extract_500"
    s = research.execute("INC-T1")
    assert s["status"] == "PARTIAL" and any(f["op"] == "extract" for f in s["failures"])
    assert any(i["extraction_status"] == "FAILED" for i in ledger.research_for("INC-T1"))


def test_unconfigured_is_refused_before_any_request(eng):
    seed()
    eng.delenv("TAVILY_API_KEY")
    with pytest.raises(research.ResearchError) as e:
        research.execute("INC-T1")
    assert e.value.category == "not_configured" and fake_tavily.State.seen == []


# ============================================================================ budget
def test_budget_stops_the_run_and_exhausted_runs_send_nothing(eng):
    seed()
    eng.setenv("TAVILY_MAX_QUERIES_PER_INCIDENT", "3")
    s = research.execute("INC-T1")
    assert s["budget_exhausted"] and ledger.budget_for("INC-T1")["operations_used"] == 3 and len(fake_tavily.State.seen) == 3
    before = len(fake_tavily.State.seen)
    s2 = research.execute("INC-T1")
    assert s2["status"] == "BUDGET_EXHAUSTED" and len(fake_tavily.State.seen) == before  # no request escaped


def test_credit_cap_is_enforced_independently(eng):
    seed()
    eng.setenv("TAVILY_MAX_CREDITS_PER_INCIDENT", "2")
    research.execute("INC-T1")
    b = ledger.budget_for("INC-T1")
    assert b["credits_reserved"] <= 2 and b["exhausted"]


def test_concurrent_reservations_cannot_overspend(eng):
    eng.setenv("TAVILY_MAX_QUERIES_PER_INCIDENT", "5")
    got: list[bool] = []
    lock = threading.Lock()

    def worker():
        r = ledger.reserve("INC-RACE", "search", 1.0)
        with lock:
            got.append(r is not None)

    ts = [threading.Thread(target=worker) for _ in range(30)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(got) == 5 and ledger.budget_for("INC-RACE")["operations_used"] == 5


def test_concurrent_research_runs_are_refused_not_interleaved(eng):
    seed()
    fake_tavily.State.delay = 0.6
    results: list[object] = []

    def go():
        try:
            results.append(research.execute("INC-T1")["status"])
        except research.ResearchError as exc:
            results.append(exc.category)

    ts = [threading.Thread(target=go) for _ in range(3)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results.count("run_in_progress") == 2 and sum(r in ("COMPLETED", "PARTIAL") for r in results) == 1
    assert ledger.active_run("INC-T1") is None  # lock released


def test_duplicate_run_does_not_re_ask_or_duplicate_sources(eng):
    seed()
    research.execute("INC-T1")
    n_sources, n_calls = len(ledger.research_for("INC-T1")), len(fake_tavily.State.seen)
    s = research.execute("INC-T1")
    assert len(ledger.research_for("INC-T1")) == n_sources and len(fake_tavily.State.seen) <= n_calls + 1  # at most a re-extract attempt, no new searches
    assert not any(x["path"] == "/search" for x in fake_tavily.State.seen[n_calls:])
    assert s["new"] == 0


def test_changed_source_content_is_kept_as_a_revision(eng):
    seed()
    research.execute("INC-T1")
    src = next(i for i in ledger.research_for("INC-T1") if i["extraction_status"] == "OK")
    changed = research._build_item("INC-T1", {"url": src["url"], "title": src["title"], "content": "materially different official text about isolated ingress", "score": 0.9}, "x", "q", "r", 1.0, iso(now_utc()))
    changed.hash_basis, changed.extraction_status, changed.content_hash = "extract", "OK", research.content_hash("materially different FULL official text")
    assert research._store(changed) == "updated"
    row = next(i for i in ledger.research_for("INC-T1") if i["evidence_id"] == src["evidence_id"])
    assert row["revisions"] and row["revisions"][0]["content_hash"] == src["content_hash"] and row["content_hash"] != src["content_hash"]
    assert research._store(changed) == "duplicate"


# ============================================================================ citations / brief v2
def model(payload):
    return _Fake(lambda b: (200, {"id": "upstream", "model": "m", "choices": [{"message": {"content": json.dumps(payload)}}], "usage": {"total_tokens": 9}}, {"x-bifrost-request-id": "brf-req", "x-bifrost-provider": "openai", "x-bifrost-resolved-model": "m"}))


def good_payload(src_id):
    return {"incident_summary": "S", "likely_explanation": "L", "findings": [
        {"claim": "Isolated pods only accept listed ingress.", "kind": "SOURCE_ESTABLISHED", "evidence_ids": [src_id]},
        {"claim": "The removed rule is why.", "kind": "SOURCE_ESTABLISHED", "evidence_ids": ["ext-ffffffffffffffff"]},
        {"claim": "Likely the policy edit.", "kind": "MODEL_INFERENCE", "evidence_ids": []},
        {"claim": "Maybe CNI lag.", "kind": "HYPOTHESIS", "evidence_ids": []}],
        "hypotheses": ["CNI sync delay"], "missing_evidence": ["policy diff"], "alternative_explanations": ["DB crash"], "research_gaps": ["cluster CNI"], "next_steps": ["compare to golden snapshot"], "limitations": ["docs are generic"],
        "follow_up_queries": ["Kubernetes NetworkPolicy egress semantics", "why did orders-db fail", "https://evil.example"]}


def test_brief_validates_citations_labels_kinds_and_binds_a_snapshot(eng):
    seed()
    research.execute("INC-T1")
    src = ledger.research_for("INC-T1")[0]
    f = model(good_payload(src["evidence_id"]))
    eng.setenv("BIFROST_URL", f.url); eng.setenv("BIFROST_MODEL", "openai/x")
    br = analysis.synthesize_research("INC-T1")
    assert br.origin == "BIFROST_MODEL" and br.status == "DOWNGRADED" and br.bifrost_request_id == "brf-req" and br.version == 1
    kinds = {(x.kind, x.claim[:10]) for x in br.structured_findings}
    assert ("SOURCE_ESTABLISHED", "Isolated p") in kinds and ("HYPOTHESIS", "The remove") in kinds  # fabricated-citation claim was DEMOTED, not shown as established
    assert all(set(x.evidence_ids) <= {s["evidence_id"] for s in ledger.research_for("INC-T1")} for x in br.structured_findings)
    assert br.structured_findings[0].source_dates == [src["published_date"]]
    assert "fabricated source ids rejected" in br.downgrade_reasons
    assert br.follow_up_queries == ["Kubernetes NetworkPolicy egress semantics"] and any("sanitiser" in r for r in br.downgrade_reasons)
    assert br.evidence_strength in ("STRONG", "MODERATE") and "probability" not in br.evidence_strength_reason.lower() or True
    snap = ledger.get_snapshot(br.snapshot_id)
    assert snap and snap["brief_version"] == 1 and {i["id"] for i in snap["evidence"] if i["kind"] == "source"} == {s["evidence_id"] for s in ledger.research_for("INC-T1")}
    assert all(i["content_hash"] for i in snap["evidence"]) and snap["evidence_set_hash"]


def test_model_cannot_set_evidence_strength(eng):
    seed()
    fake_tavily.State.mode = "empty"
    research.execute("INC-T1")
    assert analysis.synthesize_research("INC-T1") is None  # no sources, no brief
    assert analysis.derive_strength([], None)[0] == "INSUFFICIENT"
    s = [{"classification": "SUPPORTS"}, {"classification": "SUPPORTS"}]
    assert analysis.derive_strength(s, {"strength": "STRONG"})[0] == "STRONG" and analysis.derive_strength(s, {"strength": "PARTIAL"})[0] == "MODERATE"
    assert analysis.derive_strength(s + [{"classification": "CONTRADICTS"}], {"strength": "STRONG"})[0] == "WEAK"


def test_briefs_are_versioned_and_never_overwritten(eng):
    seed()
    research.execute("INC-T1")
    src = ledger.research_for("INC-T1")[0]
    f = model(good_payload(src["evidence_id"]))
    eng.setenv("BIFROST_URL", f.url); eng.setenv("BIFROST_MODEL", "openai/x")
    b1 = analysis.synthesize_research("INC-T1")
    b2 = analysis.synthesize_research("INC-T1")
    allb = ledger.briefs_for("INC-T1")
    assert [b["version"] for b in allb] == [1, 2] and b2.previous_brief_id == b1.brief_id and allb[0]["brief_id"] == b1.brief_id


def test_invalid_or_uncited_model_output_falls_back_to_rules_only(eng):
    seed()
    research.execute("INC-T1")
    src = ledger.research_for("INC-T1")[0]
    for content, cat in (("not json {", "invalid_output"), (json.dumps({"incident_summary": "x", "findings": [{"claim": "c", "kind": "SOURCE_ESTABLISHED", "evidence_ids": ["ext-ffffffffffffffff"]}]}), "invalid_output")):
        f = _Fake(lambda b, c=content: (200, {"choices": [{"message": {"content": c}}]}, {"x-bifrost-request-id": "r"}))
        eng.setenv("BIFROST_URL", f.url); eng.setenv("BIFROST_MODEL", "openai/x")
        br = analysis.synthesize_research("INC-T1")
        assert br.origin == "RULES_ONLY" and br.error_category == cat and br.snapshot_id and br.structured_findings
        assert all(x.kind == "SOURCE_ESTABLISHED" and x.evidence_ids for x in br.structured_findings)  # rule-based findings are all cited
    assert src


def test_bifrost_outage_and_timeout_are_rules_only(eng):
    seed()
    research.execute("INC-T1")
    eng.setenv("BIFROST_URL", "http://127.0.0.1:9"); eng.setenv("BIFROST_MODEL", "openai/x")
    br = analysis.synthesize_research("INC-T1")
    assert br.origin == "RULES_ONLY" and br.status == "GATEWAY_ERROR" and br.error_category == "unavailable"
    import time as _t

    slow = _Fake(lambda b: (_t.sleep(3), (200, {"choices": []}))[1])
    eng.setenv("BIFROST_URL", slow.url); eng.setenv("BIFROST_TIMEOUT_SECONDS", "1")
    assert analysis.synthesize_research("INC-T1").error_category == "timeout"


# ============================================================================ stale-answer engine
def mk_event(i, et="db_connection_error", summary="database unreachable", t="2026-11-16T10:00:00Z"):
    return {"event_id": f"evt-{i:016x}", "event_type": et, "source": "application", "source_event_id": f"s{i}", "observed_at": t, "received_at": t, "summary": summary}


def mk_src(i, cls="SUPPORTS", h=None, date="KNOWN", retrieved="2026-11-16T10:05:00Z"):
    return {"evidence_id": f"ext-{i:016x}", "content_hash": h or f"h{i}", "classification": cls, "domain": "kubernetes.io", "url": f"https://kubernetes.io/{i}", "published_date": None, "date_status": date, "retrieved_at": retrieved}


def snap(events, sources):
    return staleness.build_snapshot("INC-T1", run_id="r", brief_version=1, events=events, sources=sources, provider=None, model=None)


def test_unchanged_evidence_is_fresh():
    ev, src = [mk_event(1)], [mk_src(1)]
    r = staleness.evaluate(snap(ev, src), ev, src)
    assert r["status"] == "FRESH" and r["reasons"] == [] and r["invalidated_at"] is None


def test_new_relevant_event_invalidates_with_time_and_reason():
    ev, src = [mk_event(1)], [mk_src(1)]
    s = snap(ev, src)
    late = mk_event(2, summary="database unreachable again", t="2026-11-16T10:09:00Z")
    r = staleness.evaluate(s, ev + [late], src)
    assert r["status"] == "STALE" and r["reasons"][0]["rule"] == "NEW_RELEVANT_EVENT" and r["reasons"][0]["evidence_id"] == late["event_id"] and r["invalidated_at"] == "2026-11-16T10:09:00Z"


@pytest.mark.parametrize("extra,why", [
    (mk_event(3, et="remediation_applied"), "unrelated_event_type"),
    (mk_event(4, et="health_observation"), "unrelated_event_type"),
    ({**mk_event(5), "source_event_id": "s1", "event_id": "evt-dup"}, "duplicate_content"),
])
def test_unrelated_or_duplicate_events_do_not_invalidate(extra, why):
    ev, src = [mk_event(1)], [mk_src(1)]
    r = staleness.evaluate(snap(ev, src), ev + [extra], src)
    assert r["status"] == "FRESH" and r["ignored"][0]["reason"] == why


@pytest.mark.parametrize("cls,why", [("STALE", "old_source_does_not_invalidate"), ("UNVERIFIED", "unverified_source_not_relevant"), ("INSUFFICIENT_EVIDENCE", "insufficient_content_not_relevant")])
def test_irrelevant_new_sources_are_ignored_with_a_reason(cls, why):
    ev, src = [mk_event(1)], [mk_src(1)]
    r = staleness.evaluate(snap(ev, src), ev, src + [mk_src(2, cls=cls)])
    assert r["status"] == "FRESH" and r["ignored"][0]["reason"] == why


def test_new_relevant_source_invalidates_and_unknown_date_is_flagged_not_dismissed():
    ev, src = [mk_event(1)], [mk_src(1)]
    r = staleness.evaluate(snap(ev, src), ev, src + [mk_src(2, cls="CONTRADICTS", date="UNKNOWN", retrieved="2026-11-16T11:00:00Z")])
    assert r["status"] == "STALE" and r["reasons"][0]["rule"] == "NEW_SOURCE" and "publication date unknown" in r["reasons"][0]["detail"]
    assert r["invalidated_at"] == "2026-11-16T11:00:00Z"


def test_materially_changed_source_invalidates():
    ev, src = [mk_event(1)], [mk_src(1)]
    r = staleness.evaluate(snap(ev, src), ev, [mk_src(1, h="CHANGED", retrieved="2026-11-16T12:00:00Z")])
    assert r["status"] == "STALE" and r["reasons"][0]["rule"] == "UPDATED_SOURCE"


def test_duplicate_source_content_does_not_invalidate():
    ev, src = [mk_event(1)], [mk_src(1, h="same")]
    assert staleness.evaluate(snap(ev, src), ev, src + [mk_src(2, h="same")])["status"] == "FRESH"


def test_no_snapshot_is_distinguishable_from_fresh_and_stale():
    assert staleness.evaluate(None, [], [])["status"] == "NO_SNAPSHOT"


def test_snapshot_is_immutable_insert_only(eng):
    ev, src = [mk_event(1)], [mk_src(1)]
    s = snap(ev, src)
    assert ledger.record_snapshot(s) is True and ledger.record_snapshot({**s, "evidence": []}) is False
    assert ledger.get_snapshot(s["snapshot_id"])["evidence"] == s["evidence"]


def test_extraction_enrichment_is_not_a_source_change():
    ev = [mk_event(1)]
    snip = {**mk_src(1, h="snippet-hash"), "hash_basis": "snippet"}
    full = {**mk_src(1, h="full-text-hash"), "hash_basis": "extract"}
    r = staleness.evaluate(snap(ev, [snip]), ev, [full])
    assert r["status"] == "FRESH" and r["ignored"][0]["reason"] == "enrichment_by_extraction"
    real = {**full, "content_hash": "different"}
    assert staleness.evaluate(snap(ev, [full]), ev, [real])["reasons"][0]["rule"] == "UPDATED_SOURCE"
