"""Evidence workspace: normalisation, Pathway-over-NATS, Bifrost gateway, Tavily, analysis safety, approval safety.

Provider tests here use local contract fakes (MOCK). They never count as live-provider verification.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from beacon import analysis, approvals, incident_flow, research
from beacon.evidence import ledger, normalize
from beacon.evidence.contracts import Correlation, iso, now_utc
from beacon.llm import gateway
from beacon.remediation import guard

NS_TABLES = ("NS_EVENTS_TABLE", "NS_CORRELATIONS_TABLE", "NS_RESEARCH_TABLE", "NS_ANALYSES_TABLE", "NS_TRACE_TABLE", "NS_PAYLOADS_TABLE")


@pytest.fixture()
def ns(tables, monkeypatch):
    sfx = uuid.uuid4().hex[:8]
    for n in NS_TABLES:
        monkeypatch.setenv(n, f"t_{n.lower()}_{sfx}")
    return tables


def _audit(aid="a-1", ts="2026-11-16T10:00:00.000000Z", user="alice", name="demo-db-ingress"):
    return {"auditID": aid, "stage": "ResponseComplete", "verb": "patch", "user": {"username": user}, "objectRef": {"resource": "networkpolicies", "namespace": "demo", "name": name}, "responseStatus": {"code": 200}, "stageTimestamp": ts, "requestURI": "/x"}


def _corr(cid_event, ids, ns="demo"):
    return Correlation(correlation_id="cor-1", incident_id="INC-T1", rule="r", change_event_id=cid_event, included_event_ids=ids, symptom_types=["alert_firing"], namespace=ns, resource="demo/demo-db-ingress", target_app="demo-db", window_start=iso(now_utc()), window_end=iso(now_utc()), window_seconds=600, strength="PARTIAL", explanation="x", processed_at=iso(now_utc()))


# ---- normalisation / ingestion -------------------------------------------------
def test_audit_event_keeps_source_id_and_timestamp_and_is_idempotent(ns):
    ev = normalize.from_audit(_audit())
    assert ev and ev.source_event_id == "a-1" and ev.observed_at == "2026-11-16T10:00:00.000000Z"
    assert ledger.record_event(ev) is True and ledger.record_event(ev) is False  # duplicate delivery


def test_remediator_write_is_not_a_new_change_to_correlate():
    ev = normalize.from_audit(_audit(user="system:serviceaccount:beacon:beacon-remediator"))
    assert ev and ev.event_type == "remediation_applied"


def test_only_connection_errors_become_events_and_secrets_are_redacted():
    assert normalize.from_app_log({"id": "1", "ts": "2026-11-16T10:00:01Z", "namespace": "demo", "line": "all good"}) is None
    ev = normalize.from_app_log({"id": "2", "ts": "2026-11-16T10:00:01Z", "namespace": "demo", "app": "api", "line": "database unreachable at demo-db:6379"})
    assert ev and ev.resource.target_app == "demo-db"
    assert "[redacted]" in normalize.redact_payload({"authorization": "Bearer abc", "x": 1})


def test_ingest_endpoints_reject_unauthorised(client):
    assert client.post("/ingest/app-logs", json={"records": []}).status_code == 401
    assert client.post("/k8s/audit", json={"items": []}).status_code == 401


def test_ingest_without_bus_persists_directly_and_correlation_ignores_unknown_change(ns):
    from beacon import ingest

    ev = normalize.from_audit(_audit("a-2"))
    asyncio.run(ingest.publish_event(ev))  # NATS_URL unset in tests -> direct
    assert ledger.get_event(ev.event_id)
    stale = _corr("evt-missing", ["evt-missing"])
    asyncio.run(ingest.on_correlation({**stale.model_dump(), "diff": 1}))
    assert ledger.correlations_for("INC-T1") == []


# ---- analysis safety -------------------------------------------------------------
def _bundle():
    return {"ids": {"e1", "e2", "x1"}, "event_ids": {"e1", "e2"}, "external_ids": {"x1"}}


def _good(**over):
    d = {"incident_summary": "s", "root_cause_hypothesis": "h", "supporting_event_ids": ["e1"], "what_is_confirmed": [{"text": "c", "evidence_ids": ["e1"]}], "what_is_unknown": ["u"], "recommended_action_id": "networkpolicy.restore_ingress", "reasoning_summary": "r", "risk_summary": "k", "requires_human_approval": False}
    return {**d, **over}


def test_invented_ids_are_stripped_and_uncited_claims_dropped():
    s, why = analysis.validate(_good(supporting_event_ids=["e1", "ghost"], what_is_confirmed=[{"text": "c", "evidence_ids": ["ghost"]}]), _bundle())
    assert s and s.supporting_event_ids == ["e1"] and s.what_is_confirmed == [] and why


def test_model_cannot_skip_approval_or_name_unlisted_action():
    s, _ = analysis.validate(_good(recommended_action_id="kubectl delete ns demo"), _bundle())
    assert s and s.recommended_action_id is None and s.requires_human_approval is True


def test_all_invented_evidence_is_rejected_for_rules_only():
    s, why = analysis.validate(_good(supporting_event_ids=["ghost"]), _bundle())
    assert s is None and "no valid supporting event ids" in why


# ---- Bifrost gateway (contract fake) ----------------------------------------------
class _Fake:
    def __init__(self, handler):
        self.seen: list[dict[str, Any]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.seen.append({"headers": dict(self.headers), "body": body, "path": self.path})
                code, payload = handler(body)
                raw = json.dumps(payload).encode()
                self.send_response(code); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(raw)

            def log_message(self, *a): pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()


@pytest.fixture()
def bifrost(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("BIFROST_MODEL", "anthropic/test")
    return monkeypatch


def test_gateway_sends_trace_headers_and_copies_only_returned_metadata(bifrost):
    f = _Fake(lambda b: (200, {"id": "req-9", "model": "m", "choices": [{"message": {"content": "{}"}}], "usage": {"total_tokens": 5}, "extra_fields": {"provider": "anthropic", "latency": 120}}))
    bifrost.setenv("BIFROST_URL", f.url)
    r = gateway.chat([{"role": "user", "content": "x"}], meta={"incident_id": "INC-1", "workflow_stage": "analysis", "evidence_set": "abc"})
    h = {k.lower(): v for k, v in f.seen[0]["headers"].items()}
    assert h["x-bf-lh-incident-id"] == "INC-1" and h["x-bf-lh-evidence-set"] == "abc"
    assert r.request_id == "req-9" and r.provider == "anthropic" and r.latency_ms == 120 and r.usage == {"total_tokens": 5}
    assert r.cost is None  # never invented


@pytest.mark.parametrize("code,cat", [(429, "rate_limited"), (401, "auth"), (500, "provider_error")])
def test_gateway_error_categories(bifrost, code, cat):
    f = _Fake(lambda b: (code, {"error": "x"}))
    bifrost.setenv("BIFROST_URL", f.url)
    with pytest.raises(gateway.GatewayError) as e:
        gateway.chat([], meta={})
    assert e.value.category == cat


def test_gateway_unavailable_and_unconfigured(bifrost):
    bifrost.setenv("BIFROST_URL", "http://127.0.0.1:9")
    with pytest.raises(gateway.GatewayError) as e:
        gateway.chat([], meta={})
    assert e.value.category == "unavailable"
    bifrost.delenv("BIFROST_URL")
    with pytest.raises(gateway.GatewayError) as e:
        gateway.chat([], meta={})
    assert e.value.category == "not_configured"


def _seed_incident(ns_):
    ev = normalize.from_audit(_audit("a-3"))
    ledger.record_event(ev)
    ledger.record_correlation(_corr(ev.event_id, [ev.event_id]))
    return ev


def test_analyze_downgrades_to_rules_only_on_invalid_output_and_on_outage(ns, bifrost):
    ev = _seed_incident(ns)
    f = _Fake(lambda b: (200, {"id": "r", "choices": [{"message": {"content": "not json"}}]}))
    bifrost.setenv("BIFROST_URL", f.url)
    a = analysis.analyze("INC-T1")
    assert a.origin == "RULES_ONLY" and a.status == "DOWNGRADED" and a.error_category == "invalid_output" and a.structured
    bifrost.setenv("BIFROST_URL", "http://127.0.0.1:9")
    assert analysis.analyze("INC-T1").status == "GATEWAY_ERROR"
    good = _good(supporting_event_ids=[ev.event_id], what_is_confirmed=[{"text": "c", "evidence_ids": [ev.event_id]}])
    f2 = _Fake(lambda b: (200, {"id": "r2", "model": "m", "choices": [{"message": {"content": json.dumps(good)}}]}))
    bifrost.setenv("BIFROST_URL", f2.url)
    b = analysis.analyze("INC-T1")
    assert b.origin == "BIFROST_MODEL" and b.bifrost_request_id == "r2" and b.structured.requires_human_approval is True


def test_no_module_bypasses_the_gateway():
    import pathlib
    import re

    root = pathlib.Path(__file__).parents[1] / "src" / "beacon"
    offenders = [p.name for p in root.rglob("*.py") if p.name != "gateway.py" and re.search(r"litellm\.completion\(", p.read_text())]
    assert offenders == []


# ---- Tavily (contract fake) ---------------------------------------------------------
def test_research_preserves_provenance_and_unknown_dates(ns, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    def handler(b):
        if "urls" in b:
            return 200, {"results": [{"url": "https://kubernetes.io/docs/concepts/services-networking/network-policies/", "raw_content": "full page"}]}
        return 200, {"results": [{"title": "Network Policies", "url": "https://kubernetes.io/docs/concepts/services-networking/network-policies/", "content": "By default, a pod is non-isolated for ingress... isolated pods ingress default deny", "score": 0.91}, {"title": "blog", "url": "https://example.com/x", "content": "something", "score": 0.5}]}
    f = _Fake(handler)
    monkeypatch.setenv("TAVILY_API_URL", f.url); monkeypatch.setenv("TAVILY_API_KEY", "tvly-test")
    items = research.run("INC-T1", {}, {"symptom_types": ["db_connection_error"], "target_app": "demo-db"})
    k8s = next(i for i in items if "kubernetes.io" in i.url)
    assert k8s.published_date is None and k8s.updated_date is None and k8s.score == 0.91
    assert k8s.classification == "SUPPORTS" and k8s.extraction_status == "OK"
    assert next(i for i in items if "example.com" in i.url).classification == "UNVERIFIED"
    assert f.seen[0]["headers"]["Authorization"] == "Bearer tvly-test"
    assert len(ledger.research_for("INC-T1")) == len(items)


@pytest.mark.parametrize("code,cat", [(429, "rate_limited"), (401, "auth")])
def test_research_errors_are_categorised(monkeypatch, code, cat):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    f = _Fake(lambda b: (code, {}))
    monkeypatch.setenv("TAVILY_API_URL", f.url); monkeypatch.setenv("TAVILY_API_KEY", "k")
    with pytest.raises(research.ResearchError) as e:
        research.run("INC-T1", {}, {"symptom_types": []})
    assert e.value.category == cat


# ---- sandbox guard ---------------------------------------------------------------------
def test_guard_refuses_outside_sandbox(monkeypatch):
    monkeypatch.setenv("SIMULATOR_URL", "http://x")
    monkeypatch.setenv("SANDBOX_CONTEXTS", "demo-simulator")
    monkeypatch.setenv("REMEDIABLE_NAMESPACES", "demo,prod")
    assert guard.sandbox_error({"namespace": "demo"}) is None
    monkeypatch.setenv("SANDBOX_NAMESPACES", "demo")
    assert "outside the sandbox" in guard.sandbox_error({"namespace": "prod"})
    monkeypatch.setenv("SANDBOX_CONTEXTS", "some-other-context")
    assert "not in SANDBOX_CONTEXTS" in guard.sandbox_error({"namespace": "demo"})
    monkeypatch.delenv("SANDBOX_CONTEXTS"); monkeypatch.setenv("REQUIRE_SANDBOX", "true")
    assert "not configured" in guard.sandbox_error({"namespace": "demo"})


# ---- approval safety ----------------------------------------------------------------------
PARAMS = {"namespace": "demo", "name": "demo-db-ingress", "from_app": "demo-api", "port": 6379, "protocol": "TCP"}


@pytest.fixture()
def proposal(ns, monkeypatch):
    started: list[dict] = []
    monkeypatch.setattr(incident_flow.workflows, "start_remediation", lambda p: started.append(p) or "exec-1")
    monkeypatch.setenv("REMEDIATION_MODE", "inline")
    from beacon import store
    from beacon.events import TriggerInfo, TriggerType

    iid = store.put_incident("", TriggerInfo(TriggerType.ALARM, alarm_name="A"), table_name=ns["INCIDENTS_TABLE_NAME"])
    p = approvals.create_proposal(iid, 1, "networkpolicy.restore_ingress", PARAMS, blast_radius="b", dry_run={"ok": True}, table_name=ns["APPROVALS_TABLE_NAME"])
    return iid, p, started


def _approve(iid, p, **kw):
    base = dict(typed_phrase="approve fix 1", params_hash=p["params_hash"], user="alice", idempotency_key="k1", authenticated=True)
    out = incident_flow.approve(iid, 1, **{**base, **kw})
    time.sleep(0.2)
    return out


def test_approval_refusals_never_start_execution(proposal):
    iid, p, started = proposal
    assert _approve(iid, p, authenticated=False)[0] == 401
    assert _approve(iid, p, typed_phrase="yes please")[0] == 422
    assert _approve(iid, p, params_hash="changed")[0] == 409
    assert _approve(iid, p, idempotency_key="")[0] == 400
    assert started == []


def test_approval_is_bound_idempotent_and_executes_once(proposal):
    iid, p, started = proposal
    code, out = _approve(iid, p)
    assert code == 202 and out["approved"]
    assert _approve(iid, p)[0] == 200  # same key: replay
    assert _approve(iid, p, idempotency_key="k2")[0] == 409  # different request
    assert len(started) == 1 and started[0]["action"] == "networkpolicy.restore_ingress"
    from beacon import db
    rec = db.get(os.environ["APPROVALS_TABLE_NAME"], out["approval_id"])
    assert rec["attestation"]["evidence"] == "typed_console" and rec["attestation"]["params_hash"] == p["params_hash"]


def test_cancelled_or_expired_proposal_cannot_be_approved(proposal):
    iid, p, started = proposal
    assert incident_flow.cancel(iid, 1, user="alice")[0] == 200
    assert _approve(iid, p)[0] == 410 and started == []


def test_apply_disabled_blocks_approval(proposal, monkeypatch):
    iid, p, started = proposal
    monkeypatch.setenv("APPLY_ENABLED", "false")
    assert _approve(iid, p)[0] == 409 and started == []


def test_verified_requires_all_three_independent_check_groups():
    def attempt(ok_app):
        checks = [{"name": "alarm_ok_after_fix", "ok": True}, {"name": "metric_zero", "ok": True}, {"name": "postcondition", "ok": True}, {"name": "app_health", "ok": ok_app}]
        return [{"t": "t", "event": "verify_attempt", "detail": {"checks": checks}}]
    good = incident_flow.verification_view(attempt(True))
    bad = incident_flow.verification_view(attempt(False))
    assert incident_flow.lifecycle({"status": "resolved", "timeline": []}, True, [], good) == "VERIFIED"
    assert incident_flow.lifecycle({"status": "resolved", "timeline": []}, True, [], bad) == "VERIFICATION_FAILED"
    assert incident_flow.lifecycle({"status": "remediating", "timeline": [{"event": "executed"}]}, True, [], {"all_passed": True}) == "VERIFYING"


# ---- Pathway over real NATS ----------------------------------------------------------------
def _nats_up() -> bool:
    import socket
    try:
        socket.create_connection(("127.0.0.1", 4222), 0.5).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _nats_up(), reason="NATS JetStream not running (see make demo-up)")
def test_pathway_correlates_over_nats_with_dedup_late_arrival_and_isolation():
    from beacon import eventbus
    from beacon.evidence.contracts import (
        EventType,
        NightShiftEvent,
        Resource,
        stable_id,
    )

    tag = uuid.uuid4().hex[:6]
    nsname = f"pw{tag}"
    env = {**os.environ, "NATS_URL": "nats://127.0.0.1:4222", "CORRELATOR_PORT": "9187"}
    proc = subprocess.Popen([sys.executable, "-m", "beacon.correlator"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def ev(src, sid, et, ts, namespace, target="", name="x"):
        return NightShiftEvent(event_id=stable_id("evt", src, sid), source=src, source_event_id=sid, event_type=et, observed_at=ts, received_at=iso(now_utc()), resource=Resource(namespace=namespace, name=name, target_app=target), source_mode="DEMO_SIMULATOR").model_dump(mode="json")

    async def run() -> list[dict]:
        os.environ["NATS_URL"] = "nats://127.0.0.1:4222"
        nc, js = await eventbus.connect()
        sub = await js.pull_subscribe("beacon.correlations", durable=f"t{tag}", stream="BEACON")
        pub = lambda e: js.publish("beacon.events", json.dumps(e).encode())  # noqa: E731
        await asyncio.sleep(8)  # correlator start-up
        change = ev("kubernetes", f"c-{tag}", EventType.NETPOL_CHANGE, "2026-11-16T10:00:00.000000Z", nsname, "demo-db", "demo-db-ingress")
        await pub(ev("prometheus", f"p-{tag}", EventType.ALERT_FIRING, "2026-11-16T10:00:30.000000Z", nsname))  # symptom BEFORE its change arrives
        await pub(change); await pub(change)  # duplicate delivery
        await pub(ev("application", f"l-{tag}", EventType.APP_ERROR, "2026-11-16T10:00:40.000000Z", nsname, "demo-db"))
        await pub(ev("application", f"u-{tag}", EventType.APP_ERROR, "2026-11-16T10:00:41.000000Z", f"other{tag}", "demo-db"))  # unrelated namespace
        await pub(ev("application", f"o-{tag}", EventType.APP_ERROR, "2026-11-16T10:00:42.000000Z", nsname, "some-other-db"))  # different dependency
        out: list[dict] = []
        end = time.time() + 40
        while time.time() < end:
            try:
                for m in await sub.fetch(10, timeout=2):
                    d = json.loads(m.data)
                    await m.ack()
                    if d["namespace"] == nsname and d["diff"] == 1:
                        out.append(d)
            except Exception:
                pass
            if out and {t for d in out for t in d["symptom_types"]} == {"alert_firing", "db_connection_error"}:
                break
        await nc.close()
        return out

    try:
        out = asyncio.run(run())
    finally:
        proc.terminate()
    assert out, "no Pathway output"
    # the backend merges monotonically, so the union over all emitted rows is the persisted evidence set
    ids = list(dict.fromkeys(i for d in out for i in d["included_event_ids"]))
    assert len(ids) == 3  # change + alert + one matching log; duplicate / unrelated namespace / other dependency excluded
    assert stable_id("evt", "kubernetes", f"c-{tag}") in ids and {t for d in out for t in d["symptom_types"]} == {"alert_firing", "db_connection_error"}
