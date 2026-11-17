"""Phase IV: authenticated reads, shared rate limiting, signed one-time consent, concurrency, barge-in, chaos refusals."""

from __future__ import annotations

import threading
import time
import uuid

import pytest

from beacon import approvals, auth, consent, db, incident_flow, store
from beacon.events import TriggerInfo, TriggerType
from tests.conftest import PASS

PARAMS = {"namespace": "demo", "name": "demo-db-ingress", "from_app": "demo-api", "port": 6379, "protocol": "TCP"}


@pytest.fixture(autouse=True)
def _iso(monkeypatch):
    sfx = uuid.uuid4().hex[:8]
    for n in ("NS_SESSIONS_TABLE", "NS_AUTH_FAILURES_TABLE", "NS_SECRETS_TABLE"):
        monkeypatch.setenv(n, f"t_{n.lower()}_{sfx}")
    auth.reset_rate_limits()


@pytest.fixture()
def prop(tables, client, monkeypatch):
    started: list[dict] = []
    monkeypatch.setattr(incident_flow.workflows, "start_remediation", lambda p: (time.sleep(0.05), started.append(p), "x")[2])
    iid = store.put_incident("", TriggerInfo(TriggerType.ALARM, alarm_name="A"), table_name=tables["INCIDENTS_TABLE_NAME"])
    p = approvals.create_proposal(iid, 1, "networkpolicy.restore_ingress", PARAMS, blast_radius="b", dry_run={"ok": True}, table_name=tables["APPROVALS_TABLE_NAME"])
    return iid, p, started, tables


def body(p, key="k1"):
    return {"typed_phrase": "approve fix 1", "params_hash": p["params_hash"], "idempotency_key": key}


# ---------------------------------------------------------------- authenticated reads
@pytest.mark.parametrize("path", ["/api/ns/incidents", "/api/ns/events/recent", "/api/ns/incidents/INC-X", "/api/ns/incidents/INC-X/report", "/api/ns/incidents/INC-X/stream", "/api/ns/stream"])
def test_workspace_reads_require_authentication(client, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"x-beacon-passcode": "wrong"}).status_code == 401


def test_authenticated_reads_work_with_session_cookie_and_header(client):
    assert client.get("/api/ns/incidents", headers=PASS).status_code == 200
    login = client.post("/api/auth/login", json={"passcode": "test-pass"})
    assert login.status_code == 200
    assert client.get("/api/ns/incidents").status_code == 200  # cookie alone is enough for reads


def test_the_browser_bundle_never_stores_or_embeds_a_credential():
    import pathlib

    web = pathlib.Path(__file__).parents[1] / "web" / "src"
    offenders = [p.name for p in web.rglob("*.ts*") if p.name != "hooks.ts" and "localStorage" in p.read_text() and "passcode" in p.read_text().lower()]
    assert offenders == []
    app = (web / "App.tsx").read_text()
    assert 'useLocalState("beacon.passcode"' not in app and "window.prompt" not in app.split("onSummarise")[1][:900]
    for needle in ("test-pass", "od-test-key", "tvly-test-key", "sk-local-upstream"):
        assert needle not in "".join(p.read_text() for p in web.rglob("*.ts*"))


# ---------------------------------------------------------------- rate limit shared via the database
def test_rate_limit_lives_in_the_database_so_it_holds_across_processes(client):
    for _ in range(5):
        assert client.post("/api/auth/login", json={"passcode": "x"}).status_code == 401
    row = db.get(auth._fail_table(), "testclient")
    assert row and len(row["times"]) == 5  # state is in PostgreSQL, not in this process
    assert auth._blocked("testclient") is True  # any other process reading the same table is blocked too
    assert client.post("/api/auth/login", json={"passcode": "test-pass"}).status_code == 429


def test_concurrent_failures_are_all_counted():
    ts = [threading.Thread(target=auth._fail, args=("10.0.0.9",)) for _ in range(25)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(db.get(auth._fail_table(), "10.0.0.9")["times"]) == 25


def test_old_failures_age_out(monkeypatch):
    monkeypatch.setenv("LOGIN_FAILURE_WINDOW_SECONDS", "1")
    for _ in range(5):
        auth._fail("1.2.3.4")
    assert auth._blocked("1.2.3.4")
    time.sleep(1.2)
    assert not auth._blocked("1.2.3.4")


# ---------------------------------------------------------------- voice credentials are not approval credentials
def test_voice_tool_token_cannot_approve_or_read_the_workspace(client, prop):
    iid, p, started, _ = prop
    tool = {"authorization": "Bearer tool-token"}
    url = f"/api/ns/incidents/{iid}/proposals/1/approve"
    assert client.post(url, json=body(p), headers=tool).status_code == 401
    assert client.post(url, json=body(p), headers={"x-beacon-passcode": "tool-token"}).status_code == 401
    assert client.get("/api/ns/incidents", headers=tool).status_code == 401
    assert started == []


# ---------------------------------------------------------------- signed one-time consent
def test_consent_record_is_signed_and_tampering_is_detected(client, prop):
    iid, p, started, tables = prop
    r = client.post(f"/api/ns/incidents/{iid}/proposals/1/approve", json=body(p), headers=PASS)
    assert r.status_code == 202
    time.sleep(0.2)
    rec = db.get(tables["APPROVALS_TABLE_NAME"], r.json()["approval_id"])
    assert rec["consent_signature"]["alg"] == "HMAC-SHA256" and rec["consent"]["principal"] == "LOCAL_DEMO_OPERATOR"
    assert consent.verify(rec["consent"], rec["consent_signature"]) is True
    for field, val in (("principal", "CTO-Alice"), ("params_hash", "0" * 64), ("granted_at", "2000-01-01T00:00:00+00:00"), ("auth_method", "SSO")):
        assert consent.verify({**rec["consent"], field: val}, rec["consent_signature"]) is False
    assert "consent_key" not in str(rec) and consent._key()  # the key itself is never stored on the approval


def test_signature_needs_the_server_key(monkeypatch):
    rec = {"incident_id": "i", "principal": "p"}
    monkeypatch.setenv("CONSENT_SIGNING_KEY", "key-one")
    sig = consent.sign(rec)
    monkeypatch.setenv("CONSENT_SIGNING_KEY", "key-two")
    assert consent.verify(rec, sig) is False


# ---------------------------------------------------------------- concurrency / replay
def test_concurrent_approvals_execute_exactly_once(client, prop):
    iid, p, started, _ = prop
    codes: list[int] = []
    lock = threading.Lock()

    def go(i):
        r = client.post(f"/api/ns/incidents/{iid}/proposals/1/approve", json=body(p, f"key-{i}"), headers=PASS)
        with lock:
            codes.append(r.status_code)

    ts = [threading.Thread(target=go, args=(i,)) for i in range(10)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    time.sleep(0.5)
    assert codes.count(202) == 1 and set(codes) <= {202, 409} and len(started) == 1


def test_replayed_request_with_the_same_key_does_not_execute_again(client, prop):
    iid, p, started, _ = prop
    url = f"/api/ns/incidents/{iid}/proposals/1/approve"
    assert client.post(url, json=body(p), headers=PASS).status_code == 202
    for _ in range(3):
        assert client.post(url, json=body(p), headers=PASS).status_code == 200  # idempotent replay
    time.sleep(0.4)
    assert len(started) == 1


def test_modified_params_hash_expired_and_cancelled_proposals_are_refused(client, prop):
    iid, p, started, tables = prop
    url = f"/api/ns/incidents/{iid}/proposals/1/approve"
    assert client.post(url, json={**body(p), "params_hash": "f" * 64}, headers=PASS).status_code == 409
    db.patch(tables["APPROVALS_TABLE_NAME"], p["approval_id"], {"expires_at": "2000-01-01T00:00:00+00:00"})
    assert client.post(url, json=body(p), headers=PASS).status_code == 410
    assert started == []


# ---------------------------------------------------------------- barge-in
def test_voice_interruption_cancels_the_proposal_and_nothing_can_execute_later(client, prop):
    iid, p, started, tables = prop
    out = client.post("/voice/tools/cancel_proposal", json={"incident_id": iid, "channel": "console", "args": {"fix_id": 1, "reason": "engineer said stop"}}, headers=PASS)
    assert out.status_code == 200 and out.json()["result"]["withdrawn"] is True
    inc = store.get_incident(iid, table_name=tables["INCIDENTS_TABLE_NAME"])
    assert "proposal_withdrawn" in [e["event"] for e in inc["timeline"]]  # the cancellation is persisted
    r = client.post(f"/api/ns/incidents/{iid}/proposals/1/approve", json=body(p), headers=PASS)
    assert r.status_code == 410 and started == []
    time.sleep(0.2)
    assert incident_flow.lifecycle(store.get_incident(iid, table_name=tables["INCIDENTS_TABLE_NAME"]), True, [], {"all_passed": False}) == "CANCELLED"


# ---------------------------------------------------------------- lifecycle honesty
def test_final_states_are_distinguished():
    base = {"status": "remediating", "timeline": []}
    assert incident_flow.lifecycle({**base, "timeline": [{"event": "approved"}, {"event": "executing"}, {"event": "execute_failed"}]}, True, [], {}) == "EXECUTION_FAILED"
    assert incident_flow.lifecycle({"status": "escalated", "timeline": [{"event": "executed"}]}, True, [], {}) == "ESCALATED"
    assert incident_flow.lifecycle({"status": "resolved", "timeline": [{"event": "executed"}]}, True, [], {"all_passed": False}) == "VERIFICATION_FAILED"
    assert incident_flow.lifecycle({"status": "resolved", "timeline": [{"event": "executed"}]}, True, [], {"all_passed": True}) == "VERIFIED"
    assert incident_flow.lifecycle({"status": "awaiting_engineer", "timeline": [{"event": "proposal_cancelled"}]}, True, [], {}) == "CANCELLED"
