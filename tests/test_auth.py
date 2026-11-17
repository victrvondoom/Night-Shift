"""Approver identity and session security."""

import uuid

import pytest

from beacon import approvals, auth, db, incident_flow, store
from beacon.events import TriggerInfo, TriggerType
from tests.conftest import PASS

PARAMS = {"namespace": "demo", "name": "demo-db-ingress", "from_app": "demo-api", "port": 6379, "protocol": "TCP"}


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.setenv("NS_SESSIONS_TABLE", f"t_sessions_{uuid.uuid4().hex[:8]}")
    auth.reset_rate_limits()
    yield
    auth.reset_rate_limits()


@pytest.fixture()
def prop(tables, client, monkeypatch):
    started = []
    monkeypatch.setattr(incident_flow.workflows, "start_remediation", lambda p: started.append(p) or "x")
    iid = store.put_incident("", TriggerInfo(TriggerType.ALARM, alarm_name="A"), table_name=tables["INCIDENTS_TABLE_NAME"])
    p = approvals.create_proposal(iid, 1, "networkpolicy.restore_ingress", PARAMS, blast_radius="b", dry_run={"ok": True}, table_name=tables["APPROVALS_TABLE_NAME"])
    return iid, p, started, tables


def _body(p, key="k1"):
    return {"typed_phrase": "approve fix 1", "params_hash": p["params_hash"], "idempotency_key": key}


def test_forged_user_header_cannot_choose_the_recorded_approver(client, prop):
    iid, p, started, tables = prop
    r = client.post(f"/api/ns/incidents/{iid}/proposals/1/approve", json=_body(p), headers={**PASS, "x-beacon-user": "CTO-Alice"})
    assert r.status_code == 202
    rec = db.get(tables["APPROVALS_TABLE_NAME"], r.json()["approval_id"])
    assert rec["attestation"]["user"] == "LOCAL_DEMO_OPERATOR" and "Alice" not in str(rec)
    assert rec["attestation"]["auth_method"] == "LOCAL_PASSCODE_HEADER" and rec["attestation"]["verified_human_identity"] is False


def test_unauthenticated_and_wrong_passcode_approvals_fail(client, prop):
    iid, p, started, _ = prop
    url = f"/api/ns/incidents/{iid}/proposals/1/approve"
    assert client.post(url, json=_body(p)).status_code == 401
    assert client.post(url, json=_body(p), headers={"x-beacon-passcode": "nope"}).status_code == 401
    assert started == []


def test_login_cookie_flags_csrf_and_logout(client, prop):
    iid, p, started, tables = prop
    bad = client.post("/api/auth/login", json={"passcode": "wrong"})
    assert bad.status_code == 401 and "set-cookie" not in bad.headers
    ok = client.post("/api/auth/login", json={"passcode": "test-pass"})
    assert ok.status_code == 200
    cookie = ok.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert "test-pass" not in ok.text and "test-pass" not in cookie  # the passcode is never echoed or stored in the cookie
    url = f"/api/ns/incidents/{iid}/proposals/1/approve"
    assert client.post(url, json=_body(p)).status_code == 401  # cookie but no CSRF token
    csrf = ok.json()["csrf_token"]
    r = client.post(url, json=_body(p), headers={"x-csrf-token": csrf, "x-beacon-user": "root"})
    assert r.status_code == 202
    rec = db.get(tables["APPROVALS_TABLE_NAME"], r.json()["approval_id"])
    assert rec["attestation"]["auth_method"] == "LOCAL_PASSCODE" and rec["attestation"]["session"]
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_expired_session_fails(client, prop):
    iid, p, _, _ = prop
    ok = client.post("/api/auth/login", json={"passcode": "test-pass"})
    for row in db.scan(auth._table()):
        db.patch(auth._table(), row["sid"], {"expires_at": "2000-01-01T00:00:00+00:00"})
    r = client.post(f"/api/ns/incidents/{iid}/proposals/1/approve", json=_body(p), headers={"x-csrf-token": ok.json()["csrf_token"]})
    assert r.status_code == 401


def test_failed_passcodes_are_rate_limited(client):
    for _ in range(5):
        assert client.post("/api/auth/login", json={"passcode": "x"}).status_code == 401
    assert client.post("/api/auth/login", json={"passcode": "x"}).status_code == 429
    assert client.post("/api/auth/login", json={"passcode": "test-pass"}).status_code == 429  # even the right one while blocked
    assert client.get("/api/ns/incidents/x/report", headers=PASS).status_code == 401  # a blocked client is refused everywhere (fail closed)


def test_workspace_does_not_use_local_storage_for_the_passcode():
    import pathlib

    src = pathlib.Path(__file__).parents[1] / "web/src/workspace/Workspace.tsx"
    assert "localStorage" not in src.read_text()
