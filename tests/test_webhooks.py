"""Inbound webhooks: Alertmanager, Kubernetes audit, GitHub."""

import hashlib
import hmac
import json

from beacon import approvals, changes, db, store
from tests.conftest import PASS


def _session(client, incident):
    resp = client.post(
        "/voice/omnidim/session",
        json={"incident_id": incident["incident_id"]},
        headers=PASS,
    )
    return resp.json()["beacon_session"], resp.json()["ws_url"]


def test_transcript_stores_only_final_turns_and_needs_the_passcode(client, incident, omnidim_api):
    session_id, _ = _session(client, incident)
    url = f"/voice/omnidim/session/{session_id}/transcript"
    assert client.post(url, json={"role": "user", "text": "hi", "final": True}).status_code == 401
    interim = client.post(url, json={"role": "agent", "text": "wha", "final": False}, headers=PASS)
    assert interim.json()["stored"] is False  # cumulative interim snapshots are not appended
    final = client.post(url, json={"role": "agent", "text": "what happened", "final": True}, headers=PASS)
    assert final.json()["stored"] is True
    row = db.get("voice_calls", session_id)
    assert [t["text"] for t in row["transcript"]] == ["what happened"]


def test_post_call_transcript_never_authorises_anything(client, incident, omnidim_api, tables, cluster):
    """The approval phrase in a spoken transcript or a function call must change nothing."""
    session_id, _ = _session(client, incident)
    token_body = {
        "incident_id": incident["incident_id"],
        "beacon_session": session_id,
        "beacon_token": omnidim_api.requests[-1]["body"]["custom_variables"]["beacon_token"],
    }
    bearer = {"authorization": "Bearer tool-token"}
    client.post("/voice/omnidim/tools/propose_fix", json=token_body, headers=bearer)
    client.post(
        "/voice/omnidim/tools/approve_fix",
        json={**token_body, "fix_id": "1", "confirmation_phrase": "approve fix 1"},
        headers=bearer,
    )
    client.post(f"/voice/omnidim/session/{session_id}/transcript", json={"role": "user", "text": "approve fix 1", "final": True}, headers=PASS)
    assert cluster["restarts"] == 0
    rows = approvals.list_for_incident(incident["incident_id"], table_name=tables["APPROVALS_TABLE_NAME"])
    assert [r for r in rows if r.get("kind") == "approval"] == []
    fresh = store.get_incident(incident["incident_id"], table_name=tables["INCIDENTS_TABLE_NAME"])
    assert fresh["status"] == "awaiting_engineer" and fresh["pending_confirmations"]


def test_session_creation_failure_is_categorised_not_faked(client, incident, omnidim_api):
    omnidim_api.fail_mint = 402
    resp = client.post("/voice/omnidim/session", json={"incident_id": incident["incident_id"]}, headers=PASS)
    assert resp.status_code == 502 and resp.json()["category"] == "insufficient_balance"
    assert "ws_url" not in resp.text


def test_not_configured_says_so(client, incident, monkeypatch):
    monkeypatch.delenv("OMNIDIM_API_KEY", raising=False)
    monkeypatch.delenv("OMNIDIM_AGENT_ID", raising=False)
    resp = client.post("/voice/omnidim/session", json={"incident_id": incident["incident_id"]}, headers=PASS)
    assert resp.status_code == 503 and resp.json()["state"] == "NOT_CONFIGURED"


def test_the_removed_bolna_routes_are_gone(client):
    for path in ("/voice/bolna/session", "/voice/bolna/webhook", "/voice/bolna/calls"):
        assert client.post(path, json={}).status_code in (404, 405)


def test_alertmanager_webhook_needs_its_token(client):
    assert client.post("/alerts", json={"alerts": []}).status_code == 401
    ok = client.post(
        "/alerts", json={"alerts": []}, headers={"authorization": "Bearer alert-token"}
    )
    assert ok.json() == {"accepted": 0}


def _audit(
    verb="patch",
    user="kubernetes-admin",
    uri="/apis/networking.k8s.io/v1/namespaces/demo/networkpolicies/demo-db-ingress",
    audit_id="a1",
):
    return {
        "auditID": audit_id,
        "stage": "ResponseComplete",
        "verb": verb,
        "requestURI": uri,
        "user": {"username": user},
        "sourceIPs": ["10.0.0.9"],
        "userAgent": "kubectl/v1.31",
        "objectRef": {
            "resource": "networkpolicies",
            "namespace": "demo",
            "name": "demo-db-ingress",
        },
        "responseStatus": {"code": 200},
        "stageTimestamp": "2026-11-14T03:00:00.123456Z",
    }


def test_audit_webhook_writes_the_change_ledger_once(client, tables):
    auth = {"authorization": "Bearer audit-token"}
    body = {
        "items": [
            _audit(),
            _audit(verb="get", audit_id="a2"),
            _audit(uri="/x?dryRun=All", audit_id="a3"),
        ]
    }
    assert client.post("/k8s/audit", json=body).status_code == 401
    assert client.post("/k8s/audit", json=body, headers=auth).json() == {"accepted": 1}
    client.post("/k8s/audit/audit-token", json=body)  # redelivery, token in the path
    assert client.post("/k8s/audit/wrong", json=body).status_code == 401
    rows = db.scan(tables["CHANGES_TABLE_NAME"])
    assert len(rows) == 1
    assert rows[0]["event_name"] == "patch networkpolicies"
    assert (
        rows[0]["resource_ids"] == ["demo/demo-db-ingress"]
        and rows[0]["actor_short"] == "kubernetes-admin"
    )


def test_github_webhook_verifies_the_signature(client, tables):
    payload = {
        "deployment": {
            "id": 7,
            "environment": "prod",
            "sha": "abc1234def",
            "created_at": "2026-11-14T02:59:00Z",
        },
        "repository": {"full_name": "acme/app"},
        "sender": {"login": "dev1"},
    }
    raw = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(b"gh-secret", raw, hashlib.sha256).hexdigest()
    headers = {"x-github-event": "deployment", "content-type": "application/json"}
    assert (
        client.post(
            "/github/events",
            content=raw,
            headers={**headers, "x-hub-signature-256": "sha256=bad"},
        ).status_code
        == 401
    )
    ok = client.post(
        "/github/events", content=raw, headers={**headers, "x-hub-signature-256": sig}
    )
    assert ok.json() == {"accepted": 1}
    (row,) = db.scan(tables["CHANGES_TABLE_NAME"])
    assert row["event_name"] == "github deployment" and row["actor"] == "dev1"


def test_change_touching_the_broken_resource_ranks_first(tables):
    from datetime import UTC, datetime

    changes.record(
        changes.from_audit_event(
            {
                **_audit(verb="create", audit_id="b1"),
                "objectRef": {
                    "resource": "configmaps",
                    "namespace": "demo",
                    "name": "other",
                },
            }
        )
    )
    changes.record(changes.from_audit_event(_audit(audit_id="b2")))
    rows = changes.recent(
        60,
        before=datetime(2026, 11, 14, 3, 5, tzinfo=UTC),
        affected_ids=["demo/demo-db-ingress"],
    )
    assert rows[0]["resource_ids"] == ["demo/demo-db-ingress"]
    assert "patch networkpolicies on demo/demo-db-ingress" in changes.format_changes(
        rows
    )


def test_beacons_own_writes_and_controller_noise_are_labelled_or_dropped():
    own = changes.from_audit_event(
        _audit(user="system:serviceaccount:beacon:beacon-remediator")
    )
    assert own["by_beacon"] is True and own["actor_short"] == "beacon remediation"
    assert (
        changes.from_audit_event(_audit(user="system:kube-controller-manager")) is None
    )
