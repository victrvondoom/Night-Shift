"""Inbound webhooks: Bolna call lifecycle, Alertmanager, Kubernetes audit, GitHub."""

import hashlib
import hmac
import json

from beacon import approvals, changes, db, store
from tests.conftest import PASS

HOOK = {"x-beacon-webhook-secret": "hook-secret"}


def _session(client, incident):
    resp = client.post(
        "/voice/bolna/session",
        json={"incident_id": incident["incident_id"]},
        headers=PASS,
    )
    return resp.json()["beacon_session"], resp.json()["session"]["run_id"]


def _completed(run_id, transcript="assistant: say approve fix 1\nuser: approve fix 1"):
    return {
        "id": run_id,
        "status": "completed",
        "conversation_duration": 42,
        "total_cost": 3.5,
        "cost_breakdown": {
            "platform": 2,
            "llm": 0.5,
            "transcriber": 0.5,
            "synthesizer": 0.5,
        },
        "transcript": transcript,
        "telephony_data": {
            "recording_url": f"https://api.bolna.ai/recordings/call/{run_id}"
        },
    }


def test_bolna_webhook_needs_the_shared_secret(client):
    assert client.post("/voice/bolna/webhook", json={"id": "x"}).status_code == 401
    bad = {"x-beacon-webhook-secret": "wrong"}
    assert (
        client.post("/voice/bolna/webhook", json={"id": "x"}, headers=bad).status_code
        == 401
    )


def test_bolna_webhook_honours_the_source_ip_allowlist(client, monkeypatch):
    monkeypatch.setenv("BOLNA_WEBHOOK_IPS", "13.203.39.153,13.126.9.249,13.202.133.53")
    assert (
        client.post("/voice/bolna/webhook", json={"id": "x"}, headers=HOOK).status_code
        == 403
    )


def test_unknown_execution_is_acknowledged_but_not_stored(client, tables):
    out = client.post("/voice/bolna/webhook", json={"id": "nobody"}, headers=HOOK)
    assert out.status_code == 202 and out.json()["matched"] is False


def test_webhook_records_transcript_recording_and_cost(
    client, incident, bolna_api, tables
):
    session_id, run_id = _session(client, incident)
    client.post(
        "/voice/bolna/webhook",
        json={"id": run_id, "status": "in-progress"},
        headers=HOOK,
    )
    out = client.post("/voice/bolna/webhook", json=_completed(run_id), headers=HOOK)
    assert out.json() == {"ok": True, "matched": True}
    call = client.get(f"/voice/bolna/calls/{session_id}", headers=PASS).json()["call"]
    assert call["status"] == "completed" and call["final"] is True
    assert call["total_cost"] == 3.5 and call["duration_seconds"] == 42
    assert (
        call["recording_url"].endswith(run_id) and "approve fix 1" in call["transcript"]
    )
    assert "token_hash" not in call
    listing = client.get(
        f"/voice/bolna/calls?incident_id={incident['incident_id']}", headers=PASS
    ).json()
    assert listing["total_cost"] == 3.5 and listing["costed_calls"] == 1
    rec = client.get(f"/voice/recordings/{session_id}", headers=PASS).json()
    assert rec["audio_url"].endswith(run_id)
    timeline = store.get_incident(
        incident["incident_id"], table_name=tables["INCIDENTS_TABLE_NAME"]
    )["timeline"]
    statuses = [
        e["detail"]["status"] for e in timeline if e["event"] == "voice_call_status"
    ]
    assert statuses == ["in-progress", "completed"]


def test_post_call_transcript_never_authorises_anything(
    client, incident, bolna_api, tables, cluster
):
    """The approval phrase arriving in a webhook transcript must change nothing."""
    session_id, run_id = _session(client, incident)
    session = db.get("voice_calls", session_id)
    token_body = {
        "incident_id": incident["incident_id"],
        "beacon_session": session_id,
        "beacon_token": bolna_api.requests[-1]["body"]["user_data"]["beacon_token"],
    }
    bearer = {"authorization": "Bearer tool-token"}
    client.post("/voice/bolna/tools/propose_fix", json=token_body, headers=bearer)
    client.post(
        "/voice/bolna/tools/approve_fix",
        json={**token_body, "fix_id": "1", "confirmation_phrase": "approve fix 1"},
        headers=bearer,
    )
    client.post("/voice/bolna/webhook", json=_completed(run_id), headers=HOOK)
    assert session is not None and cluster["restarts"] == 0
    rows = approvals.list_for_incident(
        incident["incident_id"], table_name=tables["APPROVALS_TABLE_NAME"]
    )
    assert [r for r in rows if r.get("kind") == "approval"] == []
    fresh = store.get_incident(
        incident["incident_id"], table_name=tables["INCIDENTS_TABLE_NAME"]
    )
    assert fresh["status"] == "awaiting_engineer" and fresh["pending_confirmations"]


def test_call_history_needs_the_passcode(client):
    for path in ("/voice/bolna/calls", "/voice/bolna/history", "/voice/bolna/agent"):
        assert client.get(path).status_code == 401


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
