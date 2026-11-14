"""Who may authorise a change, tested through the HTTP API.

A Bolna function call is a model asking for something. It can read, propose and
cancel. It can never approve: that takes the exact phrase typed by the engineer
in the passcode-authenticated console.
"""

from typing import Any

import pytest

from beacon import approvals, db, store
from tests.conftest import PASS

BOLNA = {"authorization": "Bearer tool-token"}


@pytest.fixture()
def call(client, incident, bolna_api, cluster):
    """A live Bolna web call on the incident: returns a function-call helper."""
    resp = client.post(
        "/voice/bolna/session",
        json={"incident_id": incident["incident_id"]},
        headers=PASS,
    )
    assert resp.status_code == 200, resp.text
    session_id = resp.json()["beacon_session"]
    token = bolna_api.requests[-1]["body"]["user_data"]["beacon_token"]

    def tool(name: str, **args: Any) -> dict[str, Any]:
        body = {
            "incident_id": incident["incident_id"],
            "beacon_session": session_id,
            "beacon_token": token,
            **args,
        }
        out = client.post(f"/voice/bolna/tools/{name}", json=body, headers=BOLNA)
        assert out.status_code == 200, out.text
        return out.json()

    tool.session_id = session_id  # type: ignore[attr-defined]
    tool.token = token  # type: ignore[attr-defined]
    tool.run_id = resp.json()["session"]["run_id"]  # type: ignore[attr-defined]
    return tool


def _fresh(tables, incident):
    return store.get_incident(
        incident["incident_id"], table_name=tables["INCIDENTS_TABLE_NAME"]
    )


def _approvals(tables, incident):
    rows = approvals.list_for_incident(
        incident["incident_id"], table_name=tables["APPROVALS_TABLE_NAME"]
    )
    return [r for r in rows if r.get("kind") == "approval"]


def _typed(client, incident, text):
    return client.post(
        "/voice/turn",
        json={
            "incident_id": incident["incident_id"],
            "session_id": "c1",
            "text": text,
            "channel": "typed",
        },
        headers=PASS,
    ).json()


# -- the session ---------------------------------------------------------------


def test_session_needs_the_passcode_and_never_returns_the_api_key(
    client, incident, bolna_api
):
    assert (
        client.post(
            "/voice/bolna/session", json={"incident_id": incident["incident_id"]}
        ).status_code
        == 401
    )
    resp = client.post(
        "/voice/bolna/session",
        json={"incident_id": incident["incident_id"]},
        headers=PASS,
    )
    assert "bn-test-key" not in resp.text and "beacon_token" not in resp.text


def test_mint_failure_is_reported_not_hidden(client, incident, bolna_api):
    bolna_api.fail_mint = 429
    resp = client.post(
        "/voice/bolna/session",
        json={"incident_id": incident["incident_id"]},
        headers=PASS,
    )
    assert resp.status_code == 429 and "could not start" in resp.json()["error"]


# -- function-call authentication ------------------------------------------------


def test_tool_call_needs_the_agent_bearer_token(client, call, incident):
    body = {
        "incident_id": incident["incident_id"],
        "beacon_session": call.session_id,
        "beacon_token": call.token,
    }
    assert client.post("/voice/bolna/tools/propose_fix", json=body).status_code == 401
    wrong = {"authorization": "Bearer nope"}
    assert (
        client.post(
            "/voice/bolna/tools/propose_fix", json=body, headers=wrong
        ).status_code
        == 401
    )


def test_tool_call_needs_a_live_session_for_that_incident(client, call, incident):
    base = {
        "incident_id": incident["incident_id"],
        "beacon_session": call.session_id,
        "beacon_token": call.token,
    }
    for bad in (
        {"beacon_token": "x"},
        {"incident_id": "other"},
        {"beacon_session": "bs_missing"},
    ):
        resp = client.post(
            "/voice/bolna/tools/propose_fix", json={**base, **bad}, headers=BOLNA
        )
        assert resp.status_code == 403
    db.patch(
        "voice_calls", call.session_id, {"expires_at": "2000-01-01T00:00:00+00:00"}
    )
    assert (
        client.post(
            "/voice/bolna/tools/propose_fix", json=base, headers=BOLNA
        ).status_code
        == 403
    )


def test_unknown_tool_and_ip_allowlist(client, call, incident, monkeypatch):
    base = {
        "incident_id": incident["incident_id"],
        "beacon_session": call.session_id,
        "beacon_token": call.token,
    }
    assert (
        client.post(
            "/voice/bolna/tools/run_shell", json=base, headers=BOLNA
        ).status_code
        == 404
    )
    monkeypatch.setenv("BOLNA_ALLOWED_IPS", "203.0.113.0/24")
    assert (
        client.post(
            "/voice/bolna/tools/propose_fix", json=base, headers=BOLNA
        ).status_code
        == 403
    )


# -- what a voice call may and may not do ----------------------------------------


def test_bolna_can_read_and_propose_with_a_dry_run(call, cluster):
    assert call("get_incident_brief")["alarm_name"] == "DemoApiDown"
    proposal = call("propose_fix")
    assert proposal["fix_id"] == 1 and proposal["dry_run"]["ok"]
    assert proposal["confirmation_phrase"] == "approve fix 1"
    assert cluster["dry_runs"] == 1 and cluster["restarts"] == 0


def test_bolna_approve_is_held_and_nothing_executes(call, cluster, tables, incident):
    call("propose_fix")
    out = call("approve_fix", fix_id="1", confirmation_phrase="approve fix 1")
    assert out["approved"] is False and out["pending_confirmation"] is True
    assert out["confirm_with"] == "approve fix 1"
    assert cluster["restarts"] == 0 and _approvals(tables, incident) == []
    fresh = _fresh(tables, incident)
    assert fresh["status"] == "awaiting_engineer"
    pending = fresh["pending_confirmations"][0]
    assert pending["provenance"] == "bolna_llm_function_call"
    assert pending["execution_id"] == call.run_id
    # the proposal is retained, still pending, for a verified confirmation
    assert approvals.get_proposal(
        incident["incident_id"], 1, table_name=tables["APPROVALS_TABLE_NAME"]
    )


@pytest.mark.parametrize("words", ["yes", "okay", "do it", "go ahead and fix it"])
def test_agreement_is_not_the_phrase_on_any_channel(
    call, client, incident, cluster, tables, words
):
    call("propose_fix")
    out = call("approve_fix", fix_id="1", confirmation_phrase=words)
    assert out["approved"] is False and "pending_confirmation" not in out
    client.post(
        "/voice/tools/approve_fix",
        json={
            "incident_id": incident["incident_id"],
            "args": {"fix_id": 1, "confirmation_phrase": words},
            "transcript": words,
            "channel": "typed",
        },
        headers=PASS,
    )
    assert cluster["restarts"] == 0 and _approvals(tables, incident) == []


def test_typed_phrase_confirms_the_held_request_and_executes_once(
    call, client, incident, cluster, tables
):
    call("propose_fix")
    call("approve_fix", fix_id="1", confirmation_phrase="approve fix 1")
    reply = _typed(client, incident, "approve fix 1")
    assert "Approved" in reply["reply_text"]
    assert cluster["restarts"] == 1
    (record,) = _approvals(tables, incident)
    att = record["attestation"]
    assert att["evidence"] == "typed_console" and record["channel"] == "typed"
    assert att["voice_request"]["execution_id"] == call.run_id
    assert record["used_at"] and record["execute_result"]["ok"]
    fresh = _fresh(tables, incident)
    assert fresh["status"] == "resolved" and fresh["pending_confirmations"] == []
    _typed(client, incident, "approve fix 1")  # typing it again changes nothing
    assert cluster["restarts"] == 1


def test_typed_approval_for_the_wrong_number_is_refused(
    call, client, incident, cluster
):
    call("propose_fix")
    reply = _typed(client, incident, "approve fix 2")
    assert "nothing was applied" in reply["reply_text"]
    assert cluster["restarts"] == 0


def test_browser_speech_is_not_consent(call, client, incident, cluster, tables):
    call("propose_fix")
    out = client.post(
        "/voice/turn",
        json={
            "incident_id": incident["incident_id"],
            "session_id": "c1",
            "text": "approve fix 1",
            "channel": "webspeech",
        },
        headers=PASS,
    ).json()
    assert "type" in out["reply_text"] and cluster["restarts"] == 0
    assert _approvals(tables, incident) == []


def test_console_event_channel_cannot_approve(call, client, incident, cluster):
    call("propose_fix")
    out = client.post(
        "/voice/tools/approve_fix",
        json={
            "incident_id": incident["incident_id"],
            "args": {"fix_id": 1, "confirmation_phrase": "approve fix 1"},
            "transcript": "approve fix 1",
            "channel": "bolna",
        },
        headers=PASS,
    ).json()
    assert out["result"]["approved"] is False and cluster["restarts"] == 0


def test_typed_tools_need_the_passcode(client, incident):
    body = {
        "incident_id": incident["incident_id"],
        "text": "approve fix 1",
        "channel": "typed",
    }
    assert client.post("/voice/turn", json=body).status_code == 401
    assert client.post("/voice/tools/approve_fix", json=body).status_code == 401


# -- cancellation and interruption -----------------------------------------------


def test_cancel_withdraws_the_proposal_and_the_pending_request(
    call, client, incident, cluster, tables
):
    call("propose_fix")
    call("approve_fix", fix_id="1", confirmation_phrase="approve fix 1")
    assert call("cancel_proposal", fix_id="1")["withdrawn"] is True
    assert _fresh(tables, incident)["pending_confirmations"] == []
    reply = _typed(client, incident, "approve fix 1")
    assert (
        "withdrawn" in reply["reply_text"]
        or "nothing was applied" in reply["reply_text"]
    )
    assert cluster["restarts"] == 0


def test_interrupting_the_read_back_withdraws_the_proposal(
    call, client, incident, cluster, tables
):
    """The console detects the barge-in and calls cancel_proposal, as before."""
    call("propose_fix")
    out = client.post(
        "/voice/tools/cancel_proposal",
        json={
            "incident_id": incident["incident_id"],
            "channel": "console",
            "args": {"fix_id": 1, "reason": "engineer interrupted the read-back"},
        },
        headers=PASS,
    ).json()
    assert out["result"]["withdrawn"] is True
    reply = _typed(client, incident, "approve fix 1")
    assert "interrupted the read-back" in reply["reply_text"]
    assert cluster["restarts"] == 0
    events = [e["event"] for e in _fresh(tables, incident)["timeline"]]
    assert "proposal_withdrawn" in events


def test_cancel_invalidates_an_unused_approval_immediately(tables, incident, cluster):
    from beacon import remediate

    t = tables["APPROVALS_TABLE_NAME"]
    params = {"namespace": "demo", "name": "demo-api"}
    record = approvals.create(
        incident["incident_id"],
        "deployment.restart",
        params,
        source="voice",
        channel="typed",
        transcript_quote="approve fix 1",
        fix_id=1,
        table_name=t,
        attestation={"evidence": "typed_console"},
    )
    assert (
        approvals.invalidate_for_fix(
            incident["incident_id"], 1, reason="cancelled", table_name=t
        )
        == 1
    )
    out = remediate.execute(
        {
            "approval_id": record["approval_id"],
            "incident_id": incident["incident_id"],
            "action": "deployment.restart",
            "params": params,
        }
    )
    assert not out["ok"] and "expired" in out["error"] and cluster["restarts"] == 0


def test_undo_and_contract_requests_over_voice_are_held_too(
    call, client, incident, cluster, tables
):
    call("propose_fix")
    _typed(client, incident, "approve fix 1")
    out = call("undo_fix", fix_id="1", confirmation_phrase="undo fix 1")
    assert out.get("undone") is False
    grant = call(
        "grant_sleep_contract",
        days="7",
        confirmation_phrase="grant contract for 7 days",
    )
    assert grant.get("granted") is not True
    assert db.scan(tables["CONTRACTS_TABLE_NAME"]) == []


def test_console_sees_the_calls_tool_events(call, client):
    call("propose_fix")
    call("approve_fix", fix_id="1", confirmation_phrase="approve fix 1")
    data = client.get(
        f"/voice/bolna/session/{call.session_id}/events", headers=PASS
    ).json()
    assert [e["name"] for e in data["events"]] == ["propose_fix", "approve_fix"]
    assert data["pending_confirmations"][0]["phrase"] == "approve fix 1"
    assert "token_hash" not in str(data)
