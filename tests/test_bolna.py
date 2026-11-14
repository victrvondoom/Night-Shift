"""The Bolna client and agent configuration (against a local stand-in API)."""

import json

import pytest

from beacon import bolna, voice_tools


def test_mint_sends_the_key_from_the_backend_and_forwards_user_data(bolna_api):
    out = bolna.mint_web_session({"incident_id": "i1"})
    req = bolna_api.requests[-1]
    assert req["path"] == "/web-call/session" and req["auth"] == "Bearer bn-test-key"
    assert req["body"] == {"agent_id": "agent-1", "user_data": {"incident_id": "i1"}}
    assert out["run_id"] and "bn-test-key" not in json.dumps(out)


def test_api_errors_surface_with_their_status(bolna_api):
    bolna_api.fail_mint = 429
    with pytest.raises(bolna.BolnaError) as exc:
        bolna.mint_web_session({})
    assert exc.value.status == 429


def test_unconfigured_key_fails_closed(monkeypatch):
    monkeypatch.delenv("BOLNA_API_KEY", raising=False)
    assert not bolna.configured()
    with pytest.raises(bolna.BolnaError):
        bolna.get_execution("x")


def test_execution_summary_copies_only_what_bolna_reported():
    summary = bolna.summarise_execution(
        {
            "id": "e1",
            "status": "completed",
            "conversation_duration": 16,
            "total_cost": 3.23,
            "cost_breakdown": {"llm": 0, "transcriber": 0.23},
            "transcript": "assistant: hi\nuser: approve fix 1",
            "telephony_data": {
                "recording_url": "https://api.bolna.ai/recordings/call/e1"
            },
        }
    )
    assert summary["final"] and summary["total_cost"] == 3.23
    assert summary["recording_url"].endswith("/e1")
    assert "confidence" not in summary  # Bolna reports none; none is invented
    assert (
        bolna.summarise_execution({"id": "e2", "status": "in-progress"})["final"]
        is False
    )


def _config():
    return bolna.agent_config(
        public_url="https://beacon.example", tool_token="tok", webhook_secret="whs"
    )


def test_agent_config_uses_only_non_aws_providers():
    tools_config = _config()["agent_config"]["tasks"][0]["tools_config"]
    providers = {
        tools_config["transcriber"]["provider"],
        tools_config["synthesizer"]["provider"],
        tools_config["llm_agent"]["llm_config"]["provider"],
    }
    assert providers == {"deepgram", "elevenlabs", "openai"}
    assert not providers & bolna.FORBIDDEN_PROVIDERS


@pytest.mark.parametrize(
    ("env", "value"),
    [("BOLNA_TTS_PROVIDER", "polly"), ("BOLNA_LLM_PROVIDER", "bedrock")],
)
def test_aws_providers_are_refused(monkeypatch, env, value):
    monkeypatch.setenv(env, value)
    with pytest.raises(ValueError, match="AWS"):
        _config()


def test_agent_exposes_the_nine_tools_as_custom_functions():
    api_tools = _config()["agent_config"]["tasks"][0]["tools_config"]["api_tools"]
    names = [t["name"] for t in api_tools["tools"]]
    assert names == [
        "get_incident_brief",
        "get_incident_evidence",
        "propose_fix",
        "approve_fix",
        "cancel_proposal",
        "undo_fix",
        "grant_sleep_contract",
        "open_fix_pr",
        "check_recovery",
    ]
    assert all(t["key"] == "custom_task" for t in api_tools["tools"])
    call = api_tools["tools_params"]["approve_fix"]
    assert call["url"] == "https://beacon.example/voice/bolna/tools/approve_fix"
    assert call["method"] == "POST" and call["api_token"] == "Bearer tok"
    assert call["param"]["fix_id"] == "%(fix_id)i"
    for var in bolna.CONTEXT_VARS:  # every call is bound to one session
        assert call["param"][var] == f"%({var})s"


def test_every_tool_points_back_at_beacon_and_nowhere_else():
    params = _config()["agent_config"]["tasks"][0]["tools_config"]["api_tools"][
        "tools_params"
    ]
    assert {p["url"].rsplit("/", 1)[0] for p in params.values()} == {
        "https://beacon.example/voice/bolna/tools"
    }
    assert len(params) == len(voice_tools.TOOL_SCHEMAS)


def test_pipelines_shape_and_prompt_carry_the_consent_rule():
    cfg = _config()
    task = cfg["agent_config"]["tasks"][0]
    assert task["toolchain"]["pipelines"] == [["transcriber", "llm", "synthesizer"]]
    prompt = cfg["agent_prompts"]["task_1"]["system_prompt"]
    assert "pending_confirmation" in prompt and "{beacon_token}" in prompt
    assert "AWS" not in prompt


def test_agent_shown_to_a_browser_has_no_tokens(bolna_api):
    shown = json.dumps(bolna.get_agent())
    assert "Bearer t" not in shown and "secret=s" not in shown
