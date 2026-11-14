"""Bolna Voice AI: the one module that talks to ``api.bolna.ai``.

Everything here runs server-side with the ``bn-`` API key from Vault/env; the
browser only ever receives the short-lived, single-use web-call session that
``mint_web_session`` returns. Endpoints follow the current (v2) API reference:

* ``POST /web-call/session``                -- mint a browser WebRTC session
* ``POST /v2/agent`` / ``PUT /v2/agent/{id}`` / ``GET /v2/agent/{id}``
* ``POST /call``                            -- place a phone call
* ``GET  /executions/{id}``                 -- transcript, recording, cost
* ``GET  /executions/{id}/log``             -- raw pipeline logs
* ``GET  /v2/agent/{id}/executions``        -- call history

Speech and LLM providers are chosen here and never include an AWS service:
Bolna offers ``polly`` (TTS) and ``bedrock`` (LLM), and ``agent_config``
refuses both.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

from beacon import secrets

logger = logging.getLogger(__name__)

_TIMEOUT = 15
# Statuses after which an execution's transcript, cost and recording are final.
TERMINAL = frozenset(
    {
        "completed",
        "no-answer",
        "busy",
        "failed",
        "canceled",
        "stopped",
        "error",
        "balance-low",
    }
)
# Source addresses Bolna documents for webhook deliveries.
WEBHOOK_IPS = ("13.203.39.153", "13.126.9.249", "13.202.133.53")
FORBIDDEN_PROVIDERS = frozenset({"polly", "bedrock", "aws", "transcribe"})
# Context variables Night Shift passes as ``user_data`` when it mints a session;
# Bolna substitutes them into the prompt and into every function call.
CONTEXT_VARS = ("incident_id", "beacon_session", "beacon_token")


class BolnaError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"bolna {status}: {message}")
        self.status = status


def base_url() -> str:
    return os.environ.get("BOLNA_API_BASE", "https://api.bolna.ai").rstrip("/")


def api_key() -> str:
    return secrets.get("BOLNA_API_KEY")


def agent_id() -> str:
    return secrets.get("BOLNA_AGENT_ID")


def configured() -> bool:
    return bool(api_key() and agent_id())


def _request(method: str, path: str, body: Any = None) -> Any:
    key = api_key()
    if not key:
        raise BolnaError(503, "BOLNA_API_KEY is not configured")
    req = urllib.request.Request(  # noqa: S310
        base_url() + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
            raw = resp.read().decode()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:300]
        raise BolnaError(exc.code, detail) from exc
    except Exception as exc:
        raise BolnaError(502, str(exc)) from exc
    return json.loads(raw) if raw else {}


# ---------------------------------------------------------------------------
# Sessions and calls
# ---------------------------------------------------------------------------


def mint_web_session(user_data: dict[str, Any]) -> dict[str, Any]:
    """A single-use WebRTC session for ``@bolna/web-call`` (expires in ~120 s).

    Returned to the browser as-is; ``run_id`` is the execution id that call
    history, webhooks and ``get_execution`` all use.
    """
    return dict(
        _request(
            "POST",
            os.environ.get("BOLNA_WEB_SESSION_PATH", "/web-call/session"),
            {"agent_id": agent_id(), "user_data": user_data},
        )
    )


def place_call(phone: str, user_data: dict[str, Any]) -> dict[str, Any]:
    """Ring the on-call engineer; returns ``{execution_id, status, ...}``."""
    body: dict[str, Any] = {
        "agent_id": agent_id(),
        "recipient_phone_number": phone,
        "user_data": user_data,
    }
    from_number = os.environ.get("BOLNA_FROM_NUMBER", "")
    if from_number:
        body["from_phone_number"] = from_number
    return dict(_request("POST", "/call", body))


def get_execution(execution_id: str) -> dict[str, Any]:
    return dict(_request("GET", f"/executions/{execution_id}"))


def get_execution_log(execution_id: str) -> dict[str, Any]:
    return dict(_request("GET", f"/executions/{execution_id}/log"))


def list_executions(days: int = 7, page: int = 1, size: int = 50) -> Any:
    """Call history for the agent (the API caps the window at seven days)."""
    end = datetime.now(tz=UTC)
    start = end - timedelta(days=min(max(days, 1), 7))
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    return _request(
        "GET",
        f"/v2/agent/{agent_id()}/executions?page_number={page}&page_size={size}"
        f"&from={start.strftime(fmt)}&to={end.strftime(fmt)}",
    )


def summarise_execution(data: dict[str, Any]) -> dict[str, Any]:
    """The fields Night Shift keeps from an execution payload (API or webhook).

    Only what Bolna reported is copied; nothing is derived or estimated.
    """
    telephony = data.get("telephony_data") or {}
    return {
        "execution_id": data.get("id"),
        "status": data.get("status"),
        "termination_reason": data.get("termination_reason"),
        "duration_seconds": data.get("conversation_duration"),
        "total_cost": data.get("total_cost"),
        "cost_breakdown": data.get("cost_breakdown"),
        "transcript": data.get("transcript"),
        "summary": data.get("summary"),
        "recording_url": telephony.get("recording_url"),
        "final": data.get("status") in TERMINAL,
    }


# ---------------------------------------------------------------------------
# Agent configuration
# ---------------------------------------------------------------------------


def _provider(env: str, default: str) -> str:
    value = os.environ.get(env, default).strip().lower()
    if value in FORBIDDEN_PROVIDERS:
        raise ValueError(f"{env}={value} is an AWS service and is not allowed")
    return value


def _tool(schema: dict[str, Any], public_url: str, token: str) -> tuple[dict, dict]:
    """One Night Shift tool as a Bolna custom function calling back into FastAPI."""
    name = str(schema["name"])
    props = dict((schema.get("parameters") or {}).get("properties") or {})
    for var in CONTEXT_VARS:
        props[var] = {"type": "string", "description": f"Context variable {var}"}
    spec = {"integer": "i", "number": "f"}
    param = {k: f"%({k}){spec.get(str(v.get('type')), 's')}" for k, v in props.items()}
    definition = {
        "name": name,
        "description": schema["description"],
        "pre_call_message": "One moment.",
        "parameters": {
            "type": "object",
            "properties": props,
            "required": [
                *((schema.get("parameters") or {}).get("required") or []),
                *CONTEXT_VARS,
            ],
        },
        "key": "custom_task",
    }
    call = {
        "method": "POST",
        "url": f"{public_url.rstrip('/')}/voice/bolna/tools/{name}",
        "param": param,
        "api_token": f"Bearer {token}",
        "headers": {},
    }
    return definition, call


def agent_config(
    *, public_url: str, tool_token: str, webhook_secret: str = ""
) -> dict[str, Any]:
    """The full ``POST /v2/agent`` body for the Night Shift on-call agent."""
    from beacon import voice_brief, voice_tools

    tools, params = [], {}
    for schema in voice_tools.bolna_tool_schemas():
        definition, call = _tool(schema, public_url, tool_token)
        tools.append(definition)
        params[definition["name"]] = call
    webhook = f"{public_url.rstrip('/')}/voice/bolna/webhook"
    if webhook_secret:
        webhook += f"?secret={webhook_secret}"
    return {
        "agent_config": {
            "agent_name": os.environ.get("BOLNA_AGENT_NAME", "Night Shift on-call"),
            "agent_type": "other",
            "agent_welcome_message": (
                "This is Night Shift. I have the incident in front of me; "
                "ask me what happened."
            ),
            "webhook_url": webhook,
            "tasks": [
                {
                    "task_type": "conversation",
                    "toolchain": {
                        "execution": "sequential",
                        "pipelines": [["transcriber", "llm", "synthesizer"]],
                    },
                    "tools_config": {
                        "llm_agent": {
                            "agent_type": "simple_llm_agent",
                            "agent_flow_type": "streaming",
                            "llm_config": {
                                "provider": _provider("BOLNA_LLM_PROVIDER", "openai"),
                                "model": os.environ.get(
                                    "BOLNA_LLM_MODEL", "gpt-4.1-mini"
                                ),
                                "max_tokens": 250,
                                "temperature": 0.2,
                            },
                        },
                        "transcriber": {
                            "provider": _provider("BOLNA_STT_PROVIDER", "deepgram"),
                            "model": os.environ.get("BOLNA_STT_MODEL", "nova-3"),
                            "language": os.environ.get("BOLNA_LANGUAGE", "en"),
                            "stream": True,
                            "encoding": "linear16",
                            "sampling_rate": 16000,
                            "endpointing": 250,
                            "keywords": "approve fix,undo fix,Night Shift,rollback",
                        },
                        "synthesizer": {
                            "provider": _provider("BOLNA_TTS_PROVIDER", "elevenlabs"),
                            "provider_config": {
                                "voice": os.environ.get("BOLNA_TTS_VOICE", "Angelica"),
                                "voice_id": os.environ.get(
                                    "BOLNA_TTS_VOICE_ID", "IkSv4tkouLJ6kYsQA7XD"
                                ),
                                "model": os.environ.get(
                                    "BOLNA_TTS_MODEL", "eleven_turbo_v2_5"
                                ),
                            },
                            "stream": True,
                            "buffer_size": 250,
                            "audio_format": "wav",
                        },
                        "input": {"provider": "plivo", "format": "wav"},
                        "output": {"provider": "plivo", "format": "wav"},
                        "api_tools": {"tools": tools, "tools_params": params},
                    },
                    "task_config": {
                        "call_terminate": 900,
                        "hangup_after_silence": 30,
                    },
                }
            ],
        },
        "agent_prompts": {"task_1": {"system_prompt": voice_brief.bolna_prompt()}},
    }


def create_agent(config: dict[str, Any]) -> dict[str, Any]:
    return dict(_request("POST", "/v2/agent", config))


def update_agent(config: dict[str, Any]) -> dict[str, Any]:
    return dict(_request("PUT", f"/v2/agent/{agent_id()}", config))


def get_agent() -> dict[str, Any]:
    """The stored agent with every credential removed (safe to show a browser)."""
    return redact_agent(dict(_request("GET", f"/v2/agent/{agent_id()}")))


def redact_agent(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: (
                "[redacted]" if k in ("api_token", "headers") and v else redact_agent(v)
            )
            for k, v in value.items()
            if k != "webhook_url"
        }
    if isinstance(value, list):
        return [redact_agent(v) for v in value]
    return value
