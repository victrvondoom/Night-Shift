"""Voice and console routes (FastAPI router mounted at ``/voice``).

Three callers reach the same nine Python tools, and what each may do differs
only by how much it can prove about who is speaking:

* **Console, typed** (``POST /turn``, ``POST /tools/{name}``; passcode). Text
  the engineer typed in the authenticated console. This is verified consent.
* **Bolna custom functions** (``POST /bolna/tools/{name}``; bearer token +
  per-session token). The agent's LLM asking for a tool. It can read, propose
  and cancel; a consent tool is recorded as a *request* and held until the
  engineer confirms it in the console. Nothing Bolna sends can execute a change.
* **Bolna webhooks** (``POST /bolna/webhook``; shared secret + source IPs).
  Call lifecycle only: status, transcript, recording, cost. Never authorises.

The Bolna API key stays here; the browser receives only the single-use
web-call session minted for it.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets as pysecrets
from datetime import UTC, datetime, timedelta
from functools import cache
from importlib.resources import files
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from beacon import bolna, db, observability, secrets, store, voice_brief, voice_tools
from beacon.turn_context import TurnContext, turn_context

logger = logging.getLogger(__name__)
SERVICE = "beacon-voice"
router = APIRouter()

_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_MAX_TEXT = 2000
_CITATION_RE = re.compile(r"\s*\[(E\d+)\]")
_MAX_HISTORY = 20
_SESSION_TTL_MINUTES = 30
_CALLS = "voice_calls"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _incidents_table() -> str:
    return _env("INCIDENTS_TABLE_NAME", "incidents")


@cache
def _system_prompt() -> str:
    return (
        files("beacon").joinpath("prompts/voice_system.txt").read_text(encoding="utf-8")
    )


def _json(status: int, body: dict[str, Any]) -> JSONResponse:
    return JSONResponse(status_code=status, content=db._plain(body))


def _eq(given: str, expected: str) -> bool:
    return bool(expected and given) and hmac.compare_digest(
        given.encode(), expected.encode()
    )


def _passcode_ok(request: Request) -> bool:
    """Constant-time compare; an unset passcode fails closed."""
    return _eq(request.headers.get("x-beacon-passcode", ""), secrets.get("PASSCODE"))


def _now() -> datetime:
    return datetime.now(tz=UTC)


def strip_citations(text: str) -> tuple[str, list[str]]:
    """Remove ``[E#]`` tags for speech; return the ids in order of appearance."""
    ids = _CITATION_RE.findall(text)
    clean = _CITATION_RE.sub("", text)
    clean = re.sub(r"\s+([.,;!?])", r"\1", clean)
    return re.sub(r"[ \t]{2,}", " ", clean).strip(), ids


def _public_incident(incident_id: str) -> dict[str, Any]:
    fresh = store.get_incident(incident_id, table_name=_incidents_table())
    fresh.pop("conversation", None)
    fresh.pop("rca", None)
    return fresh


# ---------------------------------------------------------------------------
# Tools: one runner, the caller decides what the words are worth
# ---------------------------------------------------------------------------


def _run_tool(
    name: str,
    args: dict[str, Any],
    *,
    incident_id: str,
    session_id: str,
    transcript: str,
    channel: str,
    attestation: dict[str, Any],
) -> dict[str, Any]:
    ctx = TurnContext(
        incident_id=incident_id,
        session_id=session_id,
        transcript=transcript,
        channel=channel,
        passcode_ok=True,
        attestation=attestation,
    )
    with turn_context(ctx):
        result = voice_tools.dispatch(name, args)
    if name in voice_tools.CONSENT_TOOLS and voice_tools.consent_verified(ctx):
        done = any(result.get(k) for k in ("approved", "undone", "granted", "opened"))
        if done:
            voice_tools.clear_pending(incident_id, name)
    return {
        "ok": "error" not in result,
        "result": result,
        "tool_events": ctx.tool_events,
        "evidence": ctx.evidence,
    }


def _typed(session_id: str) -> dict[str, Any]:
    """Provenance of words typed in the passcode-authenticated console."""
    return {"evidence": "typed_console", "stt": "typed", "session_id": session_id}


@router.post("/tools/{name}")
async def tools_route(name: str, request: Request) -> JSONResponse:
    if not _passcode_ok(request):
        return _json(401, {"error": "passcode required"})
    if name not in voice_tools.TOOL_FUNCTIONS:
        return _json(404, {"error": f"unknown tool {name}"})
    body = await request.json()
    incident_id = str(body.get("incident_id", ""))
    if not _ID_RE.match(incident_id):
        return _json(400, {"error": "incident_id is required"})
    transcript = str(body.get("transcript", "")).strip()
    if len(transcript) > _MAX_TEXT:
        return _json(413, {"error": f"transcript is limited to {_MAX_TEXT} characters"})
    if not store.get_incident(incident_id, table_name=_incidents_table()):
        return _json(404, {"error": f"incident {incident_id} not found"})
    session_id = str(body.get("session_id", "console"))[:64]
    # Only the typed channel is consent. Anything else the console sends (a
    # barge-in cancellation, say) runs with no authority to approve.
    typed = str(body.get("channel", "")) == "typed"
    import anyio

    out = await anyio.to_thread.run_sync(
        lambda: _run_tool(
            name,
            dict(body.get("args") or {}),
            incident_id=incident_id,
            session_id=session_id,
            transcript=transcript,
            channel="typed" if typed else "console",
            attestation=_typed(session_id) if typed else {"evidence": "console_event"},
        )
    )
    out["incident"] = _public_incident(incident_id)
    return _json(200, out)


# ---------------------------------------------------------------------------
# Typed turn: exact consent phrases are routed by code, the rest by the model
# ---------------------------------------------------------------------------

_ROUTES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bapprove fix (\d+)\b"), "approve_fix"),
    (re.compile(r"\bundo fix (\d+)\b"), "undo_fix"),
    (re.compile(r"\b(?:cancel|withdraw) fix (\d+)\b"), "cancel_proposal"),
)


def _route_phrase(text: str) -> tuple[str, dict[str, Any]] | None:
    """A typed consent phrase as ``(tool, args)``; None for everything else.

    The phrase decides, not a model: "approve fix 2" typed in the console calls
    approve_fix(2) whether or not an LLM is reachable.
    """
    spoken = voice_tools._normalise(text)
    for pattern, tool in _ROUTES:
        match = pattern.search(spoken)
        if match:
            args: dict[str, Any] = {"fix_id": int(match.group(1))}
            if tool != "cancel_proposal":
                args["confirmation_phrase"] = text
            else:
                args["reason"] = "engineer cancelled in the console"
            return tool, args
    if any(p.search(spoken) for p in voice_tools._GRANT_PATTERNS):
        days = re.search(r"for (\d+) days?", spoken)
        return "grant_sleep_contract", {"days": int(days.group(1)) if days else 7}
    from beacon import fix_pr

    if fix_pr.said_phrase(text):
        return "open_fix_pr", {"confirmation_phrase": text}
    return None


def _routed_reply(tool: str, result: dict[str, Any]) -> str:
    if result.get("error"):
        return str(result["error"])
    if tool == "approve_fix":
        return f"Approved. Fix {result.get('fix_id')} is being applied and verified."
    if tool == "undo_fix":
        return f"Undo of fix {result.get('fix_id')} is being applied."
    return str(
        result.get("spoken_hint")
        or result.get("read_back_spoken")
        or result.get("instruction")
        or "Done."
    )


def _turn_prompt(body: dict[str, Any]) -> str:
    mode = body.get("mode", "chat")
    hint = ""
    if str(body.get("lang", "")).lower().startswith("hi"):
        hint = (
            " Answer in Hinglish (Hindi in Latin script with English technical terms)."
        )
    if mode == "brief":
        return (
            "The engineer just opened the incident. Brief them: call "
            "get_incident_brief, then in two or three sentences say what is wrong, "
            "the likely cause, and that you can propose a fix if they ask." + hint
        )
    if mode == "event":
        event = str(body.get("event", ""))
        if event == "resolved":
            return (
                "System event: the remediation loop has verified recovery (resolved). "
                "Call check_recovery, then tell the engineer the alarm is back to OK "
                "in one sentence, and offer a Sleep Contract in one sentence."
            )
        if event == "escalated":
            return (
                "System event: verification failed (escalated). Call check_recovery "
                "and tell the engineer honestly what did not pass and that a human "
                "is needed."
            )
        return f"System event: {event}. Tell the engineer briefly." + hint
    return str(body.get("text", "")).strip() + hint


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _build_agent(*, history: list[dict[str, Any]]) -> Any:
    from beacon.voice_loop import LiteLLMAgent

    return LiteLLMAgent(system_prompt=_system_prompt(), history=history)


def _record_turn_usage(incident_id: str, agent: Any) -> None:
    usage = getattr(agent, "usage", None) or {}
    if usage:
        try:
            store.add_usage(incident_id, usage, table_name=_incidents_table())
        except Exception:
            logger.exception("usage write failed")


@router.post("/turn")
async def turn(request: Request) -> JSONResponse:
    if not _passcode_ok(request):
        return _json(401, {"error": "passcode required"})
    body = await request.json()
    with observability.metrics_scope(service=SERVICE):
        import anyio

        return await anyio.to_thread.run_sync(_turn, body)


def _turn(body: dict[str, Any]) -> JSONResponse:
    incident_id = str(body.get("incident_id", ""))
    session_id = str(body.get("session_id", "default"))[:64]
    raw_text = str(body.get("text", ""))
    if len(raw_text) > _MAX_TEXT:
        return _json(413, {"error": f"text is limited to {_MAX_TEXT} characters"})
    if not _ID_RE.match(incident_id):
        return _json(400, {"error": "incident_id is required (letters, digits, . _ -)"})
    text = _turn_prompt(body)
    if not text:
        return _json(400, {"error": "text (or mode) is required"})
    # Only text typed in the console is consent. Browser speech recognition
    # reports no confidence Night Shift can check, so it can ask but not approve.
    channel = "typed" if str(body.get("channel", "typed")) == "typed" else "webspeech"
    attest = (
        _typed(session_id)
        if channel == "typed"
        else {
            "evidence": "browser_speech",
            "stt": "webspeech",
            "session_id": session_id,
        }
    )
    incident = store.get_incident(incident_id, table_name=_incidents_table())
    if not incident:
        return _json(404, {"error": f"incident {incident_id} not found"})

    history = [m for m in (incident.get("conversation") or []) if isinstance(m, dict)][
        -_MAX_HISTORY:
    ]
    turns_so_far = int(incident.get("turn_count") or 0)
    cap = int(_env("SESSION_CAP_TURNS", "30"))
    if turns_so_far >= cap:
        return _json(
            429, {"error": f"session cap of {cap} turns reached for this incident"}
        )

    routed = _route_phrase(raw_text) if body.get("mode", "chat") == "chat" else None
    if routed:
        tool, args = routed
        out = _run_tool(
            tool,
            args,
            incident_id=incident_id,
            session_id=session_id,
            transcript=raw_text.strip(),
            channel=channel,
            attestation=attest,
        )
        reply_text = _routed_reply(tool, out["result"])
        tool_events, evidence = out["tool_events"], out["evidence"]
        new_messages = [
            {"role": "user", "content": [{"text": raw_text.strip()}]},
            {"role": "assistant", "content": [{"text": reply_text}]},
        ]
    else:
        ctx = TurnContext(
            incident_id=incident_id,
            session_id=session_id,
            transcript=raw_text.strip(),
            channel=channel,
            passcode_ok=True,
            attestation=attest,
        )
        with turn_context(ctx):
            agent = _build_agent(history=history)
            history_len = len(agent.messages)
            try:
                reply_text = str(agent(text)).strip()
            except Exception as exc:
                # No model, no conversation -- but the exact phrases above never
                # needed one, so say what still works instead of failing the turn.
                logger.warning("agent turn failed: %s", exc)
                reply_text = (
                    "I cannot reach the language model right now, so I can only act "
                    "on exact phrases. Nothing was changed. Type 'approve fix <n>' to "
                    "apply a proposed fix, or 'cancel fix <n>' to withdraw it."
                )
        _record_turn_usage(incident_id, agent)
        tool_events, evidence = ctx.tool_events, ctx.evidence
        new_messages = [m for m in agent.messages[history_len:] if isinstance(m, dict)]

    spoken, cited = strip_citations(reply_text)
    observability.metric("ToolCalls", len(tool_events))
    fresh = store.get_incident(incident_id, table_name=_incidents_table())
    store.update_status(
        incident_id,
        str(fresh.get("status") or incident.get("status") or "awaiting_engineer"),
        table_name=_incidents_table(),
        extra={
            "conversation": (history + new_messages)[-_MAX_HISTORY:],
            "turn_count": turns_so_far + 1,
            "last_channel": channel,
        },
    )
    return _json(
        200,
        {
            "reply_text": reply_text,
            "spoken_text": spoken,
            "cited": cited,
            # Speech is Bolna's job; a typed turn is answered in text.
            "audio_b64": None,
            "speech_marks": [],
            "voice": None,
            "tts_error": None,
            "tool_events": tool_events,
            "evidence": evidence,
            "incident": _public_incident(incident_id),
            "turn": turns_so_far + 1,
        },
    )


@router.get("/brief/{incident_id}")
async def voice_brief_route(incident_id: str, request: Request) -> JSONResponse:
    if not _passcode_ok(request):
        return _json(401, {"error": "passcode required"})
    if not _ID_RE.match(incident_id):
        return _json(400, {"error": "incident_id is required"})
    incident = store.get_incident(incident_id, table_name=_incidents_table())
    if not incident:
        return _json(404, {"error": f"incident {incident_id} not found"})
    channel = str(request.query_params.get("channel") or "browser")[:16]
    language = str(request.query_params.get("language") or "en")[:8]
    return _json(
        200, voice_brief.session_brief(incident, channel=channel, language=language)
    )


# ---------------------------------------------------------------------------
# Bolna: sessions
# ---------------------------------------------------------------------------


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_voice_session(incident_id: str, *, channel: str) -> tuple[str, str]:
    """Create a Night Shift voice session row; returns ``(session_id, token)``.

    The token is a per-call capability Bolna echoes back on every function
    call. Only its hash is stored. It grants reads, proposals and cancellation
    for this one incident for thirty minutes, and never an approval.
    """
    session_id = f"bs_{pysecrets.token_hex(12)}"
    token = pysecrets.token_urlsafe(24)
    now = _now()
    db.put(
        _CALLS,
        session_id,
        {
            "session_id": session_id,
            "incident_id": incident_id,
            "channel": channel,
            "token_hash": _hash(token),
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=_SESSION_TTL_MINUTES)).isoformat(),
            "status": "minted",
            "events": [],
        },
    )
    return session_id, token


def user_data_for(
    incident: dict[str, Any], session_id: str, token: str
) -> dict[str, Any]:
    return {
        "incident_id": incident["incident_id"],
        "beacon_session": session_id,
        "beacon_token": token,
        "incident_brief": voice_brief.brief_context(incident)[:4000],
    }


@router.post("/bolna/session")
async def bolna_session(request: Request) -> JSONResponse:
    """Mint a single-use Bolna web-call session for the authenticated console."""
    if not _passcode_ok(request):
        return _json(401, {"error": "passcode required"})
    body = await request.json()
    incident_id = str(body.get("incident_id", ""))
    if not _ID_RE.match(incident_id):
        return _json(400, {"error": "incident_id is required"})
    incident = store.get_incident(incident_id, table_name=_incidents_table())
    if not incident:
        return _json(404, {"error": f"incident {incident_id} not found"})
    if not bolna.configured():
        return _json(503, {"error": "Bolna is not configured on this deployment"})
    session_id, token = new_voice_session(incident_id, channel="bolna-web")
    try:
        minted = bolna.mint_web_session(user_data_for(incident, session_id, token))
    except bolna.BolnaError as exc:
        logger.warning("bolna mint failed: %s", exc)
        db.patch(_CALLS, session_id, {"status": "mint_failed", "error": str(exc)})
        status = 429 if exc.status == 429 else 502
        return _json(status, {"error": f"could not start a Bolna call: {exc}"})
    db.patch(_CALLS, session_id, {"execution_id": minted.get("run_id")})
    store.append_timeline(
        incident_id,
        "voice_call_started",
        table_name=_incidents_table(),
        detail={"session_id": session_id, "execution_id": minted.get("run_id")},
    )
    return _json(200, {"beacon_session": session_id, "session": minted})


def _session_for(session_id: str, token: str) -> dict[str, Any] | None:
    if not _ID_RE.match(session_id or ""):
        return None
    row = db.get(_CALLS, session_id)
    if not row or not _eq(_hash(token or ""), str(row.get("token_hash") or "")):
        return None
    if str(row.get("expires_at", "")) <= _now().isoformat():
        return None
    return row


# ---------------------------------------------------------------------------
# Bolna: custom function calls
# ---------------------------------------------------------------------------

_INT_ARGS = ("fix_id", "days", "max_uses")


def _client_ip(request: Request) -> str:
    if _env("TRUST_PROXY", "").lower() == "true":
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _ip_allowed(request: Request, env: str) -> bool:
    """True when no allowlist is configured, or the caller is on it."""
    allowed = [a.strip() for a in _env(env).split(",") if a.strip()]
    if not allowed:
        return True
    try:
        ip = ipaddress.ip_address(_client_ip(request))
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(a, strict=False) for a in allowed)


@router.post("/bolna/tools/{name}")
async def bolna_tool(name: str, request: Request) -> JSONResponse:
    """A Bolna custom function calling one Night Shift tool.

    Authenticated twice: the bearer token configured on the agent (proves the
    caller is our Bolna agent) and the per-session token (binds the call to one
    incident). Arguments are whatever the agent's LLM produced, so they are
    validated here and are never treated as the engineer's words.
    """
    bearer = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if not _eq(bearer, secrets.get("BOLNA_TOOL_TOKEN")):
        return _json(401, {"error": "unauthorised"})
    if not _ip_allowed(request, "BOLNA_ALLOWED_IPS"):
        return _json(403, {"error": "source address not allowed"})
    tool = voice_tools.BOLNA_ALIASES.get(name, name)
    if tool not in voice_tools.TOOL_FUNCTIONS:
        return _json(404, {"error": f"unknown tool {name}"})
    try:
        body = dict(await request.json())
    except Exception:
        return _json(400, {"error": "a JSON object is required"})
    session = _session_for(
        str(body.pop("beacon_session", "")), str(body.pop("beacon_token", ""))
    )
    incident_id = str(body.pop("incident_id", ""))
    if session is None or session.get("incident_id") != incident_id:
        return _json(403, {"error": "unknown or expired voice session"})

    claimed = str(body.pop("confirmation_phrase", ""))[:200]
    schema = next(s for s in voice_tools.TOOL_SCHEMAS if s["name"] == tool)
    known = (schema.get("parameters") or {}).get("properties") or {}
    args: dict[str, Any] = {}
    for key, value in body.items():
        if key not in known or value in ("", None):
            continue  # unknown or unfilled template parameters are dropped
        if key in _INT_ARGS:
            try:
                value = int(float(value))
            except (TypeError, ValueError):
                return _json(200, {"error": f"{key} must be a number"})
        args[key] = value
    if "confirmation_phrase" in known:
        args["confirmation_phrase"] = claimed

    def run() -> dict[str, Any]:
        return _run_tool(
            tool,
            args,
            incident_id=incident_id,
            session_id=str(session["session_id"]),
            # What the model says the engineer said. Used only to decide what to
            # read back; the attestation below keeps it from ever being consent.
            transcript=claimed,
            channel="bolna",
            attestation={
                "evidence": "bolna_llm_function_call",
                "stt": None,
                "session_id": session["session_id"],
                "execution_id": session.get("execution_id"),
            },
        )

    import anyio

    out = await anyio.to_thread.run_sync(run)
    db.append(
        _CALLS,
        str(session["session_id"]),
        "events",
        {
            "t": _now().isoformat(),
            "name": tool,
            "args": args,
            "result": out["result"],
            "tool_events": out["tool_events"],
            "evidence": out["evidence"],
        },
    )
    observability.metric("BolnaToolCalls", 1)
    return _json(200, out["result"])


@router.get("/bolna/session/{session_id}/events")
async def bolna_events(session_id: str, request: Request) -> JSONResponse:
    """Tool calls the live call has made so far (the console polls this)."""
    if not _passcode_ok(request):
        return _json(401, {"error": "passcode required"})
    row = db.get(_CALLS, session_id) if _ID_RE.match(session_id) else None
    if not row:
        return _json(404, {"error": "unknown session"})
    after = int(request.query_params.get("after") or 0)
    events = list(row.get("events") or [])
    incident = _public_incident(str(row["incident_id"]))
    return _json(
        200,
        {
            "events": events[after:],
            "next": len(events),
            "status": row.get("status"),
            "pending_confirmations": incident.get("pending_confirmations") or [],
            "incident": incident,
        },
    )


# ---------------------------------------------------------------------------
# Bolna: webhooks, history, recordings, cost
# ---------------------------------------------------------------------------


def _apply_execution(session_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Store what Bolna reported about a call. Metadata only: no approvals."""
    summary = bolna.summarise_execution(data)
    db.patch(
        _CALLS,
        session_id,
        {
            **{k: v for k, v in summary.items() if v is not None},
            "updated_at": _now().isoformat(),
        },
    )
    return summary


@router.post("/bolna/webhook")
async def bolna_webhook(request: Request) -> JSONResponse:
    """Call lifecycle from Bolna: status, transcript, recording, cost.

    A webhook is a report about a call that already happened. It updates the
    call record and the incident timeline and has no path to an approval, so a
    transcript that arrives after the call can never authorise anything.
    """
    secret = secrets.get("BOLNA_WEBHOOK_SECRET")
    given = request.headers.get("x-beacon-webhook-secret") or request.query_params.get(
        "secret", ""
    )
    if not _eq(given, secret):
        return _json(401, {"error": "unauthorised"})
    if not _ip_allowed(request, "BOLNA_WEBHOOK_IPS"):
        return _json(403, {"error": "source address not allowed"})
    try:
        data = dict(await request.json())
    except Exception:
        return _json(400, {"error": "a JSON object is required"})
    execution_id = str(data.get("id") or data.get("execution_id") or "")
    if not _ID_RE.match(execution_id):
        return _json(400, {"error": "execution id missing"})
    rows = db.scan(_CALLS, "doc->>'execution_id' = %s", (execution_id,))
    if not rows:
        return _json(202, {"ok": True, "matched": False})
    row = max(rows, key=lambda r: str(r.get("created_at", "")))
    previous = row.get("status")
    summary = _apply_execution(str(row["session_id"]), data)
    if summary["status"] != previous:
        store.append_timeline(
            str(row["incident_id"]),
            "voice_call_status",
            table_name=_incidents_table(),
            detail={
                "session_id": row["session_id"],
                "execution_id": execution_id,
                "status": summary["status"],
                "duration_seconds": summary["duration_seconds"],
                "total_cost": summary["total_cost"],
            },
        )
    return _json(200, {"ok": True, "matched": True})


def _public_call(row: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in row.items() if k not in ("token_hash",)}


@router.get("/bolna/calls")
async def bolna_calls(request: Request) -> JSONResponse:
    """Night Shift's own record of voice calls, newest first (``?incident_id=``)."""
    if not _passcode_ok(request):
        return _json(401, {"error": "passcode required"})
    incident_id = request.query_params.get("incident_id")
    rows = (
        db.scan(_CALLS, "doc->>'incident_id' = %s", (incident_id,))
        if incident_id
        else db.scan(_CALLS)
    )
    rows.sort(key=lambda r: str(r.get("created_at", "")), reverse=True)
    calls = [
        {k: v for k, v in _public_call(r).items() if k != "events"} for r in rows[:100]
    ]
    costs = [float(c["total_cost"]) for c in calls if c.get("total_cost") is not None]
    return _json(
        200,
        {
            "calls": calls,
            "total_cost": round(sum(costs), 4),
            "costed_calls": len(costs),
        },
    )


@router.get("/bolna/calls/{session_id}")
async def bolna_call(session_id: str, request: Request) -> JSONResponse:
    """One call with transcript, recording reference and cost, refreshed from Bolna."""
    if not _passcode_ok(request):
        return _json(401, {"error": "passcode required"})
    row = db.get(_CALLS, session_id) if _ID_RE.match(session_id) else None
    if not row:
        return _json(404, {"error": "unknown session"})
    if row.get("execution_id") and not row.get("final") and bolna.configured():
        try:
            _apply_execution(session_id, bolna.get_execution(str(row["execution_id"])))
            row = db.get(_CALLS, session_id) or row
        except bolna.BolnaError as exc:
            logger.warning("execution refresh failed: %s", exc)
    return _json(200, {"call": _public_call(row)})


@router.get("/bolna/history")
async def bolna_history(request: Request) -> JSONResponse:
    """Bolna's execution history for the agent (last seven days)."""
    if not _passcode_ok(request):
        return _json(401, {"error": "passcode required"})
    try:
        return _json(200, {"executions": bolna.list_executions()})
    except bolna.BolnaError as exc:
        return _json(
            exc.status if exc.status in (401, 503) else 502, {"error": str(exc)}
        )


@router.get("/bolna/agent")
async def bolna_agent(request: Request) -> JSONResponse:
    """The agent as stored at Bolna, with tokens and webhook URL removed."""
    if not _passcode_ok(request):
        return _json(401, {"error": "passcode required"})
    try:
        return _json(200, {"agent_id": bolna.agent_id(), "agent": bolna.get_agent()})
    except bolna.BolnaError as exc:
        return _json(
            exc.status if exc.status in (401, 503) else 502, {"error": str(exc)}
        )


@router.get("/recordings/{session_id}")
async def recording(session_id: str, request: Request) -> JSONResponse:
    """The recording reference for a call (kept for the Audit view's contract)."""
    if not _passcode_ok(request):
        return _json(401, {"error": "passcode required"})
    row = db.get(_CALLS, session_id) if _ID_RE.match(session_id) else None
    if not row:
        return _json(404, {"error": "no recording for this session"})
    return _json(
        200,
        {
            "session_id": session_id,
            "status": row.get("status"),
            "duration_seconds": row.get("duration_seconds"),
            "audio_url": row.get("recording_url"),
        },
    )


@router.post("/sessions/{session_id}/summary")
async def session_summary(session_id: str, request: Request) -> JSONResponse:
    """Bolna's own summary of a call, when the agent has call summaries on."""
    if not _passcode_ok(request):
        return _json(401, {"error": "passcode required"})
    row = db.get(_CALLS, session_id) if _ID_RE.match(session_id) else None
    if not row:
        return _json(404, {"error": "unknown session"})
    if not row.get("final") and row.get("execution_id") and bolna.configured():
        try:
            _apply_execution(session_id, bolna.get_execution(str(row["execution_id"])))
            row = db.get(_CALLS, session_id) or row
        except bolna.BolnaError as exc:
            return _json(502, {"error": str(exc)})
    if not row.get("summary"):
        return _json(404, {"error": "Bolna has no summary for this call"})
    return _json(
        200,
        {
            "cached": True,
            "summary": row["summary"],
            "seconds": row.get("duration_seconds"),
        },
    )


@router.post("/sessions/{session_id}/attest")
async def session_attest(session_id: str, request: Request) -> JSONResponse:
    """Kept for the Audit view: says plainly that nothing can be scored.

    Bolna gives Night Shift no word-level confidence, and consent is typed, so there
    is no audio to score. Inventing a number here would be worse than none.
    """
    if not _passcode_ok(request):
        return _json(401, {"error": "passcode required"})
    return _json(
        200,
        {
            "ok": False,
            "checks": [],
            "problems": [],
            "note": "No speech confidence is available: approvals are typed, "
            "and Bolna reports no word-level confidence.",
        },
    )
