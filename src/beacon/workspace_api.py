"""The incident workspace API: real backend state for the live console.

Reads are open (like the existing dashboard API); every state-changing route needs the
console passcode.  ``X-Beacon-User`` names the approver in the record (it is an asserted name
bound to the passcode-authenticated session, not an identity provider).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, Response, StreamingResponse

from beacon import analysis, incident_flow, integrations, research
from beacon.dashboard_api import _json, _passcode_ok
from beacon.evidence import ledger

router = APIRouter()
_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")


def _auth(request: Request) -> bool:
    return _passcode_ok(request)


def _user(request: Request) -> str:
    return re.sub(r"[^\w .@-]", "", request.headers.get("x-beacon-user", "engineer"))[:60] or "engineer"


@router.get("/system/integrations")
async def system_integrations() -> Response:
    rows = await asyncio.to_thread(integrations.snapshot)
    return _json(200, {"integrations": rows})


@router.get("/ns/incidents")
async def list_incidents() -> Response:
    from beacon import db

    rows = await asyncio.to_thread(lambda: db.scan(ledger.incidents_table(), "doc ? 'correlation_ids'"))
    rows.sort(key=lambda r: str(r.get("detected_at", "")), reverse=True)
    return _json(200, {"incidents": [{k: r.get(k) for k in ("incident_id", "source_mode", "status", "severity", "affected_service", "alarm_name", "detected_at")} for r in rows[:30]]})


@router.get("/ns/events/recent")
async def recent_events() -> Response:
    return _json(200, {"events": await asyncio.to_thread(ledger.recent_events, 30)})


@router.get("/ns/incidents/{incident_id}")
async def get_incident(incident_id: str) -> Response:
    if not _ID.match(incident_id):
        return _json(400, {"error": "bad id"})
    v = await asyncio.to_thread(incident_flow.view, incident_id)
    return _json(200, v) if v else _json(404, {"error": "not found"})


@router.get("/ns/incidents/{incident_id}/stream")
async def stream(incident_id: str, request: Request) -> StreamingResponse:
    """Server-sent events: pushes the full view whenever persisted state changes."""

    async def gen() -> Any:
        last = ""
        while not await request.is_disconnected():
            v = await asyncio.to_thread(incident_flow.view, incident_id)
            if v and v["digest"] != last:
                last = v["digest"]
                yield f"event: incident\ndata: {json.dumps(v, default=str)}\n\n"
            else:
                yield ": keep-alive\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"cache-control": "no-cache", "x-accel-buffering": "no"})


@router.get("/ns/stream")
async def stream_all(request: Request) -> StreamingResponse:
    """Server-sent events for the incident list: lets the console discover a new incident live."""

    async def gen() -> Any:
        last = ""
        while not await request.is_disconnected():
            data = json.loads((await list_incidents()).body)
            sig = json.dumps(data, sort_keys=True)
            if sig != last:
                last = sig
                yield f"event: incidents\ndata: {sig}\n\n"
            else:
                yield ": keep-alive\n\n"
            await asyncio.sleep(1)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"cache-control": "no-cache", "x-accel-buffering": "no"})


@router.post("/ns/incidents/{incident_id}/research")
async def run_research(incident_id: str, request: Request) -> Response:
    if not _auth(request):
        return _json(401, {"error": "passcode required"})
    if not research.configured():
        return _json(503, {"state": "NOT_CONFIGURED", "error": "TAVILY_API_KEY is not set"})
    v = await asyncio.to_thread(incident_flow.view, incident_id)
    if not v or not v["correlations"]:
        return _json(409, {"error": "no correlation yet; research is derived from the correlated incident"})
    try:
        items = await asyncio.to_thread(research.run, incident_id, {}, v["correlations"][-1])
    except research.ResearchError as exc:
        return _json(502, {"error": exc.category, "detail": exc.detail})
    return _json(200, {"results": len(items)})


@router.post("/ns/incidents/{incident_id}/analyze")
async def run_analysis(incident_id: str, request: Request) -> Response:
    if not _auth(request):
        return _json(401, {"error": "passcode required"})
    v = await asyncio.to_thread(incident_flow.view, incident_id)
    if not v or not v["correlations"]:
        return _json(409, {"error": "no correlation yet"})
    a = await asyncio.to_thread(analysis.analyze, incident_id)
    return _json(200, a.model_dump(mode="json"))


@router.post("/ns/incidents/{incident_id}/proposal")
async def make_proposal(incident_id: str, request: Request) -> Response:
    if not _auth(request):
        return _json(401, {"error": "passcode required"})
    out = await asyncio.to_thread(incident_flow.propose, incident_id)
    return _json(409 if "error" in out else 200, out)


@router.post("/ns/incidents/{incident_id}/proposals/{fix_id}/approve")
async def approve(incident_id: str, fix_id: int, request: Request) -> Response:
    body: dict[str, Any] = {}
    with contextlib.suppress(Exception):
        body = dict(await request.json())
    status, out = await asyncio.to_thread(
        lambda: incident_flow.approve(
            incident_id,
            fix_id,
            typed_phrase=str(body.get("typed_phrase", "")),
            params_hash=str(body.get("params_hash", "")),
            user=_user(request),
            idempotency_key=str(body.get("idempotency_key", "")),
            authenticated=_auth(request),
        )
    )
    return _json(status, out)


@router.post("/ns/incidents/{incident_id}/proposals/{fix_id}/cancel")
async def cancel(incident_id: str, fix_id: int, request: Request) -> Response:
    if not _auth(request):
        return _json(401, {"error": "passcode required"})
    status, out = await asyncio.to_thread(incident_flow.cancel, incident_id, fix_id, user=_user(request))
    return _json(status, out)


@router.get("/ns/incidents/{incident_id}/report")
async def get_report(incident_id: str, format: str = "json") -> Response:
    r = await asyncio.to_thread(incident_flow.report, incident_id)
    if r is None:
        return _json(404, {"error": "not found"})
    if format == "md":
        return PlainTextResponse(incident_flow.report_markdown(r), headers={"content-disposition": f'attachment; filename="{incident_id}-report.md"'})
    return _json(200, r)


# --- demo control (only when a simulator is configured; never touches a real cluster) -------


def _sim() -> str:
    return os.environ.get("SIMULATOR_URL", "").rstrip("/")


@router.post("/demo/trigger")
async def demo_trigger(request: Request) -> Response:
    if not _auth(request):
        return _json(401, {"error": "passcode required"})
    if not _sim():
        return _json(409, {"error": "no DEMO_SIMULATOR configured; the live trigger is `make break-netpol` on a real sandbox cluster"})
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.post(f"{_sim()}/sim/break-netpol")
        return _json(r.status_code, {**r.json(), "source_mode": "DEMO_SIMULATOR"})
    except httpx.HTTPError as exc:
        return _json(502, {"error": f"simulator unreachable: {type(exc).__name__}"})


@router.post("/demo/reset")
async def demo_reset(request: Request) -> Response:
    if not _auth(request):
        return _json(401, {"error": "passcode required"})
    if not _sim():
        return _json(409, {"error": "no DEMO_SIMULATOR configured"})
    from beacon import db

    n = await asyncio.to_thread(_purge_demo_data, db)
    async with httpx.AsyncClient(timeout=5) as c:
        await c.post(f"{_sim()}/sim/reset")
    purged = await _purge_stream()
    return _json(200, {"reset": True, "demo_records_removed": n, "stream_messages_purged": purged, "note": "Pathway keeps in-memory state; `make demo-reset` also restarts the correlator for a fully clean state"})


async def _purge_stream() -> int:
    from beacon import eventbus

    if not eventbus.url():
        return 0
    try:
        nc, js = await eventbus.connect()
        try:
            for subject in ("beacon.events", "beacon.correlations"):
                await js.purge_stream(eventbus.STREAM, subject=subject)
        finally:
            await nc.close()
        return 2
    except Exception:
        return 0


def _purge_demo_data(db: Any) -> int:
    """Delete only records belonging to DEMO_SIMULATOR incidents/events; never LIVE data."""
    n = 0
    inc_rows = db.scan(ledger.incidents_table(), "doc->>'source_mode' = 'DEMO_SIMULATOR'")
    ids = [r["incident_id"] for r in inc_rows]
    for table in (ledger.events_table(),):
        for r in db.scan(table, "doc->>'source_mode' = 'DEMO_SIMULATOR'"):
            db.delete(table, r["event_id"])
            n += 1
    for iid in ids:
        for table, col in ((ledger.corr_table(), "incident_id"), (ledger.research_table(), "incident_id"), (ledger.analysis_table(), "incident_id"), (ledger.trace_table(), "incident_id")):
            for r in db.scan(table, f"doc->>'{col}' = %s", (iid,)):
                key = r.get("correlation_id") or r.get("evidence_id") or r.get("analysis_id") or f"{r['incident_id']}#{r['stage']}#{r['ref']}"
                db.delete(table, key)
                n += 1
        for r in db.scan(os.environ.get("APPROVALS_TABLE_NAME", "approvals"), "doc->>'incident_id' = %s", (iid,)):
            db.delete(os.environ.get("APPROVALS_TABLE_NAME", "approvals"), r["approval_id"])
            n += 1
        db.delete(ledger.incidents_table(), iid)
        n += 1
    return n
