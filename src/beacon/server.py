"""The Night Shift API: one FastAPI app for ingestion, the dashboard and voice.

    uvicorn beacon.server:app --host 0.0.0.0 --port 8080

* ``/alerts``        Alertmanager webhook  -> NATS ``beacon.alerts``
* ``/k8s/audit``     Kubernetes audit webhook -> NATS ``beacon.changes``
* ``/github/events`` GitHub webhook (HMAC verified) -> NATS ``beacon.changes``
* ``/api/*``         read-only dashboard API for the console
* ``/voice/*``       typed turns, console tools and the OmniDimension integration
* ``/metrics``       Prometheus exposition

The API holds no Kubernetes write permission: every change is made by the
worker. Without NATS (``NATS_URL`` unset) events are handled in-process, which
is what the tests and a single-process run use.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from beacon import (
    auth,
    changes,
    dashboard_api,
    db,
    eventbus,
    events,
    ingest,
    secrets,
    voice_turn,
    workspace_api,
)
from beacon.evidence import normalize

logger = logging.getLogger("beacon.server")
logging.basicConfig(level=logging.INFO)


class _NoTokenPaths(logging.Filter):
    """Keep the audit webhook (token in its path) out of the access log."""

    def filter(self, record: logging.LogRecord) -> bool:
        return "/k8s/audit/" not in record.getMessage()


logging.getLogger("uvicorn.access").addFilter(_NoTokenPaths())

app = FastAPI(title="Night Shift", docs_url=None, redoc_url=None)
_origins = [
    o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()
]
if _origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["content-type", "x-beacon-passcode", "x-csrf-token"],
    )
app.include_router(dashboard_api.router, prefix="/api")
app.include_router(workspace_api.router, prefix="/api")
app.include_router(auth.router, prefix="/api/auth")
app.include_router(voice_turn.router, prefix="/voice")


def _token_ok(request: Request, name: str) -> bool:
    """Shared-secret check for cluster-internal webhooks (bearer or ?token=)."""
    expected = secrets.get(name)
    given = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    given = given or request.query_params.get("token", "")
    return bool(expected and given) and hmac.compare_digest(
        given.encode(), expected.encode()
    )


async def _emit(subject: str, payload: dict[str, Any], dedup_id: str = "") -> None:
    if eventbus.url():
        await eventbus.publish(subject, payload, dedup_id=dedup_id)
        return
    if subject == eventbus.ALERTS:
        from beacon import handler

        asyncio.get_running_loop().run_in_executor(None, handler.handler, payload, None)
    else:
        kind = str(payload.get("kind"))
        row = (
            changes.from_audit_event(payload["event"])
            if kind == "k8s_audit"
            else changes.from_github_event(kind, payload["event"])
        )
        if row:
            await asyncio.to_thread(changes.record, row)


@app.get("/healthz")
async def healthz() -> JSONResponse:
    ok = await asyncio.to_thread(db.ping)
    return JSONResponse({"ok": ok}, status_code=200 if ok else 503)


@app.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/alerts")
async def alertmanager(request: Request) -> JSONResponse:
    """Alertmanager webhook: one event per firing alert."""
    if not _token_ok(request, "ALERT_WEBHOOK_TOKEN"):
        return JSONResponse({"error": "unauthorised"}, status_code=401)
    payload = await request.json()
    firing = events.firing_alerts(payload)
    for alert in firing:
        dedup = f"{alert.get('fingerprint')}-{alert.get('startsAt')}"
        await _emit(eventbus.ALERTS, {"alert": alert}, dedup_id=dedup)
        ev = normalize.from_alert(alert)
        if ev:
            await ingest.publish_event(ev, normalize.redact_payload(alert))
    return JSONResponse({"accepted": len(firing)})


@app.post("/k8s/audit")
@app.post("/k8s/audit/{path_token}")
async def k8s_audit(request: Request, path_token: str = "") -> JSONResponse:
    """Kubernetes audit webhook backend: an ``EventList`` of audit events.

    The API server will not send a bearer token over plain HTTP, so on a local
    cluster (where the webhook is the node's own loopback NodePort) the token
    rides in the path. Over HTTPS, use the Authorization header instead.
    """
    expected = secrets.get("AUDIT_WEBHOOK_TOKEN")
    by_path = bool(expected and path_token) and hmac.compare_digest(
        path_token.encode(), expected.encode()
    )
    if not (by_path or _token_ok(request, "AUDIT_WEBHOOK_TOKEN")):
        return JSONResponse({"error": "unauthorised"}, status_code=401)
    payload = await request.json()
    n = 0
    for item in payload.get("items") or []:
        if changes.from_audit_event(item) is None:
            continue  # reads, dry runs and controller noise never reach the bus
        await _emit(
            eventbus.CHANGES,
            {"kind": "k8s_audit", "event": item},
            dedup_id=str(item.get("auditID") or ""),
        )
        ev = normalize.from_audit(item)
        if ev:
            await ingest.publish_event(ev, normalize.redact_payload(item))
        n += 1
    return JSONResponse({"accepted": n})


@app.post("/github/events")
async def github_events(request: Request) -> JSONResponse:
    """GitHub webhook: deployments and pushes, verified by ``X-Hub-Signature-256``."""
    secret = secrets.get("GITHUB_WEBHOOK_SECRET")
    raw = await request.body()
    given = request.headers.get("x-hub-signature-256", "")
    want = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not secret or not hmac.compare_digest(given.encode(), want.encode()):
        return JSONResponse({"error": "bad signature"}, status_code=401)
    kind = request.headers.get("x-github-event", "")
    if kind not in ("deployment", "deployment_status", "push"):
        return JSONResponse({"accepted": 0})
    await _emit(
        eventbus.CHANGES,
        {"kind": kind, "event": json.loads(raw)},
        dedup_id=request.headers.get("x-github-delivery", ""),
    )
    gh = normalize.from_github(kind, json.loads(raw), request.headers.get("x-github-delivery", ""))
    if gh:
        await ingest.publish_event(gh, normalize.redact_payload(json.loads(raw)))
    return JSONResponse({"accepted": 1})


@app.post("/ingest/app-logs")
async def app_logs(request: Request) -> JSONResponse:
    """Application log shipper -> normalised events (only connection-error lines qualify)."""
    if not (_token_ok(request, "APP_LOG_WEBHOOK_TOKEN") or _token_ok(request, "ALERT_WEBHOOK_TOKEN")):
        return JSONResponse({"error": "unauthorised"}, status_code=401)
    payload = await request.json()
    records = payload.get("records") or []
    n = 0
    for rec in records:
        ev = normalize.from_app_log(rec) if isinstance(rec, dict) else None
        if ev:
            await ingest.publish_event(ev, normalize.redact_payload(rec))
            n += 1
    return JSONResponse({"accepted": n, "ignored": len(records) - n})


@app.post("/api/schedule/morning-report")
async def morning_report(request: Request) -> JSONResponse:
    """Run by the Kubernetes CronJob at 07:00 local time."""
    if not _token_ok(request, "ALERT_WEBHOOK_TOKEN"):
        return JSONResponse({"error": "unauthorised"}, status_code=401)
    from beacon import handler

    out = await asyncio.to_thread(handler.handler, {"mode": "morning_report"}, None)
    return JSONResponse(db._plain(out))
