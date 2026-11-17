"""DEMO_SIMULATOR: a deterministic stand-in for the isolated demo cluster.

    python -m beacon.sim.server        # :8090

It does **not** touch any real Kubernetes cluster.  It holds one NetworkPolicy
(``demo/demo-db-ingress``) in memory and exposes just enough of Kubernetes,
Prometheus and the demo app for Night Shift's unchanged code paths:

* ``/k8s/...``     NetworkPolicy / ConfigMap reads + JSON-patch (used via ``beacon.k8s``
                   when ``SIMULATOR_URL`` is set);
* ``/prom/...``    Prometheus HTTP API subset (query, query_range, rules);
* ``/app/ready``   the demo API readiness probe;
* ``/sim/*``       control: break-netpol, reset, info.

Breaking the policy publishes events through Night Shift's real webhooks
(``/k8s/audit``, ``/alerts``, ``/ingest/app-logs``), every one labelled
``DEMO_SIMULATOR``.  Recovery happens only when the NetworkPolicy is actually
patched back through the shim, so the same verification checks run for real.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import time
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

MODE = "DEMO_SIMULATOR"
MODE_KEY = "nightshift.io/source-mode"
RUN_KEY = "nightshift.io/run-id"
NS, POLICY = "demo", "demo-db-ingress"
GOLDEN_RULE = {
    "from": [{"podSelector": {"matchLabels": {"app": "demo-api"}}}],
    "ports": [{"protocol": "TCP", "port": 6379}],
}
REMEDIATOR = "system:serviceaccount:beacon:beacon-remediator"
ALERT_EXPR = 'sum by (namespace) (rate(demo_db_requests_total{result="error"}[30s])) > 0'

app = FastAPI(title="Night Shift DEMO_SIMULATOR", docs_url=None, redoc_url=None)


def _api() -> str:
    return os.environ.get("NIGHTSHIFT_API", "http://localhost:8080").rstrip("/")


def _recovery_delay() -> float:
    return float(os.environ.get("SIM_RECOVERY_DELAY", "3"))


def _alert_delay() -> float:
    return float(os.environ.get("SIM_ALERT_DELAY", "6"))


def _z(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class State:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.rv = 1
        self.ingress: list[dict[str, Any]] = [copy.deepcopy(GOLDEN_RULE)]
        self.broken_at: float | None = None
        self.restored_at: float | None = None
        self.alert_fired_at: float | None = None
        self.emitted = {"audit": 0, "logs": 0, "alerts": 0}
        self.run_id = uuid.uuid4().hex[:8]
        self.generation = getattr(self, "generation", 0) + 1

    @property
    def rule_present(self) -> bool:
        return any(r == GOLDEN_RULE for r in self.ingress)

    @property
    def healthy(self) -> bool:
        if self.broken_at is None:
            return True
        return self.rule_present and self.restored_at is not None and time.time() >= self.restored_at + _recovery_delay()

    @property
    def alert_firing(self) -> bool:
        return self.alert_fired_at is not None and not self.healthy


S = State()


def _policy() -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": POLICY, "namespace": NS, "resourceVersion": str(S.rv)},
        "spec": {
            "podSelector": {"matchLabels": {"app": "demo-db"}},
            "policyTypes": ["Ingress"],
            "ingress": S.ingress,
        },
    }


def _audit(verb: str, user: str) -> dict[str, Any]:
    now = time.time()
    return {
        "kind": "Event",
        "apiVersion": "audit.k8s.io/v1",
        "auditID": f"sim-{S.run_id}-{uuid.uuid4().hex[:10]}",
        "stage": "ResponseComplete",
        "verb": verb,
        "requestURI": f"/apis/networking.k8s.io/v1/namespaces/{NS}/networkpolicies/{POLICY}",
        "user": {"username": user},
        "userAgent": "kubectl/sim" if user != REMEDIATOR else "beacon-remediator/sim",
        "sourceIPs": ["127.0.0.1"],
        "objectRef": {"resource": "networkpolicies", "namespace": NS, "name": POLICY, "apiVersion": "networking.k8s.io/v1"},
        "responseStatus": {"code": 200},
        "requestReceivedTimestamp": _z(now),
        "stageTimestamp": _z(now),
        "annotations": {MODE_KEY: MODE, RUN_KEY: S.run_id},
    }


async def _post(path: str, body: dict[str, Any], token_env: str) -> None:
    token = os.environ.get(token_env, "")
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.post(f"{_api()}{path}", json=body, headers={"authorization": f"Bearer {token}"})
            r.raise_for_status()
    except Exception as exc:  # the simulator must never crash on a down API
        print(f"sim: POST {path} failed: {exc}")


async def _emit_audit(verb: str, user: str) -> None:
    await _post("/k8s/audit", {"items": [_audit(verb, user)]}, "AUDIT_WEBHOOK_TOKEN")
    S.emitted["audit"] += 1


async def _scenario(gen: int) -> None:
    """While the policy stays broken: connection-error logs every 2 s, one alert after a delay."""
    t0 = time.time()
    n = 0
    while gen == S.generation and not S.rule_present and n < 6:
        n += 1
        rec = {
            "id": f"sim-{S.run_id}-log-{n}",
            "ts": _z(time.time()),
            "namespace": NS,
            "app": "demo-api",
            "target_app": "demo-db",
            "line": "ERROR database unreachable at demo-db:6379: timed out",
            "source_mode": MODE,
            "run_id": S.run_id,
        }
        await _post("/ingest/app-logs", {"records": [rec]}, "ALERT_WEBHOOK_TOKEN")
        S.emitted["logs"] += 1
        if S.alert_fired_at is None and time.time() - t0 >= _alert_delay():
            S.alert_fired_at = time.time()
            starts = _z(S.alert_fired_at)
            alert = {
                "status": "firing",
                "fingerprint": f"sim{S.run_id}",
                "startsAt": starts,
                "labels": {"alertname": "DemoDbErrors", "namespace": NS, "service": "demo-api", "severity": "page"},
                "annotations": {
                    "summary": "demo-api cannot reach demo-db",
                    "description": "database connection errors > 0 over 30s in namespace demo",
                    "beacon_health_url": f"http://127.0.0.1:{os.environ.get('SIM_PORT', '8090')}/app/ready",
                    MODE_KEY: MODE,
                    RUN_KEY: S.run_id,
                },
            }
            await _post("/alerts", {"version": "4", "status": "firing", "alerts": [alert]}, "ALERT_WEBHOOK_TOKEN")
            S.emitted["alerts"] += 1
        await asyncio.sleep(2)


@app.post("/sim/break-netpol")
async def break_netpol() -> JSONResponse:
    if S.broken_at is not None and not S.healthy:
        return JSONResponse({"error": "already broken; POST /sim/reset first"}, status_code=409)
    S.reset()
    S.ingress = []  # the same change demo/trigger.sh break-netpol applies for real
    S.rv += 1
    S.broken_at = time.time()
    await _emit_audit("patch", "sim:demo-operator")
    asyncio.get_running_loop().create_task(_scenario(S.generation))
    return JSONResponse({"mode": MODE, "run_id": S.run_id, "broken_at": _z(S.broken_at), "policy": f"{NS}/{POLICY}"})


@app.post("/sim/reset")
async def reset() -> JSONResponse:
    S.reset()
    return JSONResponse({"mode": MODE, "reset": True})


@app.get("/sim/info")
async def info() -> JSONResponse:
    return JSONResponse(
        {
            "mode": MODE,
            "note": "in-memory simulator; no real Kubernetes cluster is read or changed",
            "policy": f"{NS}/{POLICY}",
            "ingress_rules": len(S.ingress),
            "broken_at": _z(S.broken_at) if S.broken_at else None,
            "restored_at": _z(S.restored_at) if S.restored_at else None,
            "healthy": S.healthy,
            "alert_firing": S.alert_firing,
            "emitted": S.emitted,
            "run_id": S.run_id,
        }
    )


# --- Kubernetes shim ----------------------------------------------------------------


@app.get("/k8s/apis/networking.k8s.io/v1/namespaces/{ns}/networkpolicies/{name}")
async def get_np(ns: str, name: str) -> JSONResponse:
    if (ns, name) != (NS, POLICY):
        return JSONResponse({"reason": "NotFound", "message": f"networkpolicy {ns}/{name} not found"}, status_code=404)
    return JSONResponse(_policy())


@app.patch("/k8s/apis/networking.k8s.io/v1/namespaces/{ns}/networkpolicies/{name}")
async def patch_np(ns: str, name: str, request: Request) -> JSONResponse:
    if (ns, name) != (NS, POLICY):
        return JSONResponse({"reason": "NotFound", "message": "not found"}, status_code=404)
    ops = await request.json()
    dry = request.query_params.get("dryRun") == "All"
    new_ingress = S.ingress
    for op in ops:
        if op["op"] == "test" and op["path"] == "/metadata/resourceVersion":
            if str(op["value"]) != str(S.rv):
                return JSONResponse({"reason": "Conflict", "message": "resourceVersion changed"}, status_code=409)
        elif op["op"] == "add" and op["path"] == "/spec/ingress":
            new_ingress = op["value"]
        else:
            return JSONResponse({"reason": "Invalid", "message": f"unsupported op {op}"}, status_code=422)
    result = _policy()
    result["spec"]["ingress"] = new_ingress
    if dry:
        return JSONResponse(result)
    S.ingress = new_ingress
    S.rv += 1
    if S.rule_present and S.broken_at is not None and S.restored_at is None:
        S.restored_at = time.time()
    await _emit_audit("patch", REMEDIATOR)
    return JSONResponse(_policy())


@app.get("/k8s/api/v1/namespaces/{ns}/configmaps/{name}")
async def get_cm(ns: str, name: str) -> JSONResponse:
    data = json.dumps({f"{NS}/{POLICY}": [GOLDEN_RULE]}, sort_keys=True)
    return JSONResponse({"metadata": {"name": name, "namespace": ns}, "data": {"snapshot.json": data}})


# --- Prometheus subset ----------------------------------------------------------------


@app.get("/prom/api/v1/rules")
async def rules() -> JSONResponse:
    rule = {"name": "DemoDbErrors", "query": ALERT_EXPR, "type": "alerting", "state": "firing" if S.alert_firing else "inactive"}
    return JSONResponse({"status": "success", "data": {"groups": [{"name": "demo", "rules": [rule]}]}})


@app.get("/prom/api/v1/query")
async def prom_query(query: str) -> JSONResponse:
    if query.startswith("ALERTS{"):
        res = [{"metric": {"alertname": "DemoDbErrors", "alertstate": "firing", "namespace": NS}, "value": [time.time(), "1"]}] if S.alert_firing else []
    else:
        res = [{"metric": {"namespace": NS}, "value": [time.time(), "0.5"]}] if not S.healthy else []
    return JSONResponse({"status": "success", "data": {"resultType": "vector", "result": res}})


@app.get("/prom/api/v1/query_range")
async def prom_range(query: str, start: float, end: float, step: int = 15) -> JSONResponse:
    values: list[list[Any]] = []
    if query.startswith("ALERTS{") and S.alert_fired_at is not None:
        stop = time.time() if S.alert_firing else (S.restored_at or time.time()) + _recovery_delay()
        t = max(start, S.alert_fired_at)
        while t <= min(end, stop):
            values.append([t, "1"])
            t += max(step, 1)
        if not S.alert_firing and (not values or values[-1][0] < stop - 1):
            values.append([min(end, stop), "1"])
    res = [{"metric": {"alertname": "DemoDbErrors"}, "values": values}] if values else []
    return JSONResponse({"status": "success", "data": {"resultType": "matrix", "result": res}})


# --- demo app ------------------------------------------------------------------------


@app.get("/app/ready")
async def ready() -> JSONResponse:
    if S.healthy:
        return JSONResponse({"ready": True, "mode": MODE})
    return JSONResponse({"ready": False, "reason": "database unreachable", "mode": MODE}, status_code=503)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("SIM_PORT", "8090")))
