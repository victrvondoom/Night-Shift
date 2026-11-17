"""EMULATED data plane for the real-control-plane sandbox (this VM cannot start pods, so no CNI enforces NetworkPolicy).

    python -m beacon.sandbox.dataplane

* ``demo-db``    a tiny TCP server answering ``PING`` with ``+PONG`` (the redis the demo manifests would run)
* the gate       listens where the app expects its database (127.0.0.1:6379) and forwards to ``demo-db`` ONLY while the
                 REAL ``demo/demo-db-ingress`` NetworkPolicy, read from the REAL API server, admits app=demo-api on TCP/6379.
                 Otherwise it accepts and swallows the connection (a dropped packet, as a CNI would), so the app sees a genuine timeout.
* the app        the unmodified ``demo/app.py`` (real code, real metrics, real health endpoint) on :8081
* log shipper    forwards the app's real connection-error log lines to Night Shift's ``/ingest/app-logs``

This is NOT a Kubernetes data plane and is labelled EMULATED_DATAPLANE everywhere it is surfaced.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

from kubernetes import client, config

logging.basicConfig(level=logging.INFO, format="%(asctime)s dataplane %(message)s")
log = logging.getLogger("dataplane")
STATE = {"allowed": True, "checked_at": 0.0, "error": ""}
DB_PORT, GATE_PORT = 16379, int(os.environ.get("GATE_PORT", "6379"))
NS, POLICY = os.environ.get("POLICY_NS", "demo"), os.environ.get("POLICY_NAME", "demo-db-ingress")


def serve_db() -> None:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", DB_PORT))
    s.listen(64)

    def handle(c: socket.socket) -> None:
        with c:
            try:
                if c.recv(16).startswith(b"PING"):
                    c.sendall(b"+PONG\r\n")
            except OSError:
                pass

    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def admits(policy: client.V1NetworkPolicy) -> bool:
    for rule in policy.spec.ingress or []:
        peer_ok = any(((p.pod_selector and p.pod_selector.match_labels) or {}).get("app") == "demo-api" for p in rule._from or [])
        port_ok = any(str(p.protocol or "TCP").upper() == "TCP" and int(p.port) == 6379 for p in rule.ports or [])
        if peer_ok and port_ok:
            return True
    return False


def watch_policy(api: client.NetworkingV1Api) -> None:
    while True:
        try:
            STATE["allowed"] = admits(api.read_namespaced_network_policy(POLICY, NS))
            STATE["error"] = ""
        except Exception as exc:  # an unreachable API server must not silently re-open traffic
            STATE["allowed"], STATE["error"] = False, type(exc).__name__
        STATE["checked_at"] = time.time()
        time.sleep(0.5)


def serve_gate() -> None:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", GATE_PORT))
    s.listen(64)

    def pipe(src: socket.socket, dst: socket.socket) -> None:
        try:
            while data := src.recv(4096):
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for x in (src, dst):
                with contextlib.suppress(OSError):
                    x.shutdown(socket.SHUT_RDWR)

    def handle(c: socket.socket) -> None:
        if not STATE["allowed"]:
            try:  # dropped by policy: no reply, like a filtered packet; the client times out
                c.settimeout(5)
                c.recv(1)
            except OSError:
                pass
            finally:
                c.close()
            return
        try:
            up = socket.create_connection(("127.0.0.1", DB_PORT), timeout=2)
        except OSError:
            c.close()
            return
        threading.Thread(target=pipe, args=(c, up), daemon=True).start()
        threading.Thread(target=pipe, args=(up, c), daemon=True).start()

    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def ship(proc: subprocess.Popen[str]) -> None:
    api = os.environ.get("NIGHTSHIFT_API", "http://127.0.0.1:8080").rstrip("/")
    token = os.environ.get("ALERT_WEBHOOK_TOKEN", "alert-token")
    assert proc.stderr is not None
    for line in proc.stderr:
        line = line.rstrip()
        sys.stderr.write(line + "\n")
        if "database unreachable" not in line:
            continue
        rec = {"id": f"app-{uuid.uuid4().hex[:16]}", "ts": datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "namespace": NS, "app": "demo-api", "line": line.split(" ", 3)[-1]}
        try:
            req = urllib.request.Request(f"{api}/ingest/app-logs", data=json.dumps({"records": [rec]}).encode(), headers={"content-type": "application/json", "authorization": f"Bearer {token}"}, method="POST")  # noqa: S310
            urllib.request.urlopen(req, timeout=5).read()  # noqa: S310
        except Exception as exc:
            log.warning("log ship failed: %s", exc)


def main() -> None:
    kc = os.environ.get("DATAPLANE_KUBECONFIG")
    config.load_kube_config(config_file=kc) if kc else config.load_incluster_config()
    threading.Thread(target=serve_db, daemon=True).start()
    threading.Thread(target=watch_policy, args=(client.NetworkingV1Api(),), daemon=True).start()
    threading.Thread(target=serve_gate, daemon=True).start()
    app = Path(__file__).resolve().parents[3] / "demo" / "app.py"
    env = {**os.environ, "DB_HOST": "demo-db", "DB_PORT": str(GATE_PORT), "PORT": os.environ.get("APP_PORT", "8081"), "APP_VERSION": "v1"}
    proc = subprocess.Popen([sys.executable, str(app)], env=env, stderr=subprocess.PIPE, text=True)  # noqa: S603
    log.info("dataplane up: gate :%s -> demo-db :%s, app :%s (EMULATED_DATAPLANE)", GATE_PORT, DB_PORT, env["PORT"])
    ship(proc)


if __name__ == "__main__":
    main()
