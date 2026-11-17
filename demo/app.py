"""Demo workload: an API that depends on a database across a NetworkPolicy.

Every two seconds it opens a TCP connection to the database and sends PING.
Success and failure are counted for Prometheus and logged for Loki, so removing
the NetworkPolicy rule produces a real failure, real metrics and real log lines.

``FAIL_MODE=crash`` makes this version exit on start: the "bad deploy".
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("demo-api")
DB_HOST = os.environ.get("DB_HOST", "demo-db")
DB_PORT = int(os.environ.get("DB_PORT", "6379"))
VERSION = os.environ.get("APP_VERSION", "v1")
state = {"ok": 0, "errors": 0, "healthy": False}


def ping() -> None:
    with socket.create_connection((DB_HOST, DB_PORT), timeout=1.5) as s:
        s.sendall(b"PING\r\n")
        if not s.recv(16).startswith(b"+PONG"):
            raise RuntimeError("unexpected reply from database")


def loop() -> None:
    while True:
        try:
            ping()
            state["ok"] += 1
            state["healthy"] = True
        except Exception as exc:
            state["errors"] += 1
            state["healthy"] = False
            log.error("database unreachable at %s:%s: %s", DB_HOST, DB_PORT, exc)
        time.sleep(2)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/metrics":
            body = (
                "# TYPE demo_db_requests_total counter\n"
                f'demo_db_requests_total{{result="ok"}} {state["ok"]}\n'
                f'demo_db_requests_total{{result="error"}} {state["errors"]}\n'
                "# TYPE demo_db_up gauge\n"
                f"demo_db_up {1 if state['healthy'] else 0}\n"
            ).encode()
            code = 200
        elif self.path == "/healthz":  # liveness: the process is up
            body, code = b"ok", 200
        elif self.path == "/ready":  # the dependency actually answers
            code = 200 if state["healthy"] else 503
            body = b"ready" if code == 200 else b"database unreachable"
        else:
            body, code = b"not found", 404
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


if __name__ == "__main__":
    if os.environ.get("FAIL_MODE") == "crash":
        log.error("fatal: invalid configuration in %s (FAIL_MODE=crash); exiting", VERSION)
        sys.exit(1)
    log.info("demo-api %s starting; database %s:%s", VERSION, DB_HOST, DB_PORT)
    threading.Thread(target=loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()  # noqa: S104
