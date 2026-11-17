"""LOCAL CONTRACT FAKE of the Tavily HTTP API (search + extract). NOT Tavily; never counts as live evidence.

Shapes follow the current official reference: search -> {results:[{title,url,content,score,published_date(RFC 2822),...}],
response_time, usage:{credits}, request_id}; extract -> {results:[{url,raw_content}], failed_results:[{url,error}], usage, request_id};
errors -> {"detail": {"error": ...}}.  Modes are switched with POST /__mode.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGES = [
    ("Network Policies", "https://kubernetes.io/docs/concepts/services-networking/network-policies/", "By default pods are non-isolated for ingress. Once selected by an ingress policy a pod is isolated and only accepts listed connections (default deny).", "Tue, 11 Mar 2025 17:00:00 GMT", 0.93),
    ("Debug Services", "https://kubernetes.io/docs/tasks/debug/debug-application/debug-service/", "Troubleshooting service connectivity: check endpoints, DNS and network policy.", None, 0.71),
    ("Declare Network Policy", "https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/", "Network policies are enforced by the network plugin; an isolated pod rejects ingress not allowed by a policy.", "not a real date", 0.64),
    ("Blog post", "https://example.com/netpol-tips", "Some random tips about policies.", "Mon, 01 Jan 2024 10:00:00 GMT", 0.3),
]


EXTRA = ("Network Policy egress", "https://kubernetes.io/docs/concepts/services-networking/network-policies/#egress-extra", "Egress policies: once selected by an egress policy a pod is isolated for egress and only allowed destinations are reachable (default deny ingress and egress isolation).", "Wed, 12 Mar 2025 09:00:00 GMT", 0.88)


class State:
    mode = "ok"
    seen: list[dict] = []
    calls = 0
    extract_version = 1
    delay = 0.0


def handler_cls():
    class H(BaseHTTPRequestHandler):
        def _send(self, code, payload, headers=None):
            raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):  # noqa: N802
            self._send(200, State.seen[-50:] if self.path == "/__seen" else {"fake": "tavily"})

        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            if self.path == "/__mode":
                State.mode = body.get("mode", "ok")
                State.extract_version = int(body.get("extract_version", State.extract_version))
                State.delay = float(body.get("delay", State.delay))
                return self._send(200, {"mode": State.mode})
            if self.path == "/__reset":
                State.seen.clear(); State.calls = 0; State.mode = "ok"; State.delay = 0.0
                return self._send(200, {})
            State.calls += 1
            State.seen.append({"path": self.path, "body": body, "auth": self.headers.get("Authorization"), "n": State.calls})
            if State.delay:
                time.sleep(State.delay)
            m, n = State.mode, State.calls
            if m == "401" or self.headers.get("Authorization") == "Bearer bad":
                return self._send(401, {"detail": {"error": "Unauthorized: missing or invalid API key."}})
            if m == "403":
                return self._send(403, {"detail": {"error": "Forbidden"}})
            if m == "429" or (m == "429_then_ok" and n == 1):
                return self._send(429, {"detail": {"error": "rate limited"}}, {"Retry-After": "0"})
            if m == "500" or (m == "500_then_ok" and n == 1):
                return self._send(500, {"detail": {"error": "boom"}})
            if m == "hang":
                time.sleep(30)
            if m == "garbage":
                return self._send(200, b"<html>not json</html>")
            if m == "432":
                return self._send(432, {"detail": {"error": "plan limit"}})
            rid = str(uuid.uuid4())
            if self.path == "/extract":
                if m == "extract_500":
                    return self._send(500, {"detail": {"error": "extract down"}})
                urls = body.get("urls") or []
                ok = [{"url": u, "raw_content": f"FULL PAGE TEXT v{State.extract_version} for {u}: isolated ingress default deny"} for u in urls if "fail" not in u and m != "partial_extract"]
                failed = [{"url": u, "error": "extraction failed"} for u in urls if "fail" in u or m == "partial_extract"]
                if m == "partial_extract" and urls:
                    ok = [{"url": urls[0], "raw_content": f"FULL PAGE TEXT v{State.extract_version}"}]
                    failed = [{"url": u, "error": "extraction failed"} for u in urls[1:]]
                return self._send(200, {"results": ok, "failed_results": failed, "response_time": 0.5, "usage": {"credits": 1}, "request_id": rid})
            if m == "empty":
                results = []
            elif m == "missing_fields":
                results = [{"title": "no url", "content": "x"}, {"url": "https://kubernetes.io/docs/a", "title": "t"}, "junk"]
            else:
                pages = PAGES + ([EXTRA] if "egress" in str(body.get("query", "")).lower() or "ipblock" in str(body.get("query", "")).lower() else [])
                results = [{"title": t, "url": u, "content": c, "score": s, **({"published_date": d} if d else {})} for t, u, c, d, s in pages]
            payload = {"query": body.get("query"), "results": results, "response_time": "0.8", "usage": {"credits": 1}, "request_id": rid}
            if m == "no_results_key":
                payload.pop("results")
            self._send(200, payload)

        def log_message(self, *a):
            pass

    return H


def start(port: int = 0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler_cls())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"


if __name__ == "__main__":
    import os

    _, url = start(int(os.environ.get("FAKE_TAVILY_PORT", "9400")))
    print("fake tavily on", url, flush=True)
    while True:
        time.sleep(3600)
