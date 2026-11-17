"""LOCAL FAKE of an OpenAI-compatible upstream. It is NOT a language model.

Used to exercise a *real* Bifrost gateway process end to end without a paid provider key.
It reads the evidence ids out of the request and answers with a schema-valid analysis that cites
only those ids (so the validation path is exercised), records every request's headers/body, and can
be told to fail (HTTP 429 / 500 / garbage / hang) per request via the `x-fake-mode` header or
globally via POST /__mode.
"""

from __future__ import annotations

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SEEN: list[dict] = []
MODE = {"mode": "ok"}


def brief_for(text: str) -> str:
    ids = list(dict.fromkeys(re.findall(r"ext-[0-9a-f]{16}", text)))
    obs = list(dict.fromkeys(re.findall(r"evt-[0-9a-f]{16}", text)))
    return json.dumps(
        {
            "incident_summary": "FAKE-UPSTREAM: a policy change was followed by connection errors (correlation only).",
            "likely_explanation": "FAKE-UPSTREAM: the policy change most likely removed ingress the application needs (unconfirmed).",
            "findings": [
                {"claim": "Pods selected by an ingress NetworkPolicy only accept the listed connections.", "kind": "SOURCE_ESTABLISHED", "evidence_ids": ids[:2]},
                {"claim": "This incident is caused by the removed rule.", "kind": "SOURCE_ESTABLISHED", "evidence_ids": ["ext-ffffffffffffffff"]},
                {"claim": "The change preceded the first error by seconds.", "kind": "MODEL_INFERENCE", "evidence_ids": obs[:1]},
                {"claim": "A slow CNI sync could also explain the delay.", "kind": "HYPOTHESIS", "evidence_ids": []},
            ],
            "hypotheses": ["CNI enforcement lag"],
            "missing_evidence": ["the policy diff", "confirmation that the rule was the only change"],
            "alternative_explanations": ["database restart"],
            "research_gaps": ["cluster-specific CNI behaviour"],
            "next_steps": ["compare the live policy with the golden snapshot"],
            "limitations": ["sources describe general Kubernetes behaviour"],
            "follow_up_queries": ["Kubernetes NetworkPolicy egress semantics for isolated pods", "why did demo-db lose connectivity"],
        }
    )


def analysis_for(messages: list[dict]) -> str:
    text = "\n".join(str(m.get("content", "")) for m in messages)
    if "RESEARCH_SYNTHESIS" in text:
        return brief_for(text)
    ids = re.findall(r"evt-[0-9a-f]{16}", text)
    ids = list(dict.fromkeys(ids))
    return json.dumps(
        {
            "incident_summary": "FAKE-UPSTREAM: network policy change followed by connection errors.",
            "root_cause_hypothesis": "FAKE-UPSTREAM hypothesis: the policy change removed required ingress (unconfirmed).",
            "supporting_event_ids": ids[:4],
            "contradicting_event_ids": [],
            "external_evidence_ids": [],
            "what_is_confirmed": [{"text": "events were recorded", "evidence_ids": ids[:1]}] if ids else [],
            "what_is_unknown": ["root cause is not confirmed"],
            "recommended_action_id": "networkpolicy.restore_ingress",
            "reasoning_summary": "fake upstream, schema exercise only",
            "risk_summary": "one rule on one policy",
            "requires_human_approval": True,
        }
    )


def make_handler(name: str):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            if self.path == "/__mode":
                MODE["mode"] = json.loads(self.rfile.read(int(self.headers["Content-Length"]))).get("mode", "ok")
                return self._send(200, {"mode": MODE["mode"]})
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            SEEN.append({"upstream": name, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "model": body.get("model")})
            mode = self.headers.get("x-fake-mode") or MODE["mode"]
            if mode == "hang":
                time.sleep(60)
            if mode == "429":
                return self._send(429, {"error": {"message": "rate limited", "type": "rate_limit"}})
            if mode == "500" or (mode == "primary_down" and name == "A"):
                return self._send(500, {"error": {"message": "upstream exploded", "type": "server_error"}})
            content = "this is not json {" if mode == "garbage" else analysis_for(body.get("messages", []))
            self._send(200, {"id": f"chatcmpl-fake-{name}-{len(SEEN)}", "object": "chat.completion", "created": int(time.time()), "model": body.get("model", "fake"), "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 11, "completion_tokens": 22, "total_tokens": 33}})

        def do_GET(self):  # noqa: N802
            self._send(200, SEEN[-20:] if self.path == "/__seen" else {"fake": True, "upstream": name})

        def _send(self, code, payload):
            raw = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass

    return H


if __name__ == "__main__":
    for name, port in (("A", 9300), ("B", 9301)):
        srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(name))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    print("fake upstreams on 9300 (A) and 9301 (B)", flush=True)
    while True:
        time.sleep(3600)
