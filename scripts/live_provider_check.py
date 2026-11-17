"""`make live-provider-check`: a small, bounded REAL request per configured provider.

* Bifrost: one tiny chat completion through the gateway; verifies the response carries Bifrost's
  own request id (echo of our x-request-id) and records provider/model/latency as returned.
* Tavily: ONE search (costs ~1 credit) derived from the golden incident's context.
* OmniDimension: creates ONE session only with --voice-session (it does not connect audio).

Unconfigured providers report NOT_CONFIGURED; failures report the real category.  Mock/contract
tests are never counted here.  Writes .agent/live-provider-results.json.  Never prints secrets.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
os.environ.setdefault("DATABASE_URL", "postgresql://beacon:beacon@localhost:5433/beacon")

from live_preflight import load_dotenv  # noqa: E402

load_dotenv()
from beacon import omnidim, research, research_plan  # noqa: E402
from beacon.llm import gateway  # noqa: E402

results: list[dict] = []


def add(provider: str, status: str, detail: str, **extra) -> None:
    results.append({"provider": provider, "status": status, "detail": detail, "kind": "live", **extra})
    print(f"{status:<15} {provider:<14} {detail}")


# --- Bifrost
if not (gateway.configured() and gateway.model()):
    add("bifrost", "NOT_CONFIGURED", "set BIFROST_URL and BIFROST_MODEL")
else:
    ok, d = gateway.probe()
    if not ok:
        add("bifrost", "FAIL", f"gateway not reachable: {d}")
    else:
        rid = f"live-check-{uuid.uuid4().hex[:10]}"
        try:
            r = gateway.chat([{"role": "user", "content": 'Reply with the JSON object {"ok": true}'}], meta={"incident_id": "LIVE-PROVIDER-CHECK", "workflow_stage": "preflight", "purpose": "provider_check", "risk": "none"}, request_id=rid, timeout=30)
            good = r.request_id == rid
            add("bifrost", "PASS" if good else "FAIL", f"request {r.request_id} provider={r.provider} model={r.model} latency_ms={r.latency_ms} usage={r.usage}" + ("" if good else " (gateway did not echo x-request-id)"), request_id=r.request_id, trace_id=r.trace_id, provider_name=r.provider, model=r.model)
        except gateway.GatewayError as exc:
            add("bifrost", "FAIL", f"{exc.category}: {exc.detail[:120]}")

# --- Tavily
if not research.configured():
    add("tavily", "NOT_CONFIGURED", "set TAVILY_API_KEY")
else:
    q = research_plan.plan({"event_types": ["networkpolicy_change"]})[0].query
    status, _, data, cat = research._send("/search", {"query": q, "search_depth": "basic", "max_results": 3, "include_domains": list(research.OFFICIAL), "include_published_date": True})
    if data is None:
        add("tavily", "FAIL", f"search failed: {cat} (HTTP {status})")
    else:
        res = [r for r in (data.get("results") or []) if isinstance(r, dict) and r.get("url")]
        add("tavily", "PASS" if res else "FAIL", f"search HTTP {status}: {len(res)} result(s), request_id={data.get('request_id')}, credits={(data.get('usage') or {}).get('credits')}", request_id=data.get("request_id"))
        if res:
            st2, _, d2, cat2 = research._send("/extract", {"urls": [res[0]["url"]]})
            got = bool(d2 and (d2.get("results") or [{}])[0].get("raw_content"))
            add("tavily-extract", "PASS" if got else "FAIL", f"extract HTTP {st2}: {'content returned' if got else cat2 or 'no content'}, request_id={(d2 or {}).get('request_id')}, credits={((d2 or {}).get('usage') or {}).get('credits')}")

# --- OmniDimension
if not omnidim.configured():
    add("omnidimension", "NOT_CONFIGURED", "set OMNIDIM_API_KEY and OMNIDIM_AGENT_ID (integer)")
elif "--voice-session" not in sys.argv:
    add("omnidimension", "SKIPPED", "configured; pass --voice-session to create one (unconnected) session")
else:
    try:
        s = omnidim.create_session({"incident_brief": "provider check"}, {"purpose": "provider_check"})
        add("omnidimension", "PASS", f"session {s.get('session_id')} created; expires {s.get('expires_at')}; ws_url NOT printed (single-use credential). Browser audio is verified manually in the console.")
    except omnidim.OmniDimError as exc:
        add("omnidimension", "FAIL", f"{exc.category} (HTTP {exc.status})")

(ROOT / ".agent").mkdir(exist_ok=True)
(ROOT / ".agent" / "live-provider-results.json").write_text(json.dumps({"generated_at": datetime.now(tz=UTC).isoformat(), "results": results}, indent=2))
sys.exit(1 if any(r["status"] == "FAIL" for r in results) else 0)
