"""Machine-readable verification: PASS | FAIL | SKIPPED | BLOCKED | NOT_CONFIGURED.

Mock/contract tests are reported as ``kind: contract`` and never count as live-provider verification.
Writes .agent/verification-results.json.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
results: list[dict[str, str]] = []


def add(name: str, kind: str, status: str, detail: str) -> None:
    results.append({"check": name, "kind": kind, "status": status, "detail": detail})


def run(name: str, cmd: list[str], kind: str, cwd: Path = ROOT, env: dict[str, str] | None = None) -> bool:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env={**os.environ, **(env or {})})  # noqa: S603
    tail = (p.stdout + p.stderr).strip().splitlines()[-1:] or [""]
    add(name, kind, "PASS" if p.returncode == 0 else "FAIL", tail[0][:200])
    return p.returncode == 0


def api_json(path: str):
    try:
        with urllib.request.urlopen(os.environ.get("API", "http://127.0.0.1:8080") + path, timeout=3) as r:  # noqa: S310
            return json.load(r)
    except Exception:
        return None


run("ruff", [PY, "-m", "ruff", "check", "src", "tests", "scripts"], "static")
for _f in ("test_live_providers.py",):
    _p = subprocess.run([PY, "-m", "pytest", f"tests/{_f}", "-q", "-p", "no:cacheprovider", "-rs"], cwd=ROOT, capture_output=True, text=True)  # noqa: S603
    _t = (_p.stdout.strip().splitlines() or [""])[-1]
    add("pytest: LIVE Tavily / Bifrost-provider / OmniDimension calls", "live", "NOT_CONFIGURED" if "skipped" in _t and " passed" not in _t else ("PASS" if _p.returncode == 0 else "FAIL"), _t)
run("pytest: unit + contract fakes + local NATS/Pathway/OPA/PG integration", [PY, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider", "--ignore=tests/test_live_bifrost.py"], "contract+local")
p = subprocess.run([PY, "-m", "pytest", "tests/test_live_bifrost.py", "-q", "-p", "no:cacheprovider"], cwd=ROOT, capture_output=True, text=True)  # noqa: S603
tail = (p.stdout.strip().splitlines() or [""])[-1]
status = "FAIL" if p.returncode else ("SKIPPED" if " passed" not in tail else "PASS")
add("pytest: REAL Bifrost gateway process, LOCAL FAKE upstream model (not a live LLM)", "live-gateway", status, tail if status != "SKIPPED" else "no gateway running on :8088 (see docs/HACKATHON.md)")
run("web unit tests (transcript semantics)", ["npm", "test"], "unit", cwd=ROOT / "web")
run("web typecheck + build", ["npm", "run", "build"], "static", cwd=ROOT / "web")
integ = api_json("/api/system/integrations")
if integ is None:
    add("browser journey", "e2e", "BLOCKED", "stack not running (make demo-up)")
else:
    root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()  # noqa: S603, S607
    state = {r["integration"]: r for r in integ["integrations"]}
    k8s_mode = state["kubernetes"]["mode"]
    if k8s_mode.startswith("REAL_CONTROL_PLANE"):
        run("browser journey: REAL k3s control plane + real Prometheus/Alertmanager + EMULATED data plane (e2e/live_journey.mjs)", ["node", "e2e/live_journey.mjs"], "e2e-k3s", env={"NODE_PATH": root})
        p = subprocess.run([PY, "-m", "pytest", "tests/test_live_k3s.py", "-q", "-p", "no:cacheprovider"], cwd=ROOT, capture_output=True, text=True)  # noqa: S603
        tail = (p.stdout.strip().splitlines() or [""])[-1]
        add("pytest: real k3s API server RBAC matrix, 403s, dry-run, optimistic concurrency, snapshot + context guards", "live-k3s", "PASS" if p.returncode == 0 and " passed" in tail else "FAIL", tail)
    else:
        run("browser journey (DEMO_SIMULATOR; NOT a real cluster)", ["node", "e2e/journey.mjs"], "e2e", env={"NODE_PATH": root})
        add("browser journey on a real k3s control plane", "e2e-k3s", "BLOCKED", f"kubernetes mode is {k8s_mode}; start with DEMO_MODE=k3s make demo-up")
    if k8s_mode.startswith("REAL_CONTROL_PLANE"):
        add("browser research journey", "e2e", "BLOCKED", "e2e/research.mjs drives the DEMO_SIMULATOR buttons; run it in sim mode (DEMO_MODE=sim) with the Tavily contract fake")
    elif state["tavily"]["state"] == "NOT_CONFIGURED":
        add("browser research journey", "e2e", "BLOCKED", "Tavily not configured; to run against the CONTRACT FAKE: python tests/fixtures/fake_tavily.py & TAVILY_API_KEY=fake TAVILY_API_URL=http://127.0.0.1:9400 make demo-up (not live evidence)")
    else:
        run("browser research journey (Tavily endpoint as configured; a contract fake is NOT live evidence)", ["node", "e2e/research.mjs"], "e2e", env={"NODE_PATH": root})
    add("voice: real OmniDimension session, microphone, barge-in", "live", "BLOCKED", "needs OMNIDIM_API_KEY/OMNIDIM_AGENT_ID and a human with a microphone; manual procedure in docs/PHASE_IV.md")
    add("execution mode", "info", "PASS", f"temporal={state['temporal']['mode']}/{state['temporal']['state']} kubernetes={state['kubernetes']['mode']}/{state['kubernetes']['state']}")
    for name in ("bifrost", "tavily", "omnidimension"):
        s = state[name]["state"]
        if s == "NOT_CONFIGURED":
            add(f"live {name}", "live", "NOT_CONFIGURED", "credentials absent")
        elif s == "CONNECTED":
            add(f"live {name}", "live", "PASS", f"observed interactions: {state[name]['success_count']} ok / {state[name]['failure_count']} failed")
        else:
            add(f"live {name}", "live", "SKIPPED", f"state {s}: no successful live interaction recorded yet")
    for name in ("nats", "pathway", "opa", "postgresql"):
        add(f"service {name}", "live", "PASS" if state[name]["state"] == "CONNECTED" else "FAIL", state[name]["detail"][:120])
out = {"generated_at": datetime.now(tz=UTC).isoformat(), "results": results}
(ROOT / ".agent").mkdir(exist_ok=True)
(ROOT / ".agent" / "verification-results.json").write_text(json.dumps(out, indent=2))
for r in results:
    print(f"{r['status']:<15} {r['kind']:<9} {r['check']}  {r['detail']}")
sys.exit(1 if any(r["status"] == "FAIL" for r in results) else 0)
