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
run("pytest (unit, contract fakes, Pathway over NATS)", [PY, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"], "contract")
run("web typecheck + build", ["npm", "run", "build"], "static", cwd=ROOT / "web")
integ = api_json("/api/system/integrations")
if integ is None:
    add("browser journey", "e2e", "BLOCKED", "stack not running (make demo-up)")
else:
    root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True).stdout.strip()  # noqa: S603, S607
    run("browser journey (DEMO_SIMULATOR)", ["node", "e2e/journey.mjs"], "e2e", env={"NODE_PATH": root})
    state = {r["integration"]: r for r in integ["integrations"]}
    for name in ("bifrost", "tavily", "omnidimension"):
        s = state[name]["state"]
        if s == "NOT_CONFIGURED":
            add(f"live {name}", "live", "NOT_CONFIGURED", "credentials absent")
        elif s == "CONNECTED":
            add(f"live {name}", "live", "PASS", state[name]["detail"])
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
