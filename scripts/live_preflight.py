"""`make live-preflight`: report configuration and service availability. Reads, never mutates, never prints secrets.

Exit status 0 if nothing REQUIRED is missing; optional integrations just report NOT_CONFIGURED.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import urllib.request
from pathlib import Path


def load_dotenv() -> None:
    env = Path(__file__).resolve().parents[1] / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if line.strip() and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.split("#")[0].strip())


def present(name: str) -> str:
    return "set" if os.environ.get(name) else "NOT_CONFIGURED"


def port(host: str, p: int) -> bool:
    try:
        socket.create_connection((host, p), 1).close()
        return True
    except OSError:
        return False


def http_ok(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=2) as r:  # noqa: S310
            return r.status < 500
    except Exception:
        return False


load_dotenv()
rows: list[tuple[str, str, str]] = []
missing_required = False


def add(area: str, status: str, detail: str = "", required: bool = False) -> None:
    global missing_required
    rows.append((area, status, detail))
    if required and status not in ("OK", "set"):
        missing_required = True


for name in ("BIFROST_URL", "BIFROST_MODEL", "BIFROST_FALLBACK_MODELS", "TAVILY_API_KEY", "OMNIDIM_API_KEY", "OMNIDIM_AGENT_ID"):
    add(f"config {name}", present(name), "value never printed")
add("config OMNIDIM_AGENT_ID is integer", "OK" if os.environ.get("OMNIDIM_AGENT_ID", "").isdigit() else "NOT_CONFIGURED")
add("PostgreSQL", "OK" if port("127.0.0.1", 5433) else "MISSING", "127.0.0.1:5433", required=True)
add("NATS", "OK" if port("127.0.0.1", 4222) else "MISSING", "127.0.0.1:4222", required=True)
add("OPA", "OK" if http_ok(os.environ.get("OPA_URL", "http://localhost:8281") + "/health") else "MISSING", required=True)
add("Pathway correlator", "OK" if http_ok(os.environ.get("CORRELATOR_URL", "http://127.0.0.1:9103") + "/healthz") else "MISSING", "make demo-up", required=True)
add("Temporal", "OK" if port("127.0.0.1", 7233) else "NOT_RUNNING", "needed only for DEMO_EXEC=temporal / live sandbox")
bf = os.environ.get("BIFROST_URL") or os.environ.get("BIFROST_BASE_URL", "")
add("Bifrost gateway /health", ("OK" if http_ok(bf.rstrip("/") + "/health") else "UNREACHABLE") if bf else "NOT_CONFIGURED")
add("execution mode", os.environ.get("REMEDIATION_MODE", "temporal") == "inline" and "INLINE_DEMO_ADAPTER" or "TEMPORAL")
add("cluster mode", "DEMO_SIMULATOR" if os.environ.get("SIMULATOR_URL") else "LIVE_CLUSTER (needs sandbox context)")
add("SANDBOX_CONTEXTS", present("SANDBOX_CONTEXTS"), os.environ.get("SANDBOX_CONTEXTS", ""))
add("REQUIRE_SANDBOX", os.environ.get("REQUIRE_SANDBOX", "false"))
add("APPLY_ENABLED (kill switch)", os.environ.get("APPLY_ENABLED", "true"))
add("kubectl", "present" if any(Path(p, "kubectl").exists() for p in os.environ.get("PATH", "").split(":")) else "NOT_INSTALLED", "live cluster mode only")

w = max(len(r[0]) for r in rows)
for a, s, d in rows:
    print(f"{a:<{w}}  {s:<20} {d}")
print(json.dumps({"missing_required": missing_required}))
sys.exit(1 if missing_required else 0)
