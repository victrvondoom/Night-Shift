# Phase II baseline (2026-11-16, fresh container)
Branch vsrupeshkumar/relaxed-ride-cs8iup @ 4b21fba, clean tree. No `.env`; no BIFROST/TAVILY/OMNIDIM credentials in env.
Container was reset: services down; binaries (nats-server, opa, postgres) survived; restarted via `make demo-up`.

| Handover claim | Status | Evidence |
|---|---|---|
| pytest 178 pass / 6 skip | REPRODUCED | `scripts/hackathon_verify.py` |
| ruff, tsc, vite build | REPRODUCED | same |
| Browser journey (11 steps) | REPRODUCED | same |
| NATS 2.10.22 / Pathway 0.33.1 / OPA 1.0.0 / PG16 live | REPRODUCED | service checks PASS |
| `make demo-up` works | **REGRESSED→FIXED**: hung forever (web launch never returned, no pid file); now returns in ~5 s | scripts/demo.sh |
| llm_gateway_routing CONNECTED without model path | CONFIRMED defect (to fix in Gate 1) | integrations.py |
| X-Beacon-User asserted identity | CONFIRMED defect (Gate 7) | workspace_api._user |
| Reset needs correlator restart | CONFIRMED (Gate 5) | |
| Live Bifrost/Tavily/OmniDimension | BLOCKED: no credentials | |
| Temporal / k3d / Kubernetes | BLOCKED until tested (no Docker daemon, no kubectl/k3d) | |
