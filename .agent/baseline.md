# Baseline (Gate 0) — before any code change

Branch `vsrupeshkumar/relaxed-ride-cs8iup`, HEAD `ea0bcca`, clean tree (258 tracked files).

## Environment (this cloud container)
| Tool | State |
|---|---|
| Docker CLI | present, **no daemon** (no containers possible) |
| k3d / kubectl / Temporal | **missing** → no real cluster, no Temporal server |
| PostgreSQL 16 | binaries present → started on :5433 (`/var/tmp/nspg`) |
| NATS JetStream | built from source with Go (`nats-server v2.10.22`) → :4222 |
| OPA 1.0.0 | built from source with Go → :8281, bundle = `policy/` |
| Python 3.13 / Node 22 / uv / Go 1.24 | present |
| Pathway 0.33.1 | installable from PyPI; has `pw.io.nats` JetStream connector |
| Credentials: TAVILY / BIFROST / OMNIDIM / LLM keys | **none in env** |

## Commands run and results
- `uv pip install -e '.[dev]'` ok
- `pytest tests -q` → **165 passed, 6 skipped** (6 = `integration`, need a live cluster)
- `npm ci && npm run typecheck && npm run build` → ok (chunk-size warning only)
- `ruff check src tests scripts` → 1 pre-existing auto-fixable finding

## Existing architecture (verified by reading the code)
- Ingestion: `/alerts` (Alertmanager), `/k8s/audit[/token]`, `/github/events` (HMAC) → NATS `beacon.alerts` / `beacon.changes` (stream `BEACON`, `beacon.>`).
- Worker: Temporal workflow `RemediationWorkflow` (dryrun → require_approval → execute → verify* → resolve|escalate), `REMEDIATION_MODE=inline` runs the same steps in-process.
- Allowlist `remediation/registry.py` (4 actions) incl. `networkpolicy.restore_ingress` = inverse of `demo/trigger.sh break-netpol`, golden-snapshot gated.
- OPA `policy/remediation.rego`; approval ledger with single-use approvals (`approvals.mark_used` conditional UPDATE); 4-check verification (`verify.py`).
- Voice: Bolna (`bolna.py`, `web/src/voice/bolna.ts`, `@bolna/web-call`), typed fallback via `/voice/turn` (litellm→Ollama).
- LLM call sites bypassing any gateway: `triage.py`, `prefetch.py`, `voice_loop.py` (litellm) — to be routed through Bifrost.
- Pathway / Tavily / Bifrost / OmniDimension: **absent**.

## Pre-existing defects / gaps (not caused by this work)
- No change-to-symptom correlation: `changes.recent()` ranks by affected-resource only.
- No application-log ingestion event; no SSE/WebSocket (console polls).
- No sandbox/context hard guard on remediation (only OPA namespace allowlist).
