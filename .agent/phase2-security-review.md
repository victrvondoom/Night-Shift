# Phase II security review

| Finding | Severity | Status |
|---|---|---|
| Approver identity was a client-supplied `X-Beacon-User` header (impersonation) | High | **Fixed.** Identity is server-derived (`beacon/auth.py`): `LOCAL_DEMO_OPERATOR` + method `LOCAL_PASSCODE` (session) or `LOCAL_PASSCODE_HEADER`; `verified_human_identity: false` recorded; header ignored. Tests: `tests/test_auth.py` |
| Passcode kept in browser local storage by the console; sent on every request | Medium | Workspace now uses a server-side session: HttpOnly + SameSite=Strict cookie (+`Secure` over HTTPS / `COOKIE_SECURE=true`), CSRF token (in memory), 8 h expiry, server-side logout. **The older Night Board page still keeps its passcode in local storage** (not changed). |
| No brute-force limit on passcode | Medium | Fixed: 5 failures / 5 min per client address → 429 (login and header path). In-memory, per process. |
| CSRF on cookie-authenticated mutations | Medium | Fixed (`X-CSRF-Token` required with a cookie session; tested). |
| Integration health could report CONNECTED without evidence | High (trust) | Fixed: capability-level, interaction-derived (`integrations.py`, 9 tests). |
| Stale/old demo events could join a new incident | Medium | Fixed: `run_id` scoping in the Pathway join (live test). |
| Two correlators split the stream | Medium | Fixed (explicit consumer) + manifest `replicas: 1, Recreate`. |
| Wrong "Bifrost request id" (upstream completion id) | Medium (traceability) | Fixed against the real gateway. |
| Bifrost accepts unbounded `x-bf-lh-*` label size (60 KB persisted) | Low–Med (upstream) | Reported, patch prototype in `docs/bifrost-contribution/`; Night Shift itself only sends short labels. |
| External (Tavily) content treated as untrusted | — | Stored/displayed only; classification is rule-based; `research.py` imports no tool/approval/remediation code (tested) |
| Sandbox guard | — | Unchanged; tests `test_guard_*`; `live_sandbox.sh` refuses unnamed/protected contexts (verified refusal paths only) |

Residual risks (not fixed): single shared passcode (no per-person identity); reads on `/api/ns/*` are unauthenticated by design (existing dashboard convention); rate limiter and sessions are per-process; `docker compose`/Kubernetes manifests untested on a cluster; secrets in `.env` for the demo are plain env vars.
