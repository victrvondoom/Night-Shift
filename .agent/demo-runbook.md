# Night Shift — the one-incident proof

**Tagline:** Connect the change to the failure. Prove the fix before closing the incident.

**The problem.** A NetworkPolicy change lands; seconds later the app cannot reach its database. The change is in the Kubernetes audit log, the errors are in app logs, the page is from Prometheus. The on-call engineer joins them by hand at 3 AM. Night Shift reconstructs that relationship from source events, says what is evidence and what is hypothesis, gets a *typed* human approval for one bounded fix, runs it through OPA + the existing remediation workflow, and refuses to say `VERIFIED` until Kubernetes state, monitoring and application health all independently pass.

## Run it

```bash
make setup                 # .venv + web deps (once)
make demo-up               # NATS, OPA, API, Pathway, worker, DEMO_SIMULATOR, console
make demo-trigger          # prints the incident id
# open http://127.0.0.1:5173/#workspace  (console passcode printed by demo-up)
make demo-status           # honest integration health
make demo-reset            # clear DEMO_SIMULATOR data, restart Pathway
make hackathon-verify      # machine-readable report -> .agent/verification-results.json
make demo-down
```

Prerequisites: Python 3.12+, Node 20+, PostgreSQL on :5433, `nats-server` (JetStream) and `opa` on PATH — or `docker compose -f deploy/demo/docker-compose.yml up -d` for the three services (compose file not exercised in the authoring container, which has no Docker daemon). `make demo-up` fails with an actionable message for anything missing.

**Modes.** `DEMO_MODE=sim` (default) uses the deterministic simulator: every event is labelled `DEMO_SIMULATOR`, it never touches a real cluster, and it publishes through the *real* webhooks → NATS → Pathway → ledger → UI path. `DEMO_MODE=live` calls the existing `demo/trigger.sh break-netpol` against the current kubectl context of a sandbox k3d cluster (`make cluster up`). The mode is remembered; trigger/reset never silently switch. **Live-cluster mode could not be run in the authoring environment** (no Docker daemon, no k3d).

## 3–4 minute demo script
1. (0:00) `make demo-up`; open `#workspace`. Point at the integration strip: Bifrost/Tavily/OmniDimension say `NOT_CONFIGURED` unless keys are set; Kubernetes/Prometheus say `DEMO_ADAPTER`. Nothing is faked green.
2. (0:30) Press **Trigger NetworkPolicy incident**. Rows stream into the timeline with source, UTC timestamp and original event id (audit id, alert fingerprint, log id) — no reload.
3. (1:00) **Correlation**: engine `pathway`, the rule, window, grouped event ids, and *missing evidence*. Say out loud: strength is a rule category, not a probability, and this is not a confirmed root cause.
4. (1:30) **Research** (Tavily, if keyed): real kubernetes.io sources, classification + reason, unknown dates stay unknown. **Explain**: Bifrost structured answer with evidence links — or `RULES_ONLY` when no gateway is configured.
5. (2:00) **Voice** (OmniDimension, if keyed): start the briefing; transcript is shown live. Say "approve" — nothing happens.
6. (2:30) **Create proposal**: exact action, parameters, blast radius, dry-run result, expiry. Type `approve fix 1`. OPA allows, the worker executes the allowlisted action once.
7. (3:15) **Recovery**: three independent check groups with their own timestamps → `VERIFIED`. Download the report. `make demo-reset` and repeat.

## Sponsor contribution matrix

| Partner | How it participates in the *same* incident | State here | Files | Config |
|---|---|---|---|---|
| **Pathway** | The streaming correlation engine: reads `beacon.events` from NATS JetStream with `pw.io.nats.read`, dedups, windowed-joins change→symptoms (nearest preceding change wins), writes `beacon.correlations` with `pw.io.nats.write` | **LIVE** (real Pathway 0.33.1 + real NATS, tested) | `src/beacon/correlator.py`, `ingest.py` | `CORRELATOR_URL`, `CORRELATION_WINDOW_SECONDS` |
| **Tavily** | Targeted Search (kubernetes.io) + Extract of the best official page, from incident-derived queries; stored with provenance | **NOT_CONFIGURED** here (no key). Adapter verified against a contract fake only | `src/beacon/research.py` | `TAVILY_API_KEY` |
| **Bifrost** | Only model path for the explanation (`/v1/chat/completions`), carries Incident Trace Enrichment headers; legacy litellm call sites are routed through it | **NOT_CONFIGURED** here. Adapter verified against a contract fake only | `src/beacon/llm/gateway.py`, `analysis.py` | `BIFROST_URL`, `BIFROST_MODEL`, `BIFROST_FALLBACK_MODELS`, `BIFROST_VIRTUAL_KEY` |
| **OmniDimension** | Replaces Bolna: backend creates the session, browser uses `@omnidim-ai/client` `WebSession`; briefing of the same incident; read/propose tools only | **NOT_CONFIGURED** here. Adapter verified against a contract fake; browser client typechecks and builds | `src/beacon/omnidim.py`, `voice_turn.py`, `web/src/voice/omnidim.ts` | `OMNIDIM_API_KEY`, `OMNIDIM_AGENT_ID`, `OMNIDIM_TOOL_TOKEN` |

### Bifrost extension: Incident Trace Enrichment
Selected interface: Bifrost's **native, documented log-metadata headers** (`x-bf-lh-<key>`, see docs.getbifrost.ai "Request Options"). Each request carries `incident-id`, `workflow-stage`, `purpose`, `evidence-set` (hash of the evidence ids), `risk`, `requested-at`, so a request in Bifrost's logs joins back to `Incident → Evidence bundle → Model request → Decision record` (Night Shift persists the Bifrost response id and evidence-set hash on the analysis). **Standard-install compatible by construction (no custom binary), but NOT verified against a running Bifrost** — none was available. No Go plugin was written: a dynamic Go plugin needs a specially built gateway, and the native headers need none. Tested: header emission against a contract fake (`tests/test_workspace.py::test_gateway_sends_trace_headers…`). Not done: an upstream plugin/PR (not authorised).

### Bolna removal
Active Bolna code, scripts, tests, env vars, npm package, routes and policy evidence kind are removed (`bolna.py`, `scripts/bolna_agent.py`, `tests/test_bolna.py`, `web/src/voice/bolna.ts`, `TalkDuplex.tsx`, `@bolna/web-call`, `/voice/bolna/*`, `bolna_transcriber_log`). Remaining mentions: only in `.agent/baseline.md`, the removal test (`test_the_removed_bolna_routes_are_gone`) and this document — historical. Phone paging via Bolna is removed, not replaced (`caller.py` is a no-op).

## Judge acceptance checklist
- [ ] `make demo-up` prints UI/API addresses and which optional credentials are missing
- [ ] Timeline rows have source, UTC time, resource and the *original* source event id
- [ ] Correlation panel names the engine (`pathway`), rule, window, missing evidence
- [ ] Explanation says `RULES_ONLY` without a gateway; with Bifrost shows provider/model/latency only if returned
- [ ] Spoken "approve" does nothing; typed phrase + passcode does
- [ ] Changing the proposal, cancelling, or re-approving never double-executes (see tests)
- [ ] Remediation refuses outside `SANDBOX_CONTEXTS` / namespaces
- [ ] `VERIFIED` only with Kubernetes + monitoring + app-health groups all `PASS`
- [ ] `make hackathon-verify` writes `.agent/verification-results.json`

## Known limitations (honest)
- Live Tavily, Bifrost and OmniDimension were **not** exercised (no credentials); only contract-fake tests ran.
- No Temporal server or k3d cluster in the authoring container: the demo uses `REMEDIATION_MODE=inline` (same remediation steps, in-process; `DEMO_ADAPTER` in the integration view) and the simulator. The Temporal workflow and real RBAC path are unchanged but were not re-run end to end here.
- The correlator is not yet packaged as a Kubernetes Deployment (runs via `make demo-up`).
- Pathway keeps correlation state in memory; `make demo-reset` restarts it. Running two correlators concurrently double-publishes (persistence is monotonic, so this is harmless but wasteful).
- `X-Beacon-User` is an asserted approver name bound to the passcode session, not an identity provider.
- The simulator's recovery is only as real as the simulation: it recovers only when the NetworkPolicy is genuinely patched back through the shim, and the same four verification checks run.
