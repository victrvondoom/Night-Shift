# Night Shift — the one-incident proof

**Tagline:** Connect the change to the failure. Prove the fix before closing the incident.

**The problem.** A NetworkPolicy change lands; seconds later the app cannot reach its database. The change is in the Kubernetes audit log, the errors are in app logs, the page is from Prometheus. The on-call engineer joins them by hand at 3 AM. Night Shift reconstructs that relationship from source events, says what is evidence and what is hypothesis, gets a *typed* human approval for one bounded fix, runs it through OPA + the existing remediation workflow, and refuses to say `VERIFIED` until Kubernetes state, monitoring and application health all independently pass.

> **Which track?** See [`docs/TRACKS.md`](TRACKS.md): best fit is the Tavily Research Agent; the Bifrost gateway track is not claimed.
>
> **Status as of Phase II (read this first; it supersedes anything below that disagrees).**
> Verified here: real NATS+Pathway+OPA+PostgreSQL; a **real Bifrost gateway process** (built from source) with a **local fake upstream model**;
> a **real Temporal dev server + worker** (including a worker-kill durability test); the browser journey 11/11 in both `INLINE_DEMO_ADAPTER` and `TEMPORAL_LOCAL`.
> **Not verified: a real LLM answer through Bifrost, a successful Tavily search, any OmniDimension session/audio, any real Kubernetes cluster** (no credentials / no Docker daemon).
> Provider endpoints for Tavily and OmniDimension were reached with an invalid key only (HTTP 401 → category `auth`). Full detail: `.agent/phase2-integration-results.md`.
> Note: a third-party listing (hacklist.io) gives the prototype-submission deadline as **Nov 15, 2026** — confirm against the official rules; the official track text was not accessible.


## Run it

```bash
make setup                 # .venv + web deps (once)
make demo-up               # NATS, OPA, API, Pathway, worker, DEMO_SIMULATOR, console  (DEMO_EXEC=temporal for a real Temporal server)
make demo-trigger          # prints the incident id
# open http://127.0.0.1:5173/#workspace  (console passcode printed by demo-up)
make demo-status           # honest integration health
make demo-reset            # clear DEMO_SIMULATOR data (no Pathway restart: events are run_id-scoped)
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
| **Bifrost** | Only model path for the explanation (`/v1/chat/completions`), carries Incident Trace Enrichment headers; legacy litellm call sites are routed through it | Real gateway process + **fake upstream** tested (routing, request-id echo, metadata in Bifrost's log store, fallback, outage, timeout, 429). No real LLM / key. | `src/beacon/llm/gateway.py`, `analysis.py` | `BIFROST_URL`, `BIFROST_MODEL`, `BIFROST_FALLBACK_MODELS`, `BIFROST_VIRTUAL_KEY` |
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
- No k3d cluster in the authoring container: Kubernetes is the simulator. Temporal **was** run for real (`DEMO_EXEC=temporal`); the default `inline` mode is labelled `INLINE_DEMO_ADAPTER` everywhere and is never presented as Temporal. Real RBAC against a real API server was not exercised.
- The correlator Kubernetes manifest (`deploy/k8s/beacon/correlator.yaml`) is structurally tested but **never applied to a cluster**; the image build was not run (no Docker daemon).
- Pathway keeps correlation state in memory (a restart replays the JetStream backlog). Run exactly ONE correlator per stream: the consumer is a single named durable (`CORRELATOR_CONSUMER`); a second instance with the same name would split the stream.
- The approver is the server-derived principal `LOCAL_DEMO_OPERATOR` (method `LOCAL_PASSCODE`): it identifies the passcode holder, **not a verified individual**. A client-supplied name is ignored.
- The simulator's recovery is only as real as the simulation: it recovers only when the NetworkPolicy is genuinely patched back through the shim, and the same four verification checks run.

## Real Bifrost gateway (local recipe used for the live-gateway tests)
```bash
git clone --depth 1 https://github.com/maximhq/bifrost && cd bifrost
mods=$(find . -name go.mod -not -path "./.github/*" -not -path "./examples/*" -not -path "./tests/*" -printf "%h " ); go work init $mods
mkdir -p transports/bifrost-http/ui && echo "<html></html>" > transports/bifrost-http/ui/index.html   # embed placeholder; API-only
(cd transports/bifrost-http && go build -o /usr/local/bin/bifrost-http .)       # needs Go >= 1.27 (auto-fetched)
python tests/fixtures/fake_llm_upstream.py &                                   # LOCAL FAKE model on :9300/:9301, not an LLM
mkdir -p /var/tmp/bifrost-app && cp deploy/bifrost/config.local.json /var/tmp/bifrost-app/config.json
bifrost-http -app-dir /var/tmp/bifrost-app -port 8088 &
pytest tests/test_live_bifrost.py            # skips cleanly when no gateway is running
```
For a real model: put your provider key in a Bifrost provider config, set `BIFROST_URL`, `BIFROST_MODEL` (e.g. `openai/gpt-4o-mini`), then `make live-provider-check`.

## Commands added in Phase II
`make live-preflight` · `make live-provider-check` (one bounded real request per configured provider; `ARGS=--voice-session` for OmniDimension) · `make live-sandbox-up|verify` (fail closed; need `SANDBOX_KUBE_CONTEXT`) · `DEMO_EXEC=temporal make demo-up`.
