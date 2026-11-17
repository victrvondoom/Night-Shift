# Phase II integration results (what was actually performed)

Legend: **LIVE-REAL** = real external service/process, real response; **LIVE-GATEWAY/FAKE-UPSTREAM** = real gateway process, local fake model behind it; **AUTH-PATH** = real provider endpoint reached with an invalid key (proves reachability + error mapping, NOT a successful call); **CONTRACT** = local fake only; **BLOCKED** = not possible here.

## Bifrost
| Check | Level | Evidence |
|---|---|---|
| Real gateway built from source (`maximhq/bifrost@3cc76d2`, transport v2.5.1, Go 1.27.4 via go.work) and run | LIVE-GATEWAY | `/health` → `{"status":"ok"}`; config `deploy/bifrost/config.local.json` |
| Night Shift analysis request routed through it (`gateway.chat`) | LIVE-GATEWAY/FAKE-UPSTREAM | `tests/test_live_bifrost.py::test_real_gateway_request_…` |
| **Bifrost's own request id**: it echoes our `x-request-id` as `X-Bifrost-Request-Id` and uses it as the log row id | LIVE-GATEWAY | asserted: `a.bifrost_request_id == a.analysis_id` and row `id` in `logs.db` |
| `x-bf-lh-*` metadata retained in Bifrost's log store (`{"incident-id","evidence-set","workflow-stage","purpose","risk","requested-at"}`) | LIVE-GATEWAY | asserted from the gateway's `logs` table; no secrets/raw evidence in labels |
| Fallback (`openai` → `groq`): response `X-Bifrost-Fallback-Index: 1`, provider `groq`; logged as a **child row** (`parent_request_id` = our id) **with metadata preserved** | LIVE-GATEWAY | `test_fallback_to_second_provider…` |
| All providers down → `GATEWAY_ERROR` + `RULES_ONLY` | LIVE-GATEWAY | test |
| Upstream 429 → categorised, `RULES_ONLY` | LIVE-GATEWAY | test |
| Client timeout (`BIFROST_TIMEOUT_SECONDS=2`, hung upstream) → `timeout` | LIVE-GATEWAY | test |
| Garbage model output → `DOWNGRADED`, `RULES_ONLY`, cannot authorise anything | LIVE-GATEWAY | test |
| Gateway unreachable → `unavailable` | LIVE-GATEWAY | test |
| **A real LLM answered** | **NOT DONE** | no provider key; the upstream is `tests/fixtures/fake_llm_upstream.py` (not a model) |
| Defect found & fixed in Phase I code: it used the response body `id` (the *upstream's* completion id) as the "Bifrost request id" and read non-existent `extra_fields.number_of_retries`. Now uses Bifrost response headers (`x-bifrost-request-id/-trace-id/-provider/-resolved-model/-latency-ms/-fallback-index`) | fixed | `llm/gateway.py` |
| Legacy call sites (triage/prefetch/voice_loop) go through `gateway.completion` and are counted (`BYPASS_NO_GATEWAY` vs `bifrost`) | CONTRACT | `test_no_module_bypasses_the_gateway` |

## Tavily
| Check | Level |
|---|---|
| Current official contract re-verified (docs.tavily.com search reference): response has `request_id`, `usage.credits`, per-result `published_date` (RFC-2822, only when `include_published_date:true`), error body `{"detail":{"error":…}}` | docs |
| Implementation updated: sends `include_published_date`, stores `request_id`/`credits`, parses RFC-2822 for staleness (the Phase I check assumed ISO and never fired) | CONTRACT tests |
| Real endpoint reached with an invalid key → HTTP 401 → category `auth` | AUTH-PATH |
| **A real successful search / extract** | **BLOCKED: no `TAVILY_API_KEY`** |

## OmniDimension
| Check | Level |
|---|---|
| Official contract re-verified (create-session, `@omnidim-ai/client` `WebSession`, cumulative transcript, status reasons) | docs |
| Real endpoint `POST https://omnidim.io/api/v1/sessions/create` reached with an invalid key → 401 → category `auth` | AUTH-PATH |
| Transcript reducer (cumulative snapshots replace, never append) | node unit tests (3) |
| Real session creation, browser audio, barge-in, stop/cleanup | **BLOCKED: no `OMNIDIM_API_KEY`/agent; no microphone in this container** |
| Voice cannot approve: tool call held (`omnidim_llm_function_call` is not consent); spoken/transcript "approve" changes nothing | CONTRACT tests (`test_consent.py`, `test_webhooks.py`) |

## Pathway / NATS
- Real Pathway 0.33.1 over real NATS JetStream: dedup, out-of-order, unrelated namespace, **run isolation** (new `run_id` scoping), junk payloads (non-JSON, wrong shape, empty) leave the correlator healthy (uptime continuous), outage test (events published while down are persisted; the incident appears after restart from the JetStream backlog).
- **Defect found**: Pathway auto-names its JetStream durable consumer from its sources, so two correlator processes silently *share* one consumer and split the stream (each sees half the events). Fixed: explicit pre-created durable (`CORRELATOR_CONSUMER`), single replica in the manifest, tests use isolated consumers.

## Temporal
- Real Temporal dev server (CLI 1.10.1 / server 1.32.2; obtained via the Python SDK's supported local-server helper) + real worker: `RemediationWorkflow` and `StepWorkflow` **Completed** (`temporal workflow list`), browser journey 11/11 ×3 in `TEMPORAL_LOCAL` mode.
- Durability: worker `kill -9` during the verify timer → restart → workflow completed, exactly one `executed` event, lifecycle `VERIFIED`.

## Kubernetes
- **BLOCKED**: no Docker daemon, kubectl or k3d. `live-sandbox-*` scripts fail closed (verified: refuse without kubectl / without an explicit context). Cluster integration tests (6) remain SKIPPED. The correlator Kubernetes manifest is structurally tested only.
