# Phase IV — Real incident → recovery

## Honest scope statement (read first)

| Layer | Real? |
|---|---|
| kube-apiserver, etcd, RBAC, admission, server-side dry-run, optimistic concurrency, audit webhook | **REAL** (k3s) |
| Prometheus, Alertmanager (and the alert → Night Shift webhook) | **REAL** upstream binaries |
| Pathway 0.33.1 correlation over NATS JetStream, OPA, PostgreSQL, Temporal (dev server) | **REAL** |
| kubelet, CNI, pods, **NetworkPolicy enforcement** | **NOT REAL.** This VM cannot start pod sandboxes (runc fails), so k3s runs `--disable-agent`. `beacon.sandbox.dataplane` *emulates* the data plane: it reads the real NetworkPolicy from the real API server and gates the app→db connection. |
| The demo app | the unmodified `demo/app.py` |
| Tavily / real LLM / OmniDimension | **NOT VERIFIED** (no credentials / no microphone) |

The UI labels the Kubernetes row `REAL_CONTROL_PLANE+EMULATED_DATAPLANE`. Never describe this as a full cluster.

## Architecture

```
kubectl (outside actor) ─► k3s apiserver ──audit webhook──► API /k8s/audit ─► NATS BEACON ─► Pathway ─► correlation ─► ledger
demo app errors ─► log shipper ─► API /ingest/app-logs ─┘      Prometheus ─► Alertmanager ─► API /alerts ─┘
operator (cookie session + CSRF) ─► propose ─► worker `diagnose`+`dryrun` as SA beacon-remediator ─► OPA ─► typed approval
   ─► HMAC-signed consent ─► Temporal RemediationWorkflow ─► worker patch (restricted SA) ─► verify: 3 independent check groups
   ─► VERIFIED ─► report (JSON nightshift.report.v2 + markdown)
```

* **API holds no cluster write credentials.** Only the worker has `remediator.yaml` (token for ServiceAccount
  `beacon-remediator`, RBAC from `deploy/k8s/beacon/rbac.yaml`: get/patch NetworkPolicies in `demo` only).
* **Consent** is a typed phrase (`approve fix <n>`) from an authenticated session; the approver is derived server-side
  (`LOCAL_DEMO_OPERATOR`, method `LOCAL_PASSCODE`, `verified_human_identity:false`) and stamped with an HMAC-SHA256 signature.
  Voice, LLM output and webhooks can never constitute consent.
* **Fail-closed guards:** sandbox context allow-list, namespace allow-list, golden-snapshot match, OPA, single-use
  approvals, idempotency keys, kill switch.
* **VERIFIED** only if status resolved **and** three independent check groups pass (health endpoint, Prometheus, app errors).

## Runbook

```bash
DEMO_MODE=k3s DEMO_EXEC=temporal make demo-up      # k3s + Prometheus/Alertmanager + dataplane + Temporal + API/worker/correlator/web
make demo-status                                   # kubernetes: REAL_CONTROL_PLANE+EMULATED_DATAPLANE
make demo-trigger                                  # real `kubectl patch` removing the ingress rule
# open http://127.0.0.1:5173/#workspace  (passcode: demo-pass) -> Create proposal -> type "approve fix 1" -> Approve
make demo-reset                                    # restore the policy (real apply)
make demo-down                                     # stop everything started by demo-up
scripts/k3s_sandbox.sh down                        # destroy the disposable cluster and its data
```
Prerequisites: PostgreSQL on :5433, `nats-server`, `opa`, `temporal` CLI, k3s at `/var/tmp/k3s-bin/k3s`,
Prometheus/Alertmanager under `/var/tmp/mon-bin` (override with `K3S_BIN`, `MON_BIN`).

**Operational finding (observed, not hypothetical):** after the Night Shift API was restarted, the k3s apiserver's audit
webhook stopped delivering until the control plane was restarted (`scripts/k3s_sandbox.sh up` re-attaches). Audit delivery is
therefore **at-most-once across an intake outage**: a change made while the API is down or the sender is wedged is not
replayed. Detection still has the app-error and Prometheus signals, but a missed change event means no change→symptom
correlation. Mitigation for production: run the API behind a stable address with ≥2 replicas, or use an audit log file
with a tailing shipper.

## 3–5 minute judge demo
1. (0:00) `make demo-status`: point at `REAL_CONTROL_PLANE+EMULATED_DATAPLANE`, say plainly there is no kubelet/CNI.
2. (0:30) `make demo-trigger`: a *real* kubectl edit; show the audit event, app errors and Prometheus alert appear (source mode **LIVE**).
3. (1:30) Correlation from Pathway (STRONG), then **Create proposal**: dry-run passed as the restricted ServiceAccount.
4. (2:15) Show Approve is disabled until the exact phrase is typed; type it. Mention voice/LLM cannot do this.
5. (2:45) Temporal executes; verification may fail once honestly (monitoring) and retry; reaches **VERIFIED** with 3 groups.
6. (3:45) Download the report: signed consent, execution count 1, Kubernetes change, errors/interruptions, remaining uncertainty.
7. Close with the limits table above.

## Manual OmniDimension voice verification (BLOCKED here)
Needs `OMNIDIM_API_KEY`, `OMNIDIM_AGENT_ID` and a person with a microphone.
1. `make live-preflight`, then `make live-provider-check ARGS=--voice-session` — must report a real `ws_url` session.
2. In the console start the voice session; speak the incident summary request; confirm a transcript appears and is labelled voice.
3. Speak over the agent mid-answer (**barge-in**): audio must stop and the transcript must show the interruption.
4. Say "approve it": confirm **nothing executes** and the proposal stays `PROPOSED`. Only typing the phrase approves.
Record the session id and screenshots; until then the matrix row stays `BLOCKED`. Offline coverage exists
(`tests/test_phase4_security.py`: voice token ≠ approval, barge-in cancel; `web/tests/transcript.test.mjs`), but that is not a real session.

## Chaos / safety matrix
| Scenario | Evidence | Outcome |
|---|---|---|
| Forbidden verbs/namespaces for the remediator | `tests/test_live_k3s.py` (8-row RBAC matrix + real 403s) vs the real API | refused by the real apiserver |
| Admin creds in worker kubeconfig | `test_admin_credentials_are_not_in_the_worker_kubeconfig` | none present |
| Server-side dry-run as the SA | `test_real_server_side_dry_run_as_the_remediator` | passes without mutation |
| Stale `resourceVersion` | `test_optimistic_concurrency_conflict_is_real` | real 409/422, nothing changed |
| Corrupt / non-matching golden snapshot | `test_invalid_golden_snapshot_refuses_the_restore` | precondition fails, no restore |
| Wrong context / wrong namespace | `test_wrong_context_and_wrong_namespace_are_refused_before_any_api_call` | refused before any API call |
| Concurrent approvals, replay, tampered consent | `tests/test_phase4_security.py`, `test_idempotency.py` | exactly one execution; tamper detected |
| Voice/LLM as consent | `test_phase4_security.py` | never counts |
| Prometheus outage during verify | `test_verify.py::test_prometheus_outage_is_a_failed_check_not_a_pass` | failed check, not a pass |
| Live verification retry | live k3s run | attempt 1 monitoring FAIL → attempt 2 PASS → VERIFIED |
| Tavily rate-limit/timeout/outage/budget exhausted | `test_research_engine.py` | retried once / PARTIAL / FAILED / nothing sent |
| Bifrost outage / invalid output | `test_research_engine.py`, `test_integration.py` | `RULES_ONLY` |
| Pathway late/duplicate/isolated runs | `test_integration.py` (real Pathway over NATS) | monotonic, run-scoped |
| API restart → audit webhook wedged | observed live (see runbook) | **gap**: events lost; documented, not fixed |
| Worker killed mid-remediation, NATS/Pathway/OPA outage on the k3s stack | **NOT exercised live in this session** | Temporal-retry and OPA fail-closed are unit-covered only; mark as UNVERIFIED-LIVE |

## Verification evidence (this build)
* `pytest tests`: **317 passed, 9 skipped**; `tests/test_live_k3s.py` 14 passed against the real k3s API.
* `e2e/live_journey.mjs`: **14 steps PASS** end to end (new incident id per break, LIVE mode, 3 check groups, signed consent, no secret values, state restored).
* `ruff` clean; `web` typecheck + build pass; web unit tests pass.
* `make hackathon-verify` → `.agent/verification-results.json` (machine-readable PASS / FAIL / BLOCKED / NOT_CONFIGURED).

## Sponsor matrix
| Sponsor | Used for | Status |
|---|---|---|
| Pathway | streaming correlation over NATS (run-scoped, nearest-preceding change) | **VERIFIED-LIVE** |
| Temporal | RemediationWorkflow execution | **VERIFIED-LIVE** on the dev server; worker-kill **not** exercised live |
| Bifrost | LLM gateway, headers/metadata, fallback logs | real gateway + **fake upstream**; real model **NOT VERIFIED** |
| Tavily | research search/extract | contract fake only; **NOT VERIFIED live** |
| OmniDimension | voice | offline semantics only; real session **BLOCKED** |
| OPA / NATS / PostgreSQL / k3s / Prometheus / Alertmanager | policy / bus / ledger / control plane / alerting | **VERIFIED-LIVE** |
