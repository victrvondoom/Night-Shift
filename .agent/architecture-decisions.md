# Architecture decisions
1. **Reuse, don't replace.** FastAPI, React/Vite, PostgreSQL JSON ledger, NATS, OPA, the 4-action allowlist, single-use approvals and the 4-check verifier are unchanged. New data lives in the existing ledger (`ns_*` tables).
2. **Pathway = separate process** (`beacon.correlator`) using `pw.io.nats` JetStream read/write. Rule: NetworkPolicy change → symptoms (alert, app connection errors) in same namespace, symptom dependency must match or be unset, window 600 s, nearest preceding change wins. Output is a *correlation* with a category (`STRONG/PARTIAL/CHANGE_ONLY`), never a probability or a root cause. Persistence is monotonic (union) so replays/interleaving cannot shrink evidence.
3. **Incident id** = hash of the change event id, assigned by the correlator → stable and idempotent.
4. **Fix choice is deterministic** (`diagnose` drift vs golden snapshot). The model only explains; `recommended_action_id` must be allowlisted and `requires_human_approval` is forced true.
5. **Bifrost trace enrichment via native `x-bf-lh-*` headers**, not a custom Go plugin (a dynamic plugin needs a special gateway build; unverified in this environment).
6. **OmniDimension replaces Bolna**; the tool-call route keeps the "model asked, human must type" hold (`omnidim_llm_function_call` is never consent; the `bolna_transcriber_log` evidence kind is removed from OPA).
7. **Simulator = a k8s/Prometheus/app shim** behind `beacon.k8s` (`SIMULATOR_URL`), posting through real webhooks, every event labelled `DEMO_SIMULATOR`. Remediator writes are `remediation_applied` events, not new changes.
8. **Sandbox guard** (`remediation/guard.py`) runs before dry-run and execute; fail-closed with `REQUIRE_SANDBOX=true`.
9. **VERIFIED is derived** from persisted records (status resolved AND three check groups PASS), never stored as a flag.
