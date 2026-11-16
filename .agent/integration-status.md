# Integration status (this environment)
| Integration | State | Evidence |
|---|---|---|
| NATS JetStream | LIVE (nats-server 2.10.22 built from source) | e2e, pathway test |
| Pathway 0.33.1 | LIVE | `test_pathway_correlates_over_nats…` + browser journey |
| OPA 1.0.0 | LIVE | dry-run + execute decisions in journey |
| PostgreSQL 16 | LIVE | ledger |
| Kubernetes | DEMO_ADAPTER (simulator); live path unchanged but **not run** | no Docker/k3d |
| Prometheus | DEMO_ADAPTER (simulator) | |
| Temporal | not run; `REMEDIATION_MODE=inline` (DEMO_ADAPTER) | no server |
| Tavily | NOT_CONFIGURED; contract-fake tests only | no key |
| Bifrost | NOT_CONFIGURED; contract-fake tests only | no gateway/key |
| OmniDimension | NOT_CONFIGURED; contract-fake + SDK typecheck/build | no key/agent |
Docs verified (2026-11): OmniDimension create-session + `@omnidim-ai/client` WebSession (cumulative transcripts), Bifrost `x-bf-lh-*` headers. Tavily Search/Extract shape from prior knowledge, not re-fetched: **unverified against the live API**.
