# Phase III — Evidence Intelligence Engine

Status of every claim below is one of **VERIFIED-LIVE**, **VERIFIED-CONTRACT** (against a local fake that follows the
provider's documented API — *not* proof of the real provider), or **NOT VERIFIED**. Nothing here was verified against a
real Tavily account or a real LLM: no credentials were available in the build environment.

## What it does

For one incident, Night Shift plans bounded research, spends a bounded budget, snapshots the evidence, and has a model
write a *versioned* brief whose citations are checked by the server. Later, a deterministic rule says whether the answer is stale.

```
incident ──► research_plan.plan()        category -> ≤6 mechanism queries (never raw incident text)
             research_plan.sanitize_query  regex blocklist; the ONLY egress path to Tavily
          ──► research.execute()          budget reserved atomically BEFORE each call; one retry; per-attempt rows
          ──► Tavily Search (+ one Extract of the best 2 official sources)
          ──► snapshot (immutable, insert-only)  ──► analysis.synthesize_research() via Bifrost
          ──► brief v2 (versioned, bound to snapshot_id)  ──► staleness.evaluate() on every view
```

## Guarantees (each has a test in `tests/test_research_engine.py` / `tests/test_research_api.py`)

| Guarantee | Mechanism |
|---|---|
| No internal identifier, IP, URL, email, UUID, secret, cluster DNS, path or shell text leaves the system | `sanitize_query` blocklist + context-derived identifiers; server re-sanitises model follow-ups (cap 2) |
| Hard spend ceiling | atomic SQL reservation (`TAVILY_MAX_QUERIES_PER_INCIDENT`=8, `TAVILY_MAX_CREDITS_PER_INCIDENT`=16); every attempt consumes budget; exhausted ⇒ nothing is sent |
| No interleaved runs | single in-flight run lock per incident; second request ⇒ HTTP 409 `run_in_progress` |
| Failures are visible, never silent | statuses `COMPLETED / PARTIAL / FAILED / BUDGET_EXHAUSTED`; error categories `auth, rate_limited, plan_limit, server_error, http_error, invalid_response, timeout, unavailable` |
| Evidence cannot be rewritten | snapshots are insert-only; a brief stores its `snapshot_id` |
| Model cannot invent citations or strength | unknown citation ids are demoted/rejected; `evidence_strength` is derived server-side; findings are labelled `SOURCE_ESTABLISHED / MODEL_INFERENCE / HYPOTHESIS` |
| Honest fallback | gateway/model outage or invalid output ⇒ `RULES_ONLY`, labelled as such |
| Deterministic staleness | `NEW_RELEVANT_EVENT`, `NEW_SOURCE`, `UPDATED_SOURCE`; ignored categories are reported; older versions show `SUPERSEDED` |

Brief schema: `nightshift.research_brief.v2` (version, previous_brief_id, snapshot_id, evidence_strength, structured_findings,
hypotheses, missing_evidence, alternative_explanations, next_steps, limitations).

## UI
`web/src/workspace/ResearchPanel.tsx`: status badge, budget, per-attempt activity table, brief versions, stale alert with reasons.
Browser journey: `e2e/research.mjs` (19 steps; uses the contract fake — see Verification).

## Configuration
`TAVILY_API_KEY`, `TAVILY_API_URL`, `TAVILY_TIMEOUT`, `TAVILY_MAX_QUERIES_PER_INCIDENT`, `TAVILY_MAX_CREDITS_PER_INCIDENT`,
`TAVILY_RETRY_CAP_S`; Bifrost: `BIFROST_URL` (+ model env in `docs/HACKATHON.md`). Unset ⇒ `NOT_CONFIGURED`, and the UI says so.

## Verification evidence (this build)

| Item | Result | Kind |
|---|---|---|
| `pytest tests` | 317 passed, 9 skipped (skips = live-provider/opt-in) | contract + local services |
| `tests/test_research_engine.py`, `test_research_api.py` | pass (sanitiser, dates, failures, budget, concurrency, brief v2, stale rules, HTTP lifecycle) | VERIFIED-CONTRACT |
| `tests/test_live_bifrost.py` | 7 passed against a **real Bifrost gateway process** with a **local fake upstream model** | gateway real, **model fake** |
| Real Tavily request | **NOT VERIFIED** (`TAVILY_API_KEY` absent) → `make hackathon-verify` prints `NOT_CONFIGURED` | — |
| Real LLM through Bifrost | **NOT VERIFIED** (no provider key) | — |
| An invalid-key response from a provider would **not** count as an integration | rule applied | — |

To produce live evidence yourself: set `TAVILY_API_KEY` and a Bifrost provider key, run `make live-provider-check`, then
`pytest tests/test_live_providers.py`; results land in `.agent/verification-results.json`.

## Known limits
* Tavily `published_date` may be absent/unparseable ⇒ `date_status` UNKNOWN/UNPARSEABLE; staleness never guesses a date.
* Only the `networkpolicy_connectivity` category has a research plan; other categories plan nothing (reported, not faked).
