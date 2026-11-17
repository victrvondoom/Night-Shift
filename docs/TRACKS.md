# Track fit (honest)

One product — **Night Shift** — submitted to the track where it genuinely belongs. Nothing is built as a separate demo for a track.
Track names are as given by the team; the official rules text was not accessible (a third-party listing says the prototype deadline was **Nov 15, 2026**, and a requirement to join the official Discord — confirm both, and whether one project may enter more than one track).

| Track | Fit | What in Night Shift is the evidence | What is missing |
|---|---|---|---|
| **[Tavily] Tavily Research Agent** | **Best fit (recommended primary)** | For every incident the system derives *generic* technical queries (no internal names are ever sent), runs Tavily Search + Extract under a per-incident query/credit **budget**, classifies each source (`SUPPORTS/CONTEXT_ONLY/UNVERIFIED/STALE/…`) with a reason and its real publication age, has **Bifrost synthesise a cited research brief** (every finding must cite a retrieved source id; invented ids are dropped), lists **what the sources do not establish**, and proposes sanitised follow-up searches that only run on request. Retrieved text is inert data (tested). | A real Tavily key was never available: no successful live search has been run (real endpoint reached with an invalid key only → 401). Research is one stage of an incident product, not a standalone research agent. |
| **[Tavily] Stale-Answer Detector** | **Good secondary angle** | Two deterministic detectors: (1) **source staleness** from the provider's real date (RFC-2822 parsed; unknown stays unknown); (2) **explanation staleness** — an AI/rule explanation is flagged `STALE ANSWER` when evidence arrived that it never saw (id-set comparison, no model). Shown live (verified: an explanation went stale as 4 more events arrived). Also: the model can't skip human approval, and `VERIFIED` can't be claimed without independent checks. | It detects staleness of Night Shift's own answers/sources, not a general-purpose detector for arbitrary AI applications. |
| **[Bifrost] Open-Source Bifrost Gateway** | **Weak / unproven** | We are a Bifrost *client*: all model calls route through it; verified against a real gateway built from source (request-id echo, `x-bf-lh-*` metadata in Bifrost's log store, fallback child rows). One real upstream gap found (unbounded log-label size) with a tested local patch (`docs/bifrost-contribution/`). | The patch is plugin-level, not wired to the HTTP config, not submitted, and is hardening — probably not "a gateway extension" in the track's sense. Do not claim this track on current evidence. |
| [Bifrost] Fewest-token coding agent | Not connected | — | Night Shift is not a coding agent. |
| [Bifrost] Benchmarking platform for AI agents | Not connected | — | — |
| [Bifrost] Autonomous pentest agent | Not connected | — | Night Shift is a defensive, human-approved remediation system. |

OmniDimension (voice) and Pathway (streaming correlation) are **not** in the track list you gave; they are product components. Keep them only because they serve the incident journey; none of the above claims depend on them.

## Recommendation
Submit Night Shift to **Tavily Research Agent**, and lead the README/pitch with the evidence-grounded, cited, budgeted, staleness-aware research loop feeding a human-approved fix. Mention stale-answer detection as a feature, not a second product. Only add the Bifrost gateway track if the organisers allow multiple tracks *and* the patch is wired to config and reviewed.
