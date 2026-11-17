# Remaining blockers (actual, with exact resolution)
1. **No provider credentials.** Needed: `BIFROST_URL`+`BIFROST_MODEL` (+ a provider key configured inside Bifrost), `TAVILY_API_KEY`, `OMNIDIM_API_KEY`+`OMNIDIM_AGENT_ID` (integer agent id; agent prompt/tools per README). Then `make live-preflight && make live-provider-check ARGS=--voice-session`, and run the voice session manually in a browser with a microphone.
2. **No Kubernetes**: needs Docker daemon + k3d + kubectl. Then `make cluster up`, `SANDBOX_KUBE_CONTEXT=k3d-beacon make live-sandbox-up live-sandbox-verify`, `DEMO_MODE=live make demo-up`.
3. **Correlator image/manifest never built or applied** (same prerequisite as 2).
4. **Bifrost patch** needs HTTP-config plumbing + maintainer discussion before any PR (not authorised to submit).
5. **Submission deadline**: a third-party listing says Nov 15, 2026 — verify with the organisers.
6. Voice microphone/barge-in/reconnect behaviours can only be verified in a real browser with a real OmniDimension session.
