# Bifrost contribution candidate (NOT submitted)

**Status:** a local, tested prototype patch against `maximhq/bifrost@3cc76d2`. Nothing was pushed, opened as a PR or
sent upstream (no authorisation). It is a **plugin-level hardening patch, not a gateway extension/plugin** — whether it
satisfies the hackathon's "open-source Bifrost gateway extension" theme is **unverified**: the official track rules were not
accessible; only a third-party listing (hacklist.io) mentions the theme.

## What I checked first (so the candidate is not invented)
| Candidate | Finding on a real gateway | Verdict |
|---|---|---|
| Correlate a request across retries / provider fallback / logs | Already supported: `x-request-id` is echoed as `X-Bifrost-Request-Id` and used as the log row id; a fallback is logged as a **child row** (`parent_request_id` = our id, `fallback_index`=1) and **the `x-bf-lh-*` metadata is preserved on it**; logs are filterable by `metadata_<key>` (GIN-indexed). Night Shift's tests `test_live_bifrost.py` prove it. | **No gap. Not a contribution.** |
| Bound the size of caller-controlled log metadata | `plugins/logging/main.go: captureLoggingHeaders` stores every `x-bf-lh-*` label, configured logging header and `x-bf-dim-*` dimension verbatim. Measured on the running gateway: a **60 KB** label was accepted (HTTP 200) and persisted (**60,011 bytes**) in the log row. The only bound is the 64 KB header read buffer; there is no per-value cap. With `enforce_auth_on_inference: false` any client can bloat the log store. | **Real, small gap.** |

## The patch (`0001-logging-cap-metadata-value-size.patch`)
- New optional plugin config `max_metadata_value_bytes` (default `0` = unlimited, i.e. **no behaviour change by default**).
- When set, every captured metadata string is truncated to that many bytes, rune-aligned (never splits a UTF-8 character).
- Test `TestCaptureLoggingHeadersCapsValueSize` (label, logging header, dimension, multi-byte, default-unlimited).
- Verified: `go test ./plugins/logging` passes (existing + new), `gofmt` clean.

## Not done / limitations
- **Not wired to the HTTP transport's `config.json`** (`transports/bifrost-http/server/plugins.go:276` builds `logging.Config` from client config; a `client.log_metadata_max_value_bytes` field + schema + config-store persistence is still needed). So the cap works at plugin level only.
- Not run against the standard distribution; it is a source change, so it would ship with a normal Bifrost release if accepted (no dynamic Go plugin involved).
- No existing upstream issue search was done beyond reading the source; a maintainer may prefer a different default or a count cap too.
- Reproducing the measurement: run a gateway (see `docs/HACKATHON.md`, "Real Bifrost gateway"), then
  `curl .../v1/chat/completions -H "x-request-id: big-1" -H "x-bf-lh-blob: $(python3 -c 'print("A"*60000)')" ...`
  and read `length(metadata)` from the gateway's `logs` table.
