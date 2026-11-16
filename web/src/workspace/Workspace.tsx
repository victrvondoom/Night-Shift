import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { OmniVoice, type VoiceSnapshot } from "../voice/omnidim";
import type { Analysis, Integration, Proposal, View } from "./types";

/**
 * The live incident workspace. Every value shown comes from the backend (REST + server-sent events);
 * the only local state is UI chrome (selection, form text, in-flight flags) and is labelled as such.
 */
interface Props {
  base: string; // e.g. /api
  voiceBase: string; // e.g. /voice
  passcode: string;
  setPasscode: (v: string) => void;
  incidentId: string | null;
}

const fmt = (iso?: string | null) => (iso ? new Date(iso).toISOString().slice(11, 23) + "Z" : "—");

async function call<T>(base: string, path: string, pass: string, method = "GET", body?: unknown): Promise<{ ok: boolean; status: number; data: T }> {
  const r = await fetch(`${base}${path}`, {
    method,
    headers: { "content-type": "application/json", "x-beacon-passcode": pass, "x-beacon-user": "console-engineer" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = (await r.json().catch(() => ({}))) as T;
  return { ok: r.ok, status: r.status, data };
}

export function Workspace({ base, voiceBase, passcode, setPasscode, incidentId }: Props) {
  const [ids, setIds] = useState<{ incident_id: string; source_mode: string; detected_at: string }[]>([]);
  const [sel, setSel] = useState<string | null>(incidentId);
  const [view, setView] = useState<View | null>(null);
  const [conn, setConn] = useState<"connecting" | "live" | "disconnected">("connecting");
  const [stale, setStale] = useState(false);
  const lastMsg = useRef(Date.now());
  const [integrations, setIntegrations] = useState<Integration[]>([]);
  const [busy, setBusy] = useState("");
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, []);

  // incident list over SSE: a new incident appears without a reload
  useEffect(() => {
    const es = new EventSource(`${base}/ns/stream`);
    es.addEventListener("incidents", (e) => {
      const list = (JSON.parse((e as MessageEvent).data) as { incidents: typeof ids }).incidents;
      setIds(list);
      setSel((cur) => (cur && list.some((i) => i.incident_id === cur) ? cur : list[0]?.incident_id ?? null));
    });
    return () => es.close();
  }, [base]);

  // selected incident over SSE
  useEffect(() => {
    if (!sel) return;
    setView(null);
    setConn("connecting");
    const es = new EventSource(`${base}/ns/incidents/${sel}/stream`);
    es.onopen = () => setConn("live");
    es.onerror = () => setConn("disconnected");
    es.addEventListener("incident", (e) => {
      lastMsg.current = Date.now();
      setStale(false);
      setConn("live");
      setView(JSON.parse((e as MessageEvent).data) as View);
    });
    const t = window.setInterval(() => setStale(Date.now() - lastMsg.current > 30000 && conn === "live"), 5000);
    return () => {
      es.close();
      window.clearInterval(t);
    };
  }, [base, sel]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadIntegrations = useCallback(async () => {
    const r = await call<{ integrations: Integration[] }>(base, "/system/integrations", "");
    if (r.ok) setIntegrations(r.data.integrations);
  }, [base]);
  useEffect(() => {
    void loadIntegrations();
    const t = window.setInterval(loadIntegrations, 15000);
    return () => window.clearInterval(t);
  }, [loadIntegrations]);

  const act = async (label: string, path: string, body?: unknown) => {
    if (!passcode) return setMsg({ kind: "err", text: "Unlock the console with the passcode first (Night Board → unlock)." });
    setBusy(label);
    setMsg(null);
    const r = await call<Record<string, unknown>>(base, path, passcode, "POST", body);
    setBusy("");
    const text = String(r.data.error || r.data.message || (r.ok ? "done" : `HTTP ${r.status}`));
    setMsg({ kind: r.ok ? "ok" : "err", text: `${label}: ${text}${r.data.detail ? ` (${r.data.detail})` : ""}` });
    void loadIntegrations();
    return r;
  };

  const detected = view?.detected_at ? Math.max(0, Math.floor((now - new Date(view.detected_at).getTime()) / 1000)) : null;

  return (
    <div className="ws">
      <IntegrationStrip rows={integrations} />
      <div className="ws-bar">
        <label>
          Incident{" "}
          <select value={sel ?? ""} onChange={(e) => setSel(e.target.value || null)}>
            <option value="">{ids.length ? "select…" : "none yet"}</option>
            {ids.map((i) => (
              <option key={i.incident_id} value={i.incident_id}>
                {i.incident_id} · {i.source_mode}
              </option>
            ))}
          </select>
        </label>
        <span className={`ws-conn ${conn}`}>{stale ? "stale" : conn}</span>
        {passcode ? (
          <button disabled={!!busy} onClick={() => act("trigger", "/demo/trigger")}>
            Trigger NetworkPolicy incident (DEMO_SIMULATOR)
          </button>
        ) : (
          <form className="ws-row" onSubmit={(e) => { e.preventDefault(); const v = String(new FormData(e.currentTarget).get("pc") || ""); if (v) setPasscode(v); }}>
            <input name="pc" type="password" placeholder="console passcode" autoComplete="off" aria-label="console passcode" />
            <button>Unlock</button>
            <span className="dim">read-only until unlocked</span>
          </form>
        )}
        <button className="ghost" disabled={!!busy || !passcode} onClick={() => act("reset", "/demo/reset")}>
          Reset demo data
        </button>
      </div>
      {msg ? <div className={`ws-msg ${msg.kind}`} role="status">{msg.text}</div> : null}

      {!sel ? (
        <section className="ws-card">
          <h2>No incident yet</h2>
          <p className="dim">Nothing has been correlated. Trigger the scenario above, or run <code>make demo-trigger</code>. This page updates live when Pathway emits a correlation.</p>
        </section>
      ) : !view ? (
        <section className="ws-card"><p className="dim">{conn === "disconnected" ? "Disconnected from the API. Retrying…" : "Loading incident…"}</p></section>
      ) : (
        <>
          <Header v={view} detected={detected} />
          <Timeline v={view} />
          <Correlation v={view} />
          <div className="ws-grid">
            <Research v={view} act={act} busy={busy} />
            <Explanation v={view} act={act} busy={busy} />
          </div>
          <Voice v={view} voiceBase={voiceBase} passcode={passcode} />
          <Remediation v={view} act={act} busy={busy} passcode={passcode} now={now} />
          <Recovery v={view} base={base} />
        </>
      )}
    </div>
  );
}

function IntegrationStrip({ rows }: { rows: Integration[] }) {
  return (
    <section className="ws-int" aria-label="Integration health">
      {rows.length === 0 ? <span className="dim">integration health unavailable</span> : null}
      {rows.map((r) => (
        <span key={r.integration} className={`chip st-${r.state}`} title={`${r.detail}${r.last_success_at ? ` · last ok ${r.last_success_at}` : ""}${r.last_error_category ? ` · last error ${r.last_error_category}` : ""}`}>
          <b>{r.integration}</b> {r.state}
          {r.mode !== "LIVE" ? <i> · {r.mode}</i> : null}
        </span>
      ))}
    </section>
  );
}

function Header({ v, detected }: { v: View; detected: number | null }) {
  return (
    <section className="ws-card ws-head">
      <div>
        <h1>{v.incident_id}</h1>
        <div className="dim">{v.alarm_name || "no alert yet"} · service {v.affected_service || "—"} · severity {v.severity}</div>
      </div>
      <div className="ws-badges">
        <span className={`badge lc-${v.lifecycle}`}>{v.lifecycle}</span>
        <span className={`badge mode-${v.source_mode}`}>{v.source_mode}</span>
        <span className="badge" title="computed from the first event's source timestamp">{detected === null ? "—" : `${Math.floor(detected / 60)}m ${detected % 60}s`} since detection</span>
      </div>
    </section>
  );
}

function Timeline({ v }: { v: View }) {
  return (
    <section className="ws-card">
      <h2>Live timeline <span className="dim">{v.events.length} events · source timestamps (UTC)</span></h2>
      <table className="ws-table">
        <thead><tr><th>Observed</th><th>Source</th><th>Resource</th><th>Event</th><th>Original event id</th></tr></thead>
        <tbody>
          {v.events.map((e) => (
            <tr key={e.event_id} id={e.event_id}>
              <td className="mono">{fmt(e.observed_at)}</td>
              <td>{e.source}{e.source_mode === "DEMO_SIMULATOR" ? <i className="sim"> SIM</i> : null}</td>
              <td className="mono">{[e.resource.namespace, e.resource.name].filter(Boolean).join("/") || e.resource.kind}</td>
              <td>{e.summary}</td>
              <td className="mono small" title={`night shift id ${e.event_id}`}>{e.source_event_id}</td>
            </tr>
          ))}
          {v.events.length === 0 ? <tr><td colSpan={5} className="dim">no events claimed by this incident yet</td></tr> : null}
        </tbody>
      </table>
    </section>
  );
}

function Correlation({ v }: { v: View }) {
  const c = v.correlations[v.correlations.length - 1];
  if (!c) return <section className="ws-card"><h2>Correlation</h2><p className="dim">no correlation output</p></section>;
  const byId = new Map(v.events.map((e) => [e.event_id, e]));
  return (
    <section className="ws-card">
      <h2>Correlation <span className="dim">engine: {c.engine} · rule {c.rule}</span></h2>
      <p>{c.explanation}</p>
      <div className="ws-kv">
        <span>Strength category</span><b>{c.strength}</b>
        <span>Changed resource</span><b className="mono">{c.resource}</b>
        <span>Affected workload</span><b className="mono">{c.target_app || "—"}</b>
        <span>Window</span><b className="mono">{fmt(c.window_start)} → {fmt(c.window_end)} (max {c.window_seconds}s)</b>
        <span>Processed</span><b className="mono">{fmt(c.processed_at)}</b>
      </div>
      <p className="dim small">Strength is a rule-based category, not a probability. This is a correlation, not a confirmed root cause.</p>
      <h3>Grouped events ({c.included_event_ids.length})</h3>
      <ul className="ws-list">
        {c.included_event_ids.map((id) => (
          <li key={id}><a href={`#${id}`} className="mono">{byId.get(id)?.source_event_id ?? id}</a> <span className="dim">{byId.get(id)?.event_type ?? "not in view"}</span></li>
        ))}
      </ul>
      <h3>Missing or unconfirmed evidence</h3>
      <ul className="ws-list">{c.missing_evidence.map((m) => <li key={m}>{m}</li>)}</ul>
    </section>
  );
}

type Act = (label: string, path: string, body?: unknown) => Promise<{ ok: boolean; status: number; data: Record<string, unknown> } | void>;

function Research({ v, act, busy }: { v: View; act: Act; busy: string }) {
  return (
    <section className="ws-card">
      <h2>External research <span className="dim">Tavily</span></h2>
      <button disabled={!!busy} onClick={() => act("research", `/ns/incidents/${v.incident_id}/research`)}>Research this incident</button>
      {v.research.length === 0 ? <p className="dim">No sources retrieved. If Tavily shows NOT_CONFIGURED above, set TAVILY_API_KEY.</p> : null}
      {v.research.map((r) => (
        <article key={r.evidence_id} className="ws-src">
          <div><span className={`badge cls-${r.classification}`}>{r.classification}</span> <a href={r.url} target="_blank" rel="noreferrer noopener">{r.title || r.url}</a></div>
          <div className="dim small">query: “{r.query}” · retrieved {r.retrieved_at} · published {r.published_date ?? "unknown"} · updated {r.updated_date ?? "unknown"} · search score {r.score ?? "n/a"} (relevance, not confidence) · extract {r.extraction_status}</div>
          <blockquote>{r.excerpt.slice(0, 400)}</blockquote>
          <div className="small">Why: {r.classification_reason}</div>
          <div className="mono small">{r.evidence_id}</div>
        </article>
      ))}
    </section>
  );
}

function Explanation({ v, act, busy }: { v: View; act: Act; busy: string }) {
  const a: Analysis | undefined = [...v.analyses].reverse().find((x) => x.structured) ?? v.analyses[v.analyses.length - 1];
  const s = a?.structured;
  const link = (id: string) => <a key={id} href={`#${id}`} className="mono small">{id.slice(0, 12)}</a>;
  return (
    <section className="ws-card">
      <h2>Explanation <span className="dim">via Bifrost gateway</span></h2>
      <button disabled={!!busy} onClick={() => act("analyze", `/ns/incidents/${v.incident_id}/analyze`)}>Explain with evidence</button>
      {!a ? <p className="dim">Not analysed yet.</p> : (
        <>
          <p><span className={`badge org-${a.origin}`}>{a.origin === "RULES_ONLY" ? "RULES_ONLY (not AI-generated)" : "AI via Bifrost"}</span> {a.status !== "OK" ? <span className="badge warn">{a.status}{a.error_category ? ` · ${a.error_category}` : ""}</span> : null}</p>
          {a.origin === "BIFROST_MODEL" ? (
            <div className="dim small">request {a.bifrost_request_id ?? "id n/a"} · provider {a.provider ?? "n/a"} · model {a.model ?? "n/a"} · latency {a.latency_ms ?? "n/a"} ms · usage {a.usage ? JSON.stringify(a.usage) : "n/a"} · cost {a.cost ?? "n/a"} · evidence set {a.evidence_set_hash}</div>
          ) : null}
          {a.downgrade_reasons.length ? <ul className="ws-list warn">{a.downgrade_reasons.map((d) => <li key={d}>{d}</li>)}</ul> : null}
          {s ? (
            <>
              <p>{s.incident_summary}</p>
              <p><b>Hypothesis:</b> {s.root_cause_hypothesis}</p>
              <p className="small">Supporting events: {s.supporting_event_ids.map(link)}</p>
              <h3>Confirmed</h3>
              <ul className="ws-list">{s.what_is_confirmed.map((c) => <li key={c.text}>{c.text} {c.evidence_ids.map(link)}</li>)}</ul>
              <h3>Unknown</h3>
              <ul className="ws-list">{s.what_is_unknown.map((u) => <li key={u}>{u}</li>)}</ul>
              <p className="small"><b>Recommended action id:</b> <code>{s.recommended_action_id ?? "none"}</code> (a recommendation, not a command) · {s.risk_summary}</p>
            </>
          ) : null}
        </>
      )}
    </section>
  );
}

function Voice({ v, voiceBase, passcode }: { v: View; voiceBase: string; passcode: string }) {
  const [snap, setSnap] = useState<VoiceSnapshot>({ state: "idle", muted: false, lines: [] });
  const passRef = useRef(passcode);
  passRef.current = passcode;
  const ctl = useMemo(() => new OmniVoice(voiceBase, () => passRef.current, setSnap), [voiceBase]);
  useEffect(() => () => ctl.stop(), [ctl]);
  return (
    <section className="ws-card">
      <h2>Voice <span className="dim">OmniDimension</span> <span className={`badge vs-${snap.state}`}>{snap.state}</span></h2>
      <div className="ws-row">
        <button disabled={!passcode || snap.state === "connecting" || snap.state === "active"} onClick={() => void ctl.start(v.incident_id)}>Start voice briefing</button>
        <button disabled={snap.state !== "active"} onClick={() => ctl.mute(!snap.muted)}>{snap.muted ? "Unmute" : "Mute"}</button>
        <button disabled={snap.state !== "active" && snap.state !== "connecting"} onClick={() => ctl.stop()}>Stop</button>
      </div>
      {snap.state === "NOT_CONFIGURED" ? <p className="dim">NOT_CONFIGURED: set OMNIDIM_API_KEY and OMNIDIM_AGENT_ID on the server. Typed interaction (Night Board → Talk) still works.</p> : null}
      {snap.error ? <p className="err">{snap.error}</p> : null}
      {snap.state === "ended" ? <p className="dim">Session ended: {snap.reason}</p> : null}
      <p className="dim small">Voice can explain and propose. It cannot approve: approval is the typed phrase below.</p>
      <ul className="ws-transcript" aria-live="polite">
        {snap.lines.map((l, i) => <li key={i} className={`${l.role}${l.final ? "" : " interim"}`}><b>{l.role}:</b> {l.text}</li>)}
      </ul>
    </section>
  );
}

function Remediation({ v, act, busy, passcode, now }: { v: View; act: Act; busy: string; passcode: string; now: number }) {
  const p: Proposal | undefined = v.proposals[v.proposals.length - 1];
  const [typed, setTyped] = useState("");
  const [key] = useState(() => crypto.randomUUID());
  const left = p ? Math.floor((new Date(p.expires_at).getTime() - now) / 1000) : 0;
  const live = p?.state === "PENDING_APPROVAL" && left > 0;
  return (
    <section className="ws-card">
      <h2>Remediation</h2>
      <button disabled={!!busy || !passcode} onClick={() => act("propose", `/ns/incidents/${v.incident_id}/proposal`)}>Create proposal (deterministic)</button>
      {!p ? <p className="dim">No proposal. The fix is chosen from live drift against the golden snapshot, never by a model.</p> : (
        <>
          <div className="ws-kv">
            <span>Action</span><b className="mono">{p.action}</b>
            <span>Target</span><b className="mono">{p.target}</b>
            <span>Parameters</span><b className="mono">{JSON.stringify(p.params)}</b>
            <span>Expected effect</span><b>{p.expected_effect}</b>
            <span>Blast radius</span><b>{p.blast_radius}</b>
            <span>Dry run</span><b className={p.dry_run.ok ? "ok" : "err"}>{p.dry_run.ok ? "PASSED" : "FAILED"} · {p.dry_run.code} · {p.dry_run.detail}</b>
            <span>Required approver</span><b>{p.required_approver}</b>
            <span>Supporting evidence</span><b className="mono small">{p.supporting_evidence_ids.length} events</b>
            <span>State</span><b>{p.state}{live ? ` · expires in ${left}s` : ""}</b>
            <span>Params hash</span><b className="mono small">{p.params_hash.slice(0, 16)}…</b>
          </div>
          {p.approval ? <p className="ok">Approved by {p.approval.user} at {p.approval.approved_at} via {p.approval.evidence}.</p> : null}
          {live ? (
            <form className="ws-row" onSubmit={(e) => { e.preventDefault(); void act("approve", `/ns/incidents/${v.incident_id}/proposals/${p.fix_id}/approve`, { typed_phrase: typed, params_hash: p.params_hash, idempotency_key: key }).then((r) => { if (r && r.ok) setTyped(""); }); }}>
              <label>Type <code>{p.confirmation_phrase}</code> to approve <input value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" /></label>
              <button disabled={!!busy || !passcode || typed.trim().toLowerCase() !== p.confirmation_phrase}>Approve</button>
              <button type="button" className="ghost" disabled={!!busy} onClick={() => act("cancel", `/ns/incidents/${v.incident_id}/proposals/${p.fix_id}/cancel`)}>Cancel proposal</button>
            </form>
          ) : p.state === "PENDING_APPROVAL" ? <p className="err">Proposal expired. Create a new one.</p> : null}
          <h3>Execution (from the persisted timeline)</h3>
          <ul className="ws-list">{v.execution.map((e, i) => <li key={i}><span className="mono">{fmt(e.t)}</span> {e.event}</li>)}</ul>
        </>
      )}
    </section>
  );
}

function Recovery({ v, base }: { v: View; base: string }) {
  const cats = Object.entries(v.verification.categories);
  return (
    <section className="ws-card">
      <h2>Recovery and report <span className={`badge lc-${v.lifecycle}`}>{v.lifecycle}</span></h2>
      <p className="dim small">VERIFIED appears only when Kubernetes state, monitoring and application health all pass independently. {v.verification.attempts} verification attempt(s) recorded.</p>
      {cats.length === 0 ? <p className="dim">No verification has run.</p> : (
        <div className="ws-checks">
          {cats.map(([name, c]) => (
            <div key={name} className={`ws-check ${c.status}`}>
              <b>{name.replace(/_/g, " ")}</b> <span className="badge">{c.status}</span>
              {c.checks.map((k) => <div key={k.name} className="small"><span className={k.ok ? "ok" : "err"}>{k.ok ? "✓" : "✗"}</span> {k.name} · <span className="mono">{fmt(k.checked_at)}</span> · {k.detail}</div>)}
            </div>
          ))}
        </div>
      )}
      <div className="ws-row">
        <a className="btn" href={`${base}/ns/incidents/${v.incident_id}/report?format=md`} download>Download report (.md)</a>
        <a className="btn" href={`${base}/ns/incidents/${v.incident_id}/report`} target="_blank" rel="noreferrer">Report JSON</a>
      </div>
      <details><summary>Provenance ({v.provenance.length} stages)</summary>
        <ul className="ws-list mono small">{v.provenance.map((p, i) => <li key={i}>{fmt(p.at)} {p.stage} {p.ref}</li>)}</ul>
      </details>
    </section>
  );
}
