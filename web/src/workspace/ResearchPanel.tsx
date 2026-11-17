import { useState } from "react";
import type { Brief, ResearchItem, ResearchState, View } from "./types";

type Act = (label: string, path: string, body?: unknown) => Promise<{ ok: boolean; status: number; data: Record<string, unknown> } | void>;
const fmt = (iso?: string | null) => (iso ? new Date(iso).toISOString().slice(0, 19).replace("T", " ") + "Z" : "—");

const STATUS_HELP: Record<string, string> = {
  NOT_STARTED: "No external research has run for this incident.",
  RESEARCHING: "A research run is in progress on the server.",
  COMPLETED: "Every planned query succeeded.",
  PARTIAL: "Some queries succeeded; others failed or were stopped by the budget.",
  FAILED: "No query succeeded. This is a real provider/credential failure, not a result.",
  BUDGET_EXHAUSTED: "The per-incident query/credit budget is used up; nothing more will be sent.",
};

export function ResearchPanel({ v, act, busy }: { v: View; act: Act; busy: string }) {
  const rs: ResearchState | undefined = v.research_state;
  const briefs = v.research_briefs ?? [];
  const [sel, setSel] = useState<number | null>(null);
  const shown: Brief | undefined = sel === null ? briefs[briefs.length - 1] : briefs.find((b) => b.version === sel);
  const latest = briefs[briefs.length - 1];
  const stale = latest?.staleness?.status === "STALE";
  const byId = new Map(v.research.map((r) => [r.evidence_id, r]));
  const fails = (rs?.runs[rs.runs.length - 1]?.failures ?? []).map((f) => `${f.op}:${f.category}`).join(", ");
  const b = rs?.budget;
  return (
    <section className="ws-card" id="research">
      <h2>
        Research <span className="dim">Tavily → Bifrost</span>{" "}
        <span className={`badge rs-${rs?.status ?? "NOT_STARTED"}`} title={STATUS_HELP[rs?.status ?? "NOT_STARTED"]}>{rs?.status ?? "NOT_STARTED"}</span>
        {latest ? <span className={`badge bs-${latest.staleness?.status}`}>answer v{latest.version}: {latest.staleness?.status}</span> : <span className="badge bs-NEVER">NEVER_RESEARCHED</span>}
      </h2>
      {rs?.status === "FAILED" && fails ? <div className="ws-msg err">Last run failed: {fails}</div> : null}

      <div className="ws-row">
        <button disabled={!!busy || rs?.active || b?.exhausted} onClick={() => act("research", `/ns/incidents/${v.incident_id}/research`, {})}>{v.research.length ? "Run planned research again" : "Research this incident"}</button>
        <button disabled={!!busy || v.research.length === 0} onClick={() => act(latest ? "refresh explanation" : "synthesize", `/ns/incidents/${v.incident_id}/research/synthesize`)}>{latest ? (stale ? "Refresh explanation (new version)" : "Re-synthesize (new version)") : "Synthesize with Bifrost"}</button>
        <button disabled={!!busy || !latest || (latest.follow_up_queries?.length ?? 0) === 0 || b?.exhausted} onClick={() => act("follow-up research", `/ns/incidents/${v.incident_id}/research`, { followups: true })}>Run follow-up searches ({latest?.follow_up_queries?.length ?? 0})</button>
      </div>

      {b ? (
        <div className="ws-kv small" aria-label="research budget">
          <span>Operations</span><b>{b.operations_used} / {b.max_operations} used · {b.operations_remaining} remaining</b>
          <span>Tavily credits</span><b>{b.credits_reported} reported · {b.credits_reserved} reserved · cap {b.max_credits}</b>
        </div>
      ) : null}

      {stale && latest?.staleness ? (
        <div className="ws-msg err" role="alert">
          <b>STALE ANSWER (version {latest.version}).</b> {latest.staleness.summary}
          {latest.staleness.invalidated_at ? ` Invalidated at ${fmt(latest.staleness.invalidated_at)}.` : ""}
          <ul className="ws-list">{latest.staleness.reasons.map((r) => <li key={r.evidence_id + r.rule}><b>{r.rule}</b> — {r.detail} <a href={`#${r.evidence_id}`} className="mono small">{r.evidence_id.slice(0, 12)}</a></li>)}</ul>
        </div>
      ) : null}

      {briefs.length ? (
        <div className="ws-row small">
          Versions:
          {briefs.map((x) => <button key={x.brief_id} className={`ghost${shown?.version === x.version ? " on" : ""}`} onClick={() => setSel(x.version ?? null)}>v{x.version} · {x.staleness?.status}</button>)}
        </div>
      ) : null}

      {shown ? <BriefView b={shown} byId={byId} /> : <p className="dim">No explanation yet. Retrieve sources, then synthesize. If Tavily or Bifrost shows NOT_CONFIGURED above, that capability is unavailable (a rules-only summary is used for the brief).</p>}

      <details open>
        <summary>Research activity ({rs?.attempts.length ?? 0} external attempts)</summary>
        <table className="ws-table small">
          <thead><tr><th>Sent</th><th>Op</th><th>Query</th><th>Result</th><th>Tavily request</th><th>Credits</th></tr></thead>
          <tbody>
            {(rs?.attempts ?? []).map((a) => (
              <tr key={a.attempt_id}><td className="mono">{fmt(a.sent_at)}</td><td>{a.op}{a.retry ? " (retry)" : ""}</td><td>{a.query}</td><td className={a.outcome === "ok" ? "ok" : "err"}>{a.outcome === "ok" ? `HTTP ${a.http_status}` : `${a.error_category ?? "failed"}${a.http_status ? ` (${a.http_status})` : ""}`}</td><td className="mono">{a.request_id ?? "—"}</td><td>{a.credits_reported ?? "n/a"}</td></tr>
            ))}
            {(rs?.attempts.length ?? 0) === 0 ? <tr><td colSpan={6} className="dim">nothing has been sent to Tavily</td></tr> : null}
          </tbody>
        </table>
      </details>

      <details>
        <summary>Sources ({v.research.length})</summary>
        {v.research.map((r) => <SourceCard key={r.evidence_id} r={r} />)}
      </details>
    </section>
  );
}

function SourceCard({ r }: { r: ResearchItem }) {
  const age = r.age_days === null || r.age_days === undefined ? "unknown" : `${r.age_days} days`;
  return (
    <article className="ws-src" id={r.evidence_id}>
      <div><span className={`badge cls-${r.classification}`}>{r.classification}</span> <a href={r.url} target="_blank" rel="noreferrer noopener">{r.title || r.url}</a> <span className="dim small">{r.domain}</span></div>
      <div className="dim small">published {r.published_date ?? "unknown"} ({age}) · fetched {fmt(r.retrieved_at)} · search score {r.score ?? "n/a"} (relevance, not confidence) · extract {r.extraction_status} · Tavily request {r.request_id ?? "n/a"} · credits {r.credits ?? "n/a"}</div>
      <blockquote>{r.excerpt.slice(0, 360)}</blockquote>
      <div className="small">Why: {r.classification_reason}</div>
      <div className="mono small">{r.evidence_id}</div>
    </article>
  );
}

function List({ title, items }: { title: string; items?: string[] }) {
  return items && items.length ? <><h3>{title}</h3><ul className="ws-list">{items.map((i) => <li key={i}>{i}</li>)}</ul></> : null;
}

function BriefView({ b, byId }: { b: Brief; byId: Map<string, ResearchItem> }) {
  const KIND: Record<string, string> = { SOURCE_ESTABLISHED: "established by sources", MODEL_INFERENCE: "model inference", HYPOTHESIS: "hypothesis" };
  return (
    <div className="ws-src">
      <div>
        <span className={`badge org-${b.origin}`}>{b.origin === "RULES_ONLY" ? "RULES_ONLY (not AI-generated)" : "AI via Bifrost"}</span>{" "}
        {b.status !== "OK" ? <span className="badge warn">{b.status}{b.error_category ? ` · ${b.error_category}` : ""}</span> : null}{" "}
        <span className={`badge es-${b.evidence_strength}`} title="A category of how well the retrieved sources support the mechanism. Computed by the server, not claimed by the model, and NOT a probability.">evidence strength: {b.evidence_strength}</span>
      </div>
      <div className="dim small">version {b.version} · schema {b.schema_version} · snapshot {b.snapshot_id} · {fmt(b.created_at)} · {b.evidence_strength_reason}</div>
      <p>{b.incident_summary}</p>
      <p><b>Most likely explanation (not a confirmed root cause):</b> {b.likely_explanation}</p>
      <h3>Findings</h3>
      <ul className="ws-list">
        {(b.structured_findings ?? []).map((f) => (
          <li key={f.claim}><span className={`badge kd-${f.kind}`}>{KIND[f.kind]}</span> {f.claim}{" "}
            {f.evidence_ids.map((id, i) => <a key={id} href={`#${id}`} className="small" title={byId.get(id)?.url}>[{byId.get(id)?.domain ?? id.slice(0, 10)} · {f.source_dates[i] ?? "date unknown"}] </a>)}
          </li>
        ))}
      </ul>
      <List title="Hypotheses" items={b.hypotheses} />
      <List title="Missing evidence" items={b.missing_evidence} />
      <List title="Alternative explanations" items={b.alternative_explanations} />
      <List title="Research gaps" items={b.gaps} />
      <List title="Suggested next investigation steps" items={b.next_steps} />
      <List title="Limitations" items={b.limitations} />
      {b.follow_up_queries.length ? <div className="dim small">Proposed follow-up searches (sanitised; run only when you press the button): {b.follow_up_queries.join(" · ")}</div> : null}
      {b.downgrade_reasons.length ? <div className="small err">Validation: {b.downgrade_reasons.join("; ")}</div> : null}
      {b.bifrost_request_id ? <div className="dim small">Bifrost request {b.bifrost_request_id} · provider {b.provider ?? "n/a"} · model {b.model ?? "n/a"}</div> : null}
    </div>
  );
}
