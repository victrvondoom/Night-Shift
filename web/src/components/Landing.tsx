import { useEffect, useRef, useState } from "react";
import type { Tally } from "../types";
import { loadReplay } from "../replay";
import { Marquee } from "./Marquee";

/* The product landing page (`#home`). Everything here is the product's own
   words and screenshots; the console routes sit unchanged behind it. */

/* The film, and the repository it was built in. "Watch the film"
   pointed at the First Commit film on YouTube -- a different submission, a
   different cut -- so anyone arriving from lablab.ai was shown the wrong one.
   The release page carries the film, the captions and the deck together. */
const FILM = "https://github.com/Prashant-thakur77/NightShift/releases/tag/v0.6.0";
const REPO_BRANCH = "https://github.com/updatingmyhim/hackglobal";

function minutes(v: number | null | undefined): string {
  if (v == null) return "–";
  return v < 1 ? `${Math.round(v * 60)} s` : `${Math.round(v * 10) / 10} min`;
}

const FEATURES = [
  {
    id: "talk",
    title: "Talk to it",
    text: "Hold the mic. Night Shift briefs you on the alarm, the cluster change behind it and the root cause, and every sentence it speaks is pinned to an evidence chip you can open. Pages where you are: Slack and PagerDuty, deep-linked to the incident.",
    proof: "src/beacon/voice_tools.py · tests/test_voice_tools.py::test_get_incident_brief_returns_rca_and_evidence_card",
    img: "/landing/night.png",
    pos: "70% 30%",
  },
  {
    id: "approve",
    title: "Approve with your words",
    text: "One allowlisted fix, dry-run under the executor's own role, with its blast radius spelled out. It applies only when the raw transcript contains “approve fix one”.",
    proof: "src/beacon/approvals.py · tests/test_voice_tools.py::test_approve_fix_requires_exact_phrase_in_the_raw_transcript",
    img: "/landing/board.png",
    pos: "50% 55%",
  },
  {
    id: "sleep",
    title: "Sleep through the repeat",
    text: "After the recovery is proven, grant a Sleep Contract in your own voice: one alarm, one action, exact resources, a use count, an expiry. The second night, nobody is woken.",
    proof: "src/beacon/contracts.py · tests/test_contracts.py::test_match_is_scoped_to_alarm_action_and_exact_params",
    img: "/landing/analytics.png",
    pos: "50% 30%",
  },
];

const PILLARS = [
  { title: "Evidence before the model", text: "A golden NetworkPolicy snapshot taken on a healthy cluster and a Kubernetes audit change ledger come first; the model reasons over what is already known to be true." },
  { title: "Verified means proven", text: "A fix is resolved only when the alert clears after the change, its expression is clean, the post-condition holds and the app answers its health check. Otherwise it escalates, honestly." },
  { title: "Two roles, one direction", text: "The API you talk to is read-only. The worker holds the only write RBAC, scoped to two resource kinds, and dry-runs under that same identity. The manifests are asserted by tests." },
  { title: "Undo by phrase", text: "Every fix has an allowlisted inverse. Say “undo fix 1” and Night Shift reverses exactly what it applied, records it, and hands the incident back to you." },
  { title: "Runs on your laptop too", text: "`make up` starts the whole stack on a local k3d cluster: real Prometheus, Loki, Temporal, NATS and OPA, no cloud account needed." },
];

const NIGHT_SHIFT = [
  { title: "Interrupt it", text: "A live OmniDimension voice session in the browser. Speak over a read-back and the fix it was reading is withdrawn — turn-taking with a safety meaning.", tag: "voice" },
  { title: "Answer from your phone", text: "The page lands in Telegram with Talk · Fix 1 · Ack. Type the exact phrase to approve; anything vaguer is refused, and a voice note is asked to be typed.", tag: "telegram" },
  { title: "End it with a pull request", text: "Say “open the pull request” and the missing rule is restored in the Kubernetes manifest, with the postmortem and your approval quoted. Nothing is merged at 2 AM.", tag: "github" },
  { title: "Proof you can play back", text: "Every approval records where its words came from. The audit page links the OmniDimension call that led up to the fix: transcript, recording and cost.", tag: "audit" },
];

const QUOTES = [
  { from: "from the demo night", text: "grant contract for seven days", note: "the exact phrase that creates a Sleep Contract, kept as the record" },
  { from: "from the safety tests", text: "fix 1 networkpolicy.restore_ingress · dry run PASSED (server dry-run, via remediator service account)", note: "every action is rehearsed under the role that will execute it" },
  { from: "from the runbook", text: "Resolved under your Sleep Contract; you were not woken.", note: "the line Night Shift says on the second night" },
];

const FAQ = [
  { q: "Is it safe?", a: "Only four allowlisted actions exist; params must match the schema exactly; every action passes OPA policy and a server-side dry run under the worker's identity; approval needs the exact phrase typed by the engineer, never the model's claim; one approval executes exactly once; and APPLY_ENABLED=false stops every write path." },
  { q: "What can it change?", a: "Restore one NetworkPolicy ingress rule that exists in the golden snapshot, or restart or roll back one allowlisted Deployment. All are bounded by Kubernetes RBAC and OPA policy." },
  { q: "What if the fix fails?", a: "Verification needs four things: the alert cleared after the fix, its expression clean, the post-condition, and a passing health check. After the retry window it escalates to a human and says so on the board." },
  { q: "What happens without the model?", a: "Triage falls back to a deterministic summary and the console still shows the alert, the cluster change and the timeline. Diagnosis degrades; the safety checks do not depend on it." },
  { q: "Which parts are the model, and which are code?", a: "The model decides whether to call a tool, and only after your words. Consent is checked in code against words the engineer typed; the patch in the pull request is computed from the parameters that passed the dry run; the PR text, the postmortem and the morning report are rendered from the incident record. No model writes to the cluster or to the repository." },
  { q: "Does it need a cloud account?", a: "No. `make up` runs everything on a local k3d cluster; only the OmniDimension voice call needs an outside account." },
  { q: "What did it cost?", a: "Diagnosis runs on a local model, so it has no per-token price. OmniDimension reports the cost of each voice call and Night Shift stores it with the call." },
];

function Faq() {
  const [sel, setSel] = useState(0);
  const list = useRef<HTMLUListElement>(null);
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const next = e.key === "ArrowDown" ? Math.min(FAQ.length - 1, sel + 1) : Math.max(0, sel - 1);
    setSel(next);
    list.current?.querySelectorAll<HTMLElement>("button")[next]?.focus();
  };
  return (
    <div className="faq">
      <div className="faq-q">
        <h3>Questions</h3>
        <ul ref={list} role="tablist" aria-orientation="vertical" onKeyDown={onKey}>
          {FAQ.map((f, i) => (
            <li key={f.q}>
              <button type="button" role="tab" aria-selected={i === sel} tabIndex={i === sel ? 0 : -1} className={i === sel ? "on" : ""} onClick={() => setSel(i)}>
                {f.q}
              </button>
            </li>
          ))}
        </ul>
      </div>
      <div className="faq-a" role="tabpanel">
        <h3>Answer</h3>
        <div className="faq-ask">{FAQ[sel].q}</div>
        <div className="faq-bubble" key={sel}>
          <p>{FAQ[sel].a}</p>
        </div>
        <span className="faq-mark" aria-hidden="true">
          ✓
        </span>
      </div>
    </div>
  );
}

/** Sticky list on the left; the card on the right swaps as the matching step scrolls into view. */
function Features() {
  const [active, setActive] = useState(0);
  const steps = useRef<Array<HTMLDivElement | null>>([]);
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) setActive(Number((e.target as HTMLElement).dataset.i));
        }
      },
      { rootMargin: "-40% 0px -40% 0px", threshold: 0 },
    );
    steps.current.forEach((el) => el && io.observe(el));
    return () => io.disconnect();
  }, []);
  const f = FEATURES[active];
  return (
    <div className="features">
      <div className="features-list">
        <ul role="tablist" aria-orientation="vertical">
          {FEATURES.map((it, i) => (
            <li key={it.id}>
              <button
                type="button"
                role="tab"
                aria-selected={i === active}
                className={i === active ? "on" : ""}
                onClick={() => {
                  setActive(i);
                  steps.current[i]?.scrollIntoView({ behavior: "smooth", block: "center" });
                }}
              >
                {it.title}
              </button>
            </li>
          ))}
        </ul>
        <div className="feature-card" key={f.id}>
          <div className="shot" style={{ backgroundImage: `url(${f.img})`, backgroundPosition: f.pos }} role="img" aria-label={`${f.title} in the console`} />
          <div className="feature-proof mono small">{f.proof}</div>
        </div>
      </div>
      <div className="features-steps">
        {FEATURES.map((it, i) => (
          <div key={it.id} className="feature-step" data-i={i} ref={(el) => (steps.current[i] = el)}>
            <h3 className="display">{it.title}</h3>
            <p className="lede">{it.text}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

export function Landing({ tally, replay, local, onRunNight }: { tally: Tally | null; replay: boolean; local: boolean; onRunNight?: () => void }) {
  const live = !!tally && tally.resolved > 0;
  // on a deployment with nothing resolved yet, the archived night's tally stands in (and says so)
  const [archived, setArchived] = useState<Tally | null>(null);
  useEffect(() => {
    if (live || archived) return;
    void loadReplay()
      .then((b) => setArchived(b.tally))
      .catch(() => undefined);
  }, [live, archived]);
  const shown = live ? tally : archived;
  const label = replay ? "From the archived night (replay)." : live ? "Live numbers from this deployment's tally." : archived ? "From the archived night; this deployment has no resolved incidents yet." : "From the scripted night in local mode.";
  const stats = shown
    ? [
        { n: String(shown.resolved), l: "incidents resolved" },
        { n: minutes(shown.median_minutes_to_recovery), l: "median time to recovery" },
        { n: String(shown.humans_woken), l: shown.humans_woken === 1 ? "human woken" : "humans woken" },
      ]
    : [
        { n: "2", l: "incidents resolved" },
        { n: "2.2 min", l: "median time to recovery" },
        { n: "1", l: "human woken" },
      ];
  return (
    <main key="home" className="landing route-in">
      {/* 1 · hero */}
      <section className="hero">
        <div className="eyebrow">Night Shift</div>
        <h1 className="display hero-h">
          The 2 AM page, <em>fixed with your voice.</em>
        </h1>
        <p className="lede hero-sub">An on-call agent for Kubernetes that finds the cause, proposes one safe fix, applies it on your word, proves the recovery, and does not wake you the second time.</p>
        <div className="row hero-cta">
          <a className="btn primary" href="#board">
            Open the Night Board
          </a>
          {local && onRunNight ? (
            <button type="button" className="btn" onClick={onRunNight}>
              ▶ Run the night
            </button>
          ) : (
            <a className="btn" href={FILM} target="_blank" rel="noopener noreferrer">
              ▶ Watch the film
            </a>
          )}
          <a className="btn ghost" href={REPO_BRANCH} target="_blank" rel="noopener noreferrer">
            Code on GitHub
          </a>
        </div>
        <div className="hero-shot reveal">
          <div className="shot-card">
            <img src="/landing/board.png" alt="The Night Board: tally, incident cards and the Talk panel" loading="eager" />
          </div>
          <div className="ribbon-tag" aria-hidden="true">
            <span className="wave">
              <i />
              <i />
              <i />
              <i />
              <i />
            </span>
            approve fix one
          </div>
        </div>
        <div className="faint small">Voice by OmniDimension · running on Kubernetes</div>
      </section>

      {/* 2 · ink band */}
      <div className="band">
        <Marquee label="Built on" />
      </div>

      {/* 3 · stats on deep green */}
      <section className="green-band">
        <h2 className="display">
          <em>Nobody</em> woken the second time.
        </h2>
        <p className="lede">{label}</p>
        <div className="stats reveal">
          {stats.map((s) => (
            <div key={s.l} className="stat">
              <div className="n">{s.n}</div>
              <div className="l">{s.l}</div>
            </div>
          ))}
        </div>
        <div className="versus reveal">
          <div className="vs-card small-card">
            <div className="l">Human on call</div>
            <div className="n">12 min</div>
            <div className="l">to wake, read, fix, watch</div>
          </div>
          <div className="vs-card big-card" style={{ backgroundImage: "url(/landing/night.png)" }}>
            <div className="vs-inner">
              <div className="l">Night Shift</div>
              <div className="n">30 s</div>
              <div className="l">to a proven recovery, on your word</div>
            </div>
          </div>
        </div>
      </section>

      {/* 4 · feature trio */}
      <section className="section">
        <div className="eyebrow center">How it works</div>
        <h2 className="display center">
          Three things, <em>in your own voice.</em>
        </h2>
        <Features />
      </section>

      {/* 5 · pillars */}
      <section className="section">
        <h2 className="display center">
          Built around <em>how on-call works.</em>
        </h2>
        <div className="pillars">
          {PILLARS.map((p, i) => (
            <div key={p.title} className="pillar reveal" style={{ "--i": i } as React.CSSProperties}>
              <h3>{p.title}</h3>
              <p>{p.text}</p>
            </div>
          ))}
        </div>
      </section>

      {/* 5b · the night shift */}
      <section className="section">
        <div className="eyebrow center">The night shift</div>
        <h2 className="display center">
          Where the engineer <em>actually is.</em>
        </h2>
        <div className="pillars four">
          {NIGHT_SHIFT.map((p, i) => (
            <div key={p.title} className="pillar reveal" style={{ "--i": i } as React.CSSProperties}>
              <span className="eyebrow">{p.tag}</span>
              <h3>{p.title}</h3>
              <p>{p.text}</p>
            </div>
          ))}
        </div>
      </section>

      {/* 6 · quotes */}
      <section className="section">
        <h2 className="display center">
          From the first <em>nights.</em>
        </h2>
        <div className="quotes">
          {QUOTES.map((q, i) => (
            <figure key={q.from} className="quote-card reveal" style={{ "--i": i } as React.CSSProperties}>
              <blockquote>“{q.text}”</blockquote>
              <figcaption>
                <span className="eyebrow">{q.from}</span>
                <span className="dim small">{q.note}</span>
              </figcaption>
            </figure>
          ))}
        </div>
      </section>

      {/* 7 · FAQ */}
      <section className="section">
        <div className="eyebrow center">FAQs</div>
        <h2 className="display center">
          Good <em>questions.</em>
        </h2>
        <Faq />
      </section>

      {/* 8 · final CTA */}
      <section className="section cta">
        <h2 className="display center">
          Ready for the <em>next night?</em>
        </h2>
        <div className="row center">
          <a className="btn primary" href="#board">
            Open the Night Board
          </a>
          <a className="btn" href={FILM} target="_blank" rel="noopener noreferrer">
            ▶ Watch the film
          </a>
          <a className="btn ghost" href={REPO_BRANCH} target="_blank" rel="noopener noreferrer">
            Code on GitHub
          </a>
        </div>
      </section>
    </main>
  );
}
