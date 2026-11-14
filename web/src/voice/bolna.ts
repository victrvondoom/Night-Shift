/**
 * Bolna Web Call transport (@bolna/web-call, WebRTC).
 *
 * What the SDK gives the browser is deliberately little: call state, the agent's
 * audio level, errors, and the execution id. There is no live transcript, no
 * interruption event and no way to send text into the call. So this transport:
 *
 *  - mints a single-use session through the Night Shift backend (the bn- API key never
 *    reaches the browser);
 *  - shows what the agent *did* by polling the backend for the tool calls Bolna
 *    made on this session (evidence cards, proposals, held approvals);
 *  - sends typed text to the backend's typed turn, which is also the only place an
 *    approval can be confirmed: a spoken "approve fix 1" reaches the backend as a
 *    model-written function call, which Night Shift records as a request and holds;
 *  - detects a barge-in itself, from real audio levels: the engineer's microphone
 *    is loud while the agent is still speaking a read-back. That withdraws the
 *    proposal exactly as before.
 *
 * After the call ends the full transcript is fetched from Bolna and shown.
 */
import { BolnaWebCall, type CallError, type Session } from "@bolna/web-call";
import type { Evidence, ToolEvent } from "../types";
import type { VoiceSession, VoiceTransport, VoiceTransportHandlers } from "./transport";

type Json = Record<string, unknown>;
interface SessionEvent {
  name: string;
  args: Json;
  result: Json;
  tool_events: ToolEvent[];
  evidence: Evidence[];
}
interface TurnReply {
  reply_text: string;
  cited: string[];
  tool_events: ToolEvent[];
  evidence: Evidence[];
  incident?: unknown;
}

const AGENT_SPEAKING = 0.04; // SDK volume-level (0..1) above which the agent is audibly speaking
const AGENT_QUIET_MS = 1200; // silence that ends an agent reply
const BARGE_MS = 350; // the engineer must be loud for this long, over the agent, to count
const MAX_RECONNECTS = 2;

const ERRORS: Record<string, string> = {
  mint_failed: "Could not start the call (the Night Shift backend could not mint a Bolna session).",
  at_capacity: "All Bolna lines are busy. Try again in a moment, or type below.",
  microphone_denied: "Microphone blocked. Allow it for this site, or type below: the consent rules are identical.",
  connect_failed: "The call could not connect.",
  call_rejected: "Bolna declined the call (check the agent id).",
  autoplay_blocked: "The browser blocked audio. Click Connect again.",
  already_active: "A call is already in progress.",
};

export class BolnaTransport implements VoiceTransport {
  readonly name = "bolna" as const;
  private call: BolnaWebCall | null = null;
  private h: VoiceTransportHandlers | null = null;
  private session: VoiceSession | null = null;
  private beaconSession: string | null = null;
  private poll: number | null = null;
  private cursor = 0;
  private stopped = false;
  private reconnects = 0;
  private agentLoudAt = 0;
  private agentSpeaking = false;
  private userLoudSince: number | null = null;
  private bargeThreshold = 0.06;
  private bargedThisReply = false;

  constructor(
    private readonly voiceUrl: string,
    private readonly headers: () => Record<string, string>,
  ) {}

  private async post<T>(path: string, body: unknown): Promise<T> {
    const resp = await fetch(`${this.voiceUrl}${path}`, { method: "POST", headers: this.headers(), body: JSON.stringify(body) });
    const data = (await resp.json().catch(() => ({}))) as T & { error?: string };
    if (!resp.ok) throw new Error(data.error ?? `${path}: ${resp.status}`);
    return data;
  }

  async start(session: VoiceSession, handlers: VoiceTransportHandlers): Promise<void> {
    this.session = session;
    this.h = handlers;
    this.stopped = false;
    this.reconnects = 0;
    await this.dial();
  }

  private async dial(): Promise<void> {
    const h = this.h!;
    h.onState("connecting");
    const call = new BolnaWebCall({
      getSession: async () => {
        const out = await this.post<{ beacon_session: string; session: Session }>("/bolna/session", { incident_id: this.session!.incidentId });
        this.beaconSession = out.beacon_session;
        this.cursor = 0;
        return out.session;
      },
    });
    this.call = call;
    call.on("call-start", () => {
      h.onState("listening");
      this.startPolling();
    });
    call.on("volume-level", (level) => this.onAgentLevel(level));
    call.on("error", (e: CallError) => h.onError(ERRORS[e.code] ?? e.message));
    call.on("call-end", ({ reason }) => void this.onEnd(reason));
    try {
      await call.start();
    } catch {
      /* the `error` event already reported it; typed input still works */
      h.onState("idle");
    }
  }

  /** Agent audio level, ~10/s. Turns it into speaking/listening and end-of-reply. */
  private onAgentLevel(level: number): void {
    const h = this.h;
    if (!h) return;
    const now = performance.now();
    if (level > AGENT_SPEAKING) {
      this.agentLoudAt = now;
      if (!this.agentSpeaking) {
        this.agentSpeaking = true;
        this.bargedThisReply = false;
        h.onState("speaking");
      }
    } else if (this.agentSpeaking && now - this.agentLoudAt > AGENT_QUIET_MS) {
      this.agentSpeaking = false;
      if (!this.bargedThisReply) h.onAgentDone("completed");
      h.onState("listening");
    }
  }

  /** Microphone PCM from the console: used only to notice the engineer talking over the agent. */
  sendAudio(pcm16: Int16Array): void {
    if (!this.agentSpeaking || this.bargedThisReply || !pcm16.length) {
      this.userLoudSince = null;
      return;
    }
    let sum = 0;
    for (let i = 0; i < pcm16.length; i++) sum += (pcm16[i] / 32768) ** 2;
    const rms = Math.sqrt(sum / pcm16.length);
    const now = performance.now();
    if (rms < this.bargeThreshold) {
      this.userLoudSince = null;
      return;
    }
    this.userLoudSince ??= now;
    if (now - this.userLoudSince >= BARGE_MS) {
      this.userLoudSince = null;
      this.bargedThisReply = true;
      // The console reacts to this exactly as it always has: a read-back that was
      // interrupted withdraws its proposal through cancel_proposal.
      this.h?.onAgentDone("interrupted");
    }
  }

  setTurnDetection(opts: { vad_threshold: number }): void {
    // Noisy room: ask for a louder voice before calling it a barge-in.
    this.bargeThreshold = opts.vad_threshold >= 0.7 ? 0.12 : 0.06;
  }

  private startPolling(): void {
    this.stopPolling();
    this.poll = window.setInterval(() => void this.pollOnce(), 1000);
  }

  private stopPolling(): void {
    if (this.poll !== null) window.clearInterval(this.poll);
    this.poll = null;
  }

  private async pollOnce(): Promise<void> {
    const h = this.h;
    if (!h || !this.beaconSession) return;
    let data: { events: SessionEvent[]; next: number };
    try {
      const resp = await fetch(`${this.voiceUrl}/bolna/session/${this.beaconSession}/events?after=${this.cursor}`, { headers: this.headers() });
      if (!resp.ok) return;
      data = await resp.json();
    } catch {
      return;
    }
    this.cursor = data.next;
    for (const ev of data.events) {
      h.onToolStart?.(ev.name);
      h.onToolResult(ev.name, ev.args, ev.result, ev.tool_events, ev.evidence);
      h.onAgentText({ text: describe(ev), cited: ev.evidence.map((c) => c.id) });
    }
  }

  private async onEnd(reason: string): Promise<void> {
    const h = this.h;
    this.stopPolling();
    await this.pollOnce();
    this.agentSpeaking = false;
    if (!h) return;
    if (!this.stopped && reason === "failed" && this.reconnects < MAX_RECONNECTS) {
      this.reconnects += 1;
      h.onResumed?.(this.reconnects);
      await this.dial();
      return;
    }
    h.onState("idle");
    void this.showTranscript(this.beaconSession);
  }

  /** The real transcript, once Bolna has finalised the call (a few seconds after hang-up). */
  private async showTranscript(id: string | null): Promise<void> {
    const h = this.h;
    if (!h || !id) return;
    for (let attempt = 0; attempt < 8; attempt++) {
      await new Promise((r) => window.setTimeout(r, 4000));
      try {
        const resp = await fetch(`${this.voiceUrl}/bolna/calls/${id}`, { headers: this.headers() });
        if (!resp.ok) return;
        const { call } = (await resp.json()) as { call: { transcript?: string; final?: boolean } };
        if (!call.final) continue;
        for (const line of (call.transcript ?? "").split("\n")) {
          const m = /^(assistant|user):\s*(.+)$/i.exec(line.trim());
          if (!m) continue;
          if (m[1].toLowerCase() === "user") h.onUserTranscript({ text: m[2], final: true });
          else h.onAgentText({ text: m[2], cited: [] });
        }
        return;
      } catch {
        return;
      }
    }
  }

  /** Typed text goes to the backend's typed turn: the verified channel for consent. */
  async sendText(text: string): Promise<void> {
    const h = this.h;
    if (!h || !this.session) return;
    h.onState("thinking");
    try {
      const out = await this.post<TurnReply>("/turn", { incident_id: this.session.incidentId, session_id: this.session.sessionId, text, channel: "typed" });
      for (const ev of out.tool_events) h.onToolResult(ev.name, ev.args, { incident: out.incident }, [ev], out.evidence);
      h.onAgentText({ text: out.reply_text, cited: out.cited });
      h.onAgentDone("completed");
    } catch (e) {
      h.onError(e instanceof Error ? e.message : String(e));
    }
    h.onState(this.call?.getState() === "active" ? "listening" : "idle");
  }

  /** System-side facts (resolved, escalated) are shown; the Bolna agent learns them from check_recovery. */
  async inject(): Promise<void> {
    /* the SDK cannot push text into a live call */
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<{ ok: boolean; result: unknown }> {
    const s = this.session;
    if (!s) return { ok: false, result: { error: "no session" } };
    const out = await this.post<{ ok: boolean; result: unknown; tool_events: ToolEvent[]; evidence: Evidence[] }>(`/tools/${name}`, {
      incident_id: s.incidentId,
      session_id: this.beaconSession ?? s.sessionId,
      args,
      transcript: "",
      channel: "console",
    });
    this.h?.onToolResult(name, args, out.result, out.tool_events, out.evidence);
    return { ok: out.ok, result: out.result };
  }

  /** The Interrupt button / Esc: mute nothing, but treat it as the engineer cutting the agent off. */
  interrupt(): void {
    if (!this.agentSpeaking || this.bargedThisReply) return;
    this.bargedThisReply = true;
    this.h?.onAgentDone("interrupted");
  }

  async stop(): Promise<void> {
    this.stopped = true;
    this.stopPolling();
    await this.call?.stop().catch(() => undefined);
    this.call = null;
  }
}

/** One factual line for the conversation pane about what a tool call did. */
function describe(ev: SessionEvent): string {
  const r = ev.result;
  if (r.pending_confirmation) return `Voice request received. Nothing has changed: type “${String(r.confirm_with)}” below to authorise it.`;
  if (typeof r.error === "string") return r.error;
  if (ev.name === "propose_fix") return `Proposed fix ${String(r.fix_id)}: ${String(r.blast_radius ?? "")} To approve, type “${String(r.confirmation_phrase)}”.`;
  if (ev.name === "cancel_proposal") return String(r.spoken_hint ?? "Proposal withdrawn.");
  if (ev.name === "check_recovery") return `Recovery status: ${String(r.status)}.`;
  return ev.tool_events[0]?.summary ?? `${ev.name} ran.`;
}
