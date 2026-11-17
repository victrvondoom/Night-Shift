/**
 * OmniDimension browser voice: a thin controller over the official `@omnidim-ai/client` WebSession.
 *
 * - The backend creates the session and returns only `ws_url` (single use, 15 min); we pass it to
 *   `session.start({ wsUrl })` exactly as returned: never built, edited, stored or cached here.
 * - `transcript` events carry a *cumulative snapshot of the current turn*: the latest snapshot
 *   REPLACES the open line for that role; it is never appended. Only `final: true` closes a line.
 * - Voice is read/propose only. A spoken "approve" cannot authorise anything: approval is the typed,
 *   authenticated action in the remediation panel.
 */
import { WebSession } from "@omnidim-ai/client";
import { applyTranscript, type TranscriptLine } from "./transcript";

export { applyTranscript, type TranscriptLine };

export type VoiceState = "NOT_CONFIGURED" | "idle" | "connecting" | "active" | "ended" | "error";
export interface VoiceSnapshot {
  state: VoiceState;
  muted: boolean;
  reason?: string;
  error?: string;
  lines: TranscriptLine[];
}

export class OmniVoice {
  private session: WebSession | null = null;
  private snap: VoiceSnapshot = { state: "idle", muted: false, lines: [] };
  private beaconSession = "";
  constructor(
    private voiceBase: string,
    private csrf: () => string,
    private onChange: (s: VoiceSnapshot) => void,
  ) {}

  private set(patch: Partial<VoiceSnapshot>) {
    this.snap = { ...this.snap, ...patch };
    this.onChange(this.snap);
  }

  private headers() {
    return { "content-type": "application/json", "x-csrf-token": this.csrf() };
  }

  private async post(path: string, body: unknown) {
    try {
      await fetch(`${this.voiceBase}${path}`, { method: "POST", headers: this.headers(), body: JSON.stringify(body) });
    } catch {
      /* audit linkage is best effort; the live call is unaffected */
    }
  }

  async start(incidentId: string): Promise<void> {
    this.set({ state: "connecting", error: undefined, reason: undefined, lines: [] });
    let resp: Response;
    try {
      resp = await fetch(`${this.voiceBase}/omnidim/session`, { method: "POST", headers: this.headers(), body: JSON.stringify({ incident_id: incidentId }) });
    } catch (e) {
      this.set({ state: "error", error: `API unreachable: ${e instanceof Error ? e.message : e}` });
      return;
    }
    const body = (await resp.json().catch(() => ({}))) as { ws_url?: string; beacon_session?: string; error?: string; state?: string };
    if (!resp.ok || !body.ws_url) {
      this.set(body.state === "NOT_CONFIGURED" ? { state: "NOT_CONFIGURED", error: body.error } : { state: "error", error: body.error || `HTTP ${resp.status}` });
      return;
    }
    this.beaconSession = body.beacon_session || "";
    const s = new WebSession();
    this.session = s;
    s.on("status", (st) => {
      if (st === "connecting") this.set({ state: "connecting" });
      else if (st === "active") {
        this.set({ state: "active" });
        void this.post(`/omnidim/session/${this.beaconSession}/status`, { state: "active" });
      } else {
        this.set({ state: "ended", reason: st.reason });
        void this.post(`/omnidim/session/${this.beaconSession}/status`, { state: "ended", reason: st.reason });
      }
    });
    s.on("transcript", (t) => {
      this.set({ lines: applyTranscript(this.snap.lines, t) });
      if (t.final) void this.post(`/omnidim/session/${this.beaconSession}/transcript`, t);
    });
    s.on("error", (e) => this.set({ error: e.message }));
    try {
      await s.start({ wsUrl: body.ws_url }); // asks for mic permission
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      this.set({ state: "error", error: /permission|denied|NotAllowed/i.test(msg) ? "microphone permission denied" : msg });
    }
  }

  mute(muted: boolean) {
    this.session?.mute(muted);
    this.set({ muted });
  }

  stop() {
    this.session?.stop();
    this.session = null;
  }
}
