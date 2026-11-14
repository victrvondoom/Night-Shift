/**
 * One voice interface, two backends.
 *
 * - `console`: push-to-talk or typed text → POST /voice/turn on the Night Shift API, where a local
 *   model (Ollama) runs the tools. Typed text is the verified consent channel.
 * - `bolna`: a live Bolna Web Call (WebRTC). STT, turn-taking, the LLM and TTS run at Bolna;
 *   the agent's tool calls go from Bolna to the Night Shift API as custom functions, and the
 *   console shows them by polling the session. A spoken approval is held until typed.
 *
 * Both share TOOL_SCHEMAS (exported by scripts/export_tools.py) and the same Python tools,
 * so the safety model does not change when the mouth and ears do.
 */
import type { Evidence, ToolEvent } from "../types";

export interface TranscriptEvent {
  text: string;
  final: boolean;
  confidence?: number;
}

export interface AgentReplyEvent {
  text: string;
  cited: string[];
  interrupted?: boolean;
}

export interface VoiceTransportHandlers {
  onUserTranscript: (e: TranscriptEvent) => void;
  onAgentText: (e: AgentReplyEvent) => void;
  onAgentAudio: (pcm16: Int16Array, sampleRate: number) => void;
  onAgentDone: (status: "completed" | "interrupted") => void;
  onToolResult: (name: string, args: Record<string, unknown>, result: unknown, events: ToolEvent[], evidence: Evidence[]) => void;
  /** The socket dropped and the same session was resumed (nth time). */
  onResumed?: (n: number) => void;
  /** A tool call has arrived and is about to run (for the latency overlay). */
  onToolStart?: (name: string) => void;
  onState: (state: "connecting" | "listening" | "thinking" | "speaking" | "idle" | "error") => void;
  onError: (message: string) => void;
}

export interface VoiceSession {
  incidentId: string;
  sessionId: string;
  systemPrompt: string;
  greeting?: string;
  keyterms?: string[];
  languageCodes?: string[];
  /** Voice id, when the backend lets the session choose one. */
  voice?: string;
}

export interface VoiceTransport {
  readonly name: "console" | "bolna";
  start(session: VoiceSession, handlers: VoiceTransportHandlers): Promise<void>;
  /** Push microphone audio (PCM16 mono at `sampleRate`). Full-duplex backends accept it continuously. */
  sendAudio(pcm16: Int16Array, sampleRate: number): void;
  /** Send typed text as if spoken. */
  sendText(text: string): Promise<void>;
  /** Make the agent speak to a system-side fact (the loop resolved or escalated); not the engineer speaking. */
  inject(content: string): Promise<void>;
  /**
   * Run a tool from the console itself, outside any agent turn (barge-in withdraws a
   * proposal through cancel_proposal). Optional: the cascade runs its tools server-side.
   */
  callTool?(name: string, args: Record<string, unknown>): Promise<{ ok: boolean; result: unknown }>;
  /** Mid-session turn-detection tuning (noisy room: higher VAD threshold, longer silence). */
  setTurnDetection?(opts: { vad_threshold: number; min_silence?: number; max_silence?: number }): void;
  /** Interrupt the agent (barge-in). */
  interrupt(): void;
  stop(): Promise<void>;
}
