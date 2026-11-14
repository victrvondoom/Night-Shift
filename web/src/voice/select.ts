import type { Api } from "../api";
import type { Config } from "../config";
import { trimSlash } from "../config";
import { BolnaTransport } from "./bolna";
import { ConsoleTransport } from "./console";
import type { SttChoice } from "./stt";
import type { VoiceTransport } from "./transport";

export type VoiceBackend = "console" | "bolna";

export function chooseBackend(config: Config): VoiceBackend {
  const q = new URLSearchParams(window.location.search).get("voice");
  if (q === "console" || q === "bolna") return q;
  return config.voiceBackend === "bolna" ? "bolna" : "console";
}

/** Build the voice transport for this session. Both backends reach the same server-side tools. */
export function makeTransport(backend: VoiceBackend, api: Api, config: Config, stt: SttChoice, passcode: () => string): VoiceTransport {
  if (backend === "bolna") {
    return new BolnaTransport(trimSlash(config.voiceUrl), () => ({ "content-type": "application/json", "x-beacon-passcode": passcode() }));
  }
  return new ConsoleTransport(api, stt, config.sttLanguage);
}
