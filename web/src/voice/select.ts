import type { Api } from "../api";
import type { Config } from "../config";
import { ConsoleTransport } from "./console";
import type { SttChoice } from "./stt";
import type { VoiceTransport } from "./transport";

/** The typed/push-to-talk console is the always-available fallback. Live voice is OmniDimension, in the incident workspace. */
export type VoiceBackend = "console";

export function chooseBackend(_config: Config): VoiceBackend {
  return "console";
}

export function makeTransport(_backend: VoiceBackend, api: Api, config: Config, stt: SttChoice, _passcode: () => string): VoiceTransport {
  return new ConsoleTransport(api, stt, config.sttLanguage);
}
