/** One interface, two transports: Web Speech (browser) and typed. */
export interface SttHandlers {
  onPartial: (text: string) => void;
  onFinal: (text: string) => void;
  onError: (message: string) => void;
}

export interface SttTransport {
  readonly name: "webspeech" | "typed";
  start(handlers: SttHandlers): Promise<void>;
  stop(): Promise<void>;
}

export type SttChoice = "webspeech" | "typed";

export function chooseStt(): SttChoice {
  const q = new URLSearchParams(window.location.search).get("stt");
  if (q === "webspeech" || q === "typed") return q;
  return "webspeech";
}
