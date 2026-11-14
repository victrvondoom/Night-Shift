/** Runtime config served at /config.json (never cached by Caddy), so URLs never need a rebuild. */
export interface Config {
  voiceUrl: string;
  dashboardUrl: string;
  region: string;
  sttLanguage: string;
  voiceBackend: "console" | "bolna";
  archivedIncidentId: string;
  replay: boolean;
  /** Whether the push-to-talk console backend is offered next to the Bolna call. */
  cascadeEnabled: boolean;
  /** Local demo cluster (k3d): enables the "run the night" helpers. */
  local: boolean;
  localPasscode: string;
}

const DEFAULTS: Config = {
  voiceUrl: "",
  dashboardUrl: "",
  region: "local",
  sttLanguage: "en-IN",
  voiceBackend: "bolna",
  archivedIncidentId: "",
  cascadeEnabled: true,
  replay: false,
  local: false,
  localPasscode: "",
};

let cached: Config | null = null;

export async function loadConfig(): Promise<Config> {
  if (cached) return cached;
  const params = new URLSearchParams(window.location.search);
  let fetched: Partial<Config> = {};
  try {
    const resp = await fetch("/config.json", { cache: "no-store" });
    if (resp.ok) fetched = await resp.json();
  } catch {
    /* no config: local dev or replay */
  }
  const env = import.meta.env as Record<string, string | undefined>;
  const lang = params.get("lang");
  cached = {
    ...DEFAULTS,
    ...fetched,
    ...(lang ? { sttLanguage: lang } : {}),
    voiceUrl: fetched.voiceUrl || env.VITE_VOICE_URL || "/voice",
    dashboardUrl: fetched.dashboardUrl || env.VITE_DASHBOARD_URL || "/api",
    replay: params.get("replay") === "1" || env.VITE_REPLAY === "1",
  };
  return cached;
}

export function trimSlash(url: string): string {
  return url.endsWith("/") ? url.slice(0, -1) : url;
}
