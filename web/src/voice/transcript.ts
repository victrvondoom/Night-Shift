export interface TranscriptLine {
  role: "user" | "agent";
  text: string;
  final: boolean;
}

/**
 * The OmniDimension SDK's `transcript` event carries a CUMULATIVE snapshot of the current turn.
 * The latest snapshot REPLACES the open (non-final) line of the same role; only `final: true`
 * closes a line. A new role, or a new turn after a final line, starts a new line.
 */
export function applyTranscript(lines: TranscriptLine[], ev: TranscriptLine): TranscriptLine[] {
  const last = lines[lines.length - 1];
  if (last && last.role === ev.role && !last.final) return [...lines.slice(0, -1), { ...ev }];
  return [...lines, { ...ev }];
}
