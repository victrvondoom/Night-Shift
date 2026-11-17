import test from "node:test";
import assert from "node:assert/strict";
import { applyTranscript } from "../src/voice/transcript.ts";

test("cumulative snapshots replace the open line instead of appending", () => {
  let l = [];
  for (const t of ["what", "what hap", "what happened"]) l = applyTranscript(l, { role: "user", text: t, final: false });
  assert.equal(l.length, 1);
  assert.equal(l[0].text, "what happened");
});

test("a final line closes the turn; the next snapshot starts a new line", () => {
  let l = applyTranscript([], { role: "agent", text: "A change", final: false });
  l = applyTranscript(l, { role: "agent", text: "A change to the policy", final: true });
  l = applyTranscript(l, { role: "agent", text: "Then", final: false });
  assert.deepEqual(l.map((x) => [x.text, x.final]), [["A change to the policy", true], ["Then", false]]);
});

test("interleaved roles keep separate lines; a user interruption does not overwrite the agent line", () => {
  let l = applyTranscript([], { role: "agent", text: "The fix is", final: false });
  l = applyTranscript(l, { role: "user", text: "stop", final: false });
  l = applyTranscript(l, { role: "user", text: "stop wait", final: true });
  assert.equal(l.length, 2);
  assert.equal(l[0].role, "agent");
  assert.equal(l[1].text, "stop wait");
});
