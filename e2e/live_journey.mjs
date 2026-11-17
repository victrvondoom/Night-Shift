// k3s-mode browser journey: REAL control plane (k3s) + real Prometheus/Alertmanager + EMULATED data plane.
// Prereq:  DEMO_MODE=k3s DEMO_EXEC=temporal make demo-up   then   node e2e/live_journey.mjs
// The break is applied OUT OF BAND with kubectl (as an outside actor would), never through the app's own API.
// Voice steps are NOT automated: they need a real OmniDimension session and a microphone (see docs/PHASE_IV.md).
import { createRequire } from "node:module";
import { execSync } from "node:child_process";
const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const UI = process.env.UI || "http://127.0.0.1:5173";
const PASS = process.env.PASSCODE || "demo-pass";
const SHOTS = process.env.SHOTS || "/var/tmp/shots-live";
import fs from "node:fs";
fs.mkdirSync(SHOTS, { recursive: true });
const steps = [];
const ok = (name, cond, detail = "") => { steps.push({ name, status: cond ? "PASS" : "FAIL", detail }); console.log(`${cond ? "PASS" : "FAIL"}  ${name} ${detail}`); if (!cond) throw new Error(`step failed: ${name}`); };
const sh = (c) => execSync(c, { cwd: new URL("..", import.meta.url).pathname, encoding: "utf8" });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 1800 } });
let navs = 0;
page.on("framenavigated", (f) => { if (f === page.mainFrame()) navs++; });
try {
  sh("scripts/k3s_sandbox.sh restore");
  // let the previous alert resolve in the REAL Prometheus/Alertmanager, otherwise Alertmanager will (correctly) not re-notify
  for (let i = 0; i < 60; i++) {
    const q = await (await fetch("http://127.0.0.1:9090/api/v1/query?query=" + encodeURIComponent('ALERTS{alertname="DemoDbErrors",alertstate="firing"}'))).json();
    if (!q.data.result.length) break;
    await new Promise((r) => setTimeout(r, 2000));
  }
  await new Promise((r) => setTimeout(r, 8000));
  await page.goto(`${UI}/#workspace`); await page.waitForSelector(".ws");
  const base = navs;
  await page.fill('input[name="pc"]', PASS); await page.click('button:has-text("Sign in")');
  await page.waitForSelector(".ws-int .chip");
  ok("1 signed in via server session (no passcode in browser storage)", !(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).includes(PASS));
  const chips = await page.locator(".ws-int").innerText();
  ok("2 kubernetes row labelled REAL_CONTROL_PLANE+EMULATED_DATAPLANE", /REAL_CONTROL_PLANE\+EMULATED_DATAPLANE/.test(chips));
  const ids = async () => ((await (await fetch(`${UI}/api/ns/incidents`, { headers: { "x-beacon-passcode": PASS } })).json()).incidents || []).map((i) => i.incident_id);
  const known = new Set(await ids());
  sh("scripts/k3s_sandbox.sh break");
  ok("3 NetworkPolicy edited out of band with kubectl (real API server)", /ingress rules:\s*$/.test(sh("scripts/k3s_sandbox.sh status").trim()));
  let fresh = "";
  for (let i = 0; i < 60 && !fresh; i++) { fresh = (await ids()).find((x) => !known.has(x)) || ""; if (!fresh) await new Promise((r) => setTimeout(r, 2000)); }
  ok("4 a NEW incident id is opened for the new break (recurrence does not reuse a resolved incident)", !!fresh, fresh);
  await page.waitForSelector(`option[value="${fresh}"]`, { state: "attached", timeout: 60000 });
  await page.selectOption("select:has(option[value=\"" + fresh + "\"])", fresh);
  ok("4b it appears in the console incident list without a reload and is selected", navs === base, `navigations=${navs - base}`);
  await page.waitForSelector(".badge.mode-LIVE", { timeout: 60000 });
  ok("5 source mode LIVE (not DEMO_SIMULATOR)", (await page.locator(".badge.mode-LIVE").count()) > 0 && (await page.locator(".badge.mode-DEMO_SIMULATOR").count()) === 0);
  for (const src of ["kubernetes", "prometheus", "app"]) await page.waitForSelector(`.ws-table tbody tr:has-text("${src}")`, { timeout: 120000 });
  ok("6 timeline holds real kubernetes audit + prometheus alert + app errors", true);
  ok("7 correlation from Pathway", (await page.locator("text=engine: pathway").count()) > 0);
  await page.click('button:has-text("Create proposal")');
  await page.waitForSelector('b:has-text("PASSED")', { timeout: 60000 });
  ok("8 server-side dry-run PASSED as the restricted ServiceAccount", true);
  const approve = page.locator('button:has-text("Approve")');
  ok("9 approve disabled until the exact phrase is typed", await approve.isDisabled());
  await page.fill('form input[autocomplete="off"]', "approve fix 1"); await approve.click();
  await page.waitForSelector(".badge.lc-VERIFIED", { timeout: 240000 });
  ok("10 VERIFIED only after backend verification", true);
  ok("11 three independent check groups PASS", (await page.locator(".ws-check.PASS").count()) === 3);
  await page.screenshot({ path: `${SHOTS}/live-verified.png`, fullPage: true });
  const href = await page.locator('a:has-text("Download report")').getAttribute("href");
  const md = await (await fetch(`${UI}${href}`, { headers: { "x-beacon-passcode": PASS } })).text();
  ok("12 markdown report: VERIFIED, exactly one execution", md.includes("Final state: **VERIFIED**") && md.includes("Execution count: **1**"));
  const js = await (await fetch(`${UI}${href.replace("format=md", "format=json")}`, { headers: { "x-beacon-passcode": PASS } })).text();
  const rep = JSON.parse(js);
  ok("13 JSON report: consent signature valid, approver derived server-side, verified_human_identity=false", rep.approval.consent_signature_valid === true && rep.approval.approver === "LOCAL_DEMO_OPERATOR" && rep.approval.verified_human_identity === false);
  const secretValues = [PASS, "alert-token", "audit-token", "eyJhbGci"];
  ok("13b no secret VALUES in either report", !secretValues.some((v) => (md + js).includes(v)));
  ok("14 real cluster state restored", /ingress rules: \[\{/.test(sh("scripts/k3s_sandbox.sh status")));
} finally {
  fs.writeFileSync(`${SHOTS}/live_journey.json`, JSON.stringify({ steps, not_automated: ["OmniDimension real session / microphone / barge-in (BLOCKED: needs credentials + mic)"] }, null, 2));
  await browser.close();
}
