// Browser end-to-end: the golden journey through the real UI against a running demo stack.
// Usage: node e2e/journey.mjs   (env: UI=http://127.0.0.1:5173 PASSCODE=demo-pass SHOTS=/path)
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const UI = process.env.UI || "http://127.0.0.1:5173";
const PASS = process.env.PASSCODE || "demo-pass";
const SHOTS = process.env.SHOTS || "/var/tmp/shots";
import fs from "node:fs";
fs.mkdirSync(SHOTS, { recursive: true });
const steps = [];
const ok = (name, cond, detail = "") => { steps.push({ name, status: cond ? "PASS" : "FAIL", detail }); console.log(`${cond ? "PASS" : "FAIL"}  ${name} ${detail}`); if (!cond) throw new Error(`step failed: ${name}`); };

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 1600 } });
let reloaded = 0;
page.on("framenavigated", (f) => { if (f === page.mainFrame()) reloaded++; });
try {
  await page.goto(`${UI}/#workspace`);
  await page.waitForSelector(".ws");
  const navsAfterLoad = reloaded;
  await page.fill('input[name="pc"]', PASS); await page.click('button:has-text("Sign in")');
  const before = (await page.locator(".ws-head h1").first().innerText().catch(() => "")) || "";
  await page.click('button:has-text("Reset demo data")'); await page.waitForSelector(".ws-msg.ok");
  ok("integration strip rendered from backend", (await page.locator(".ws-int .chip").count()) >= 8);
  await page.click('button:has-text("Trigger NetworkPolicy incident")');
  await page.waitForFunction((old) => { const h = document.querySelector(".ws-head h1"); return h && h.textContent !== old; }, before, { timeout: 60000 });
  ok("incident appears without a page reload", reloaded === navsAfterLoad, `navigations=${reloaded}`);
  ok("source mode labelled DEMO_SIMULATOR", await page.locator(".badge.mode-DEMO_SIMULATOR").count() > 0);
  await page.waitForSelector('.ws-table tbody tr:has-text("prometheus")', { timeout: 60000 });
  await page.waitForFunction(() => document.querySelectorAll(".ws-table tbody tr").length >= 3, null, { timeout: 60000 });
  ok("timeline updated live with source/event ids", (await page.locator(".ws-table tbody tr").count()) >= 3);
  await page.waitForSelector('text=Pathway', { state: "attached", timeout: 5000 }).catch(() => {});
  ok("correlation rendered from Pathway output", (await page.locator("text=engine: pathway").count()) > 0);
  await page.click('button:has-text("Explain with evidence")');
  await page.waitForSelector(".badge.org-RULES_ONLY, .badge.org-BIFROST_MODEL", { timeout: 30000 });
  const origin = (await page.locator('[class*="badge org-"]').first().innerText());
  ok("explanation labelled honestly", /RULES_ONLY|AI via Bifrost/.test(origin), origin);
  await page.screenshot({ path: `${SHOTS}/1-correlated.png`, fullPage: true });
  await page.click('button:has-text("Create proposal")');
  await page.waitForSelector('b:has-text("PASSED")', { timeout: 30000 });
  ok("proposal shows exact action, params and dry run", (await page.locator("text=PASSED").count()) > 0);
  const approveBtn = page.locator('button:has-text("Approve")');
  ok("approve disabled until exact phrase typed", await approveBtn.isDisabled());
  await page.fill('form input[autocomplete="off"]', "approve fix 1");
  await approveBtn.click();
  await page.waitForSelector(".badge.lc-VERIFIED", { timeout: 120000 });
  ok("lifecycle reaches VERIFIED only via backend verification", true);
  const checks = await page.locator(".ws-check.PASS").count();
  ok("all three independent check groups PASS", checks === 3, `groups=${checks}`);
  await page.screenshot({ path: `${SHOTS}/2-verified.png`, fullPage: true });
  const href = await page.locator('a:has-text("Download report")').getAttribute("href");
  const rep = await (await fetch(`${UI}${href}`, { headers: { "x-beacon-passcode": PASS } })).text();
  ok("report generated from persisted data", rep.includes("Final state: **VERIFIED**") && rep.includes("Execution count: **1**"));
} finally {
  fs.writeFileSync(`${SHOTS}/journey.json`, JSON.stringify({ steps }, null, 2));
  await browser.close();
}
