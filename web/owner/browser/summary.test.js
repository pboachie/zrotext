/* SPDX-License-Identifier: AGPL-3.0-only */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const test = require("node:test");
const { chromium } = require("playwright");
const root = path.resolve(__dirname, "..");
const first = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const second = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const day = Date.UTC(2000, 0, 1), observed = day + 43200000;
let browser, screenshots;
test.before(async () => {
  browser = await chromium.launch();
  if (process.env.ZT_OWNER_SCREENSHOTS === "1") screenshots = await fs.mkdtemp(path.join(os.tmpdir(), "zrotext-summary-"));
});
test.after(async () => { await browser.close(); });
function summary(device = null, value = 0, capped = false) {
  return { scope: device ? "device" : "account", device_id: device, timezone: "UTC", day_start_ms: day,
    day_end_ms: day + 86400000, observed_at_ms: observed, max_age_ms: 30000, count_bound: 1000,
    submitted_today: { value, capped }, pending: { value, capped }, in_flight: { value, capped } };
}
async function owner(width, hold = false) {
  const page = await browser.newPage({ viewport: { width, height: 900 } });
  await page.clock.install({ time: observed });
  const state = { value: 0, capped: false, status: 200, hold, release: null, requests: [], observed,
    heldDevice: null, releaseDevice: null };
  await page.context().addCookies([{ name: "__Host-zrotext_csrf", value: "ztc_synthetic", url: "https://example.test", secure: true, sameSite: "Strict" }]);
  await page.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.pathname === "/owner/events") return route.abort();
    if (url.pathname.startsWith("/owner/")) {
      const asset = url.pathname.slice(7), file = asset.includes(".") ? asset : asset + ".html";
      if (!/^[a-z-]+\.(html|css|js)$/.test(file)) return route.fulfill({ status: 404 });
      return route.fulfill({ body: await fs.readFile(path.join(root, file)), contentType:
        file.endsWith(".js") ? "text/javascript" : file.endsWith(".css") ? "text/css" : "text/html" });
    }
    if (url.pathname === "/v1/owner/message-summary") {
      const device = url.searchParams.get("device_id");
      const value = { ...summary(device, state.value, state.capped), observed_at_ms: state.observed };
      state.requests.push({ device, headers: request.headers() });
      if (state.hold) await new Promise(resolve => { state.release = resolve; });
      if (device && device === state.heldDevice) await new Promise(resolve => { state.releaseDevice = resolve; });
      return route.fulfill({ status: state.status, json: value });
    }
    if (url.pathname === "/v1/enrollment/devices") return route.fulfill({ json: { devices: [first, second].map((id, index) => ({
      device_id: id, display_name: `Synthetic gateway ${index}`, revoked: false })), next_cursor: null } });
    if (url.pathname === "/v1/auth/session") return route.fulfill({ json: { role: "owner" } });
    if (url.pathname.startsWith("/v1/billing/")) return route.fulfill({ status: 404 });
    if (url.pathname === "/v1/auth/logout") return route.fulfill({ status: 204 });
    return route.fulfill({ json: url.pathname === "/v1/auth/mfa" ? { enabled: false, pending: false } :
      url.pathname === "/v1/auth/sessions" ? { sessions: [] } : { messages: [], keys: [], holds: [], endpoints: [], next_cursor: null } });
  });
  await page.goto("https://example.test/owner/devices");
  await page.waitForFunction(() => document.getElementById("summary-device").options.length === 3);
  if (!hold) await page.waitForFunction(() => document.getElementById("summary-submitted").textContent === "0");
  return { page, state };
}
for (const width of [320, 390, 1440]) {
  test(`authoritative summary cards render zero and capped bounds at ${width}px and 200% text`, async () => {
    const { page, state } = await owner(width);
    try {
      assert.match(await page.locator("#message-summary").textContent(), /Submitted today \(UTC\)/);
      assert.match(await page.locator("#message-summary").textContent(), /not ungranted queue depth/);
      assert.equal(state.requests[0].headers["x-zrotext-csrf"], "ztc_synthetic");
      state.value = 1000; state.capped = true;
      await page.locator("#refresh-summary").click();
      await page.waitForFunction(() => document.getElementById("summary-submitted").textContent.includes("capped"));
      assert.equal(await page.locator("#summary-pending").textContent(), "1000+ (capped)");
      state.capped = false;
      await page.locator("#refresh-summary").click();
      await page.waitForFunction(() => document.getElementById("summary-submitted").textContent === "1000");
      if (screenshots) await page.locator("#message-summary").screenshot({ path: path.join(screenshots, `summary-${width}.png`) });
      await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      const controlsFit = await page.locator("#message-summary button, #summary-device").evaluateAll(nodes => nodes.every(node => {
        const r = node.getBoundingClientRect(); return r.left >= 0 && r.right <= innerWidth + 1 && r.height >= 44;
      }));
      assert.equal(controlsFit, true);
    } finally { await page.close(); }
  });
}
test("loading, unavailable and historical offline observations never become a fabricated zero", async () => {
  const { page, state } = await owner(390, true);
  try {
    assert.equal(await page.locator("#summary-submitted").textContent(), "Loading…");
    state.status = 503; state.hold = false; state.release();
    await page.waitForFunction(() => document.getElementById("summary-submitted").textContent === "Unavailable");
    state.status = 200; state.value = 7;
    await page.locator("#refresh-summary").click();
    await page.waitForFunction(() => document.getElementById("summary-submitted").textContent === "7");
    await page.locator("#auto-refresh").uncheck();
    await page.clock.fastForward(31000);
    assert.equal(await page.locator("#summary-submitted").textContent(), "7 (stale)");
    assert.match(await page.locator("#summary-status").textContent(), /current counts are unknown/);
    await page.context().setOffline(true);
    assert.match(await page.locator("#summary-status").textContent(), /Offline/);
    await page.context().setOffline(false);
    state.status = 503;
    await page.locator("#refresh-summary").click();
    await page.waitForFunction(() => document.getElementById("summary-status").textContent.includes("Refresh failed"));
    assert.equal(await page.locator("#summary-submitted").textContent(), "7 (stale)");
  } finally { await page.close(); }
});
test("selected-device changes fence late responses and preserve pending input", async () => {
  const { page, state } = await owner(1440);
  try {
    await page.locator("#display-name").fill("Pending synthetic name");
    state.heldDevice = first; state.value = 9;
    await page.locator("#summary-device").selectOption(first);
    await page.waitForFunction(() => document.getElementById("summary-submitted").textContent === "Loading…");
    state.value = 3;
    await page.locator("#summary-device").selectOption(second);
    assert.equal(await page.locator("#summary-submitted").textContent(), "Loading…");
    state.heldDevice = null; state.releaseDevice();
    await page.waitForFunction(() => document.getElementById("summary-submitted").textContent === "3");
    assert.equal(state.requests.at(-1).device, second);
    assert.equal(await page.locator("#display-name").inputValue(), "Pending synthetic name");
    await page.locator("#logout").click();
    await page.waitForFunction(() => document.getElementById("owner-content").hidden);
    assert.equal(await page.locator("#owner-content").isVisible(), false);
    assert.equal(await page.locator("#summary-submitted").textContent(), "Unavailable");
  } finally { await page.close(); }
});
test("UTC midnight expires observations without a fast refresh loop", async () => {
  const { page, state } = await owner(390);
  try {
    state.observed = day + 86399000;
    await page.locator("#refresh-summary").click();
    await page.waitForFunction(() => !document.getElementById("refresh-summary").disabled);
    const count = state.requests.length;
    await page.clock.fastForward(1100);
    assert.equal(await page.locator("#summary-submitted").textContent(), "0 (stale)");
    assert.equal(state.requests.length, count);
  } finally { await page.close(); }
});
