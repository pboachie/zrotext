/* SPDX-License-Identifier: AGPL-3.0-only */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const test = require("node:test");
const { chromium } = require("playwright");
const root = path.resolve(__dirname, "..");
const gateway = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const day = Date.UTC(2000, 0, 1), observed = day + 43200000;
let browser, screenshots;
test.before(async () => {
  browser = await chromium.launch();
  if (process.env.ZT_OWNER_SCREENSHOTS === "1") screenshots = await fs.mkdtemp(path.join(os.tmpdir(), "zrotext-overview-"));
});
test.after(async () => { await browser.close(); });
function device(id, name) {
  return { device_id: id, display_name: name, revoked: false, active_socket_lease: true,
    pending_messages: 2, in_flight_messages: 1, status_observed_at_ms: observed };
}
async function overview(width) {
  const page = await browser.newPage({ viewport: { width, height: 900 }, reducedMotion: "reduce" });
  await page.clock.install({ time: observed });
  const state = { devices: [device(gateway, "Synthetic gateway Alpha"), device(other, "Synthetic gateway Beta")], summaryStatus: 200, summaryValue: 19, requests: [] };
  await page.context().addCookies([{ name: "__Host-zrotext_csrf", value: "ztc_synthetic", url: "https://example.test", secure: true, sameSite: "Strict" }]);
  await page.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url());
    state.requests.push({ method: request.method(), path: url.pathname });
    if (url.pathname === "/owner/events") return route.abort();
    if (url.pathname.startsWith("/owner/")) {
      const asset = url.pathname.slice(7), file = asset.includes(".") ? asset : asset + ".html";
      if (!/^[a-z-]+\.(html|css|js)$/.test(file)) return route.fulfill({ status: 404 });
      return route.fulfill({ body: await fs.readFile(path.join(root, file)), contentType: file.endsWith(".js") ? "text/javascript" : file.endsWith(".css") ? "text/css" : "text/html" });
    }
    if (url.pathname === "/v1/auth/session") return route.fulfill({ json: { role: "owner" } });
    if (url.pathname.startsWith("/v1/billing/")) return route.fulfill({ status: 404 });
    if (url.pathname === "/v1/enrollment/devices") return route.fulfill({ json: { devices: state.devices, next_cursor: null } });
    if (url.pathname === "/v1/owner/message-summary") return route.fulfill({ status: state.summaryStatus, json: {
      scope: "account", device_id: null, timezone: "UTC", day_start_ms: day, day_end_ms: day + 86400000,
      observed_at_ms: observed, max_age_ms: 30000, count_bound: 1000,
      submitted_today: { value: state.summaryValue, capped: false }, pending: { value: 4, capped: false }, in_flight: { value: 1, capped: false }
    } });
    if (url.pathname === "/v1/owner/messages") return route.fulfill({ json: { messages: [{ message_id: other, device_id: gateway,
      state: "unknown", created_at_ms: observed, updated_at_ms: observed, events: [], events_truncated: false,
      body: "synthetic-content-must-not-render", recipient_e164: "synthetic-recipient-must-not-render" }], next_cursor: null } });
    return route.fulfill({ json: url.pathname === "/v1/auth/mfa" ? { enabled: false, pending: false } :
      url.pathname === "/v1/auth/sessions" ? { sessions: [] } : { messages: [], events: [], deliveries: [], endpoints: [], keys: [], holds: [], next_cursor: null } });
  });
  await page.goto("https://example.test/owner/devices");
  await page.waitForFunction(() => document.getElementById("summary-submitted").textContent === "19" && document.querySelectorAll(".activity-row").length === 1 && document.getElementById("device-list").children.length === 2);
  return { page, state };
}
async function hierarchyAndFit(page) {
  const order = await page.evaluate(() => ["message-summary", "approved-devices", "message-activity"].map(id => document.getElementById(id).getBoundingClientRect().top));
  assert.ok(order[0] < order[1] && order[1] < order[2], "authoritative overview precedes hardware and activity");
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  assert.equal(await page.locator("#message-summary button:visible, #message-summary select:visible, #approved-devices button:visible, #message-activity button:visible, #message-activity summary:visible").evaluateAll(nodes => nodes.some(node => {
    const box = node.getBoundingClientRect(); return box.left < -1 || box.right > innerWidth + 1 || box.height < 44;
  })), false);
}
for (const width of [320, 390, 1440]) {
  test(`integrated overview leads fleet and activity at ${width}px and 200% text`, async () => {
    const { page } = await overview(width);
    try {
      await hierarchyAndFit(page);
      assert.equal(await page.locator("#summary-submitted").textContent(), "19");
      assert.match(await page.locator("#fleet-summary").textContent(), /loaded pages only/);
      assert.match(await page.locator("#message-list").textContent(), /unknown/i);
      assert.doesNotMatch(await page.locator("#message-list").textContent(), /synthetic-content-must-not-render|synthetic-recipient-must-not-render/);
      if (screenshots) await page.screenshot({ path: path.join(screenshots, `overview-${width}.png`), fullPage: true });
      await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
      await hierarchyAndFit(page);
      const select = page.getByRole("button", { name: "View details for Synthetic gateway Beta", exact: true });
      await select.focus();
      await page.keyboard.press("Enter");
      assert.equal(await page.locator("#device-detail-name").textContent(), "Synthetic gateway Beta");
      assert.equal(await select.evaluate(node => node === document.activeElement), true);
    } finally { await page.close(); }
  });
}
test("combined refresh preserves selected hardware, keyboard focus, pending input and unknown history", async () => {
  const { page, state } = await overview(1440);
  try {
    const select = page.getByRole("button", { name: "View details for Synthetic gateway Beta", exact: true });
    await select.click();
    await page.locator("#display-name").fill("Pending synthetic pairing name");
    await select.focus();
    state.devices = [device(other, "Renamed synthetic gateway"), device(gateway, "Synthetic gateway Alpha")];
    state.summaryValue = 20;
    await page.evaluate(() => { document.getElementById("refresh-devices").click(); document.getElementById("refresh-summary").click(); });
    await page.waitForFunction(() => document.getElementById("device-detail-name").textContent === "Renamed synthetic gateway" && document.getElementById("summary-submitted").textContent === "20");
    assert.equal(await page.locator("#display-name").inputValue(), "Pending synthetic pairing name");
    assert.equal(await page.evaluate(() => document.activeElement.getAttribute("aria-pressed")), "true");
    assert.match(await page.locator("#message-list").textContent(), /unknown/i);
    state.summaryStatus = 500;
    await page.locator("#refresh-summary").click();
    await page.waitForFunction(() => document.getElementById("message-summary").getAttribute("data-stale") === "true");
    assert.match(await page.locator("#summary-submitted").textContent(), /stale/);
    assert.equal(await page.locator("#device-detail-name").textContent(), "Renamed synthetic gateway");
    assert.equal(state.requests.some(r => r.method !== "GET"), false, "overview navigation and refresh never mutate or send");
  } finally { await page.close(); }
});
