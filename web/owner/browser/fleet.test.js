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
const snapshot = Date.UTC(2000, 0, 1);
let browser, screenshots;
test.before(async () => {
  browser = await chromium.launch();
  if (process.env.ZT_OWNER_SCREENSHOTS === "1") screenshots = await fs.mkdtemp(path.join(os.tmpdir(), "zrotext-fleet-"));
});
test.after(async () => { await browser.close(); });
function device(id, displayName, overrides = {}) {
  return { device_id: id, display_name: displayName, revoked: false, active_socket_lease: true,
    pending_messages: 2, in_flight_messages: 0, status_observed_at_ms: snapshot,
    reported_preconditions: { selected_sim: "active", sms_permission: "granted", airplane_mode: "disabled",
      network_service: "in_service", received_at_ms: snapshot - 1000, fresh: true }, ...overrides };
}
async function fleet(width, initial = [device(first, "Synthetic gateway Alpha"), device(second, "Synthetic gateway Beta")], hold = false) {
  const page = await browser.newPage({ viewport: { width, height: 900 }, reducedMotion: "reduce" });
  await page.clock.install({ time: snapshot });
  const state = { devices: initial, hold, release: null, status: 200, requests: [], pages: [] };
  await page.context().addCookies([{ name: "__Host-zrotext_csrf", value: "ztc_synthetic", url: "https://example.test", secure: true, sameSite: "Strict" }]);
  await page.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url());
    state.requests.push({ path: url.pathname, method: request.method(), headers: request.headers() });
    if (url.pathname === "/owner/events") return route.abort();
    if (url.pathname.startsWith("/owner/")) {
      const asset = url.pathname.slice(7), file = asset.includes(".") ? asset : asset + ".html";
      if (!/^[a-z-]+\.(html|css|js)$/.test(file)) return route.fulfill({ status: 404 });
      return route.fulfill({ status: 200, body: await fs.readFile(path.join(root, file)),
        contentType: file.endsWith(".js") ? "text/javascript" : file.endsWith(".css") ? "text/css" : "text/html" });
    }
    if (url.pathname === "/v1/enrollment/devices" && request.method() === "GET") {
      if (state.hold) await new Promise(resolve => { state.release = resolve; });
      return route.fulfill({ status: state.status, json: state.pages.shift() || { devices: state.devices, next_cursor: null } });
    }
    if (url.pathname.startsWith("/v1/enrollment/devices/") && request.method() === "DELETE") {
      const id = url.pathname.split("/").pop();
      state.devices = state.devices.map(d => d.device_id === id ? { ...d, revoked: true } : d);
      return route.fulfill({ status: 204 });
    }
    if (url.pathname === "/v1/auth/session") return route.fulfill({ json: { role: "owner" } });
    if (url.pathname.startsWith("/v1/billing/")) return route.fulfill({ status: 404 });
    if (url.pathname === "/v1/auth/logout") return route.fulfill({ status: 204 });
    const body = url.pathname === "/v1/auth/mfa" ? { enabled: false, pending: false } :
      url.pathname === "/v1/auth/sessions" ? { sessions: [] } :
        { messages: [], holds: [], keys: [], endpoints: [], next_cursor: null };
    return route.fulfill({ json: body });
  });
  await page.goto("https://example.test/owner/devices");
  await page.waitForFunction(() => document.getElementById("owner-nav-status").textContent.includes("Owner controls"));
  if (!hold) await page.waitForFunction(() => !document.getElementById("device-status").textContent.startsWith("Loading"));
  return { page, state };
}
async function fits(page) {
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  const clipped = await page.locator("#approved-devices button:visible").evaluateAll(nodes => nodes.some(e => {
    const r = e.getBoundingClientRect(); return r.left < -1 || r.right > innerWidth + 1 || r.height < 44;
  }));
  assert.equal(clipped, false);
}
for (const width of [320, 390, 1440]) {
  test(`multi-device fleet and selected details render at ${width}px and 200% text`, async () => {
    const { page } = await fleet(width);
    try {
      await page.getByRole("button", { name: "View details for Synthetic gateway Beta", exact: true }).focus();
      await page.keyboard.press("Enter");
      assert.equal(await page.locator("#device-detail-name").textContent(), "Synthetic gateway Beta");
      assert.match(await page.locator("#device-detail-queue").textContent(), /Pending: 2/);
      assert.match(await page.locator("#device-detail-content").textContent(), /Remote Pause is unavailable/);
      assert.match(await page.locator("#fleet-summary").textContent(), /loaded pages only/);
      const bounds = await page.locator(".fleet-workspace").evaluate(e => {
        const list = e.querySelector(".fleet-table").getBoundingClientRect(), panel = e.querySelector(".device-detail").getBoundingClientRect();
        return { side: panel.left >= list.right, below: panel.top >= list.bottom };
      });
      assert.equal(width === 1440 ? bounds.side : bounds.below, true);
      await fits(page);
      if (screenshots) {
        await page.evaluate(() => window.scrollTo(0, 0));
        await page.screenshot({ path: path.join(screenshots, `fleet-${width}.png`), fullPage: true });
      }
      await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
      await fits(page);
    } finally { await page.close(); }
  });
}
test("refresh preserves selected identity, focused row and unrelated pending input", async () => {
  const { page, state } = await fleet(1440);
  try {
    const select = page.getByRole("button", { name: "View details for Synthetic gateway Beta", exact: true });
    await select.click();
    await page.locator("#display-name").fill("Unsubmitted pairing name");
    await select.focus();
    state.devices = [device(second, "Renamed synthetic gateway"), device(first, "Synthetic gateway Alpha")];
    await page.evaluate(() => document.getElementById("refresh-devices").click());
    await page.waitForFunction(() => document.getElementById("device-detail-name").textContent === "Renamed synthetic gateway");
    assert.equal(await page.evaluate(() => document.activeElement.getAttribute("aria-pressed")), "true");
    assert.equal(await page.locator("#display-name").inputValue(), "Unsubmitted pairing name");
    state.devices = [device(first, "Synthetic gateway Alpha")];
    await page.locator("#refresh-devices").click();
    await page.waitForFunction(() => document.getElementById("device-detail-status").textContent.includes("absent"));
    assert.equal(await page.locator("#device-detail-content").isVisible(), false);
    assert.equal(await page.locator("#device-detail-name").textContent(), "");
  } finally { await page.close(); }
});
test("loading, empty, failed refresh and local stale reports remain truthful", async () => {
  const { page, state } = await fleet(390, [], true);
  try {
    assert.match(await page.locator("#fleet-summary").textContent(), /loading/);
    state.hold = false; state.release();
    await page.waitForFunction(() => document.getElementById("device-status").textContent.includes("No approved"));
    state.devices = [device(first, "Synthetic gateway Alpha", { reported_preconditions: {
      selected_sim: "not_selected", sms_permission: "denied", airplane_mode: "enabled", network_service: "out_of_service", received_at_ms: snapshot - 40000, fresh: true } })];
    await page.locator("#refresh-devices").click();
    await page.getByRole("button", { name: "View details for Synthetic gateway Alpha", exact: true }).click();
    assert.match(await page.locator("#device-detail-preconditions").textContent(), /No SIM selected.*SMS permission denied.*Airplane mode enabled.*Network service limited/);
    await page.locator("#auto-refresh").uncheck();
    const count = state.requests.filter(r => r.path === "/v1/enrollment/devices").length;
    await page.clock.fastForward(60000);
    assert.match(await page.locator("#device-detail-preconditions").textContent(), /Historical observations/);
    assert.equal(state.requests.filter(r => r.path === "/v1/enrollment/devices").length, count);
    state.status = 503;
    await page.locator("#refresh-devices").click();
    await page.waitForFunction(() => document.getElementById("device-detail-status").textContent.startsWith("Refresh failed"));
    assert.match(await page.locator("#fleet-summary").textContent(), /may be stale/);
    assert.equal(await page.locator("#device-list > li").count(), 1);
  } finally { if (state.release) state.release(); await page.close(); }
});
test("revocation remains confirmed authorization removal with CSRF, never Pause", async () => {
  const { page, state } = await fleet(390);
  try {
    await page.getByRole("button", { name: "View details for Synthetic gateway Alpha", exact: true }).click();
    page.once("dialog", dialog => dialog.dismiss());
    await page.getByRole("button", { name: "Revoke Synthetic gateway Alpha", exact: true }).click();
    assert.equal(state.requests.filter(r => r.method === "DELETE").length, 0);
    page.once("dialog", dialog => dialog.accept());
    await page.getByRole("button", { name: "Revoke Synthetic gateway Alpha", exact: true }).click();
    await page.waitForFunction(() => document.getElementById("device-detail-connectivity").textContent.startsWith("Revoked"));
    const removal = state.requests.find(r => r.method === "DELETE");
    assert.equal(removal.headers["x-zrotext-csrf"], "ztc_synthetic");
    assert.equal(await page.getByRole("button", { name: /^Pause/ }).count(), 0);
  } finally { await page.close(); }
});
