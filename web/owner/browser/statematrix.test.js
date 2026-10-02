/* SPDX-License-Identifier: AGPL-3.0-only */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const test = require("node:test");
const { chromium } = require("playwright");
const root = path.resolve(__dirname, "..");
const leased = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const idle = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const troubled = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const bare = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const offline = "edededed-eded-4eed-8eed-edededededed";
const retired = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const observed = Date.UTC(2000, 0, 1);
let browser;
test.before(async () => { browser = await chromium.launch(); });
test.after(async () => { await browser.close(); });

// Each fixture isolates one #612 state-matrix branch with synthetic data only.
function snapshotDevice(id, name, overrides = {}) {
  return { device_id: id, display_name: name, revoked: false, active_socket_lease: true,
    pending_messages: 1, in_flight_messages: 0, status_observed_at_ms: observed,
    reported_preconditions: { selected_sim: "active", sms_permission: "granted", airplane_mode: "disabled",
      network_service: "in_service", received_at_ms: observed - 1000, fresh: true }, ...overrides };
}
function message(id, deviceId, state) {
  return { message_id: id, device_id: deviceId, state, created_at_ms: observed, updated_at_ms: observed,
    events: [], events_truncated: false, body: "synthetic-body-never-rendered", recipient_e164: "+15550000001" };
}

async function matrix(width, options = {}) {
  const page = await browser.newPage({ viewport: { width, height: 900 }, reducedMotion: "reduce" });
  await page.clock.install({ time: observed });
  const state = {
    devices: options.devices === undefined ? [
      snapshotDevice(leased, "Synthetic leased gateway"),
      snapshotDevice(idle, "Synthetic idle gateway", { active_socket_lease: null, pending_messages: 0 }),
      // A leased phone whose report names a changed SIM and denied permission: named blockers, not healthy zeros.
      snapshotDevice(troubled, "Synthetic troubled gateway",
        { reported_preconditions: { selected_sim: "inactive", sms_permission: "denied", airplane_mode: "disabled",
          network_service: "in_service", received_at_ms: observed - 2000, fresh: true } }),
      snapshotDevice(bare, "Synthetic bare gateway", { reported_preconditions: null }),
      snapshotDevice(offline, "Synthetic offline gateway", { active_socket_lease: false }),
      snapshotDevice(retired, "Synthetic retired gateway", { revoked: true })
    ] : options.devices,
    messages: options.messages === undefined ? [
      message("11111111-1111-4111-8111-111111111111", leased, "queued"),
      message("22222222-2222-4222-8222-222222222222", leased, "submitted"),
      message("33333333-3333-4333-8333-333333333333", leased, "delivered"),
      message("44444444-4444-4444-8444-444444444444", leased, "unknown"),
      message("55555555-5555-4555-8555-555555555555", leased, "invented_future_state")
    ] : options.messages,
    summaryStatus: options.summaryStatus === undefined ? 200 : options.summaryStatus,
    summaryValue: options.summaryValue === undefined ? 7 : options.summaryValue,
    status: options.status || 200,
    hold: options.hold || false, release: null, requests: []
  };
  await page.context().addCookies([{ name: "__Host-zrotext_csrf", value: "ztc_synthetic", url: "https://example.test", secure: true, sameSite: "Strict" }]);
  await page.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url());
    state.requests.push({ method: request.method(), path: url.pathname });
    if (url.pathname === "/owner/events") return route.abort();
    if (url.pathname.startsWith("/owner/")) {
      const asset = url.pathname.slice(7), file = asset.includes(".") ? asset : asset + ".html";
      if (!/^[a-z-]+\.(html|css|js)$/.test(file)) return route.fulfill({ status: 404 });
      return route.fulfill({ body: await fs.readFile(path.join(root, file)),
        contentType: file.endsWith(".js") ? "text/javascript" : file.endsWith(".css") ? "text/css" : "text/html" });
    }
    if (url.pathname === "/v1/auth/session") return route.fulfill({ json: { role: "owner" } });
    if (url.pathname.startsWith("/v1/billing/")) return route.fulfill({ status: 404 });
    if (url.pathname === "/v1/enrollment/devices") {
      if (state.hold) await new Promise(resolve => { state.release = resolve; });
      return route.fulfill({ status: state.status, json: { devices: state.devices, next_cursor: null } });
    }
    if (url.pathname === "/v1/owner/message-summary") return route.fulfill({ status: state.summaryStatus, json: {
      scope: "account", device_id: null, timezone: "UTC", day_start_ms: observed - 43200000, day_end_ms: observed + 43200000,
      observed_at_ms: observed, max_age_ms: 30000, count_bound: 1000,
      submitted_today: { value: state.summaryValue, capped: false },
      pending: { value: 2, capped: false }, in_flight: { value: 0, capped: false } } });
    if (url.pathname === "/v1/owner/messages") return route.fulfill({ status: state.status, json: { messages: state.messages, next_cursor: null } });
    return route.fulfill({ json: url.pathname === "/v1/auth/mfa" ? { enabled: false, pending: false } :
      url.pathname === "/v1/auth/sessions" ? { sessions: [] } :
        { messages: [], events: [], deliveries: [], endpoints: [], keys: [], holds: [], next_cursor: null } });
  });
  await page.goto("https://example.test/owner/devices");
  await page.waitForFunction(() => document.getElementById("owner-nav-status").textContent.includes("Owner controls"));
  return { page, state };
}

test("fleet rows render every readiness branch distinctly without connected wording for unknowns", async () => {
  const { page } = await matrix(390);
  try {
    await page.waitForFunction(() => !document.getElementById("device-status").textContent.startsWith("Loading"));
    for (const id of [leased, idle, troubled, bare, offline, retired]) {
      assert.equal(await page.locator(`#device-list li[data-device-id="${id}"]`).isVisible(), true);
    }
    const row = id => page.locator(`#device-list li[data-device-id="${id}"]`).textContent();
    // Authenticated: transport lease is proven and still separated from SMS readiness.
    assert.match(await row(leased), /authenticated socket lease observed/);
    assert.match(await row(leased), /SMS readiness unknown/);
    assert.match(await row(leased), /No reported local blockers/);
    // Unknown transport state never borrows connected wording.
    assert.match(await row(idle), /live status unavailable/);
    assert.doesNotMatch(await row(idle), /socket lease observed/);
    // No lease is distinct from an unknown lease.
    assert.match(await row(offline), /no current authenticated socket lease · SMS readiness unknown/);
    // Changed SIM and denied permission are named blockers, not healthy zeros.
    assert.match(await row(troubled), /Selected SIM inactive: check the selected SIM on the phone/);
    assert.match(await row(troubled), /SMS permission denied: check the gateway app permissions on the phone/);
    // An absent report is unavailability, not an all-clear.
    assert.match(await row(bare), /Android preconditions unavailable; carrier readiness unknown/);
    // Revoked authority keeps inspection but loses its success styling and revoke control.
    assert.match(await row(retired), /Revoked · gateway authorization removed/);
    assert.equal(await page.getByRole("button", { name: "Revoke Synthetic retired gateway" }).isHidden(), true);
    // The pilot gate stays visible next to the fleet observations.
    assert.match(await page.locator("#device-detail-content").textContent(), /Private pilot sending remains gated/);
    await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  } finally { await page.close(); }
});

test("writer activity states never present unknown or unconfirmed work as delivered", async () => {
  const { page } = await matrix(1440);
  try {
    await page.waitForFunction(() => document.querySelectorAll("#message-list li").length === 5);
    assert.equal(await page.locator("#message-list").isVisible(), true);
    for (const node of await page.locator("#message-list .activity-state").all()) {
      assert.equal(await node.isVisible(), true);
    }
    const states = await page.locator("#message-list .activity-state").evaluateAll(nodes => nodes.map(node => ({
      state: node.getAttribute("data-state"), text: node.textContent })));
    assert.equal(states.length, 5);
    const text = entry => entry.text;
    // Only writer-evidence wording: submitted and delivered both carry their proof and its limit.
    assert.match(states.map(text).join(" | "), /Queued · not sent/);
    assert.match(states.map(text).join(" | "), /Sent callback · delivery unconfirmed/);
    assert.match(states.map(text).join(" | "), /Delivered callback · unread status unknown/);
    // Unknown and unrecognized states say unknown and carry the duplication caution.
    assert.equal(states.filter(entry => /outcome unknown/i.test(entry.text)).length, 2);
    for (const entry of states) {
      // No mapping anywhere presents work as delivered without writer-callback evidence.
      if (/^Delivered/.test(entry.text)) assert.match(entry.text, /callback/);
      if (entry.state === "unknown") assert.match(entry.text, /unknown/i);
    }
    assert.equal(await page.locator("#message-list .message-uncertain").count(), 2);
    for (const node of await page.locator('#message-list .activity-state[data-state="unknown"]').all()) {
      assert.equal(await node.isVisible(), true);
      const colors = await node.evaluate(el => ({ border: getComputedStyle(el).borderTopColor,
        caution: getComputedStyle(document.querySelector(".message-uncertain")).borderLeftColor }));
      assert.equal(colors.border, colors.caution);
      assert.match(await node.locator("..").locator("..").textContent(), /Sending a new message could duplicate it/);
    }
    assert.doesNotMatch(await page.locator("#message-list").textContent(), /synthetic-body-never-rendered/);
  } finally { await page.close(); }
});

test("loading, empty, failed refresh and paused automatic refresh each keep their own honest treatment", async () => {
  const held = await matrix(390, { devices: [], hold: true });
  try {
    // Loading is visible text, not a fabricated zero.
    assert.match(await held.page.locator("#fleet-summary").textContent(), /loading/i);
    held.state.hold = false; held.state.release();
    // Empty is a true-zero label once the authoritative page arrives.
    await held.page.waitForFunction(() => document.getElementById("device-status").textContent.includes("No approved devices"));
    assert.match(await held.page.locator("#fleet-summary").textContent(), /0 loaded devices/);
    // A failed refresh keeps the previous snapshot and labels it possibly stale.
    held.state.devices = [snapshotDevice(leased, "Synthetic leased gateway")];
    await held.page.locator("#refresh-devices").click();
    await held.page.waitForFunction(() => document.querySelectorAll("#device-list li").length === 1);
    held.state.status = 503;
    await held.page.locator("#refresh-devices").click();
    await held.page.waitForFunction(() => document.getElementById("device-status").textContent.startsWith("Could not load devices"));
    assert.match(await held.page.locator("#fleet-summary").textContent(), /may be stale/);
    assert.equal(await held.page.locator("#device-list li").count(), 1);
    // Turning automatic refresh off pauses polling entirely.
    await held.page.locator("#auto-refresh").uncheck();
    const polls = held.state.requests.filter(r => r.path === "/v1/enrollment/devices").length;
    await held.page.clock.fastForward(60000);
    assert.equal(held.state.requests.filter(r => r.path === "/v1/enrollment/devices").length, polls);
  } finally { if (held.state.release) held.state.release(); await held.page.close(); }
});

test("unavailable and offline summary sources never become zero", async () => {
  const { page, state } = await matrix(390, { summaryStatus: 503 });
  try {
    await page.waitForFunction(() => document.getElementById("summary-submitted").textContent === "Unavailable");
    for (const id of ["summary-submitted", "summary-pending", "summary-flight"]) {
      assert.equal(await page.locator("#" + id).isVisible(), true);
      const text = await page.locator("#" + id).textContent();
      assert.equal(text, "Unavailable");
      assert.doesNotMatch(text, /0/);
    }
    assert.match(await page.locator("#summary-status").textContent(), /unavailable|could not|failed/i);
    // A later successful observation replaces unavailability with the real count.
    state.summaryStatus = 200; state.summaryValue = 9;
    await page.locator("#refresh-summary").click();
    await page.waitForFunction(() => document.getElementById("summary-submitted").textContent === "9");
  } finally { await page.close(); }
});
