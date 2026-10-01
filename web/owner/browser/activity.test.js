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
const older = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const stamp = Date.UTC(2000, 0, 1);
let browser, screenshots;
test.before(async () => {
  browser = await chromium.launch();
  if (process.env.ZT_OWNER_SCREENSHOTS === "1") screenshots = await fs.mkdtemp(path.join(os.tmpdir(), "zrotext-activity-"));
});
test.after(async () => { await browser.close(); });
function metadata(state, id = gateway) {
  return { message_id: id, device_id: gateway, state, created_at_ms: stamp, updated_at_ms: stamp,
    events_truncated: true, events: [{ evidence: "durable_submit_intent", resulting_state: "submitting", received_at_ms: stamp,
      segment_index: 0, segment_count: 2 }, { evidence: "sent_callback_ok", resulting_state: "submitted", received_at_ms: stamp,
      segment_index: 1, segment_count: 2 }], body: "content-must-not-render", recipient_e164: "recipient-must-not-render" };
}
async function activity(width, initial = [metadata("unknown")], hold = false) {
  const page = await browser.newPage({ viewport: { width, height: 900 }, reducedMotion: "reduce" });
  await page.clock.install({ time: stamp });
  const state = { messages: initial, cursor: null, requests: [], status: 200, hold, release: null };
  await page.context().addCookies([{ name: "__Host-zrotext_csrf", value: "ztc_synthetic", url: "https://example.test", secure: true, sameSite: "Strict" }]);
  await page.route("**/*", async route => {
    const url = new URL(route.request().url());
    state.requests.push(url.pathname + url.search);
    if (url.pathname === "/owner/events") return route.abort();
    if (url.pathname.startsWith("/owner/")) {
      const asset = url.pathname.slice(7), file = asset.includes(".") ? asset : asset + ".html";
      if (!/^[a-z-]+\.(html|css|js)$/.test(file)) return route.fulfill({ status: 404 });
      return route.fulfill({ body: await fs.readFile(path.join(root, file)), contentType:
        file.endsWith(".js") ? "text/javascript" : file.endsWith(".css") ? "text/css" : "text/html" });
    }
    if (url.pathname === "/v1/owner/messages") {
      if (state.hold) await new Promise(resolve => { state.release = resolve; });
      return route.fulfill({ status: state.status, json: { messages: state.messages, next_cursor: state.cursor } });
    }
    if (url.pathname === "/v1/enrollment/devices") return route.fulfill({ json: { devices: [{ device_id: gateway,
      display_name: "Synthetic gateway", revoked: false }], next_cursor: null } });
    if (url.pathname === "/v1/auth/session") return route.fulfill({ json: { role: "owner" } });
    if (url.pathname.startsWith("/v1/billing/")) return route.fulfill({ status: 404 });
    if (url.pathname === "/v1/auth/logout") return route.fulfill({ status: 204 });
    return route.fulfill({ json: url.pathname === "/v1/auth/mfa" ? { enabled: false, pending: false } :
      url.pathname === "/v1/auth/sessions" ? { sessions: [] } : { messages: [], events: [], deliveries: [], endpoints: [], holds: [], keys: [], next_cursor: null } });
  });
  await page.goto("https://example.test/owner/devices");
  await page.waitForFunction(() => document.getElementById("device-list").children.length === 1);
  if (!hold) await page.waitForFunction(() => !document.getElementById("message-status").textContent.startsWith("Loading"));
  return { page, state };
}
async function fits(page) {
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
  assert.equal(await page.locator("#message-activity button:visible, #message-activity summary:visible").evaluateAll(nodes => nodes.some(node => {
    const r = node.getBoundingClientRect(); return r.left < -1 || r.right > innerWidth + 1 || r.height < 44;
  })), false);
}
for (const width of [320, 390, 1440]) {
  test(`activity metadata and labelled states render at ${width}px and 200% text`, async () => {
    const states = ["accepted", "claimed", "submitting", "submitted", "delivered", "failed", "unknown", "delivery_unknown"];
    const rows = states.map((status, index) => metadata(status, `cccccccc-cccc-4ccc-8ccc-${String(index).padStart(12, "c")}`));
    const { page } = await activity(width, rows);
    try {
      assert.equal(await page.locator(".activity-row").count(), states.length);
      assert.match(await page.locator("#message-list").textContent(), /delivery unconfirmed/);
      assert.doesNotMatch(await page.locator("#message-list").textContent(), /content-must-not-render|recipient-must-not-render/);
      assert.match(await page.locator(".activity-scope").textContent(), /All\/Inbound.*unavailable/);
      await fits(page);
      if (screenshots) await page.screenshot({ path: path.join(screenshots, `activity-${width}.png`), fullPage: true });
      await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
      await fits(page);
    } finally { await page.close(); }
  });
}
test("paging, writer expansion, focused refresh and device linking retain history and pending input", async () => {
  const { page, state } = await activity(1440);
  try {
    state.cursor = older;
    await page.locator("#refresh-messages").click();
    const first = page.locator(".activity-row").first();
    await first.locator("summary").click();
    assert.match(await first.textContent(), /segment 1\/2.*segment 2\/2/);
    await page.locator("#display-name").fill("Pending synthetic input");
    await first.locator("summary").focus();
    state.messages = [metadata("submitted")];
    await page.evaluate(() => document.getElementById("refresh-messages").click());
    await page.waitForFunction(() => document.querySelector(".activity-state").textContent.includes("delivery unconfirmed"));
    assert.equal(await first.locator("details").getAttribute("open"), "");
    assert.equal(await first.locator("summary").evaluate(node => node === document.activeElement), true);
    await first.getByRole("button", { name: "View device Synthetic gateway" }).focus();
    await page.keyboard.press("Enter");
    assert.equal(await page.locator("#device-detail-name").textContent(), "Synthetic gateway");
    assert.equal(await first.getByRole("button").evaluate(node => node === document.activeElement), true);
    assert.equal(await page.locator("#display-name").inputValue(), "Pending synthetic input");
    state.messages = [metadata("delivered", older)]; state.cursor = null;
    await page.locator("#more-messages").click();
    await page.waitForFunction(() => document.querySelectorAll(".activity-row").length === 2);
    assert.equal(await page.locator(".activity-row").count(), 2);
    assert.ok(state.requests.includes(`/v1/owner/messages?before=${older}`));
    const before = state.requests.filter(url => url.startsWith("/v1/owner/messages")).length;
    await page.clock.fastForward(15000);
    assert.equal(state.requests.filter(url => url.startsWith("/v1/owner/messages")).length, before);
    assert.equal(await page.locator("#inbound-history-form").isVisible(), true);
    assert.equal(await page.locator("#refresh-webhook-endpoints").isVisible(), true);
  } finally { await page.close(); }
});
test("loading, empty and failed refresh retain historical metadata until a valid empty page", async () => {
  const { page, state } = await activity(390, [], true);
  try {
    assert.match(await page.locator("#message-status").textContent(), /Loading/);
    state.hold = false; state.release();
    await page.waitForFunction(() => document.getElementById("message-status").textContent === "No messages yet.");
    state.messages = [metadata("unknown")];
    await page.locator("#refresh-messages").click();
    await page.waitForFunction(() => document.querySelectorAll(".activity-row").length === 1);
    state.status = 503;
    await page.locator("#refresh-messages").click();
    await page.waitForFunction(() => document.getElementById("message-status").textContent.includes("older metadata"));
    assert.equal(await page.locator(".activity-row").count(), 1);
    state.status = 200; state.messages = [];
    await page.locator("#refresh-messages").click();
    await page.waitForFunction(() => document.getElementById("message-status").textContent === "No messages yet.");
    assert.equal(await page.locator(".activity-row").count(), 0);
  } finally { await page.close(); }
});
