/* SPDX-License-Identifier: AGPL-3.0-only */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const test = require("node:test");
const { chromium } = require("playwright");
const root = path.resolve(__dirname, "..");
const deviceId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const now = Date.UTC(2000, 0, 1, 12);
let browser, captures;
test.before(async () => {
  browser = await chromium.launch();
  if (process.env.ZT_OWNER_SCREENSHOTS === "1") captures = await fs.mkdtemp(path.join(os.tmpdir(), "zrotext-candidate-"));
});
test.after(async () => { await browser.close(); });

async function render(name, width, scale) {
  const page = await browser.newPage({ viewport: { width, height: 640 }, reducedMotion: "reduce" });
  await page.clock.install({ time: now });
  const state = { devices: [], status: 200, requests: [] };
  await page.context().addCookies([{ name: "__Host-zrotext_csrf", value: "ztc_synthetic", url: "https://example.test", secure: true, sameSite: "Strict" }]);
  await page.route("**/*", async route => {
    const request = route.request(), url = new URL(request.url());
    state.requests.push({ path: url.pathname, method: request.method() });
    if (url.pathname === "/owner/events") return route.abort();
    if (url.pathname.startsWith("/owner/")) {
      const asset = url.pathname.slice(7), file = asset.includes(".") ? asset : asset + ".html";
      if (!/^[a-z-]+\.(html|css|js)$/.test(file)) return route.fulfill({ status: 404 });
      return route.fulfill({ body: await fs.readFile(path.join(root, file)), contentType:
        file.endsWith(".js") ? "text/javascript" : file.endsWith(".css") ? "text/css" : "text/html" });
    }
    if (url.pathname === "/v1/auth/session") return route.fulfill({ json: { role: name === "observer" ? "observer" : "owner" } });
    if (url.pathname.startsWith("/v1/billing/") || url.pathname === "/v1/owner/message-summary") return route.fulfill({ status: 503, json: { error: "unavailable" } });
    if (url.pathname === "/v1/enrollment/devices") return route.fulfill({ status: state.status, json: { devices: state.devices, next_cursor: null } });
    const value = url.pathname === "/v1/auth/mfa" ? { enabled: false, pending: false } :
      url.pathname === "/v1/auth/sms-line-owner-keys" ? [] :
      { messages: [], devices: [], seats: [], invitations: [], keys: [], holds: [], sessions: [], endpoints: [], lines: [], next_cursor: null };
    return route.fulfill({ json: value });
  });
  await page.goto(`https://example.test/owner/${name}`);
  if (name !== "observer") await page.waitForFunction(() => document.getElementById("owner-nav-status").textContent.includes("controls"));
  else await page.locator("#logout").waitFor({ state: "visible" });
  if (scale !== 1) await page.addStyleTag({ content: `html { font-size: ${scale * 100}% !important; }` });
  return { page, state };
}

async function contrastFailures(page) {
  return page.evaluate(() => {
    const channels = value => value.match(/[\d.]+/g).map(Number);
    const luminance = rgb => rgb.slice(0, 3).map(c => {
      c /= 255; return c <= .04045 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4;
    }).reduce((sum, c, i) => sum + c * [.2126, .7152, .0722][i], 0);
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const failures = [];
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const element = node.parentElement;
      if (!node.textContent.trim() || !element.getClientRects().length || element.closest("[disabled]")) continue;
      const style = getComputedStyle(element);
      if (style.visibility !== "visible") continue;
      let background = element, rgb;
      while (background) {
        rgb = channels(getComputedStyle(background).backgroundColor);
        if (rgb.length === 3 || rgb[3] === 1) break;
        background = background.parentElement;
      }
      if (!background) continue;
      const foreground = luminance(channels(style.color)), back = luminance(rgb);
      const ratio = (Math.max(foreground, back) + .05) / (Math.min(foreground, back) + .05);
      const large = parseFloat(style.fontSize) >= 24 || (parseInt(style.fontWeight, 10) >= 700 && parseFloat(style.fontSize) >= 18.667);
      if (ratio < (large ? 3 : 4.5)) failures.push({ tag: element.tagName, id: element.id, ratio });
    }
    return failures;
  });
}

for (const width of [320, 1440]) for (const scale of [1, 2]) {
  test(`candidate text, names and live statuses remain accessible at ${width}px / ${scale * 100}%`, async () => {
    for (const name of ["devices", "account", "sms-lines", "seats", "observer"]) {
      const { page } = await render(name, width, scale);
      try {
        assert.deepEqual(await contrastFailures(page), [], name);
        const unnamed = await page.locator("button:visible,a:visible,input:visible,select:visible").evaluateAll(elements => elements.filter(e => {
          if (e.matches("button,a")) return !(e.textContent.trim() || e.getAttribute("aria-label"));
          return !(e.labels?.length || e.getAttribute("aria-label") || e.getAttribute("aria-labelledby"));
        }).map(e => ({ tag: e.tagName, id: e.id })));
        assert.deepEqual(unnamed, [], name);
        assert.equal(await page.locator("h1:visible").count(), 1);
        const statuses = await page.locator("[role=status]:visible").evaluateAll(elements => elements.every(e => e.getAttribute("aria-live") === "polite"));
        assert.equal(statuses, true);
        assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
        if (captures && name === "devices") {
          await page.screenshot({ path: path.join(captures, `candidate-${width}-${scale}.png`), fullPage: true });
          await page.screenshot({ path: path.join(captures, `candidate-${width}-${scale}-viewport.png`) });
        }
      } finally { await page.close(); }
    }
  });
}

test("compact navigation preserves whole words at default and doubled text", async () => {
  for (const width of [320, 390]) for (const scale of [1, 2]) {
    const { page } = await render("devices", width, scale);
    try {
      const splitWords = await page.locator(".owner-nav a:visible").evaluateAll(links => {
        const failures = [];
        for (const link of links) {
          const walker = document.createTreeWalker(link, NodeFilter.SHOW_TEXT);
          for (let node = walker.nextNode(); node; node = walker.nextNode()) {
            for (const match of node.textContent.matchAll(/\S+/g)) {
              const range = document.createRange();
              range.setStart(node, match.index);
              range.setEnd(node, match.index + match[0].length);
              if (range.getClientRects().length > 1) failures.push(match[0]);
            }
          }
        }
        return failures;
      });
      assert.deepEqual(splitWords, [], `${width}px / ${scale * 100}%`);
    } finally { await page.close(); }
  }
});

test("keyboard-selected unknown device observations and failed refresh remain explicitly uncertain", async () => {
  const { page, state } = await render("devices", 320, 2);
  try {
    state.devices = [{ device_id: deviceId, display_name: "Synthetic unknown gateway", revoked: false,
      active_socket_lease: false, pending_messages: 0, in_flight_messages: 0, status_observed_at_ms: now }];
    await page.locator("#refresh-devices").click();
    await page.getByRole("button", { name: "View details for Synthetic unknown gateway", exact: true }).waitFor();
    await page.locator("#refresh-devices").focus();
    const selected = page.getByRole("button", { name: "View details for Synthetic unknown gateway", exact: true });
    for (let step = 0; step < 10 && !(await selected.evaluate(e => e === document.activeElement)); step++) await page.keyboard.press("Tab");
    assert.equal(await selected.evaluate(e => e === document.activeElement), true);
    await page.keyboard.press("Enter");
    assert.equal(await selected.getAttribute("aria-pressed"), "true");
    assert.match(await page.locator("#device-detail-preconditions").textContent(), /not reported|unknown|Unknown/);
    assert.match(await page.locator("#device-detail-content").textContent(), /Remote Pause is unavailable/);
    assert.equal(await page.locator("#device-detail-content").getByRole("button", { name: /Pause|Send/ }).count(), 0);
    state.status = 503;
    await page.locator("#refresh-devices").click();
    await page.waitForFunction(() => document.getElementById("device-status").textContent.includes("Could not"));
    assert.equal(await page.locator("#device-detail-name").textContent(), "Synthetic unknown gateway");
    assert.match(await page.locator("#device-detail-status").textContent(), /stale|historical|refresh/i);
    assert.ok(state.requests.every(r => r.method === "GET"));
  } finally { await page.close(); }
});
