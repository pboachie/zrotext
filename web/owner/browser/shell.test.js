/* SPDX-License-Identifier: AGPL-3.0-only */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const os = require("node:os");
const test = require("node:test");
const { chromium } = require("playwright");
const root = path.resolve(__dirname, "..");
let browser;
let screenshots;
test.before(async () => {
  browser = await chromium.launch();
  if (process.env.ZT_OWNER_SCREENSHOTS === "1") screenshots = await fs.mkdtemp(path.join(os.tmpdir(), "zrotext-owner-"));
});
test.after(async () => { await browser.close(); });
async function pageFor(name, width, { role = "owner", billing = true, textScale = 1 } = {}) {
  const page = await browser.newPage({ viewport: { width, height: 900 }, reducedMotion: "reduce" });
  const requests = [];
  await page.context().addCookies([{ name: "__Host-zrotext_csrf", value: "ztc_synthetic", url: "https://example.test", secure: true, sameSite: "Strict" }]);
  await page.route("**/*", async route => {
    const url = new URL(route.request().url());
    requests.push({ path: url.pathname, method: route.request().method(), headers: route.request().headers() });
    if (url.pathname === "/owner/events") return route.abort();
    if (url.pathname.startsWith("/owner/")) {
      const asset = url.pathname.slice(7);
      const file = asset.includes(".") ? asset : asset + ".html";
      const allowed = /^[a-z-]+\.(html|css|js)$/.test(file);
      if (!allowed) return route.fulfill({ status: 404 });
      const body = await fs.readFile(path.join(root, file));
      const type = file.endsWith(".css") ? "text/css" : file.endsWith(".js") ? "text/javascript" : "text/html";
      return route.fulfill({ status: 200, contentType: type, body });
    }
    let body = {};
    if (url.pathname === "/v1/auth/session") body = { role, account_id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", user_id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" };
    else if (url.pathname === "/v1/billing/status") return route.fulfill({ status: billing ? 200 : 404, json: { mode: "test" } });
    else if (url.pathname === "/v1/billing/device-capacity") body = { limit: null, active: 0, over_limit: false, enrollment_blocked: false };
    else if (url.pathname === "/v1/auth/mfa") body = { enabled: false, pending: false };
    else if (url.pathname === "/v1/auth/sms-line-owner-keys") body = [];
    else if (url.pathname === "/v1/auth/seats") body = { seats: [], invitations: [] };
    else if (url.pathname === "/v1/auth/sessions") body = { sessions: [{ id: "cccccccc-cccc-cccc-cccc-cccccccccccc", current: true, created_at_ms: 1000, expires_at_ms: 100000, last_used_at_ms: 2000 }] };
    else if (url.pathname === "/v1/enrollment/pairings" && route.request().method() === "POST") body = { pairing_id: "dddddddd-dddd-dddd-dddd-dddddddddddd", token: "SYNTHETIC_ONLY" };
    else if (url.pathname === "/v1/auth/logout") return route.fulfill({ status: 204 });
    else if (url.pathname.includes("events/stream")) return route.abort();
    else body = { devices: [], messages: [], holds: [], keys: [], endpoints: [], lines: [], next_cursor: null };
    return route.fulfill({ status: 200, json: body });
  });
  await page.goto("https://example.test/owner/" + name);
  if (name !== "observer") await page.waitForFunction(() => document.getElementById("owner-nav-status").textContent.includes("Owner controls") || document.getElementById("owner-nav-status").textContent.includes("Observer access"));
  if (textScale !== 1) await page.addStyleTag({ content: `html { font-size: ${textScale * 100}% !important; }` });
  return { page, requests };
}
async function fits(page) {
  const result = await page.evaluate(() => ({ width: innerWidth, scroll: document.documentElement.scrollWidth,
    controls: [...document.querySelectorAll("input,select,button")].filter(e => e.getClientRects().length).map(e => {
      const box = e.getBoundingClientRect(); return { id: e.id, left: box.left, right: box.right, width: box.width };
    }) }));
  assert.ok(result.scroll <= result.width + 1, JSON.stringify(result));
  for (const item of result.controls) assert.ok(item.left >= -1 && item.right <= result.width + 1 && item.width > 0, JSON.stringify(item));
}
for (const width of [320, 390, 1440]) {
  for (const name of ["devices", "account", "sms-lines", "seats", "observer"]) {
    test(`rendered ${name} fits ${width}px and 200% text with usable controls`, async () => {
      const { page } = await pageFor(name, width, { role: name === "observer" ? "observer" : "owner" });
      try {
        await fits(page);
        assert.equal(await page.locator("body").evaluate(e => getComputedStyle(e).backgroundColor), "rgb(11, 15, 12)");
        assert.equal(await page.locator(".owner-brand svg").count(), 1);
        assert.equal(await page.locator(".owner-nav [aria-current=page]").count(), 1);
        assert.equal(await page.locator(".owner-rail").evaluate(e => getComputedStyle(e).position), width > 960 ? "fixed" : "static");
        const accessibility = await page.evaluate(() => {
          function luminance(value) {
            const channels = value.match(/\d+/g).slice(0, 3).map(Number).map(c => {
              c /= 255; return c <= .04045 ? c / 12.92 : ((c + .055) / 1.055) ** 2.4;
            });
            return channels[0] * .2126 + channels[1] * .7152 + channels[2] * .0722;
          }
          const nav = document.querySelector(".owner-nav [aria-current=page]");
          const style = getComputedStyle(nav);
          const light = luminance(style.color), dark = luminance(style.backgroundColor);
          return { contrast: (Math.max(light, dark) + .05) / (Math.min(light, dark) + .05),
            targets: [...document.querySelectorAll(".owner-nav a,button")].filter(e => e.getClientRects().length).every(e => e.getBoundingClientRect().height >= 44),
            reducedMotion: matchMedia("(prefers-reduced-motion: reduce)").matches && getComputedStyle(nav).transitionDuration === "0s" };
        });
        assert.ok(accessibility.contrast >= 4.5);
        assert.ok(accessibility.targets);
        assert.ok(accessibility.reducedMotion);
        if (screenshots && name === "devices") {
          await page.screenshot({ path: path.join(screenshots, `owner-${width}.png`), fullPage: true });
        }
        await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
        await fits(page);
      } finally { await page.close(); }
    });
  }
}
test("overview precedes fleet and activity while keyboard navigation reaches security and credentials", async () => {
  const { page } = await pageFor("devices", 1440);
  try {
    assert.deepEqual(await page.locator("#owner-content > section").evaluateAll(nodes => nodes.slice(0, 3).map(node => node.id)), ["message-summary", "approved-devices", "message-activity"]);
    await page.keyboard.press("Tab");
    assert.equal(await page.locator(".skip-link").evaluate(e => e === document.activeElement), true);
    assert.equal(await page.locator(".skip-link").evaluate(e => getComputedStyle(e).outlineStyle), "solid");
    await page.keyboard.press("Enter");
    assert.equal(await page.locator("#owner-main").evaluate(e => e === document.activeElement), true);
    await page.getByRole("link", { name: "Connection details", exact: true }).click();
    assert.ok(page.url().endsWith("#connection-details"));
    await page.getByRole("link", { name: "Security & sessions", exact: true }).first().click();
    assert.ok(page.url().endsWith("#account-security"));
    await page.locator("#current-password").focus();
    assert.equal(await page.locator("#current-password").evaluate(e => getComputedStyle(e).outlineStyle), "solid");
  } finally { await page.close(); }
});
test("observer navigation has no owner destinations and disabled billing stays hidden", async () => {
  for (const name of ["observer", "devices"]) {
    const { page } = await pageFor(name, 390, { role: "observer", billing: false });
    try {
      assert.equal(await page.locator(".owner-nav a[href='/billing']:visible").count(), 0);
      assert.equal(await page.locator(".owner-nav a[href='/owner/seats']:visible").count(), 0);
      assert.equal(await page.locator(".owner-nav a[href='/owner/sms-lines']:visible").count(), 0);
      assert.ok(await page.locator(".owner-nav a[href='/owner/observer']:visible").count());
    } finally { await page.close(); }
  }
  const { page } = await pageFor("devices", 390, { billing: false });
  try { assert.equal(await page.locator("#owner-billing-link").isVisible(), false); } finally { await page.close(); }
});
test("pairing retains CSRF and cancellation, and pagehide clears credential fields", async () => {
  const { page, requests } = await pageFor("devices", 390);
  try {
    await page.evaluate(() => { document.cookie = "__Host-zrotext_csrf=ztc_synthetic; Secure; Path=/"; });
    await page.getByRole("link", { name: "Pair a phone", exact: true }).click();
    await page.locator("#display-name").fill("Synthetic gateway");
    await page.locator("#create-form button").click();
    await page.waitForFunction(() => document.getElementById("pair-token").textContent === "SYNTHETIC_ONLY");
    const create = requests.find(r => r.path === "/v1/enrollment/pairings" && r.method === "POST");
    assert.equal(create.headers["x-zrotext-csrf"], "ztc_synthetic");
    await page.locator("#cancel-pairing").click();
    await page.waitForFunction(() => document.getElementById("pair-token").textContent === "");
    assert.equal(await page.locator("#pair-token").textContent(), "");
    assert.equal(await page.locator("#pair-ticket").isVisible(), false);
    await page.evaluate(() => {
      document.getElementById("key-secret").textContent = "SYNTHETIC_ONLY";
      document.getElementById("key-secret-panel").hidden = false;
      document.getElementById("current-password").value = "SYNTHETIC_ONLY";
      window.dispatchEvent(new Event("pagehide"));
    });
    assert.equal(await page.locator("#key-secret").textContent(), "");
    assert.equal(await page.locator("#key-secret-panel").isVisible(), false);
    assert.equal(await page.locator("#current-password").inputValue(), "");
  } finally { await page.close(); }
});

test("sign-out closes owner navigation and does not retain credentials", async () => {
  const { page, requests } = await pageFor("devices", 390);
  try {
    assert.ok(await page.locator(".owner-nav [data-owner-only]:visible").count());
    await page.locator("#logout").click();
    await page.waitForFunction(() => document.getElementById("owner-nav-status").textContent.startsWith("Sign in"));
    assert.equal(await page.locator(".owner-nav [data-owner-only]:visible").count(), 0);
    const logout = requests.find(r => r.path === "/v1/auth/logout" && r.method === "POST");
    assert.equal(logout.headers["x-zrotext-csrf"], "ztc_synthetic");
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  } finally { await page.close(); }
});
