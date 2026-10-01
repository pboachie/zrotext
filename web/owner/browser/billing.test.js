/* SPDX-License-Identifier: AGPL-3.0-only */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const path = require("node:path");
const test = require("node:test");
const { chromium } = require("playwright");
const assets = path.resolve(__dirname, "../../../crates/server/static");
let browser;
test.before(async () => { browser = await chromium.launch(); });
test.after(async () => { await browser.close(); });
for (const width of [320, 1440]) {
  test(`local billing counters render, wrap and clear on failure at ${width}px`, async () => {
    const page = await browser.newPage({ viewport: { width, height: 900 } });
    let available = true;
    try {
      await page.route("**/*", async route => {
        const url = new URL(route.request().url());
        if (url.pathname === "/v1/billing/status") return route.fulfill({ status: available ? 200 : 503, json: {
          mode: "test", customerBound: true, subscriptions: [], pendingReconciliations: 0,
          localUsage: { used_units: 5, reserved_units: 7, refunded_units: 2, limit_units: 5, period_start: "2030-01-01", period_end: "2030-02-01" },
        } });
        const name = url.pathname === "/billing" ? "billing-dashboard.html" : url.pathname === "/billing/dashboard.js" ? "billing-dashboard.js" : null;
        if (name) return route.fulfill({ body: await fs.readFile(path.join(assets, name)), contentType: name.endsWith("js") ? "text/javascript" : "text/html" });
        if (url.pathname === "/owner/owner.css") return route.fulfill({ body: await fs.readFile(path.resolve(__dirname, "../owner.css")), contentType: "text/css" });
        return route.fulfill({ status: 404 });
      });
      await page.goto("https://example.test/billing");
      await page.waitForFunction(() => document.getElementById("local-usage").textContent.includes("5 consumed"));
      assert.match(await page.locator("#local-usage").textContent(), /hard cap 5 \(reached\)/);
      await page.addStyleTag({ content: "html { font-size: 200% !important; }" });
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      available = false;
      await page.locator("#refresh").click();
      await page.waitForFunction(() => document.getElementById("local-usage").textContent.includes("unavailable"));
      assert.doesNotMatch(await page.locator("#local-usage").textContent(), /5 consumed/);
    } finally { await page.close(); }
  });
}
