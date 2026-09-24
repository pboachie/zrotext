// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

function billingPage() {
  const elements = new Map();
  const element = () => ({
    textContent: "", children: [], listeners: {}, disabled: false, hidden: false,
    replaceChildren() { this.children = []; },
    append(child) { this.children.push(child); },
    addEventListener(name, listener) { this.listeners[name] = listener; },
  });
  const byId = (id) => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  const requests = [];
  globalThis.document = { getElementById: byId, createElement: element, cookie: "" };
  globalThis.fetch = () => new Promise((resolve) => requests.push(resolve));
  delete require.cache[require.resolve("../../crates/server/static/billing-dashboard.js")];
  require("../../crates/server/static/billing-dashboard.js");
  return { byId, requests };
}

function statusResponse() {
  return { ok: true, json: async () => ({
    mode: "test", customerBound: true, pendingReconciliations: 0,
    subscriptions: [{ stripeStatus: "active", recognizedTestPrice: true, reconciledAtUnix: 0 }],
  }) };
}
const settle = () => new Promise(setImmediate);

test("billing refresh clears the prior owner's subscriptions when the session expires", async () => {
  const { byId, requests } = billingPage();
  requests.shift()(statusResponse());
  await settle();
  assert.equal(byId("subscriptions").children.length, 1);
  const refresh = byId("refresh").listeners.click();
  assert.equal(byId("subscriptions").children.length, 0);
  requests.shift()({ ok: false, status: 401 });
  await refresh;
  assert.equal(byId("subscriptions").children.length, 0);
  assert.equal(byId("portal").disabled, true);
});

test("an older billing response cannot restore account data after a newer unauthorized refresh", async () => {
  const { byId, requests } = billingPage();
  const oldResponse = requests.shift();
  const refresh = byId("refresh").listeners.click();
  requests.shift()({ ok: false, status: 401 });
  await refresh;
  oldResponse(statusResponse());
  await settle();
  assert.equal(byId("subscriptions").children.length, 0);
  assert.equal(byId("portal").disabled, true);
  assert.equal(byId("billing-state").textContent, "Billing status unavailable.");
});
