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

function ambiguousStatusResponse() {
  return { ok: true, json: async () => ({
    mode: "test", customerBound: true, pendingReconciliations: 1,
    nonterminalSubscriptions: 2,
    subscriptions: [{ stripeStatus: "active", recognizedTestPrice: true, reconciledAtUnix: 0 }],
    projectedEntitlement: { reason: "ambiguous", outboundLimit: 0, deviceCap: 0, paymentHold: true },
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

test("an ambiguous projection is explained and closes checkout while subscriptions are live", async () => {
  const { byId, requests } = billingPage();
  requests.shift()(ambiguousStatusResponse());
  await settle();
  assert.equal(byId("checkout").disabled, true);
  assert.equal(byId("portal").disabled, false);
  const summary = byId("entitlement-status").textContent;
  assert.match(summary, /ambiguous/);
  assert.match(summary, /outbound allowance 0\/month/);
  assert.match(summary, /device cap 0/);
  assert.match(summary, /refund or dispute hold/);
  assert.match(summary, /Checkout is closed/);
  assert.match(summary, /customer portal/);
});

test("a refused checkout directs the owner to the portal and refreshes status", async () => {
  const { byId, requests } = billingPage();
  requests.shift()(statusResponse());
  await settle();
  assert.equal(byId("checkout").disabled, false);
  globalThis.document.cookie = "__Host-zrotext_csrf=fixture";
  const click = byId("checkout").listeners.click();
  requests.shift()({ ok: false, status: 409 });
  await settle();
  requests.shift()(ambiguousStatusResponse());
  await click;
  await settle();
  assert.match(byId("billing-error").textContent, /customer portal/);
  assert.equal(byId("checkout").disabled, true);
});
