// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const source = fs.readFileSync(path.join(__dirname, "devices.js"), "utf8");

function response(status, body = {}) {
  return { status, ok: status >= 200 && status < 300, json: async () => body };
}

async function ownerPage() {
  const elements = new Map();
  const makeElement = () => ({
    textContent: "", hidden: false, disabled: false, value: "", checked: false,
    children: [], listeners: {},
    replaceChildren(...children) { this.children = children; },
    append(...children) { this.children.push(...children); },
    setAttribute() {},
    addEventListener(name, listener) { this.listeners[name] = listener; },
    querySelectorAll() { return [{ value: "messages:read" }]; },
  });
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement());
    return elements.get(id);
  };
  element("key-lifetime").value = "30";
  const state = {
    unauthorized: false, pendingCreate: null, nextCreateResponse: null, pendingHistory: null,
    historyPages: [], historyRequests: [], webhookPages: [], webhookRequests: [], pendingWebhook: null,
    endpoints: [], pendingEndpoints: null,
  };
  const fetch = async (url, options) => {
    if (url === "/v1/auth/session") return response(200);
    if (url === "/v1/auth/login") return response(200);
    if (url === "/v1/auth/logout") return response(204);
    if (url === "/v1/enrollment/devices") {
      return state.unauthorized ? response(401) : response(200, { devices: [], next_cursor: null });
    }
    if (url === "/v1/auth/api-keys" && options.method === "GET") {
      return response(200, { keys: [], next_cursor: null });
    }
    if (url === "/v1/auth/api-keys" && options.method === "POST") {
      if (state.nextCreateResponse) return state.nextCreateResponse;
      if (state.pendingCreate) return state.pendingCreate;
      return response(201, { id: "test-id", token: "ztk_synthetic-only", public_prefix: "synthetic" });
    }
    if (url.startsWith("/v1/inbound/messages/")) {
      state.historyRequests.push(url);
      if (state.pendingHistory) return state.pendingHistory;
      return response(200, state.historyPages.shift() || { events: [], next_before: null });
    }
    if (url === "/v1/webhooks") {
      if (state.pendingEndpoints) return state.pendingEndpoints;
      return state.unauthorized ? response(401) : response(200, { endpoints: state.endpoints });
    }
    if (url.startsWith("/v1/webhooks/")) {
      state.webhookRequests.push({ url, options });
      if (state.pendingWebhook) return state.pendingWebhook;
      return state.unauthorized ? response(401) : response(200,
        state.webhookPages.shift() || { deliveries: [], next_before: null });
    }
    throw new Error(`Unexpected request: ${url}`);
  };
  vm.runInNewContext(source, {
    document: { cookie: "__Host-zrotext_csrf=ztc_synthetic", getElementById: element, createElement: makeElement },
    window: { location: { origin: "https://example.test" }, addEventListener() {} },
    fetch,
  });
  await new Promise(setImmediate);
  await new Promise(setImmediate);
  return { element, state };
}

const endpointId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const otherEndpointId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const deliveryId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const nextDeliveryId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const eventId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";

function delivery(id = deliveryId) {
  return {
    delivery_id: id, event_id: eventId, status: "dead", generation: 2,
    terminal_reason: "failed", attempt_count: 1, next_attempt_at_ms: null,
    created_at_ms: 0, updated_at_ms: 1000,
    attempts: [{ generation: 1, attempt_number: 1, started_at_ms: 0,
      completed_at_ms: 1000, outcome: "http_error", http_status: 500 },
    { generation: 2, attempt_number: 1, started_at_ms: 2000,
      completed_at_ms: null, outcome: null, http_status: null }],
    callback_url: "PRIVATE_URL", signing_secret_b64url: "PRIVATE_SECRET",
    payload: "PRIVATE_PAYLOAD", response_body: "PRIVATE_RESPONSE",
  };
}

function visibleText(element) {
  return [element.textContent, ...element.children.map(visibleText)].join(" ");
}

test("a 401 clears a displayed one-time key and hides owner content", async () => {
  const { element, state } = await ownerPage();
  await element("key-create-form").listeners.submit({ preventDefault() {} });
  assert.equal(element("key-secret").textContent, "ztk_synthetic-only");
  assert.equal(element("key-secret-panel").hidden, false);
  state.unauthorized = true;
  await element("refresh-devices").listeners.click();
  assert.equal(element("key-secret").textContent, "");
  assert.equal(element("key-secret-panel").hidden, true);
  assert.equal(element("owner-content").hidden, true);
});

test("a late create response cannot restore a key after a 401", async () => {
  const { element, state } = await ownerPage();
  let resolveCreate;
  state.pendingCreate = new Promise((resolve) => { resolveCreate = resolve; });
  const create = element("key-create-form").listeners.submit({ preventDefault() {} });
  state.unauthorized = true;
  await element("refresh-devices").listeners.click();
  resolveCreate(response(201, { id: "test-id", token: "ztk_synthetic-only", public_prefix: "synthetic" }));
  await create;
  assert.equal(element("key-secret").textContent, "");
  assert.equal(element("key-secret-panel").hidden, true);
  assert.equal(element("owner-content").hidden, true);
});

test("inbound history requires a selected UUID, pages 20 at a time, and renders metadata only", async () => {
  const { element, state } = await ownerPage();
  const messageId = "11111111-1111-4111-8111-111111111111";
  const cursor = "22222222-2222-4222-8222-222222222222";
  assert.equal(state.historyRequests.length, 0);
  element("inbound-message-id").value = "not-a-uuid";
  await element("inbound-history-form").listeners.submit({ preventDefault() {} });
  assert.equal(state.historyRequests.length, 0);
  state.historyPages.push({
    events: [{
      classification: "sim_unverified", observed_at_ms: 0, received_at_ms: 1000,
      part_count: 2, content_kind: "metadata_only", sender: "PRIVATE_SENDER",
      recipient: "PRIVATE_RECIPIENT", body: "PRIVATE_BODY", content_ciphertext: "PRIVATE_CIPHERTEXT",
      event_digest: "PRIVATE_DIGEST", signature_der: "PRIVATE_SIGNATURE",
    }],
    next_before: cursor,
  });
  state.historyPages.push({
    events: [{ classification: "captured_local", observed_at_ms: 2000, received_at_ms: 3000,
      part_count: 1, content_kind: "opaque_pilot" }], next_before: null,
  });
  element("inbound-message-id").value = messageId;
  await element("inbound-history-form").listeners.submit({ preventDefault() {} });
  assert.equal(state.historyRequests[0], `/v1/inbound/messages/${messageId}/events?limit=20`);
  assert.equal(element("inbound-event-list").children.length, 1);
  assert.equal(element("more-inbound-events").hidden, false);
  const shown = visibleText(element("inbound-event-list"));
  assert.match(shown, /SIM unverified/);
  assert.match(shown, /Observed .* received .* 2 parts .* Metadata only/);
  for (const forbidden of ["PRIVATE_SENDER", "PRIVATE_RECIPIENT", "PRIVATE_BODY", "PRIVATE_CIPHERTEXT", "PRIVATE_DIGEST", "PRIVATE_SIGNATURE"]) {
    assert.equal(shown.includes(forbidden), false);
  }
  await element("more-inbound-events").listeners.click();
  assert.equal(state.historyRequests[1], `/v1/inbound/messages/${messageId}/events?limit=20&before=${cursor}`);
  assert.equal(element("inbound-event-list").children.length, 2);
  assert.equal(element("more-inbound-events").hidden, true);
});

test("inbound history rejects an oversized page and clears on 401 despite a late response", async () => {
  const { element, state } = await ownerPage();
  const messageId = "33333333-3333-4333-8333-333333333333";
  state.historyPages.push({
    events: Array.from({ length: 21 }, () => ({ classification: "captured_local" })),
    next_before: null,
  });
  element("inbound-message-id").value = messageId;
  await element("inbound-history-form").listeners.submit({ preventDefault() {} });
  assert.equal(element("inbound-event-list").children.length, 0);
  assert.match(element("inbound-history-status").textContent, /invalid/);

  let resolveHistory;
  state.pendingHistory = new Promise((resolve) => { resolveHistory = resolve; });
  const pending = element("inbound-history-form").listeners.submit({ preventDefault() {} });
  state.unauthorized = true;
  await element("refresh-devices").listeners.click();
  resolveHistory(response(200, { events: [{ classification: "captured_local" }], next_before: null }));
  await pending;
  assert.equal(element("owner-content").hidden, true);
  assert.equal(element("inbound-message-id").value, "");
  assert.equal(element("inbound-selected-id").textContent, "");
  assert.equal(element("inbound-event-list").children.length, 0);
});

test("a deferred create JSON body cannot restore a key after a 401", async () => {
  const { element, state } = await ownerPage();
  let resolveBody;
  let bodyStarted;
  const body = new Promise((resolve) => { resolveBody = resolve; });
  const parsing = new Promise((resolve) => { bodyStarted = resolve; });
  state.nextCreateResponse = {
    status: 201, ok: true,
    json() { bodyStarted(); return body; },
  };
  const create = element("key-create-form").listeners.submit({ preventDefault() {} });
  await parsing;
  state.unauthorized = true;
  await element("refresh-devices").listeners.click();
  resolveBody({ id: "test-id", token: "ztk_synthetic-only", public_prefix: "synthetic" });
  await create;
  assert.equal(element("key-secret").textContent, "");
  assert.equal(element("key-secret-panel").hidden, true);
  assert.equal(element("owner-content").hidden, true);
});

test("webhook history selects a listed endpoint, pages 20 at a time, and renders metadata only", async () => {
  const { element, state } = await ownerPage();
  assert.equal(state.webhookRequests.length, 0);
  state.endpoints = [{ endpoint_id: endpointId, callback_url: "PRIVATE_URL", enabled: true }];
  await element("refresh-webhook-endpoints").listeners.click();
  assert.equal(visibleText(element("webhook-endpoint")).includes("PRIVATE_URL"), false);
  state.webhookPages.push({ deliveries: [delivery()], next_before: deliveryId });
  state.webhookPages.push({ deliveries: [delivery(nextDeliveryId)], next_before: null });
  element("webhook-endpoint").value = endpointId;
  await element("webhook-endpoint").listeners.change();
  assert.equal(state.webhookRequests[0].url, `/v1/webhooks/${endpointId}/deliveries?limit=20`);
  assert.equal(state.webhookRequests[0].options.method, "GET");
  assert.equal(state.webhookRequests[0].options.credentials, "same-origin");
  assert.equal(element("more-webhook-deliveries").hidden, false);
  const shown = visibleText(element("webhook-delivery-list"));
  assert.match(shown, /Attempts exhausted/);
  assert.match(shown, /Generation 1, attempt 1: HTTP error/);
  assert.match(shown, /Generation 2, attempt 1: In progress/);
  for (const forbidden of ["PRIVATE_URL", "PRIVATE_SECRET", "PRIVATE_PAYLOAD", "PRIVATE_RESPONSE"]) {
    assert.equal(shown.includes(forbidden), false);
  }
  await element("more-webhook-deliveries").listeners.click();
  assert.equal(state.webhookRequests[1].url, `/v1/webhooks/${endpointId}/deliveries?limit=20&before=${deliveryId}`);
  assert.equal(element("webhook-delivery-list").children.length, 2);
  assert.equal(element("more-webhook-deliveries").hidden, true);
});

test("webhook history ignores a late response after endpoint change or sign-out", async () => {
  const { element, state } = await ownerPage();
  state.endpoints = [{ endpoint_id: endpointId }, { endpoint_id: otherEndpointId }];
  await element("refresh-webhook-endpoints").listeners.click();
  let resolveFirst;
  state.pendingWebhook = new Promise((resolve) => { resolveFirst = resolve; });
  element("webhook-endpoint").value = endpointId;
  const first = element("webhook-endpoint").listeners.change();
  state.pendingWebhook = null;
  element("webhook-endpoint").value = otherEndpointId;
  const second = element("webhook-endpoint").listeners.change();
  resolveFirst(response(200, { deliveries: [delivery()], next_before: null }));
  await Promise.all([first, second]);
  assert.equal(element("webhook-delivery-list").children.length, 0);
  assert.equal(state.webhookRequests[1].url, `/v1/webhooks/${otherEndpointId}/deliveries?limit=20`);

  let resolveLate;
  state.pendingWebhook = new Promise((resolve) => { resolveLate = resolve; });
  const late = element("webhook-endpoint").listeners.change();
  state.unauthorized = true;
  await element("refresh-devices").listeners.click();
  resolveLate(response(200, { deliveries: [delivery()], next_before: null }));
  await late;
  assert.equal(element("owner-content").hidden, true);
  assert.equal(element("webhook-endpoint").value, "");
  assert.equal(element("webhook-delivery-list").children.length, 0);
});

test("webhook history rejects oversized pages and does not follow an invalid cursor", async () => {
  const { element, state } = await ownerPage();
  state.endpoints = [{ endpoint_id: endpointId }];
  await element("refresh-webhook-endpoints").listeners.click();
  state.webhookPages.push({ deliveries: Array.from({ length: 21 }, () => delivery()), next_before: null });
  element("webhook-endpoint").value = endpointId;
  await element("webhook-endpoint").listeners.change();
  assert.equal(element("webhook-delivery-list").children.length, 0);
  assert.match(element("webhook-history-status").textContent, /invalid/);
  state.webhookPages.push({ deliveries: [delivery()], next_before: otherEndpointId });
  await element("webhook-endpoint").listeners.change();
  assert.equal(element("more-webhook-deliveries").hidden, true);
  assert.equal(state.webhookRequests.length, 2);
});

test("sign-out clears the selected webhook endpoint and a deferred response cannot restore it", async () => {
  const { element, state } = await ownerPage();
  state.endpoints = [{ endpoint_id: endpointId }];
  await element("refresh-webhook-endpoints").listeners.click();
  let resolveBody;
  let parsingStarted;
  const body = new Promise((resolve) => { resolveBody = resolve; });
  const parsing = new Promise((resolve) => { parsingStarted = resolve; });
  state.pendingWebhook = response(200);
  state.pendingWebhook.json = () => { parsingStarted(); return body; };
  element("webhook-endpoint").value = endpointId;
  const pending = element("webhook-endpoint").listeners.change();
  await parsing;
  await element("logout").listeners.click();
  resolveBody({ deliveries: [delivery()], next_before: null });
  await pending;
  assert.equal(element("owner-content").hidden, true);
  assert.equal(element("webhook-endpoint").value, "");
  assert.equal(element("webhook-delivery-list").children.length, 0);
});

test("a late 401 from an old webhook request cannot clear a newer sign-in", async () => {
  const { element, state } = await ownerPage();
  state.endpoints = [{ endpoint_id: endpointId }];
  await element("refresh-webhook-endpoints").listeners.click();
  let resolveOld;
  state.pendingWebhook = new Promise((resolve) => { resolveOld = resolve; });
  element("webhook-endpoint").value = endpointId;
  const oldRequest = element("webhook-endpoint").listeners.change();
  await element("logout").listeners.click();
  element("email").value = "owner@example.test";
  element("password").value = "synthetic";
  await element("login-form").listeners.submit({ preventDefault() {} });
  assert.equal(element("owner-content").hidden, false);
  resolveOld(response(401));
  await oldRequest;
  assert.equal(element("owner-content").hidden, false);
  assert.equal(element("webhook-endpoint").disabled, false);
});
