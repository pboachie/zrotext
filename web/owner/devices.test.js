// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

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
    endpoints: [], pendingEndpoints: null, pendingDevices: null, messages: [],
    reviewPages: [], reviewRequests: [], pendingReview: null,
    devices: [], deletedDevices: [], billingCapacity: null, approveResponse: response(409),
    authRequests: [], sessions: [{ id: "11111111-1111-4111-8111-111111111111", current: true,
      created_at_ms: 1000, expires_at_ms: 100000, last_used_at_ms: 2000 }],
  };
  const fetch = async (url, options) => {
    if (url === "/v1/auth/session") return response(200);
    if (url === "/v1/auth/login") return response(204);
    if (url === "/v1/auth/logout") return response(204);
    if (url === "/v1/auth/sessions" && options.method === "GET")
      return response(200, { sessions: state.sessions });
    if (url === "/v1/auth/sessions/revoke-others" && options.method === "POST") {
      state.authRequests.push({ url, options });
      state.sessions = state.sessions.filter((session) => session.current);
      return response(204);
    }
    if (url === "/v1/auth/password" || url.startsWith("/v1/auth/password/reset/")) {
      state.authRequests.push({ url, options });
      return response(204);
    }
    if (url === "/v1/enrollment/devices") {
      if (state.pendingDevices) return state.pendingDevices;
      return state.unauthorized ? response(401) : response(200, { devices: state.devices, next_cursor: null });
    }
    if (url === "/v1/billing/status") return state.billingCapacity
      ? response(200, { mode: "test", deviceCapacity: state.billingCapacity }) : response(404);
    if (url === "/v1/enrollment/pairings" && options.method === "POST")
      return response(201, { pairing_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", token: "synthetic" });
    if (url.endsWith("/approve") && options.method === "POST") return state.approveResponse;
    if (url.startsWith("/v1/enrollment/devices/") && options.method === "DELETE") {
      const id = url.split("/").at(-1);
      state.deletedDevices.push(id);
      state.devices = state.devices.map((device) =>
        device.device_id === id ? { ...device, revoked: true } : device);
      if (state.billingCapacity) state.billingCapacity.active -= 1;
      return response(204);
    }
    if (url === "/v1/owner/messages") return response(200, { messages: state.messages, next_cursor: null });
    if (url.startsWith("/v1/owner/opt-out-review")) {
      state.reviewRequests.push({ url, options });
      if (state.pendingReview) return state.pendingReview;
      return state.unauthorized ? response(401)
        : response(200, state.reviewPages.shift() || { holds: [], next_cursor: null });
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
  globalThis.document = { cookie: "__Host-zrotext_csrf=ztc_synthetic", getElementById: element, createElement: makeElement };
  globalThis.window = { location: { origin: "https://example.test" }, addEventListener() {}, confirm: () => false };
  globalThis.fetch = fetch;
  delete require.cache[require.resolve("./devices.js")];
  require("./devices.js");
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

test("opt-out review pages active holds without showing SMS content and clears on sign-out", async () => {
  const { element, state } = await ownerPage();
  const cursor = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
  state.reviewPages.push({ holds: [{
    recipient_e164: "+15551234567", source: "sms_review", observed_at_ms: 1000,
    changed_at_ms: 2000, body: "PRIVATE_BODY", signature_der: "PRIVATE_SIGNATURE",
  }], next_cursor: cursor });
  state.reviewPages.push({ holds: [{
    recipient_e164: "+15557654321", source: "sms_unsolicited_review",
    observed_at_ms: 3000, changed_at_ms: 4000,
  }], next_cursor: null });
  await element("refresh-opt-out-review").listeners.click();
  assert.equal(state.reviewRequests.at(-1).url, "/v1/owner/opt-out-review");
  assert.equal(state.reviewRequests.at(-1).options.method, "GET");
  assert.equal(state.reviewRequests.at(-1).options.cache, "no-store");
  assert.equal(state.reviewRequests.at(-1).options.credentials, "same-origin");
  assert.equal(element("more-opt-out-review").hidden, false);
  await element("more-opt-out-review").listeners.click();
  assert.equal(state.reviewRequests.at(-1).url, `/v1/owner/opt-out-review?before=${cursor}`);
  assert.equal(element("opt-out-review-list").children.length, 2);
  const rendered = visibleText(element("opt-out-review-list"));
  assert.match(rendered, /\+15551234567/);
  assert.match(rendered, /outside a pilot reply window/);
  assert.equal(rendered.includes("PRIVATE_BODY"), false);
  assert.equal(rendered.includes("PRIVATE_SIGNATURE"), false);
  await element("logout").listeners.click();
  assert.equal(element("opt-out-review-list").children.length, 0);
  assert.equal(element("owner-content").hidden, true);
});

test("opt-out review ignores a late response after session expiry", async () => {
  const { element, state } = await ownerPage();
  let resolveReview;
  state.pendingReview = new Promise((resolve) => { resolveReview = resolve; });
  const pending = element("refresh-opt-out-review").listeners.click();
  state.unauthorized = true;
  await element("refresh-devices").listeners.click();
  resolveReview(response(200, { holds: [{ recipient_e164: "+15551234567",
    source: "sms_review", observed_at_ms: 1000, changed_at_ms: 2000 }], next_cursor: null }));
  await pending;
  assert.equal(element("opt-out-review-list").children.length, 0);
  assert.equal(element("owner-content").hidden, true);
});

test("password reset keeps the token out of URLs and clears entered passwords", async () => {
  const { element, state } = await ownerPage();
  element("reset-email").value = "owner@example.test";
  await element("reset-request-form").listeners.submit({ preventDefault() {} });
  assert.equal(state.authRequests[0].url, "/v1/auth/password/reset/request");
  assert.deepEqual(JSON.parse(state.authRequests[0].options.body), { email: "owner@example.test" });
  assert.equal(state.authRequests[0].options.headers["x-zrotext-csrf"], undefined);
  assert.equal(element("reset-email").value, "");
  element("reset-token").value = "ztp_synthetic-secret";
  element("reset-new-password").value = "a-long-new-password";
  element("reset-confirm-password").value = "a-long-new-password";
  await element("reset-confirm-form").listeners.submit({ preventDefault() {} });
  assert.equal(state.authRequests[1].url, "/v1/auth/password/reset/confirm");
  assert.deepEqual(JSON.parse(state.authRequests[1].options.body), {
    token: "ztp_synthetic-secret", new_password: "a-long-new-password",
  });
  assert.equal(state.authRequests[1].options.headers["x-zrotext-csrf"], undefined);
  assert.equal(element("reset-token").value, "");
  assert.equal(element("reset-new-password").value, "");
  assert.equal(element("reset-confirm-password").value, "");
});

test("password change uses CSRF and sessions can be reviewed and revoked", async () => {
  const { element, state } = await ownerPage();
  state.sessions.push({ id: "22222222-2222-4222-8222-222222222222", current: false,
    created_at_ms: 3000, expires_at_ms: 100000, last_used_at_ms: null });
  await element("refresh-sessions").listeners.click();
  assert.equal(element("session-list").children.length, 2);
  assert.equal(element("revoke-other-sessions-form").hidden, false);
  globalThis.window.confirm = () => true;
  element("revoke-sessions-password").value = "old-password";
  element("revoke-sessions-mfa-code").value = "123456";
  await element("revoke-other-sessions-form").listeners.submit({ preventDefault() {} });
  assert.equal(state.authRequests[0].url, "/v1/auth/sessions/revoke-others");
  assert.equal(state.authRequests[0].options.headers["x-zrotext-csrf"], "ztc_synthetic");
  assert.deepEqual(JSON.parse(state.authRequests[0].options.body), {
    current_password: "old-password", code: "123456",
  });
  assert.equal(element("revoke-sessions-password").value, "");
  assert.equal(element("session-list").children.length, 1);
  assert.equal(element("revoke-other-sessions-form").hidden, true);

  element("current-password").value = "old-password";
  element("new-password").value = "new-long-password";
  element("confirm-new-password").value = "new-long-password";
  element("password-mfa-code").value = "123456";
  await element("change-password-form").listeners.submit({ preventDefault() {} });
  assert.equal(state.authRequests[1].url, "/v1/auth/password");
  assert.equal(state.authRequests[1].options.headers["x-zrotext-csrf"], "ztc_synthetic");
  assert.deepEqual(JSON.parse(state.authRequests[1].options.body), {
    current_password: "old-password", new_password: "new-long-password", code: "123456",
  });
  assert.equal(element("current-password").value, "");
  assert.equal(element("new-password").value, "");
  assert.equal(element("password-mfa-code").value, "");
  assert.equal(element("owner-content").hidden, true);
  assert.match(element("global-status").textContent, /Sign in again.*API keys/);
});

test("a 401 clears a displayed one-time key and hides owner content", async () => {
  const { element, state } = await ownerPage();
  await element("key-create-form").listeners.submit({ preventDefault() {} });
  assert.equal(element("key-secret").textContent, "ztk_synthetic-only");
  assert.equal(element("key-secret-panel").hidden, false);
  state.unauthorized = true;
  element("message-list").children = ["synthetic owner message"];
  await element("refresh-devices").listeners.click();
  assert.equal(element("message-list").children.length, 0);
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

test("an old device 401 cannot clear a newer owner session", async () => {
  const { element, state } = await ownerPage();
  let resolveOld;
  state.pendingDevices = new Promise((resolve) => { resolveOld = resolve; });
  const oldRequest = element("refresh-devices").listeners.click();
  await element("logout").listeners.click();
  state.pendingDevices = null;
  element("email").value = "owner@example.test";
  element("password").value = "synthetic";
  await element("login-form").listeners.submit({ preventDefault() {} });
  assert.equal(element("owner-content").hidden, false);
  resolveOld(response(401));
  await oldRequest;
  assert.equal(element("owner-content").hidden, false);
});

test("unknown message state warns that a new send may duplicate it", async () => {
  const { element, state } = await ownerPage();
  const base = {
    message_id: "message-test", device_id: "device-test",
    created_at_ms: 1_800_000_000_000, events: [], events_truncated: false,
  };
  state.messages = [
    { ...base, state: "unknown" },
    { ...base, message_id: "delivered-test", state: "delivered" },
  ];
  await element("refresh-messages").listeners.click();
  const [uncertain, delivered] = element("message-list").children;
  assert.match(uncertain.children.find((child) => child.className === "message-uncertain").textContent,
    /may have sent.*could duplicate/);
  assert.equal(delivered.children.some((child) => child.className === "message-uncertain"), false);
});

test("device authorization is not presented as a live connection", async () => {
  const { element, state } = await ownerPage();
  state.devices = [
    { device_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", display_name: "Phone A", revoked: false },
    { device_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", display_name: "Phone B", revoked: true },
  ];
  await element("refresh-devices").listeners.click();
  const [approved, revoked] = element("device-list").children;
  assert.match(visibleText(approved), /Approved for connection · live status unavailable/);
  assert.doesNotMatch(visibleText(approved), /Connected|Ready to send/);
  assert.match(visibleText(revoked), /Revoked/);
  assert.doesNotMatch(visibleText(revoked), /Approved for connection/);
});

test("owner device list distinguishes a socket lease from SMS readiness", async () => {
  const { element, state } = await ownerPage();
  state.devices = [
    { device_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", display_name: "Phone A", revoked: false, active_socket_lease: true },
    { device_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", display_name: "Phone B", revoked: false, active_socket_lease: false },
    { device_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", display_name: "Phone C", revoked: true, active_socket_lease: true },
  ];
  await element("refresh-devices").listeners.click();
  const [leased, absent, revoked] = element("device-list").children;
  assert.match(visibleText(leased), /authenticated socket lease observed.*SMS readiness unknown/);
  assert.match(visibleText(absent), /no current authenticated socket lease.*SMS readiness unknown/);
  assert.match(visibleText(revoked), /Revoked/);
  assert.doesNotMatch(visibleText(revoked), /socket lease observed/);
  for (const row of [leased, absent]) {
    assert.doesNotMatch(visibleText(row), /Ready to send|SMS connected/);
  }
});

test("downgrade asks the owner to choose devices and never revokes one automatically", async () => {
  const { element, state } = await ownerPage();
  state.billingCapacity = { limit: 1, active: 2, overLimit: true, enrollmentBlocked: true };
  state.devices = [
    { device_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", display_name: "Phone A", revoked: false },
    { device_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", display_name: "Phone B", revoked: false },
  ];
  await element("refresh-devices").listeners.click();
  assert.equal(element("device-cap-prompt").hidden, false);
  assert.match(element("device-cap-prompt").textContent, /Choose which devices to revoke/);
  assert.deepEqual(state.deletedDevices, []);

  element("display-name").value = "New phone";
  await element("create-form").listeners.submit({ preventDefault() {} });
  element("compared").checked = true;
  await element("approve-form").listeners.submit({ preventDefault() {} });
  assert.match(element("pair-status").textContent, /Device limit reached/);
  assert.doesNotMatch(element("pair-status").textContent, /mismatch|phone values/i);
  assert.equal(element("pair-cap-devices-link").hidden, false);
  assert.deepEqual(state.deletedDevices, []);

  const revoke = element("device-list").children[1].children.find((child) => child.textContent === "Revoke");
  await revoke.listeners.click();
  assert.deepEqual(state.deletedDevices, []);
  globalThis.window.confirm = () => true;
  await revoke.listeners.click();
  assert.deepEqual(state.deletedDevices, ["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]);
  assert.equal(state.devices[0].revoked, false);
});

test("overlapping device refreshes render each device once", async () => {
  const { element, state } = await ownerPage();
  state.devices = [
    { device_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", display_name: "Phone A", revoked: false },
  ];
  await Promise.all([element("refresh-devices").listeners.click(), element("refresh-devices").listeners.click()]);
  assert.equal(element("device-list").children.length, 1);
  assert.equal(element("more-devices").disabled, false);
});

test("a repeated key submit while the first is pending creates one key", async () => {
  const { element, state } = await ownerPage();
  let resolveCreate;
  let creates = 0;
  let repeatPrevented = false;
  state.pendingCreate = new Promise((resolve) => { resolveCreate = resolve; });
  const original = globalThis.fetch;
  globalThis.fetch = (url, options) => {
    if (url === "/v1/auth/api-keys" && options.method === "POST") creates += 1;
    return original(url, options);
  };
  const first = element("key-create-form").listeners.submit({ preventDefault() {} });
  await element("key-create-form").listeners.submit({ preventDefault() { repeatPrevented = true; } });
  resolveCreate(response(201, { id: "test-id", token: "ztk_synthetic-only", public_prefix: "synthetic" }));
  await first;
  assert.equal(creates, 1);
  assert.equal(repeatPrevented, true);
  assert.equal(element("key-secret").textContent, "ztk_synthetic-only");
});

test("a network failure shows a connection message instead of a browser error", async () => {
  const { element } = await ownerPage();
  const original = globalThis.fetch;
  globalThis.fetch = (url, options) => url === "/v1/owner/messages"
    ? Promise.reject(new TypeError("Failed to fetch")) : original(url, options);
  await element("refresh-messages").listeners.click();
  assert.match(element("message-status").textContent, /Could not reach the server/);
  assert.equal(element("owner-content").hidden, false);
});
