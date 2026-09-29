// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

function response(status, body = {}) {
  return { status, ok: status >= 200 && status < 300, json: async () => body };
}

class FakeEventSource {
  constructor(url) {
    this.url = url;
    this.listeners = {};
    this.closed = false;
    FakeEventSource.instances.push(this);
  }
  addEventListener(name, listener) { this.listeners[name] = listener; }
  close() { this.closed = true; }
  open() { if (this.listeners.open) this.listeners.open(); }
  changed(sections) {
    if (this.listeners.changed) this.listeners.changed({ data: JSON.stringify({ changed: sections }) });
  }
  malformedChange() {
    if (this.listeners.changed) this.listeners.changed({ data: "{not json" });
  }
  error() { if (this.listeners.error) this.listeners.error(); }
}
FakeEventSource.instances = [];

async function ownerPage({ eventSource = FakeEventSource } = {}) {
  FakeEventSource.instances = [];
  const elements = new Map();
  const makeElement = () => ({
    textContent: "", hidden: false, disabled: false, value: "", checked: false,
    children: [], listeners: {}, openDetails: null,
    replaceChildren(...children) { this.children = children; },
    append(...children) { this.children.push(...children); },
    contains(node) { return this === node || this.children.some((child) => child.contains(node)); },
    querySelector() { return this.openDetails || null; },
    addEventListener(name, listener) { this.listeners[name] = listener; },
  });
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement());
    return elements.get(id);
  };
  element("auto-refresh").checked = true;
  const timers = new Map();
  const documentListeners = {};
  const windowListeners = {};
  let nextTimer = 0;
  const state = {
    signedIn: true,
    requests: [],
    devices: [],
    messages: [],
  };
  const fetch = async (url, options) => {
    state.requests.push({ url, method: (options && options.method) || "GET" });
    if (url === "/v1/auth/session") return response(state.signedIn ? 200 : 401);
    if (url === "/v1/auth/logout") return response(204);
    if (url === "/v1/auth/sessions" && (!options || options.method === "GET"))
      return response(200, { sessions: [{ id: "11111111-1111-4111-8111-111111111111", current: true,
        created_at_ms: 1000, expires_at_ms: 100000, last_used_at_ms: 2000 }] });
    if (url === "/v1/enrollment/devices" && (!options || options.method === "GET"))
      return response(200, { devices: state.devices, next_cursor: null });
    if (url === "/v1/billing/status") return response(404);
    if (url === "/v1/billing/device-capacity") return response(404);
    if (url === "/v1/owner/messages") return response(200, { messages: state.messages, next_cursor: null });
    if (url === "/v1/owner/opt-out-review") return response(200, { holds: [], next_cursor: null });
    if (url === "/v1/owner/opt-out-holds") return response(200, { holds: [], next_cursor: null });
    if (url === "/v1/auth/api-keys" && (!options || options.method === "GET"))
      return response(200, { keys: [], next_cursor: null });
    if (url === "/v1/webhooks") return response(200, { endpoints: [] });
    throw new Error(`Unexpected request: ${url}`);
  };
  globalThis.document = { hidden: false, activeElement: null,
    addEventListener(name, callback) { documentListeners[name] = callback; },
    cookie: "__Host-zrotext_csrf=ztc_synthetic", getElementById: element, createElement: makeElement };
  globalThis.window = {
    location: { origin: "https://example.test" },
    EventSource: eventSource,
    addEventListener(name, callback) { windowListeners[name] = callback; },
    setTimeout(callback, delay) { timers.set(++nextTimer, { callback, delay }); return nextTimer; },
    clearTimeout(id) { timers.delete(id); },
  };
  globalThis.fetch = fetch;
  delete require.cache[require.resolve("./devices.js")];
  require("./devices.js");
  await new Promise(setImmediate);
  await new Promise(setImmediate);
  const timerWith = (delay) => {
    const matches = [...timers.values()].filter((timer) => timer.delay === delay);
    return matches.length === 1 ? matches[0] : null;
  };
  return {
    element, state, timers, documentListeners, windowListeners, timerWith,
    counts: (path) => state.requests.filter((request) => request.url === path).length,
  };
}

test("signed-in page subscribes once and pauses the snapshot fallback while connected", async () => {
  const page = await ownerPage();
  assert.equal(FakeEventSource.instances.length, 1);
  assert.equal(FakeEventSource.instances[0].url, "/owner/events");
  // Until the stream opens, the 15-second snapshot fallback stays armed.
  const fallback = page.timerWith(15_000);
  assert.ok(fallback, "snapshot fallback timer missing before the stream opens");
  FakeEventSource.instances[0].open();
  assert.equal(page.timerWith(15_000), null, "snapshot fallback still armed after open");
});

test("change signals refresh only the signalled sections", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  source.open();
  const devicesBefore = page.counts("/v1/enrollment/devices");
  const messagesBefore = page.counts("/v1/owner/messages");
  source.changed(["devices"]);
  assert.equal(page.counts("/v1/enrollment/devices"), devicesBefore + 1);
  assert.equal(page.counts("/v1/owner/messages"), messagesBefore);
  source.changed(["messages"]);
  assert.equal(page.counts("/v1/owner/messages"), messagesBefore + 1);
  source.malformedChange();
  assert.equal(page.counts("/v1/enrollment/devices"), devicesBefore + 1);
  assert.equal(page.counts("/v1/owner/messages"), messagesBefore + 1);
});

test("an open message row pauses that list during a live update", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  source.open();
  page.element("message-list").openDetails = {};
  const messagesBefore = page.counts("/v1/owner/messages");
  const devicesBefore = page.counts("/v1/enrollment/devices");
  source.changed(["devices", "messages"]);
  assert.equal(page.counts("/v1/owner/messages"), messagesBefore, "paused list refreshed");
  assert.equal(page.counts("/v1/enrollment/devices"), devicesBefore + 1);
});

test("stream failure resumes snapshot refresh and retries with growing capped backoff", async () => {
  const page = await ownerPage();
  const first = FakeEventSource.instances[0];
  first.open();
  first.error();
  assert.ok(first.closed, "failed source was not closed");
  assert.ok(page.timerWith(15_000), "snapshot fallback not resumed after stream failure");
  const retry = page.timerWith(1_000);
  assert.ok(retry, "first retry not scheduled after one second");
  retry.callback();
  assert.equal(FakeEventSource.instances.length, 2, "retry did not open a new stream");
  const second = FakeEventSource.instances[1];
  second.open();
  // The second connection drops immediately, so the backoff keeps growing
  // instead of restarting at the base delay.
  second.error();
  assert.ok(page.timerWith(2_000), "second retry did not double the backoff");
});

test("a stream that stayed connected recovers the base retry delay", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  source.open();
  const realNow = Date.now;
  Date.now = () => realNow() + 60_000;
  try {
    source.error();
  } finally {
    Date.now = realNow;
  }
  assert.ok(page.timerWith(1_000), "healthy stream did not recover the base retry delay");
});

test("signing out closes the stream and stops retries", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  source.open();
  page.element("logout").listeners.click();
  await new Promise(setImmediate);
  await new Promise(setImmediate);
  assert.ok(source.closed, "stream stayed open after sign out");
  assert.equal(page.timers.size, 0, "timers left running after sign out");
  assert.equal(FakeEventSource.instances.length, 1, "sign out opened another stream");
});

test("turning off automatic refresh closes the stream and arms no timers", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  source.open();
  page.element("auto-refresh").checked = false;
  page.element("auto-refresh").listeners.change();
  assert.ok(source.closed, "stream stayed open after automatic refresh was turned off");
  assert.equal(page.timers.size, 0);
});

test("a hidden tab stops the stream and a visible tab restarts it", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  source.open();
  globalThis.document.hidden = true;
  page.documentListeners.visibilitychange();
  assert.ok(source.closed, "stream stayed open on a hidden tab");
  globalThis.document.hidden = false;
  page.documentListeners.visibilitychange();
  assert.equal(FakeEventSource.instances.length, 2, "visible tab did not restart the stream");
});

test("without EventSource support the dashboard keeps the snapshot fallback", async () => {
  const page = await ownerPage({ eventSource: null });
  assert.equal(FakeEventSource.instances.length, 0);
  assert.ok(page.timerWith(15_000), "snapshot fallback timer missing without EventSource");
});
