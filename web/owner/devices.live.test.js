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
    if (url === "/v1/enrollment/devices" && (!options || options.method === "GET")) {
      if (state.pendingDevices) return state.pendingDevices;
      return response(200, { devices: state.devices, next_cursor: null });
    }
    if (url === "/v1/billing/status") return response(404);
    if (url === "/v1/billing/device-capacity") return response(404);
    if (url === "/v1/owner/messages") {
      if (state.pendingMessages) return state.pendingMessages;
      return response(200, { messages: state.messages, next_cursor: null });
    }
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

test("a burst of change signals coalesces into one immediate and one trailing reload", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  source.open();
  const devicesBefore = page.counts("/v1/enrollment/devices");
  const settle = () => new Promise((resolve) => setImmediate(resolve));
  source.changed(["devices"]);
  await settle();
  await settle();
  source.changed(["devices"]);
  await settle();
  source.changed(["devices"]);
  source.changed(["devices"]);
  source.changed(["devices"]);
  assert.equal(page.counts("/v1/enrollment/devices"), devicesBefore + 1,
    "burst caused more than one immediate reload");
  assert.equal(page.timers.size, 1, "expected exactly the merged trailing reload timer");
  const trailing = [...page.timers.values()][0];
  assert.ok(trailing.delay <= 15_000, "trailing reload waits longer than the floor");
  trailing.callback();
  await settle();
  await settle();
  assert.equal(page.counts("/v1/enrollment/devices"), devicesBefore + 2,
    "trailing reload did not run");
});

test("a change after the floor passes reloads immediately again", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  source.open();
  const devicesBefore = page.counts("/v1/enrollment/devices");
  const settle = () => new Promise((resolve) => setImmediate(resolve));
  source.changed(["devices"]);
  await settle();
  await settle();
  assert.equal(page.counts("/v1/enrollment/devices"), devicesBefore + 1);
  const realNow = Date.now;
  Date.now = () => realNow() + 20_000;
  try {
    source.changed(["devices"]);
  } finally {
    Date.now = realNow;
  }
  assert.equal(page.counts("/v1/enrollment/devices"), devicesBefore + 2,
    "change after the floor did not reload immediately");
});

test("a signal arriving during an in-flight reload triggers one follow-up reload", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  source.open();
  const settle = () => new Promise((resolve) => setImmediate(resolve));
  await settle();
  await settle();
  // The first signal starts an immediate reload that stays in flight.
  let resolveDevices;
  page.state.pendingDevices = new Promise((resolve) => { resolveDevices = resolve; });
  source.changed(["devices"]);
  await settle();
  const inFlight = page.counts("/v1/enrollment/devices");
  // A second signal while that reload is in flight must not start a second
  // concurrent fetch, and must not be dropped.
  source.changed(["devices"]);
  await settle();
  assert.equal(page.counts("/v1/enrollment/devices"), inFlight,
    "signal during an in-flight reload started a concurrent fetch");
  resolveDevices(response(200, { devices: [], next_cursor: null }));
  await settle();
  await settle();
  await settle();
  // The queued follow-up is inside the reload floor, so it coalesced into a
  // single trailing reload rather than fetching a third time immediately.
  assert.equal(page.counts("/v1/enrollment/devices"), inFlight,
    "queued follow-up bypassed the reload floor");
  assert.equal(page.timers.size, 1, "queued follow-up did not coalesce into one trailing reload");
  const trailing = [...page.timers.values()][0];
  trailing.callback();
  await settle();
  await settle();
  assert.equal(page.counts("/v1/enrollment/devices"), inFlight + 1,
    "the trailing reload did not run");
});

test("a messages burst coalesces into one immediate and one trailing reload", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  source.open();
  const messagesBefore = page.counts("/v1/owner/messages");
  const devicesBefore = page.counts("/v1/enrollment/devices");
  const settle = () => new Promise((resolve) => setImmediate(resolve));
  source.changed(["messages"]);
  await settle();
  await settle();
  source.changed(["messages"]);
  await settle();
  source.changed(["messages"]);
  source.changed(["messages"]);
  assert.equal(page.counts("/v1/owner/messages"), messagesBefore + 1,
    "burst caused more than one immediate message reload");
  assert.equal(page.timers.size, 1, "expected exactly the merged trailing message reload timer");
  const trailing = [...page.timers.values()][0];
  assert.ok(trailing.delay > 0 && trailing.delay <= 15_000, "trailing reload ignores the floor");
  trailing.callback();
  await settle();
  await settle();
  assert.equal(page.counts("/v1/owner/messages"), messagesBefore + 2,
    "trailing message reload did not run");
  assert.equal(page.counts("/v1/enrollment/devices"), devicesBefore,
    "a messages burst reloaded the device list");
});

test("a messages signal arriving during an in-flight reload triggers one follow-up reload", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  source.open();
  const settle = () => new Promise((resolve) => setImmediate(resolve));
  await settle();
  await settle();
  let resolveMessages;
  page.state.pendingMessages = new Promise((resolve) => { resolveMessages = resolve; });
  source.changed(["messages"]);
  await settle();
  const inFlight = page.counts("/v1/owner/messages");
  source.changed(["messages"]);
  await settle();
  assert.equal(page.counts("/v1/owner/messages"), inFlight,
    "signal during an in-flight message reload started a concurrent fetch");
  assert.equal(page.timers.size, 0, "signal during an in-flight message reload armed a timer early");
  page.state.pendingMessages = null;
  resolveMessages(response(200, { messages: [], next_cursor: null }));
  await settle();
  await settle();
  await settle();
  assert.equal(page.counts("/v1/owner/messages"), inFlight,
    "queued message follow-up bypassed the reload floor");
  assert.equal(page.timers.size, 1, "the signal during the in-flight message reload was dropped");
  [...page.timers.values()][0].callback();
  await settle();
  await settle();
  assert.equal(page.counts("/v1/owner/messages"), inFlight + 1,
    "the trailing message reload did not run");
});

for (const [section, path, pendingKey] of [
  ["devices", "/v1/enrollment/devices", "pendingDevices"],
  ["messages", "/v1/owner/messages", "pendingMessages"],
]) {
  test(`a dropped stream discards a ${section} signal queued during an in-flight reload`, async () => {
    const page = await ownerPage();
    const source = FakeEventSource.instances[0];
    source.open();
    const settle = () => new Promise((resolve) => setImmediate(resolve));
    await settle();
    await settle();
    let release;
    page.state[pendingKey] = new Promise((resolve) => { release = resolve; });
    source.changed([section]);
    await settle();
    source.changed([section]);
    source.error();
    const timersAfterDrop = [...page.timers.values()].map((timer) => timer.delay).sort();
    const fetchesAfterDrop = page.counts(path);
    page.state[pendingKey] = null;
    release(response(200, section === "devices"
      ? { devices: [], next_cursor: null }
      : { messages: [], next_cursor: null }));
    await settle();
    await settle();
    await settle();
    assert.deepEqual([...page.timers.values()].map((timer) => timer.delay).sort(), timersAfterDrop,
      "a load finishing after the stream dropped re-armed a live reload");
    assert.equal(page.counts(path), fetchesAfterDrop,
      "a load finishing after the stream dropped fetched again");
  });
}

test("turning off automatic refresh discards a signal queued during an in-flight reload", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  source.open();
  const settle = () => new Promise((resolve) => setImmediate(resolve));
  await settle();
  await settle();
  let release;
  page.state.pendingMessages = new Promise((resolve) => { release = resolve; });
  source.changed(["messages"]);
  await settle();
  source.changed(["messages"]);
  const fetches = page.counts("/v1/owner/messages");
  page.element("auto-refresh").checked = false;
  page.element("auto-refresh").listeners.change();
  page.state.pendingMessages = null;
  const realNow = Date.now;
  // Past the reload floor, so only the automatic-refresh guard can stop it.
  Date.now = () => realNow() + 20_000;
  try {
    release(response(200, { messages: [], next_cursor: null }));
    await settle();
    await settle();
    await settle();
  } finally {
    Date.now = realNow;
  }
  assert.equal(page.counts("/v1/owner/messages"), fetches,
    "a queued signal reloaded after automatic refresh was turned off");
  assert.equal(page.timers.size, 0, "a queued signal armed a timer after automatic refresh was turned off");
});

test("a dropped stream cancels a pending trailing reload", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  source.open();
  const settle = () => new Promise((resolve) => setImmediate(resolve));
  source.changed(["devices"]);
  await settle();
  await settle();
  source.changed(["devices"]);
  assert.equal(page.timers.size, 1, "no trailing reload was scheduled");
  const trailingId = [...page.timers.keys()][0];
  source.error();
  assert.equal(page.timers.has(trailingId), false, "trailing reload survived the stream ending");
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

test("a stream that reconnects after a hidden tab reloads the lists once", async () => {
  const page = await ownerPage();
  const first = FakeEventSource.instances[0];
  first.open();
  await new Promise(setImmediate);
  await new Promise(setImmediate);
  globalThis.document.hidden = true;
  page.documentListeners.visibilitychange();
  assert.ok(first.closed, "stream stayed open on a hidden tab");
  // Data changed while no stream was open; the new stream's baseline
  // swallows it, so the client must reload once on reconnect.
  const devicesBefore = page.counts("/v1/enrollment/devices");
  const messagesBefore = page.counts("/v1/owner/messages");
  globalThis.document.hidden = false;
  page.documentListeners.visibilitychange();
  const second = FakeEventSource.instances[1];
  assert.ok(second, "visible tab did not restart the stream");
  second.open();
  await new Promise(setImmediate);
  await new Promise(setImmediate);
  assert.equal(page.counts("/v1/enrollment/devices"), devicesBefore + 1,
    "reconnect did not reload the device list");
  assert.equal(page.counts("/v1/owner/messages"), messagesBefore + 1,
    "reconnect did not reload the message list");
});

test("the first stream open after sign-in does not trigger an extra reload", async () => {
  const page = await ownerPage();
  const source = FakeEventSource.instances[0];
  const devicesBefore = page.counts("/v1/enrollment/devices");
  const messagesBefore = page.counts("/v1/owner/messages");
  source.open();
  await new Promise(setImmediate);
  await new Promise(setImmediate);
  assert.equal(page.counts("/v1/enrollment/devices"), devicesBefore,
    "first open reloaded the device list");
  assert.equal(page.counts("/v1/owner/messages"), messagesBefore,
    "first open reloaded the message list");
});

test("a stream that reconnects after an error reloads the lists once", async () => {
  const page = await ownerPage();
  const first = FakeEventSource.instances[0];
  first.open();
  await new Promise(setImmediate);
  await new Promise(setImmediate);
  first.error();
  const retry = page.timerWith(1_000);
  assert.ok(retry, "first retry not scheduled");
  const devicesBefore = page.counts("/v1/enrollment/devices");
  const messagesBefore = page.counts("/v1/owner/messages");
  retry.callback();
  const second = FakeEventSource.instances[1];
  assert.ok(second, "retry did not open a new stream");
  second.open();
  await new Promise(setImmediate);
  await new Promise(setImmediate);
  assert.equal(page.counts("/v1/enrollment/devices"), devicesBefore + 1,
    "error reconnect did not reload the device list");
  assert.equal(page.counts("/v1/owner/messages"), messagesBefore + 1,
    "error reconnect did not reload the message list");
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
