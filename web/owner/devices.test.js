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
  const element = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        textContent: "", hidden: false, value: "", checked: false,
        listeners: {}, replaceChildren() { this.children = []; },
        append() {},
        addEventListener(name, listener) { this.listeners[name] = listener; },
        querySelectorAll() { return [{ value: "messages:read" }]; },
      });
    }
    return elements.get(id);
  };
  element("key-lifetime").value = "30";
  const state = { unauthorized: false, pendingCreate: null, nextCreateResponse: null };
  const fetch = async (url, options) => {
    if (url === "/v1/auth/session") return response(200);
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
    throw new Error(`Unexpected request: ${url}`);
  };
  vm.runInNewContext(source, {
    document: { cookie: "__Host-zrotext_csrf=ztc_synthetic", getElementById: element },
    window: { location: { origin: "https://example.test" }, addEventListener() {} },
    fetch,
  });
  await new Promise(setImmediate);
  await new Promise(setImmediate);
  return { element, state };
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
