// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const assert = require("node:assert/strict");
const { randomBytes } = require("node:crypto");
const test = require("node:test");
const response = (status, body = {}) => ({
  status, ok: status >= 200 && status < 300, json: async () => body,
});

async function ownerPage(mfaEnabled) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        textContent: "", hidden: false, value: "", checked: false, listeners: {},
        addEventListener(name, listener) { this.listeners[name] = listener; },
        replaceChildren() {}, append() {}, focus() { this.focused = true; },
      });
    }
    return elements.get(id);
  };
  const state = {
    authorized: false,
    sessionAllowed: true,
    challenge: `ztm_${randomBytes(24).toString("hex")}`,
    factor: randomBytes(8).toString("hex"),
    requests: [],
  };
  const fetch = async (url, options) => {
    state.requests.push({ url, options });
    if (url === "/v1/auth/session") return response(state.authorized && state.sessionAllowed ? 200 : 401);
    if (url === "/v1/auth/login") {
      if (mfaEnabled) return response(202, { challenge_token: state.challenge });
      state.authorized = true;
      return response(204);
    }
    if (url === "/v1/auth/login/mfa") {
      const body = JSON.parse(options.body);
      if (body.challenge_token !== state.challenge || body.code !== state.factor) return response(401);
      state.authorized = true;
      return response(204);
    }
    if (url === "/v1/enrollment/devices") return response(200, { devices: [], next_cursor: null });
    if (url === "/v1/owner/messages") return response(200, { messages: [], next_cursor: null });
    throw new Error(`Unexpected request: ${url}`);
  };
  globalThis.document = { cookie: "", getElementById: element };
  globalThis.window = { location: { origin: "https://example.test" } };
  globalThis.fetch = fetch;
  delete require.cache[require.resolve("./devices.js")];
  require("./devices.js");
  await new Promise(setImmediate);
  return { element, state };
}

const submit = (form) => form.listeners.submit({ preventDefault() {} });

test("MFA challenge keeps owner controls hidden until a valid factor creates a session", async () => {
  const { element, state } = await ownerPage(true);
  element("email").value = "owner@example.test";
  element("password").value = randomBytes(24).toString("hex");
  await submit(element("login-form"));
  assert.equal(element("owner-content").hidden, true);
  assert.equal(element("mfa-form").hidden, false);
  assert.equal(element("mfa-code").focused, true);
  assert.equal(state.requests.filter((request) => request.url === "/v1/auth/session").length, 1);

  element("mfa-code").value = randomBytes(24).toString("hex");
  await submit(element("mfa-form"));
  assert.equal(element("owner-content").hidden, true);
  assert.equal(element("mfa-form").hidden, false);
  assert.equal(state.authorized, false);

  element("mfa-code").value = state.factor;
  await submit(element("mfa-form"));
  const factorRequest = state.requests.filter((request) => request.url === "/v1/auth/login/mfa").at(-1);
  assert.deepEqual(JSON.parse(factorRequest.options.body), {
    challenge_token: state.challenge, code: state.factor,
  });
  assert.equal(factorRequest.options.headers["x-zrotext-csrf"], undefined);
  assert.equal(element("owner-content").hidden, false);
  assert.equal(element("mfa-form").hidden, true);
  assert.equal(element("mfa-code").value, "");
  assert.equal(state.requests.filter((request) => request.url === "/v1/auth/session").length, 2);
});

test("a factor response without a verifiable session leaves controls hidden", async () => {
  const { element, state } = await ownerPage(true);
  state.sessionAllowed = false;
  element("password").value = randomBytes(24).toString("hex");
  await submit(element("login-form"));
  element("mfa-code").value = state.factor;
  await submit(element("mfa-form"));
  assert.equal(element("owner-content").hidden, true);
  assert.equal(element("sign-in").hidden, false);
  assert.equal(element("mfa-form").hidden, true);
  assert.match(element("login-status").textContent, /Could not verify the new session/);
});

test("cancelled challenge is discarded and password-only login verifies a session", async () => {
  const mfaPage = await ownerPage(true);
  mfaPage.element("password").value = randomBytes(24).toString("hex");
  await submit(mfaPage.element("login-form"));
  await mfaPage.element("cancel-mfa").listeners.click();
  assert.equal(mfaPage.element("mfa-form").hidden, true);
  assert.equal(mfaPage.element("login-form").hidden, false);
  await submit(mfaPage.element("mfa-form"));
  assert.equal(mfaPage.state.requests.some((request) => request.url === "/v1/auth/login/mfa"), false);

  const page = await ownerPage(false);
  page.element("password").value = randomBytes(24).toString("hex");
  await submit(page.element("login-form"));
  assert.equal(page.element("owner-content").hidden, false);
  assert.equal(page.state.requests.filter((request) => request.url === "/v1/auth/session").length, 2);
});
