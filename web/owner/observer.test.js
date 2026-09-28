// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const assert = require("node:assert/strict");
const { randomBytes } = require("node:crypto");
const test = require("node:test");
const testPassword = randomBytes(20).toString("hex");

function response(status, body = {}) {
  return {
    status, ok: status >= 200 && status < 300,
    json: async () => {
      if (status === 204) throw new Error("empty response has no JSON body");
      return body;
    },
  };
}

const device = {
  device_id: "44444444-4444-4444-8444-444444444444",
  display_name: "Synthetic gateway",
  revoked: false,
  active_socket_lease: true,
  pending_messages: 2,
  in_flight_messages: 1,
  status_observed_at_ms: 5_000,
  reported_preconditions: null,
};

async function observerPage({ role = null, devices = [device] } = {}) {
  const elements = new Map();
  const makeElement = () => ({
    textContent: "", hidden: false, value: "", children: [], listeners: {},
    replaceChildren(...children) { this.children = children; },
    append(...children) { this.children.push(...children); },
    addEventListener(name, listener) { this.listeners[name] = listener; },
  });
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement());
    return elements.get(id);
  };
  const calls = [];
  const state = { role, signedIn: role !== null };
  const fetch = async (path, options = {}) => {
    calls.push({ path, options });
    if (path === "/v1/auth/session") {
      return state.signedIn ? response(200, { role: state.role }) : response(401);
    }
    if (path === "/v1/auth/login") {
      state.signedIn = true;
      state.role = "observer";
      return response(204);
    }
    if (path === "/v1/auth/seats/accept") return response(204);
    if (path === "/v1/auth/verify-email") return response(204);
    if (path === "/v1/auth/password") return response(204);
    if (path === "/v1/auth/logout") {
      state.signedIn = false;
      return response(204);
    }
    if (path === "/v1/observer/devices") {
      return state.signedIn ? response(200, { devices, next_cursor: null }) : response(401);
    }
    throw new Error(`Unexpected request: ${path}`);
  };
  globalThis.document = {
    cookie: "__Host-zrotext_csrf=ztc_synthetic",
    getElementById: element,
    createElement: makeElement,
  };
  globalThis.window = { addEventListener() {} };
  globalThis.fetch = fetch;
  delete require.cache[require.resolve("./observer.js")];
  require("./observer.js");
  await new Promise(setImmediate);
  return { element, calls };
}

async function submit(element) {
  let prevented = false;
  await element.listeners.submit({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
}

test("anonymous observers see acceptance and sign-in only", async () => {
  const { element, calls } = await observerPage();
  assert.equal(element("accept-section").hidden, false);
  assert.equal(element("sign-in-section").hidden, false);
  assert.equal(element("verify-section").hidden, true);
  assert.equal(element("status-section").hidden, true);
  assert.equal(element("password-section").hidden, true);
  assert.equal(element("logout").hidden, true);
  assert.ok(calls.some(({ path }) => path === "/v1/auth/session"));
});

test("acceptance posts the token once and leads into verification", async () => {
  const { element, calls } = await observerPage();
  element("accept-token").value = " zti_synthetic-invitation ";
  element("accept-password").value = testPassword;
  await submit(element("accept-form"));
  const call = calls.find(({ path }) => path === "/v1/auth/seats/accept");
  assert.deepEqual(JSON.parse(call.options.body), {
    token: "zti_synthetic-invitation", password: testPassword,
  });
  assert.equal(call.options.headers["content-type"], "application/json");
  assert.equal(element("accept-section").hidden, true);
  assert.equal(element("verify-section").hidden, false);
  assert.equal(element("accept-token").value, "");
  assert.equal(element("accept-password").value, "");

  element("verify-code").value = " code-from-email ";
  element("verify-password").value = testPassword;
  await submit(element("verify-form"));
  const verify = calls.find(({ path }) => path === "/v1/auth/verify-email");
  assert.deepEqual(JSON.parse(verify.options.body), {
    token: "code-from-email", password: testPassword,
  });
  assert.equal(element("verify-section").hidden, true);
  assert.equal(element("sign-in-section").hidden, false);
  assert.ok(calls.every(({ path }) => !path.includes("?")));
});

test("sign-in reaches the read-only device status for an observer", async () => {
  const { element, calls } = await observerPage();
  element("login-email").value = "observer@example.test";
  element("login-password").value = testPassword;
  await submit(element("login-form"));
  const login = calls.find(({ path }) => path === "/v1/auth/login");
  assert.deepEqual(JSON.parse(login.options.body), {
    email: "observer@example.test", password: testPassword,
  });
  const deviceCall = calls.find(({ path }) => path === "/v1/observer/devices");
  assert.equal(deviceCall.options.headers["x-zrotext-csrf"], "ztc_synthetic");
  assert.equal(element("status-section").hidden, false);
  assert.equal(element("password-section").hidden, false);
  assert.equal(element("logout").hidden, false);
  const items = element("device-list").children;
  assert.equal(items.length, 1);
  assert.match(items[0].children[0].textContent, /Synthetic gateway/);
  assert.match(items[0].children[1].textContent, /connected/);
  assert.equal(element("login-password").value, "");
});

test("signed-in observers can change their own password and sign out", async () => {
  const { element, calls } = await observerPage({ role: "observer" });
  assert.equal(element("status-section").hidden, false);
  element("current-password").value = testPassword;
  element("new-password").value = `new-${testPassword}`;
  await submit(element("password-form"));
  const change = calls.find(({ path }) => path === "/v1/auth/password");
  assert.deepEqual(JSON.parse(change.options.body), {
    current_password: testPassword, new_password: `new-${testPassword}`,
  });
  assert.equal(change.options.headers["x-zrotext-csrf"], "ztc_synthetic");
  // A successful change signs every session out, including this one.
  assert.equal(element("password-section").hidden, true);
  assert.equal(element("status-section").hidden, true);
  assert.equal(element("sign-in-section").hidden, false);
  assert.equal(element("current-password").value, "");
  assert.equal(element("new-password").value, "");

  element("logout").listeners.click();
  assert.ok(calls.some(({ path, options }) =>
    path === "/v1/auth/logout" && options.method === "POST"));
  assert.equal(element("logout").hidden, true);
  assert.equal(element("sign-in-section").hidden, false);
});

test("owner sessions are pointed back to the owner dashboard", async () => {
  const { element, calls } = await observerPage({ role: "owner" });
  assert.equal(element("status-section").hidden, true);
  assert.equal(element("password-section").hidden, true);
  assert.equal(element("logout").hidden, false);
  assert.match(element("observer-status").textContent, /owner/);
  assert.ok(!calls.some(({ path }) => path === "/v1/observer/devices"));
});

test("unverified sign-in attempts explain verification", async () => {
  const { element } = await observerPage();
  element("login-email").value = "observer@example.test";
  element("login-password").value = testPassword;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => response(403);
  await submit(element("login-form"));
  globalThis.fetch = originalFetch;
  assert.match(element("login-status").textContent, /Verify your email/);
});
