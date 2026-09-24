// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

function response(status, body = {}) {
  return {
    status, ok: status >= 200 && status < 300,
    json: async () => {
      if (status === 202 || status === 204) throw new Error("empty response has no JSON body");
      return body;
    },
  };
}

async function accountPage({ signedIn = false, cookie = "__Host-zrotext_csrf=ztc_synthetic" } = {}) {
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
  const replies = new Map();
  const windowListeners = {};
  let mfaEnabled = false;
  const fetch = async (path, options = {}) => {
    calls.push({ path, options });
    if (replies.has(path)) return replies.get(path);
    if (path === "/v1/auth/session") return response(signedIn ? 200 : 401);
    if (path === "/v1/auth/mfa") return response(200, { enabled: mfaEnabled, pending: false });
    if (path === "/v1/auth/register") return response(202);
    if (path === "/v1/auth/verify-email") return response(204);
    if (path === "/v1/auth/resend-verification") return response(202);
    if (path === "/v1/auth/mfa/enroll") return response(200, {
      secret_base32: "ABCDEFGHIJKLMNOP234567", provisioning_uri: "otpauth://totp/ZROtext?secret=ABCDEFGHIJKLMNOP234567",
    });
    if (path === "/v1/auth/mfa/confirm") {
      mfaEnabled = true;
      return response(200, { recovery_codes: ["first-recovery", "second-recovery"] });
    }
    if (path === "/v1/auth/mfa/disable") {
      mfaEnabled = false;
      return response(204);
    }
    throw new Error(`Unexpected request: ${path}`);
  };
  globalThis.document = { cookie, getElementById: element, createElement: makeElement };
  globalThis.window = { addEventListener(name, listener) { windowListeners[name] = listener; } };
  globalThis.fetch = fetch;
  delete require.cache[require.resolve("./account.js")];
  require("./account.js");
  await new Promise(setImmediate);
  return { element, calls, replies, windowListeners };
}

async function submit(element) {
  let prevented = false;
  await element.listeners.submit({ preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
}

test("invited registration sends credentials in JSON and invite only in a header", async () => {
  const { element, calls } = await accountPage();
  element("register-email").value = "invited@example.test";
  element("register-password").value = "private passphrase";
  element("register-token").value = " address-bound-token ";
  await submit(element("register-form"));
  const call = calls.at(-1);
  assert.equal(call.path, "/v1/auth/register");
  assert.deepEqual(JSON.parse(call.options.body), {
    email: "invited@example.test", password: "private passphrase",
  });
  assert.equal(call.options.headers["x-zrotext-registration-token"], "address-bound-token");
  assert.equal(call.options.headers["x-zrotext-csrf"], undefined);
  assert.equal(call.options.redirect, "error");
  assert.equal(call.options.credentials, "same-origin");
  assert.equal(element("register-password").value, "");
  assert.equal(element("register-token").value, "");
  assert.match(element("register-status").textContent, /If registration is open/);
  assert.ok(calls.every(({ path }) => !path.includes("?")));
});

test("verification and resend never put a code or password in a URL", async () => {
  const { element, calls, replies } = await accountPage();
  element("verification-code").value = " code from email ";
  await submit(element("verify-form"));
  assert.deepEqual(JSON.parse(calls.at(-1).options.body), { token: "code from email" });
  assert.equal(element("verification-code").value, "");
  element("resend-email").value = "owner@example.test";
  element("resend-password").value = "private passphrase";
  await submit(element("resend-form"));
  assert.deepEqual(JSON.parse(calls.at(-1).options.body), {
    email: "owner@example.test", password: "private passphrase",
  });
  assert.equal(element("resend-password").value, "");
  replies.set("/v1/auth/verify-email", response(400));
  element("verification-code").value = "wrong-code";
  await submit(element("verify-form"));
  assert.match(element("verify-status").textContent, /Check the entered values/);
  assert.ok(calls.every(({ path }) => !path.includes("?")));
});

test("MFA setup requires CSRF and clears one-time secrets", async () => {
  const { element, calls, windowListeners } = await accountPage({ signedIn: true });
  assert.equal(element("mfa-section").hidden, false);
  element("mfa-enroll-password").value = "private passphrase";
  await submit(element("mfa-enroll-form"));
  assert.equal(calls.at(-1).path, "/v1/auth/mfa/enroll");
  assert.equal(calls.at(-1).options.headers["x-zrotext-csrf"], "ztc_synthetic");
  assert.equal(element("mfa-enroll-password").value, "");
  assert.equal(element("mfa-secret-panel").hidden, false);
  assert.equal(element("mfa-confirm-form").hidden, false);
  element("mfa-confirm-code").value = "123456";
  await submit(element("mfa-confirm-form"));
  assert.deepEqual(JSON.parse(calls.at(-2).options.body), { code: "123456" });
  assert.equal(element("mfa-secret").textContent, "");
  assert.equal(element("recovery-panel").hidden, false);
  assert.deepEqual(element("recovery-codes").children.map((item) => item.textContent),
    ["first-recovery", "second-recovery"]);
  windowListeners.pagehide();
  assert.deepEqual(element("recovery-codes").children, []);
  assert.equal(element("recovery-panel").hidden, true);
  assert.equal(element("mfa-provisioning-uri").textContent, "");
});

test("MFA disable uses password and code in JSON and handles missing CSRF", async () => {
  const page = await accountPage({ signedIn: true });
  page.element("mfa-enroll-password").value = "private passphrase";
  await submit(page.element("mfa-enroll-form"));
  page.element("mfa-confirm-code").value = "123456";
  await submit(page.element("mfa-confirm-form"));
  page.element("mfa-disable-password").value = "private passphrase";
  page.element("mfa-disable-code").value = "unused-recovery";
  await submit(page.element("mfa-disable-form"));
  const call = page.calls.at(-2);
  assert.equal(call.path, "/v1/auth/mfa/disable");
  assert.deepEqual(JSON.parse(call.options.body), {
    password: "private passphrase", code: "unused-recovery",
  });
  assert.equal(page.element("mfa-disable-password").value, "");
  assert.equal(page.element("mfa-disable-code").value, "");
  assert.equal(page.element("mfa-disable-form").hidden, true);

  const noCsrf = await accountPage({ signedIn: true, cookie: "" });
  const count = noCsrf.calls.length;
  noCsrf.element("mfa-enroll-password").value = "private passphrase";
  await submit(noCsrf.element("mfa-enroll-form"));
  assert.equal(noCsrf.calls.length, count);
  assert.match(noCsrf.element("mfa-status").textContent, /Sign in before managing MFA/);
});

test("a late enrollment response cannot restore a secret after leaving", async () => {
  const { element, replies, windowListeners } = await accountPage({ signedIn: true });
  let release;
  replies.set("/v1/auth/mfa/enroll", new Promise((resolve) => { release = resolve; }));
  element("mfa-enroll-password").value = "private passphrase";
  const pending = submit(element("mfa-enroll-form"));
  windowListeners.pagehide();
  release(response(200, {
    secret_base32: "ABCDEFGHIJKLMNOP234567",
    provisioning_uri: "otpauth://totp/ZROtext?secret=ABCDEFGHIJKLMNOP234567",
  }));
  await pending;
  assert.equal(element("mfa-secret").textContent, "");
  assert.equal(element("mfa-secret-panel").hidden, true);
  assert.equal(element("mfa-confirm-form").hidden, true);
});
