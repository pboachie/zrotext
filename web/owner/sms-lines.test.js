// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const assert = require("node:assert/strict");
const { createPublicKey, verify, webcrypto } = require("node:crypto");
const test = require("node:test");
const signing = require("./sms-line-signing.js");

const ACCOUNT = "00000000-0000-4000-8000-00000000000a";
const USER = "00000000-0000-4000-8000-00000000000b";
const SESSION = "00000000-0000-4000-8000-00000000000c";
const DEVICE = "00000000-0000-4000-8000-00000000000d";
const CHALLENGE = "00000000-0000-4000-8000-00000000000e";
const KEY_CHALLENGE = "00000000-0000-4000-8000-00000000000f";

function response(status, body = {}) {
  return { status, ok: status >= 200 && status < 300, json: async () => body };
}

function concat(...parts) {
  return Uint8Array.from(parts.flatMap((part) => Array.from(part)));
}

async function deviceStatement({ line, device = DEVICE, challenge = CHALLENGE, generation = 3n }) {
  const generationBytes = new Uint8Array(8);
  new DataView(generationBytes.buffer).setBigInt64(0, generation);
  const tail = new Uint8Array(7);
  const view = new DataView(tail.buffer);
  view.setUint16(0, 29);
  view.setUint8(2, 1);
  view.setInt32(3, 4);
  return concat(Buffer.from("ZTSMS/line/device-confirm/v1\0", "latin1"), signing.uuidBytes(ACCOUNT),
    signing.uuidBytes(line), signing.uuidBytes(device), generationBytes, signing.uuidBytes(challenge),
    new Uint8Array(32).fill(9), tail);
}

function verifies(sec1, message, der) {
  const x = Buffer.from(sec1.slice(1, 33)).toString("base64url");
  const y = Buffer.from(sec1.slice(33)).toString("base64url");
  const key = createPublicKey({ key: { kty: "EC", crv: "P-256", x, y }, format: "jwk" });
  return verify("sha256", message, { key, dsaEncoding: "der" }, der);
}

async function smsLinesPage({ signedIn = true, tamper = null } = {}) {
  const elements = new Map();
  const makeElement = () => ({
    textContent: "", hidden: false, disabled: false, value: "", children: [], listeners: {},
    replaceChildren(...children) { this.children = children; },
    addEventListener(name, listener) { this.listeners[name] = listener; },
  });
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, makeElement());
    return elements.get(id);
  };
  const server = { keys: [], sec1: null, registerSignatureValid: null, views: [], approvals: [], ownerSignatureValid: null };
  let stored = null;
  const timers = [];
  globalThis.ZtSmsKeyStore = {
    get: async () => stored,
    put: async (value) => { stored = value; },
    remove: async () => { stored = null; },
  };
  globalThis.document = { cookie: "__Host-zrotext_csrf=ztc_synthetic", getElementById: element, createElement: makeElement };
  globalThis.ZtSmsLinesSchedule = (fn) => { timers.push(fn); return timers.length; };
  globalThis.fetch = async (path, options = {}) => {
    const method = options.method || "GET";
    if (path === "/v1/auth/session") return signedIn
      ? response(200, { account_id: ACCOUNT, user_id: USER, session_id: SESSION }) : response(401);
    assert.equal(options.headers["x-zrotext-csrf"], "ztc_synthetic");
    const body = options.body ? JSON.parse(options.body) : undefined;
    if (path === "/v1/auth/sms-line-owner-keys" && method === "GET") return response(200, server.keys);
    if (path === "/v1/auth/sms-line-owner-keys/challenge") {
      server.sec1 = signing.fromBase64(body.signing_key_sec1_b64);
      return response(200, { challenge_id: KEY_CHALLENGE, nonce_b64: signing.base64(new Uint8Array(32).fill(5)),
        fingerprint: signing.base64url(await signing.sha256(server.sec1)) });
    }
    if (path === "/v1/auth/sms-line-owner-keys" && method === "POST") {
      const statement = await signing.registrationStatement({ accountId: ACCOUNT, userId: USER, sessionId: SESSION,
        challengeId: body.challenge_id, nonce: signing.fromBase64(body.nonce_b64), publicKeySec1: server.sec1 });
      server.registerSignatureValid = verifies(server.sec1, statement, signing.fromBase64(body.signature_der_b64));
      assert.equal(body.mfa_code, "123456");
      server.keys = [{ fingerprint: signing.base64url(await signing.sha256(server.sec1)), active: true }];
      return response(201);
    }
    if (path === "/v1/enrollment/devices")
      return response(200, { devices: [{ id: DEVICE, display_name: "Pixel", revoked: false, active_socket_lease: true }] });
    if (path.endsWith("/activations") && method === "POST") {
      server.opened = { path, body };
      return response(201, { challenge_id: CHALLENGE, generation: 3, expires_at_ms: Date.now() + 300000 });
    }
    if (path.endsWith("/approve")) {
      server.approvals.push(body);
      server.ownerSignatureValid = verifies(server.sec1, server.expectedOwner, signing.fromBase64(body.owner_signature_der_b64));
      return response(server.ownerSignatureValid ? 204 : 403);
    }
    if (path.includes("/activations/")) return response(200, server.views.shift());
    throw new Error(`unexpected ${method} ${path}`);
  };
  delete require.cache[require.resolve("./sms-lines.js")];
  globalThis.ZtSmsLineSigning = signing;
  require("./sms-lines.js");
  await globalThis.ZtSmsLinesReady;
  // One polling round: run only the timers pending now.
  const runTimers = async () => {
    for (const fn of timers.splice(0)) await fn();
  };
  const click = async (id) => element(id).listeners.click({ preventDefault() {} });
  const submit = async (id) => element(id).listeners.submit({ preventDefault() {} });
  const prepareDeclaration = async (line, overrides = {}) => {
    const deviceKey = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const statement = await deviceStatement({ line, ...overrides });
    const deviceSignature = signing.p1363ToDer(new Uint8Array(await webcrypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, deviceKey.privateKey, statement)));
    const owner = await signing.ownerApprovalStatement(statement, deviceSignature);
    server.expectedOwner = owner;
    const ownerForServer = tamper === "owner" ? concat(owner.slice(0, -1), Uint8Array.of(owner.at(-1) ^ 1)) : owner;
    return { status: "awaiting_owner", device_id: DEVICE, generation: 3, expires_at_ms: Date.now() + 300000,
      android_api_level: 29, selected_subscription_id: 4,
      device_statement_b64: signing.base64(statement), device_signature_der_b64: signing.base64(deviceSignature),
      owner_statement_b64: signing.base64(ownerForServer) };
  };
  return { element, server, click, submit, runTimers, prepareDeclaration, stored: () => stored };
}

test("signed-out owners are sent to sign in", async () => {
  const page = await smsLinesPage({ signedIn: false });
  assert.equal(page.element("signed-out").hidden, false);
});

test("the approval key is created in the browser and registered with a verified possession proof", async () => {
  const page = await smsLinesPage();
  assert.match(page.element("key-summary").textContent, /No active SMS approval key/);
  page.element("key-mfa").value = "123456";
  await page.submit("key-form");
  assert.equal(page.server.registerSignatureValid, true);
  assert.equal(page.element("key-status").textContent, "Key created and registered.");
  assert.equal(page.element("key-mfa").value, "");
  const stored = page.stored();
  assert.equal(stored.privateKey.extractable, false);
  assert.equal(stored.fingerprint, page.server.keys[0].fingerprint);
  assert.match(page.element("key-summary").textContent, /held by this browser/);
});

test("activation is approved only after the page rebuilds and checks the phone's declaration", async () => {
  const page = await smsLinesPage();
  page.element("key-mfa").value = "123456";
  await page.submit("key-form");
  await page.click("activation-new-line");
  const line = page.element("activation-line").value;
  page.element("activation-device").value = DEVICE;
  page.server.views.push({ status: "awaiting_device", device_id: DEVICE, generation: 3, expires_at_ms: Date.now() + 300000 });
  await page.submit("activation-form");
  assert.equal(page.server.opened.path, `/v1/auth/sms-lines/${line}/activations`);
  assert.deepEqual(page.server.opened.body, { device_id: DEVICE });
  assert.match(page.element("activation-status").textContent, /Waiting for the phone/);
  page.server.views.push(await page.prepareDeclaration(line));
  await page.runTimers();
  assert.equal(page.element("activation-review").hidden, false);
  assert.equal(page.element("review-subscription").textContent, "4");
  page.server.views.push({ status: "activated", device_id: DEVICE, generation: 3, expires_at_ms: Date.now() + 300000 });
  await page.click("activation-approve");
  assert.equal(page.server.ownerSignatureValid, true);
  assert.equal(page.element("activation-status").textContent, "The line is active on this phone.");
});

for (const [name, tamper, overrides] of [
  ["a server-supplied owner statement that differs from the rebuilt one", "owner", {}],
  ["a declaration for another line's challenge", null, { challenge: "00000000-0000-4000-8000-000000000099" }],
]) {
  test(`the page refuses to approve ${name}`, async () => {
    const page = await smsLinesPage({ tamper });
    page.element("key-mfa").value = "123456";
    await page.submit("key-form");
    await page.click("activation-new-line");
    const line = page.element("activation-line").value;
    page.element("activation-device").value = DEVICE;
    page.server.views.push(await page.prepareDeclaration(line, overrides));
    await page.submit("activation-form");
    assert.match(page.element("activation-status").textContent, /Do not approve it/);
    assert.equal(page.element("activation-review").hidden, true);
    await page.click("activation-approve");
    assert.equal(page.server.approvals.length, 0);
  });
}
