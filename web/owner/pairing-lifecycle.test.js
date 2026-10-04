// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

// Run the real controller with an isolated synthetic DOM and API. No global
// browser state, network, credentials, dependencies, or product mutations.
async function pairingPage() {
  const nodes = new Map();
  const listeners = new Map();
  const documentListeners = new Map();
  const calls = [];
  const node = () => ({
    textContent: "", value: "", hidden: false, checked: false, disabled: false,
    children: [], listeners: {}, attributes: {},
    addEventListener(name, handler) { this.listeners[name] = handler; },
    replaceChildren(...items) { this.children = items; },
    append(...items) { this.children.push(...items); },
    setAttribute(name, value) { this.attributes[name] = value; },
    querySelectorAll() { return []; }, querySelector() { return null; },
    contains(other) { return other === this; }, remove() {},
  });
  const element = id => {
    if (!nodes.has(id)) nodes.set(id, node());
    return nodes.get(id);
  };
  const response = (status, body = {}) => ({ status, ok: status >= 200 && status < 300, json: async () => body });
  const state = { expired: false, deferCreate: null, deferProof: null, deferApprove: null, approveStatus: 201, approvedDevice: null, cancelStatus: 204, clock: 0 };
  const context = vm.createContext({
    console, URL, Date, Intl, AbortSignal, performance: { now: () => state.clock },
    document: { hidden: false, activeElement: null,
      cookie: "__Host-zrotext_csrf=synthetic-ui-csrf",
      getElementById: element, createElement: node,
      addEventListener(name, handler) { documentListeners.set(name, handler); } },
    window: { location: { origin: "https://gateway.example.invalid" }, confirm: () => false,
      addEventListener(name, handler) { listeners.set(name, handler); },
      setTimeout() { return 1; }, clearTimeout() {} },
    fetch: async (url, options) => {
      calls.push({ url, options });
      if (url === "/v1/auth/session") return response(200, { role: "owner" });
      if (url === "/v1/enrollment/devices") return response(200, { devices: [], next_cursor: null });
      if (url === "/v1/owner/messages") return response(200, { messages: [], next_cursor: null });
      if (url === "/v1/enrollment/pairings" && options.method === "POST") {
        if (state.deferCreate) await state.deferCreate;
        return response(201, { pairing_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", token: "synthetic-pairing-token" });
      }
      if (url.endsWith("/cancel")) return response(state.cancelStatus);
      if (url.endsWith("/approve")) {
        if (state.deferApprove) await state.deferApprove;
        return response(state.approveStatus, { device_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" });
      }
      if (url === "/v1/auth/logout") return response(204);
      if (url.startsWith("/v1/enrollment/pairings/")) {
        if (state.deferProof) await state.deferProof;
        return response(state.expired ? 404 : 200, { claimed: true, proof_verified: true, approved_device_id: state.approvedDevice, comparison_code: "12345678", key_fingerprint: "A".repeat(64) });
      }
      return response(404);
    },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "devices.js"), "utf8"), context, { filename: "devices.js" });
  await new Promise(setImmediate);
  await new Promise(setImmediate);
  element("display-name").value = "Example phone";
  const create = () => element("create-form").listeners.submit({ preventDefault() {}, submitter: element("create-submit") });
  const approve = () => {
    element("compared").checked = true;
    element("phone-code").value = "12345678";
    element("phone-fingerprint").value = "A".repeat(64);
    return element("approve-form").listeners.submit({ preventDefault() {} });
  };
  return { element, listeners, documentListeners, calls, state, create, approve };
}

test("leaving the owner page retires pairing secrets and comparison fields", async () => {
  const page = await pairingPage();
  await page.create();
  assert.equal(page.element("pair-token").textContent, "synthetic-pairing-token");
  page.element("phone-code").value = "12345678";
  page.element("phone-fingerprint").value = "A".repeat(64);
  page.element("compared").checked = true;
  page.listeners.get("pagehide")({ persisted: true });
  assert.equal(page.element("pair-token").textContent, "", "pagehide must erase the one-use pairing token before a page can be cached");
  assert.equal(page.element("pair-id").textContent, "");
  assert.equal(page.element("phone-code").value, "");
  assert.equal(page.element("phone-fingerprint").value, "");
  assert.equal(page.element("compared").checked, false);
  assert.equal(page.element("pair-ticket").hidden, true);
  assert.equal(page.element("approve-form").hidden, true);
});

test("expired pairing clears secrets before allowing a fresh ticket", async () => {
  const page = await pairingPage();
  await page.create();
  page.state.expired = true;
  await page.element("check-proof").listeners.click();
  assert.equal(page.element("pair-token").textContent, "");
  assert.equal(page.element("pair-ticket").hidden, true);
  await page.create();
  assert.equal(page.calls.filter(call => call.url === "/v1/enrollment/pairings").length, 2);
});

test("repeat submission cannot mint another ticket while creation is pending", async () => {
  const page = await pairingPage();
  let release;
  page.state.deferCreate = new Promise(resolve => { release = resolve; });
  const first = page.create();
  await page.create();
  release();
  await first;
  assert.equal(page.calls.filter(call => call.url === "/v1/enrollment/pairings").length, 1);
});

test("a late pairing response cannot repopulate a page after departure", async () => {
  const page = await pairingPage();
  let release;
  page.state.deferCreate = new Promise(resolve => { release = resolve; });
  const creating = page.create();
  page.listeners.get("pagehide")({ persisted: true });
  release();
  await creating;
  assert.equal(page.element("pair-token").textContent, "", "late ticket response must be discarded after pagehide");
  assert.equal(page.element("pair-ticket").hidden, true);
});

test("elapsed display clears every manual field before a proof request", async () => {
  const page = await pairingPage();
  await page.create();
  page.state.clock = 300001;
  await page.element("check-proof").listeners.click();
  assert.equal(page.element("pair-token").value, "");
  assert.equal(page.element("pair-id").value, "");
  assert.equal(page.element("server-origin").value, "");
  assert.equal(page.element("pair-ticket").hidden, true);
  assert.equal(page.calls.some(call => call.url.endsWith("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") && call.options.method === "GET"), false);
});

test("a new ticket retires a known expired ticket before creation", async () => {
  const page = await pairingPage();
  await page.create();
  page.state.clock = 300001;
  page.documentListeners.get("visibilitychange")();
  await page.create();
  const pairingCalls = page.calls.filter(call => call.url.startsWith("/v1/enrollment/pairings"));
  assert.equal(pairingCalls.length, 3);
  assert.equal(pairingCalls[1].url.endsWith("/cancel"), true);
  assert.equal(pairingCalls[2].url, "/v1/enrollment/pairings");
});

test("unknown retirement blocks a replacement without discarding its public identity", async () => {
  const page = await pairingPage();
  await page.create();
  page.state.clock = 300001;
  page.state.cancelStatus = 503;
  await page.create();
  assert.equal(page.calls.filter(call => call.url === "/v1/enrollment/pairings").length, 1);
  assert.equal(page.element("pair-token").value, "");
  page.state.cancelStatus = 204;
  await page.create();
  assert.equal(page.calls.filter(call => call.url === "/v1/enrollment/pairings").length, 2);
});

test("late proof cannot reveal comparison or approval after departure", async () => {
  const page = await pairingPage();
  await page.create();
  let release;
  page.state.deferProof = new Promise(resolve => { release = resolve; });
  const proof = page.element("check-proof").listeners.click();
  page.listeners.get("pagehide")({ persisted: true });
  release();
  await proof;
  assert.equal(page.element("approve-form").hidden, true);
  assert.equal(page.element("browser-code").textContent, "");
  assert.equal(page.element("browser-fingerprint").textContent, "");
});

test("back navigation never resurrects a ticket or places a token in attributes", async () => {
  const page = await pairingPage();
  await page.create();
  assert.equal(page.element("pair-token").value, "synthetic-pairing-token");
  assert.deepEqual(page.element("pair-token").attributes, {});
  page.listeners.get("pagehide")({ persisted: true });
  page.listeners.get("pageshow")({ persisted: true });
  assert.equal(page.element("pair-token").value, "");
  assert.equal(page.element("pair-ticket").hidden, true);
});

test("late approval is recovered before an ambiguous cancel can create a replacement", async () => {
  const page = await pairingPage();
  await page.create();
  let release;
  page.state.deferApprove = new Promise(resolve => { release = resolve; });
  const approving = page.approve();
  page.listeners.get("pagehide")();
  page.listeners.get("pageshow")();
  release();
  await approving;
  page.state.expired = true;
  page.state.cancelStatus = 404;
  await page.create();
  assert.equal(page.calls.filter(call => call.url === "/v1/enrollment/pairings").length, 1);
  assert.equal(page.calls.some(call => call.url.endsWith("/cancel")), false);
  assert.match(page.element("approved-result").textContent, /bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/);
  assert.equal(page.element("pair-token").value, "");
});

test("pending approval with missing ticket blocks replacement and repeated approval", async () => {
  const page = await pairingPage();
  await page.create();
  let release;
  page.state.deferApprove = new Promise(resolve => { release = resolve; });
  const approving = page.approve();
  page.listeners.get("pagehide")();
  page.listeners.get("pageshow")();
  page.state.expired = true;
  await page.create();
  await page.approve();
  assert.equal(page.calls.filter(call => call.url === "/v1/enrollment/pairings").length, 1);
  assert.equal(page.calls.filter(call => call.url.endsWith("/approve")).length, 1);
  assert.match(page.element("pair-status").textContent, /outcome is unknown/);
  release();
  await approving;
});

test("server approval view recovers an unknown server error without a replacement", async () => {
  const page = await pairingPage();
  await page.create();
  page.state.approveStatus = 503;
  await page.approve();
  assert.equal(page.element("pair-token").value, "");
  page.state.approvedDevice = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  await page.element("check-proof").listeners.click();
  assert.match(page.element("approved-result").textContent, /bbbbbbbb/);
  assert.equal(page.calls.filter(call => call.url === "/v1/enrollment/pairings").length, 1);
});

test("late approval after sign-out cannot retain or display the old owner's device", async () => {
  const page = await pairingPage();
  await page.create();
  let release;
  page.state.deferApprove = new Promise(resolve => { release = resolve; });
  const approving = page.approve();
  await page.element("logout").listeners.click();
  release();
  await approving;
  assert.equal(page.element("approved-result").textContent, "");
  assert.equal(page.element("pair-token").value, "");
});

test("wrong-code404 can be explicitly cancelled before restarting setup", async () => {
  const page = await pairingPage();
  await page.create();
  page.state.approveStatus = 404;
  await page.approve();
  assert.equal(page.element("pair-ticket").hidden, true);
  assert.equal(page.element("resolve-pairing").hidden, false);
  await page.element("resolve-pairing").listeners.click();
  assert.equal(page.element("resolve-pairing").hidden, true);
  await page.create();
  assert.equal(page.calls.filter(call => call.url.endsWith("/cancel")).length, 1);
  assert.equal(page.calls.filter(call => call.url === "/v1/enrollment/pairings").length, 2);
});

test("ambiguous cancellation keeps interrupted approval recovery visible and blocks restart", async () => {
  const page = await pairingPage();
  await page.create();
  page.state.approveStatus = 503;
  await page.approve();
  page.state.cancelStatus = 404;
  await page.element("resolve-pairing").listeners.click();
  await page.create();
  assert.equal(page.element("resolve-pairing").hidden, false);
  assert.equal(page.calls.filter(call => call.url === "/v1/enrollment/pairings").length, 1);
  page.state.cancelStatus = 204;
  await page.element("resolve-pairing").listeners.click();
  await page.create();
  assert.equal(page.calls.filter(call => call.url === "/v1/enrollment/pairings").length, 2);
});

test("unexpected successful cancellation status cannot release an unknown approval", async () => {
  const page = await pairingPage();
  await page.create();
  page.state.approveStatus = 503;
  await page.approve();
  page.state.cancelStatus = 200;
  await page.element("resolve-pairing").listeners.click();
  await page.create();
  assert.equal(page.element("resolve-pairing").hidden, false);
  assert.equal(page.calls.filter(call => call.url === "/v1/enrollment/pairings").length, 1);
});
