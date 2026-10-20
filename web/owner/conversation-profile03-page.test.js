// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), vm = require("node:vm");
function page() {
  const elements = new Map(), listeners = {}, urls = [], calls = []; let phase = "unprepared", opening = null, closed = false, closeListener, pending;
  function el(id) {
    if (!elements.has(id)) elements.set(id, { id, value: "", checked: false, files: [{}], disabled: false, children: [], listeners: {},
      addEventListener(type, fn) { this.listeners[type] = fn; }, replaceChildren() { this.children = []; }, append(value) { this.children.push(value); } });
    return elements.get(id);
  }
  const state = () => ({ phase, closed, openingId: opening });
  const controller = { state, onClose: fn => closeListener = fn, close() { closed = true; phase = "closed"; closeListener?.(); },
    async begin() { calls.push("begin"); await pending; phase = "awaiting_offline_approval"; return { proposal: new Uint8Array([1]) }; },
    async reserve(file, credentials) { calls.push({ reserve: credentials }); phase = "awaiting_phone"; opening = "synthetic-original"; },
    async check() { calls.push("check"); phase = "awaiting_owner"; }, async approve(credentials) { calls.push({ approve: credentials }); phase = "accepted_pending_current"; },
    async find() { phase = "choose_recovery"; return { openings: ["synthetic-original"] }; }, async recover(id) { opening = id; phase = "recovery_loaded"; } };
  const context = { Blob, document: { getElementById: el, createElement: () => ({}) }, window: { addEventListener(type, fn) { listeners[type] = fn; } }, URL: { createObjectURL() { urls.push("public"); return "blob:public"; }, revokeObjectURL() {} }, ZtProfile03Setup: { create(options) { calls.push({ selection: options.readSelection() }); phase = "unprepared"; closed = false; return controller; } } };
  vm.runInNewContext(fs.readFileSync(__dirname + "/conversation-profile03-page.js", "utf8"), context);
  return { el, calls, controller, urls, async click(id) { await el(id).listeners.click(); }, input(id) { el("owner-setup").listeners.input({ target: { id } }); }, hold(promise) { pending = promise; }, state };
}
test("actual profile page requires separate unchecked decisions and clears transient factors after each explicit action", async () => {
  const p = page(); assert.equal(p.el("profile-reserve").disabled, true); assert.equal(p.calls.length, 0);
  await p.click("profile-begin"); assert.equal(p.calls[0].selection.retentionConsent, false); assert.equal(p.calls[0].selection.compared, false);
  assert.equal(p.el("profile-reserve").disabled, false); assert.equal(p.urls.length, 1);
  p.el("profile-password").value = "synthetic-password"; p.el("profile-factor").value = "123456"; await p.click("profile-reserve");
  assert.equal(p.el("profile-password").value, ""); assert.equal(p.el("profile-factor").value, ""); assert.equal(p.el("profile-approve").disabled, true);
  await p.click("profile-check"); assert.equal(p.el("profile-approve").disabled, false);
  p.el("profile-password").value = "synthetic-password"; p.el("profile-factor").value = "654321"; await p.click("profile-approve");
  assert.equal(p.el("profile-factor").value, ""); assert.match(p.el("profile-status").textContent, /Check the current phone connection/);
  const html = fs.readFileSync(__dirname + "/conversation.html", "utf8"); assert.match(html, /id="profile-retained-consent" type="checkbox">/); assert.match(html, /id="profile-compared" type="checkbox">/);
});
test("clear during a held proposal cannot publish its late public artifact or reopen approval", async () => {
  const p = page(); let release; p.hold(new Promise(resolve => release = resolve));
  const pending = p.click("profile-begin"); await Promise.resolve(); await p.click("clear"); release(); await pending;
  assert.equal(p.urls.length, 0); assert.equal(p.el("profile-artifacts").children.length, 0); assert.equal(p.el("profile-reserve").disabled, true);
});
test("saved attempt selection stays open while a changed owner identity closes setup", async () => {
  const p = page(); await p.click("profile-find"); assert.equal(p.el("profile-openings").children.length, 1);
  p.el("profile-openings").value = "synthetic-original"; p.input("profile-openings"); assert.equal(p.state().closed, false);
  await p.click("profile-recover"); assert.match(p.el("profile-status").textContent, /Check its status/);
  p.input("owner-account"); assert.equal(p.state().closed, true); assert.equal(p.el("profile-check").disabled, true);
});
