// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), { mount } = require("./conversation-message-key03-page.js");
function fixture() {
  const elements = new Map(), calls = []; let closed = false, phase = "key_selected", saved = false, original = false, receipt = false, onClose;
  const el = id => { if (!elements.has(id)) elements.set(id, { value: "", checked: false, files: [{}], hidden: false, disabled: false, events: {}, addEventListener(k, fn) { this.events[k] = fn; }, replaceChildren() {}, append() {} }); return elements.get(id); };
  const controller = { state: () => ({ phase, closed, hasProposal: saved, hasOriginal: original, hasReceipt: receipt }), onClose: fn => { onClose = fn; }, close() { closed = true; phase = "closed"; onClose?.(); },
    async open() { calls.push("open"); }, async prepare(d) { calls.push(d); saved = true; phase = "awaiting_offline_approval"; return { proposal: new Uint8Array([1]) }; },
    async authorize() { original = true; phase = "ready_install"; }, async install(f) { calls.push(f); receipt = true; phase = "saved_accepted"; } };
  mount({ getHistory: () => ({ state: () => ({ durable: true, busy: false }) }), document: { getElementById: el, createElement: () => ({}) }, window: { addEventListener() {} },
    create() { closed = false; phase = "key_selected"; return controller; }, url: { createObjectURL: () => "blob:synthetic", revokeObjectURL() {} }, Blob });
  return { el, calls, click: id => el(id).events.click() };
}
test("page starts without actions or retention consent and shows only the current approval step", async () => {
  const p = fixture(); assert.deepEqual(p.calls, []); assert.equal(p.el("message-retain").checked, false); assert.equal(p.el("message-install").hidden, true);
  await p.click("message-open"); p.el("message-operation").value = "enroll"; await p.click("message-prepare");
  assert.deepEqual(p.calls[1], { operation: "enroll", retain: false, newKey: false });
  assert.equal(p.el("message-prepare").hidden, true); assert.equal(p.el("message-authorize").hidden, false);
});
test("approval factors clear from the page before the explicit install call and are never used for status automatically", async () => {
  const p = fixture(); await p.click("message-open"); await p.click("message-prepare"); await p.click("message-authorize");
  p.el("message-password").value = "synthetic-password"; p.el("message-factor").value = "123456"; await p.click("message-install");
  assert.deepEqual(p.calls.at(-1), { password: "synthetic-password", factor: "123456" });
  assert.equal(p.el("message-password").value, ""); assert.equal(p.el("message-factor").value, ""); assert.equal(p.el("message-install").hidden, true);
  assert.equal(p.el("message-confirm").hidden, false); assert.match(p.el("message-status").textContent, /complete saved history/);
});
