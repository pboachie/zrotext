// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");
const { mount } = require("./conversation-interval03-page.js");
function fixture() {
  const elements = new Map(), calls = []; let onClose, s = { phase: "ready", closed: false, reconciled: false, originalSaved: false, hasReceipt: false };
  const el = id => { if (!elements.has(id)) elements.set(id, { value: "", checked: false, hidden: false, disabled: false, events: {}, addEventListener(k, fn) { this.events[k] = fn; },
    replaceChildren() { this.value = ""; }, append(option) { if (!this.value) this.value = option.value; } }); return elements.get(id); };
  const controller = { state: () => s, onClose(fn) { onClose = fn; }, close() { s = { ...s, closed: true, phase: "closed" }; onClose?.(); }, async open() { calls.push("open"); },
    async begin(v) { calls.push(v); s = { ...s, phase: "reserved", reconciled: true, hasReceipt: true, reserveSubmitted: true }; },
    async review(v) { calls.push(v); s = { ...s, phase: "signed_request", originalSaved: true }; },
    async request(v) { assert.equal(el("interval-password").value, ""); assert.equal(el("interval-factor").value, ""); calls.push(v); s = { ...s, phase: "requested" }; },
    async stop() { calls.push("stop"); s = { ...s, phase: "stopping", verifiedActive: false }; }, async check() { calls.push("check"); } };
  mount({ getHistory: () => ({ state: () => ({ durable: true, busy: false }) }), document: { getElementById: el, createElement: () => ({}) }, window: { addEventListener() {} },
    discover: async () => ({ archives: [{ keyId: "01".repeat(32) }], phones: [{ keyId: "02".repeat(32) }] }), create(o) { s.closed = false; calls.push(o.readSelection()); return controller; } });
  el("owner-peer").value = "+12"; el("interval-duration").value = "300000";
  return { el, calls, click: id => el(id).events.click() };
}
test("conversation page performs no automatic setup and fills already approved key choices", async () => {
  const f = fixture(); assert.deepEqual(f.calls, []); assert.equal(f.el("interval-retain").checked, false); assert.equal(f.el("interval-request").hidden, true);
  f.el("interval-retain").checked = true; await f.click("interval-open"); assert.equal(f.calls[0].archiveReaderKeyId, "01".repeat(32));
  assert.equal(f.calls[0].phoneSignerKeyId, "02".repeat(32)); await f.click("interval-begin"); assert.deepEqual(f.calls.at(-1), { durationMs: 300000 });
  assert.equal(f.el("interval-review").hidden, false); assert.equal(f.el("interval-request").hidden, true);
});
test("exact consent remains explicit and factors clear before its only request call", async () => {
  const f = fixture(); await f.click("interval-open"); await f.click("interval-begin"); f.el("interval-disclosure").checked = true; await f.click("interval-review");
  assert.deepEqual(f.calls.at(-1), { disclosure: true });
  f.el("interval-password").value = "synthetic-password"; f.el("interval-factor").value = "synthetic-factor"; await f.click("interval-request");
  assert.deepEqual(f.calls.at(-1), { password: "synthetic-password", factor: "synthetic-factor" }); assert.equal(f.el("interval-request").hidden, true);
  await f.click("interval-stop"); assert.equal(f.calls.at(-1), "stop"); assert.match(f.el("interval-status").textContent, /withdrawn/);
  assert.equal(f.calls.filter(v => v === "check").length, 0);
});
test("shipping page includes the exact codec disclosure and fixed packaged setup assets", async () => {
  const html = fs.readFileSync(path.join(__dirname, "conversation.html"), "utf8"), codec = await import("../../sdk/typescript/dist/conversation-interval03.js");
  assert(html.includes(codec.conversationDisclosure03));
  for (const file of ["conversation-interval03-recovery.js", "conversation-interval03.js", "conversation-interval03-page.js"]) {
    assert(html.includes(`src="${file}"`)); assert(fs.readFileSync(path.join(__dirname, "../../crates/server/src/owner_ui.rs"), "utf8").includes(`include_str!("../../../web/owner/${file}")`));
  }
});
