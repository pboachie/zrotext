// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), vm = require("node:vm");
function page() {
  const elements = new Map(), calls = []; let closed = false, durable = false, version = null, phase = "unprepared", onClose;
  function el(id) { if (!elements.has(id)) elements.set(id, { checked: false, value: "", files: [{}], disabled: false, listeners: {}, addEventListener(k, fn) { this.listeners[k] = fn; } }); return elements.get(id); }
  const c = { state: () => ({ closed, durable, version, phase }), onClose: fn => { onClose = fn; },
    close() { closed = true; phase = "closed"; onClose?.(); },
    async open() { calls.push("open"); phase = "reading_history"; version = "2"; },
    async next() { calls.push("next"); durable = true; version = "3"; phase = "verified_history"; },
    async current() { calls.push("current"); phase = "current_selection"; } };
  vm.runInNewContext(fs.readFileSync(__dirname + "/conversation-manifest03-page.js", "utf8"), {
    document: { getElementById: el }, window: { addEventListener() {} }, ZtManifest03History: { create(options) { calls.push(options.readSelection()); closed = false; durable = false; version = null; phase = "unprepared"; return c; } },
  });
  return { calls, el, click: id => el(id).listeners.click(), input: id => el("owner-setup").listeners.input({ target: { id } }) };
}
test("actual history page keeps independent decisions unchecked and requires explicit page and current reads", async () => {
  const p = page(); assert.deepEqual(p.calls, []); assert.equal(p.el("profile-history-next").disabled, true); assert.equal(p.el("profile-history-current").disabled, true);
  await p.click("profile-history-open"); assert.equal(p.calls[0].compared, false); assert.equal(p.calls[0].retentionConsent, false);
  assert.deepEqual(p.calls.slice(1), ["open"]); assert.equal(p.el("profile-history-current").disabled, true);
  await p.click("profile-history-next"); assert.deepEqual(p.calls.slice(1), ["open", "next"]);
  assert.equal(p.el("profile-history-current").disabled, false); await p.click("profile-history-current");
  assert.match(p.el("profile-history-status").textContent, /consent remain separate/);
});
test("changed selection and explicit close withdraw history controls without starting another setup", async () => {
  const p = page(); await p.click("profile-history-open"); p.input("owner-account");
  assert.equal(p.el("profile-history-next").disabled, true); assert.equal(p.el("profile-history-current").disabled, true);
  assert.deepEqual(p.calls.slice(1), ["open"]); await p.click("clear"); assert.match(p.el("profile-history-status").textContent, /checkpoint remains/);
});
