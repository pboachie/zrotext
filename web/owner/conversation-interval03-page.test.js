// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), path = require("node:path");
const { mount } = require("./conversation-interval03-page.js");
function fixture() {
  const elements = new Map(), calls = []; let onClose, s = { phase: "ready", closed: false, reconciled: false, originalSaved: false, hasReceipt: false };
  const element = () => ({ value: "", checked: false, hidden: false, disabled: false, children: [], events: {}, addEventListener(k, fn) { this.events[k] = fn; },
    replaceChildren() { this.value = ""; this.children = []; }, append(option) { this.children.push(option); if (!this.value) this.value = option.value; } });
  const el = id => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
  const controller = { state: () => s, onClose(fn) { onClose = fn; }, close() { s = { ...s, closed: true, phase: "closed" }; onClose?.(); }, async open() { calls.push("open"); },
    async begin(v) { calls.push(v); s = { ...s, phase: "reserved", reconciled: true, hasReceipt: true, reserveSubmitted: true }; },
    async review(v) { calls.push(v); s = { ...s, phase: "signed_request", originalSaved: true }; },
    async request(v) { assert.equal(el("interval-password").value, ""); assert.equal(el("interval-factor").value, ""); calls.push(v); s = { ...s, phase: "requested" }; },
    async stop() { calls.push("stop"); s = { ...s, phase: "stopping", verifiedActive: false }; }, async check() { calls.push("check"); },
    async reviewMessage(v) { calls.push({ reviewMessage: v }); s = { ...s, messagePhase: "review", messageReview: { ...v, peer: "+12", expiresMs: "900000" } }; },
    async confirmMessage() { calls.push("confirmMessage"); s = { ...s, messagePhase: "accepted", messageReview: null }; },
    cancelMessage() { calls.push("cancelMessage"); s = { ...s, messagePhase: "canceled", messageReview: null }; },
    async messageHistory(v) { calls.push({ messageHistory: v }); return { attempts: [{ message_id: "synthetic-original", stage: "submit_reserved" }], nextMessageId: v.afterMessageId === null ? "synthetic-next" : null }; },
    async checkMessage(v) { calls.push({ checkMessage: v }); } };
  const ui = mount({ getHistory: () => ({ state: () => ({ durable: true, busy: false }) }), document: { getElementById: el, createElement: element }, window: { addEventListener() {} },
    discover: async () => ({ archives: [{ keyId: "01".repeat(32) }], phones: [{ keyId: "02".repeat(32) }] }), create(o) { s.closed = false; calls.push(o.readSelection()); return controller; } });
  el("owner-peer").value = "+12"; el("interval-duration").value = "300000";
  return { el, calls, click: id => el(id).events.click(), state: value => { s = { ...s, ...value }; ui.render(); } };
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
test("only proven expired unsent state offers a fresh explicit opening without resuming the expired command", async () => {
  const f = fixture(); await f.click("interval-open");
  f.state({ phase: "saved_attempt", openingId: "synthetic-opening", canPrepareFresh: true, reserveSubmitted: false, hasReceipt: false });
  assert.equal(f.el("interval-begin").hidden, false); assert.match(f.el("interval-begin").textContent, /fresh unsent/); assert.equal(f.el("interval-resume").hidden, true);
  f.state({ phase: "unknown", canPrepareFresh: false, reserveSubmitted: true }); assert.equal(f.el("interval-begin").hidden, true);
  assert.equal(f.calls.filter(v => v && typeof v === "object" && "durationMs" in v).length, 0);
});
test("message UI keeps exact text and SMS limit explicit, and editing withdraws the previous review", async () => {
  const f = fixture(); await f.click("interval-open"); assert.equal(f.el("interval-message-review").disabled, true);
  f.state({ verifiedActive: true }); f.el("interval-message-body").value = "  Synthetic exact text\n"; f.el("interval-message-ceiling").value = "2";
  await f.click("interval-message-review"); assert.deepEqual(f.calls.at(-1), { reviewMessage: { content: "  Synthetic exact text\n", smsCeiling: 2 } });
  assert.equal(f.el("interval-message-review-body").textContent, "  Synthetic exact text\n"); assert.match(f.el("interval-message-review-summary").textContent, /At most 2 SMS/);
  assert.equal(f.calls.includes("confirmMessage"), false); f.el("interval-message-body").events.input();
  assert.equal(f.calls.at(-1), "cancelMessage"); assert.equal(f.el("interval-message-confirmation").hidden, true);
  await f.click("interval-message-review"); await f.click("interval-message-confirm"); assert.equal(f.el("interval-message-body").value, "");
  assert.match(f.el("interval-message-status").textContent, /Carrier delivery is pending/);
});
test("saved attempts use explicit bounded pages and check the original ID without a send or new review", async () => {
  const f = fixture(); await f.click("interval-open"); assert.equal(f.calls.some(v => v?.messageHistory), false);
  await f.click("interval-message-history"); assert.deepEqual(f.calls.at(-1), { messageHistory: { afterMessageId: null, limit: 16 } });
  const row = f.el("interval-message-attempts").children.at(0); assert.match(row.children.at(0).textContent, /Outcome uncertain/);
  await row.children.at(1).events.click(); assert(f.calls.some(v => v?.checkMessage === "synthetic-original"));
  await f.click("interval-message-next"); assert.deepEqual(f.calls.at(-1), { messageHistory: { afterMessageId: "synthetic-next", limit: 16 } });
  assert.equal(f.el("interval-message-next").hidden, true); assert.equal(f.calls.includes("confirmMessage"), false); assert.equal(f.calls.some(v => v?.reviewMessage), false);
  f.state({ closed: true }); assert.deepEqual(f.el("interval-message-attempts").children, []); assert.equal(f.el("interval-message-review-body").textContent, "");
});
