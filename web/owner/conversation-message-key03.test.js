// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const { fixture } = require("./message-key03-test-fixture.cjs");
const decision = { operation: "enroll", retain: true, newKey: true };
test("actual four-role history creates retained role05 only after explicit consent and saves proposal before offline handoff", async () => {
  const f = await fixture(); try {
    const { c, hc } = await f.create(); assert.equal(c.state().keyId, null);
    await assert.rejects(c.prepare({ operation: "enroll" })); assert.equal(c.state().keyId, null);
    const p = await c.prepare(decision), keyId = c.state().keyId; assert.equal(p.keyId, keyId);
    const file = await f.signedOutput(p.proposal); await c.authorize(file); assert.equal(c.state().phase, "ready_install");
    await c.install({ password: "synthetic-password", factor: "123456" }); assert.equal(c.state().phase, "saved_accepted"); assert.equal(c.state().confirmed, false);
    await c.confirm(); assert.equal(hc.state().durable, false); await hc.next(); await c.confirm();
    assert.equal(c.state().phase, "confirmed"); assert.equal(c.state().keyId, keyId); assert.equal(f.installCount, 1);
    assert.equal(f.calls.filter(v => v.route.endsWith("/manifests"))[0].body.password, "synthetic-password");
    // Successful local enrollment is not a conversation-content or SMS action.
    assert.equal(f.calls.some(v => /message|dispatch|consent/.test(v.route)), false);
  } finally { f.close(); }
});
test("fresh sign-in reconciles an accepted lost response with the same original key and no repeated install", async () => {
  const f = await fixture(); try {
    let { c, hc } = await f.create(); const p = await c.prepare(decision), keyId = c.state().keyId;
    await c.authorize(await f.signedOutput(p.proposal)); f.loseResponse = true;
    await assert.rejects(c.install({ password: "synthetic-password", factor: "123456" })); assert.equal(c.state().phase, "unknown");
    await assert.rejects(c.prepare(decision)); await assert.rejects(c.install({ password: "synthetic-password", factor: "123456" }));
    c.close(); hc.close(); f.sessionId = crypto.randomUUID(); ({ c, hc } = await f.create());
    assert.equal(c.state().keyId, keyId); await assert.rejects(c.confirm());
    await c.recoverHistory(); await hc.next(); await c.check(); await c.confirm(); await hc.next(); await c.confirm();
    assert.equal(c.state().confirmed, true); assert.equal(f.installCount, 1);
    const status = f.calls.filter(v => v.route.endsWith("/manifests/status")); assert.equal(status.length, 1);
    assert.equal("password" in status[0].body || "factor" in status[0].body, false);
  } finally { f.close(); }
});
test("public proposal survives page closure and resumes without a new key or root proposal", async () => {
  const f = await fixture(); try {
    let { c, hc } = await f.create(); const p = await c.prepare(decision), id = c.state().keyId; c.close(); hc.close();
    ({ c, hc } = await f.create()); const again = await c.resumeProposal();
    assert.deepEqual(again.proposal, p.proposal); assert.equal(c.state().keyId, id); assert.equal(f.installCount, 0);
    await c.authorize(await f.signedOutput(p.proposal)); assert.equal(c.state().phase, "ready_install");
  } finally { f.close(); }
});
test("failed durable proposal commit exposes no artifact or network mutation and retains key custody", async () => {
  const f = await fixture(); try {
    const { c } = await f.create({ openRecovery: async options => { const real = await f.openAttempts(options); return { ...real, compareAndSet: async () => { throw Error("Synthetic write failure"); } }; } });
    await assert.rejects(c.prepare(decision)); assert.match(c.state().keyId, /^[a-f0-9]{64}$/); assert.equal(f.installCount, 0);
    await assert.rejects(c.authorize({ size: 400, arrayBuffer: async () => new ArrayBuffer(400) }));
  } finally { f.close(); }
});
test("closing before submission resumes the same saved possession approval without another signature", async () => {
  const f = await fixture(); try {
    let { c, hc } = await f.create(); const p = await c.prepare(decision); await c.authorize(await f.signedOutput(p.proposal));
    const opening = c.state().openingId; c.close(); hc.close(); ({ c, hc } = await f.create());
    await c.resumeInstall(); assert.equal(c.state().openingId, opening); assert.equal(c.state().phase, "ready_install");
    await c.install({ password: "synthetic-password", factor: "123456" }); assert.equal(f.installCount, 1); assert.equal(c.state().openingId, opening);
  } finally { f.close(); }
});
test("failed local acceptance commit preserves UNKNOWN and blocks resubmission", async () => {
  const f = await fixture(); try {
    const { c } = await f.create({ openRecovery: async options => { const real = await f.openAttempts(options); return { ...real, compareAndSet: async (before, after) => { if (after.receipt) throw Error("Synthetic acceptance write failure"); return real.compareAndSet(before, after); } }; } });
    const p = await c.prepare(decision); await c.authorize(await f.signedOutput(p.proposal));
    await assert.rejects(c.install({ password: "synthetic-password", factor: "123456" })); assert.equal(c.state().phase, "unknown");
    await assert.rejects(c.install({ password: "synthetic-password", factor: "123456" })); assert.equal(f.installCount, 1);
  } finally { f.close(); }
});
test("wrong returned root artifact and hidden page refuse possession admission", async () => {
  const f = await fixture(); try {
    const { c } = await f.create(), p = await c.prepare(decision), file = await f.signedOutput(p.proposal), raw = new Uint8Array(await file.arrayBuffer()); raw[raw.length - 1] ^= 1;
    await assert.rejects(c.authorize({ size: raw.length, arrayBuffer: async () => raw.buffer })); assert.equal(c.state().openingId, null);
    f.document.hidden = true; await assert.rejects(c.authorize(file)); assert.equal(c.state().closed, true); assert.equal(f.installCount, 0);
  } finally { f.close(); }
});
test("programmatic compared selection change withdraws setup before possession without relying on a DOM event", async () => {
  const f = await fixture(); try {
    const { c } = await f.create(), p = await c.prepare(decision), file = await f.signedOutput(p.proposal);
    f.selection.account_id = crypto.randomUUID(); await assert.rejects(c.authorize(file)); assert.equal(c.state().closed, true); assert.equal(f.installCount, 0);
  } finally { f.close(); }
});
test("a definite service refusal permits only an explicit retry of the same saved original with fresh factors", async () => {
  const f = await fixture(); try {
    const forward = f.fetch; let refusals = 1, requests = 0;
    f.fetch = async (url, options) => {
      if (new URL(url, f.origin).pathname.endsWith("/manifests")) { requests++; if (refusals-- > 0) return new Response(JSON.stringify({ error: "authentication_required" }), { status: 401, headers: { "content-type": "application/json" } }); }
      return forward(url, options);
    };
    const { c } = await f.create(), p = await c.prepare(decision); await c.authorize(await f.signedOutput(p.proposal)); const id = c.state().openingId;
    await assert.rejects(c.install({ password: "synthetic-password", factor: "123456" })); assert.equal(c.state().phase, "ready_install"); assert.equal(requests, 1); assert.equal(f.installCount, 0);
    await c.install({ password: "synthetic-password", factor: "234567" }); assert.equal(requests, 2); assert.equal(c.state().openingId, id); assert.equal(f.installCount, 1);
  } finally { f.close(); }
});
