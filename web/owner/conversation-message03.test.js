// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), { fixture } = require("./interval03-test-fixture.cjs");
const { load } = require("./message03-test-fixture.cjs");
const factors = () => ({ password: "synthetic", factor: "synthetic" });
async function setup(extra = () => ({})) {
  const f = await fixture(), intent = await load("reviewed-intent03"), sent = [], receipts = new Map();
  const transport = async (url, options) => {
    const route = new URL(url).pathname;
    if (!route.startsWith("/v1/owner/conversation/send03")) return f.fetch(url, options);
    const body = JSON.parse(options.body); sent.push({ route, body });
    if (route.endsWith("/status")) {
      if (!receipts.has(body.message_id)) return new Response(JSON.stringify({ error: "not_found" }), { status: 404, headers: { "content-type": "application/json" } });
      return new Response(JSON.stringify(receipts.get(body.message_id)), { headers: { "content-type": "application/json" } });
    }
    const fields = intent.decodeReviewedIntent03V2(Uint8Array.from(Buffer.from(body.reviewed_intent, "base64url"))), b64 = f.helpers.b64, sha = f.helpers.sha;
    const receipt = { v: 1, message_id: f.helpers.text(fields.messageId), interval_id: f.helpers.text(fields.intervalId), accepted_ms: String(fields.reviewIssuedMs),
      expires_ms: String(fields.messageExpiresMs), selection_epoch: String(fields.accountSelectionEpoch), sms_ceiling: fields.smsCeiling,
      envelope_sha256: b64(await sha(Uint8Array.from(Buffer.from(body.envelope, "base64url")))), reviewed_intent_sha256: b64(await sha(Uint8Array.from(Buffer.from(body.reviewed_intent, "base64url")))),
      reviewed_signature_sha256: b64(await sha(Uint8Array.from(Buffer.from(body.reviewed_signature, "base64url")))) };
    receipts.set(receipt.message_id, receipt); await f.beforeSend?.();
    return new Response(JSON.stringify(receipt), { status: 201, headers: { "content-type": "application/json" } });
  };
  const { c } = await f.create({ fetch: transport, ...extra(f) });
  await c.begin({ durationMs: 60000 }); await c.review({ disclosure: true }); await c.request(factors()); await f.activate(); await c.check();
  return { f, c, sent, receipts, transport, close: f.close };
}
function instrument(run) {
  const native = crypto.subtle.sign.bind(crypto.subtle), descriptor = Object.getOwnPropertyDescriptor(crypto.subtle, "sign");
  Object.defineProperty(crypto.subtle, "sign", { configurable: true, value: async (...args) => { await run(args); return native(...args); } });
  return () => { if (descriptor) Object.defineProperty(crypto.subtle, "sign", descriptor); else delete crypto.subtle.sign; };
}
test("actual installed consent drives review, both separately burned signatures and one exact ordinary submission", async () => {
  const p = await setup(() => ({})); let release; try {
    const { c, f, sent } = p; assert.equal(c.state().verifiedActive, true); await c.reviewMessage({ content: "  Synthetic exact text\n", smsCeiling: 2 });
    assert.equal(c.state().messageReview.content, "  Synthetic exact text\n"); assert.equal(sent.length, 0); assert.equal((await f.readMessages()).attempts.length, 0);
    const signing = [];
    release = instrument(async args => {
      const prefix = new TextDecoder().decode(new Uint8Array(args[2]).slice(0, 40));
      if (prefix.startsWith("ZTSE/sign/v3\0")) { signing.push("envelope"); assert.equal((await f.readMessages()).attempts.at(0).stage, "envelope_sign_reserved"); }
      if (prefix.startsWith("zrotext/conversation/reviewed-send03/v2")) { signing.push("intent"); assert.equal((await f.readMessages()).attempts.at(0).stage, "intent_sign_reserved"); }
    });
    f.beforeSend = async () => assert.equal((await f.readMessages()).attempts.at(0).stage, "submit_reserved");
    const first = c.confirmMessage(); await assert.rejects(async () => c.confirmMessage()); await first;
    assert.equal(signing.filter(v => v === "envelope").length, 1); assert.equal(signing.length, 2); assert.equal(sent.length, 1);
    assert.equal(c.state().messagePhase, "accepted"); assert.equal(c.state().messageReview, null);
    const saved = (await f.readMessages()).attempts.at(0); assert.equal(saved.stage, "accepted"); assert.equal(saved.receipt.sms_ceiling, 2);
    assert.equal(JSON.stringify(saved).includes("Synthetic exact text"), false); assert.equal(JSON.stringify(sent).includes("Synthetic exact text"), false);
  } finally { release?.(); p.close(); }
});
test("a lost submission response survives reload and later same-user login as passive status only", async () => {
  const p = await setup(() => ({})); try {
    p.f.beforeSend = async () => { throw Error("Synthetic response lost after acceptance"); };
    await p.c.reviewMessage({ content: "Synthetic lost response", smsCeiling: 1 }); await assert.rejects(p.c.confirmMessage());
    const original = (await p.f.readMessages()).attempts.at(0); assert.equal(original.stage, "submit_reserved"); assert.equal(p.sent.length, 1);
    p.c.close(); p.f.sessionId = crypto.randomUUID(); const cold = (await p.f.create({ fetch: p.transport })).c;
    await assert.rejects(async () => cold.confirmMessage()); await assert.rejects(cold.reviewMessage({ content: "Do not silently replace", smsCeiling: 1 }));
    const history = await cold.messageHistory(); assert.deepEqual(history.attempts, [original]); assert.equal(p.sent.length, 1);
    await cold.checkMessage(original.message_id); assert.equal(p.sent.at(-1).route, "/v1/owner/conversation/send03/status");
    assert.equal((await p.f.readMessages()).attempts.at(0).stage, "accepted"); assert.equal(p.sent.filter(v => !v.route.endsWith("/status")).length, 1);
  } finally { p.close(); }
});
test("every failed durable burn prevents its corresponding effect and never retries on another confirm", async () => {
  for (const stage of ["envelope_sign_reserved", "intent_sign_reserved", "submit_reserved"]) {
    let fail = false;
    const p = await setup(f => ({ openMessageRecovery: async o => { const j = await f.openMessages(o); return { ...j, compareAndSet: (a, b) => {
      if (fail && b.stage === stage) return Promise.reject(Error("Synthetic durable burn refused")); return j.compareAndSet(a, b);
    } }; } })); let release; try {
      await p.c.reviewMessage({ content: "Synthetic burn interruption", smsCeiling: 1 }); fail = true; const signing = [];
      release = instrument(args => { const prefix = new TextDecoder().decode(new Uint8Array(args[2]).slice(0, 40)); if (prefix.startsWith("ZTSE/sign/v3\0") || prefix.startsWith("zrotext/conversation/reviewed-send03/v2")) signing.push(prefix); });
      await assert.rejects(p.c.confirmMessage()); await assert.rejects(async () => p.c.confirmMessage());
      assert.equal(signing.length, stage === "envelope_sign_reserved" ? 0 : stage === "intent_sign_reserved" ? 1 : 2); assert.equal(p.sent.length, 0);
    } finally { release?.(); p.close(); }
  }
});
test("Stop during a signing wait immediately withdraws RAM approval and suppresses later signing and HTTP", async () => {
  const p = await setup(() => ({})); let release; try {
    await p.c.reviewMessage({ content: "Synthetic Stop interruption", smsCeiling: 1 });
    let entered, resume; const enteredPromise = new Promise(r => { entered = r; }), waiting = new Promise(r => { resume = r; });
    release = instrument(async args => { if (new TextDecoder().decode(new Uint8Array(args[2]).slice(0, 13)).startsWith("ZTSE/sign/v3")) { entered(); await waiting; } });
    const confirm = p.c.confirmMessage(); await enteredPromise; const stopped = p.c.stop(); assert.equal(p.c.state().messageReview, null); assert.equal(p.c.state().verifiedActive, false);
    resume(); await assert.rejects(confirm); await stopped; assert.equal(p.sent.length, 0);
    const original = (await p.f.readMessages()).attempts.at(0); assert.equal(original.stage, "envelope_sign_reserved");
    await assert.rejects(async () => p.c.confirmMessage());
  } finally { release?.(); p.close(); }
});
test("a review that expires, is edited, or loses a current physical comparison cannot sign", async () => {
  for (const mode of ["expired", "edited", "physical"]) {
    const p = await setup(() => ({})); let release; try {
      await p.c.reviewMessage({ content: "Synthetic original review", smsCeiling: 1 }); let signed = 0;
      release = instrument(args => { if (new TextDecoder().decode(new Uint8Array(args[2]).slice(0, 13)).startsWith("ZTSE/sign/v3")) signed++; });
      if (mode === "expired") p.f.mono += 30000; else if (mode === "edited") p.c.cancelMessage();
      else p.f.mutateContext = v => ({ ...v, physical_selection_digest: p.f.helpers.b64(new Uint8Array(32).fill(9)) });
      await assert.rejects(async () => p.c.confirmMessage()); assert.equal(signed, 0); assert.equal(p.sent.length, 0);
    } finally { release?.(); p.close(); }
  }
});
test("not-found status keeps the original uncertainty and cannot enable another submit", async () => {
  const p = await setup(() => ({})); try {
    p.f.beforeSend = async () => { throw Error("Synthetic lost response"); };
    await p.c.reviewMessage({ content: "Synthetic missing receipt", smsCeiling: 1 }); await assert.rejects(p.c.confirmMessage());
    const original = (await p.f.readMessages()).attempts.at(0); p.receipts.clear();
    await assert.rejects(p.c.checkMessage(original.message_id)); assert.deepEqual((await p.f.readMessages()).attempts.at(0), original);
    await assert.rejects(async () => p.c.confirmMessage()); assert.equal(p.sent.filter(v => !v.route.endsWith("/status")).length, 1);
  } finally { p.close(); }
});
