// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const { fixture, load } = require("./message03-test-fixture.cjs"), recovery = require("./conversation-message03-recovery.js");
async function setup() {
  const f = await fixture(), connections = [], name = "message-recovery-test-" + crypto.randomUUID(), abort = new AbortController();
  const open = async (extra = {}) => { const j = await recovery.open({ scope: f.scope, signal: abort.signal, currentOrigin: () => f.scope.origin, name, importSdk: load, ...extra }); connections.push(j); return j; };
  return { ...f, open, abort, close: () => connections.forEach(j => j.close()) };
}
async function advance(j, p, stop = "accepted") {
  let before = null;
  for (const k of ["first", "signed", "intentReserved", "complete", "submitted", "accepted"]) { before = await j.compareAndSet(before, p[k]); if (p[k].stage === stop) break; }
  return before;
}
test("genuine ciphertext and both signatures progress through durable one-way markers with no plaintext or credential fields", async () => {
  const f = await setup(); try {
    const j = await f.open(), p = await f.make(), actual = await advance(j, p);
    assert.deepEqual(actual, p.accepted); assert(Object.isFrozen(actual.receipt));
    assert.equal(JSON.stringify(actual).includes(p.content), false);
    for (const changes of [{ content: p.content }, { password: "synthetic" }, { privateKey: {} }, { cek: new Uint8Array(32) }])
      await assert.rejects(j.compareAndSet(actual, { ...actual, ...changes }));
    assert.deepEqual(await j.read(p.first.message_id), actual);
  } finally { f.close(); }
});
test("every interrupted stage survives a new connection without any signature or network operation", async () => {
  const f = await setup(); try {
    const j = await f.open(), p = await f.make(); let before = null;
    for (const stage of [p.first, p.signed, p.intentReserved, p.complete, p.submitted, p.accepted]) {
      before = await j.compareAndSet(before, stage); const cold = await f.open();
      assert.deepEqual(await cold.read(stage.message_id), stage); cold.close();
    }
    const cold = await f.open(); await assert.rejects(cold.compareAndSet(null, p.first));
    assert.deepEqual(await cold.read(p.first.message_id), p.accepted);
  } finally { f.close(); }
});
test("two actual IndexedDB connections cannot both advance the same signing reservation", async () => {
  const f = await setup(); try {
    const a = await f.open(), b = await f.open(), p = await f.make(); await a.compareAndSet(null, p.first);
    const results = await Promise.allSettled([a.compareAndSet(p.first, p.signed), b.compareAndSet(p.first, p.signed)]);
    assert.equal(results.filter(r => r.status === "fulfilled").length, 1); assert.equal(results.filter(r => r.status === "rejected").length, 1);
    assert.deepEqual(await b.read(p.first.message_id), p.signed);
    await assert.rejects(b.compareAndSet(p.first, p.signed));
  } finally { f.close(); }
});
test("signature and submission stages cannot be skipped, reset, reopened or replaced", async () => {
  const f = await setup(); try {
    const j = await f.open(), p = await f.make(); await j.compareAndSet(null, p.first);
    await assert.rejects(j.compareAndSet(p.first, p.complete));
    const closed = await j.compareAndSet(p.first, { ...p.first, closed: true });
    await assert.rejects(j.compareAndSet(closed, { ...p.signed, closed: true }));
    await assert.rejects(j.compareAndSet(closed, p.first));
    const other = await f.make(); await assert.rejects(j.compareAndSet(closed, { ...other.first, closed: true }));
    await assert.rejects(j.compareAndSet(null, p.complete)); assert.deepEqual(await j.read(p.first.message_id), closed);
  } finally { f.close(); }
});
test("one unresolved original submission fences another tab until an exact receipt is retained", async () => {
  const f = await setup(); try {
    const a = await f.open(), b = await f.open(), first = await f.make(), second = await f.make();
    let original = await advance(a, first, "submit_reserved"), next = await advance(b, second, "intent_signed");
    assert.equal(await a.hasUnresolvedSubmission(), true); await assert.rejects(b.compareAndSet(next, second.submitted));
    assert.deepEqual(await b.read(second.first.message_id), second.complete);
    original = await a.compareAndSet(original, first.accepted); assert.equal(await b.hasUnresolvedSubmission(), false);
    next = await b.compareAndSet(next, second.submitted); assert.equal(await a.hasUnresolvedSubmission(), true);
    assert.deepEqual(await a.read(first.first.message_id), original); assert.deepEqual(await b.read(second.first.message_id), next);
  } finally { f.close(); }
});
test("exact transport records are saved before HTTP and an ambiguous response only permits passive reconciliation", async () => {
  const f = await setup(); try {
    const j = await f.open(), p = await f.make(); let saved = await advance(j, p, "intent_signed"), calls = 0;
    const options = { origin: f.scope.origin, accountId: f.scope.accountId, userId: f.scope.originalUserId, ownerSessionId: p.first.owner_session_id,
      deviceId: f.scope.deviceId, lineId: f.scope.lineId, rootFingerprint: Uint8Array.from(Buffer.from(f.scope.rootFingerprint, "hex")), signal: f.abort.signal,
      currentCsrf: () => "ztc_" + Buffer.alloc(32, 1).toString("base64url"), nowMs: () => f.present,
      saveBeforeSubmit: async r => { assert.deepEqual(r, j.recovery(saved)); saved = await j.compareAndSet(saved, { ...saved, stage: "submit_reserved" }); },
      fetchImpl: async () => { calls++; assert.equal((await j.read(saved.message_id)).stage, "submit_reserved"); throw Error("Synthetic lost response"); } };
    const client = new f.sdk.OwnerReviewedSendClient03(options); await assert.rejects(client.send(p.proof)); assert.equal(calls, 1);
    await assert.rejects(client.send(p.proof)); assert.equal(calls, 1);
    const cold = await f.open(), original = await cold.read(saved.message_id); assert.deepEqual(original, p.submitted);
    const status = new f.sdk.OwnerReviewedSendClient03({ ...options, ownerSessionId: crypto.randomUUID(), nowMs: () => { throw Error("No live clock for passive reads"); },
      saveBeforeSubmit: async () => { throw Error("No submission during passive reads"); }, fetchImpl: async (url, o) => {
        calls++; assert(url.endsWith("/send03/status")); assert.equal(JSON.parse(o.body).message_id, original.message_id);
        return new Response(JSON.stringify(p.accepted.receipt), { headers: { "content-type": "application/json" } });
      } });
    const receipt = await status.status(cold.recovery(original)); assert.equal(calls, 2);
    const withdrawn = await cold.compareAndSet(original, { ...original, closed: true });
    assert.deepEqual(await cold.compareAndSet(withdrawn, { ...withdrawn, stage: "accepted", receipt }), { ...p.accepted, closed: true });
  } finally { f.close(); }
});
test("an aborted real IndexedDB write cannot publish a signing burn or permit HTTP", async () => {
  const f = await setup(); try {
    const j = await f.open(), p = await f.make(); let before = await advance(j, p, "intent_signed"), http = 0;
    const put = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function (...args) { const request = Reflect.apply(put, this, args); this.transaction.abort(); return request; };
    try {
      await assert.rejects((async () => { before = await j.compareAndSet(before, p.submitted); http++; })());
    } finally { IDBObjectStore.prototype.put = put; }
    assert.equal(http, 0); assert.deepEqual(await j.read(p.first.message_id), p.complete);
  } finally { f.close(); }
});
test("captured descriptors and nested receipts are owned before async crypto waits", async () => {
  const f = await setup(); try {
    const j = await f.open(), p = await f.make(); let gets = 0;
    const proxied = new Proxy(p.first, { get() { gets++; throw Error("No getter reads"); } });
    assert.deepEqual(await j.compareAndSet(null, proxied), p.first); assert.equal(gets, 0);
    let before = p.first; for (const k of ["signed", "intentReserved", "complete", "submitted"]) before = await j.compareAndSet(before, p[k]);
    const candidate = structuredClone(p.accepted), pending = j.compareAndSet(before, candidate); candidate.receipt.sms_ceiling = 6;
    assert.equal((await pending).receipt.sms_ceiling, 2);
  } finally { f.close(); }
});
test("cross-owner packets, changed ciphertext, different original identities and forged receipt commitments are refused", async () => {
  const f = await setup(); try {
    const j = await f.open(), p = await f.make(), other = await f.make();
    let before = await j.compareAndSet(null, p.first);
    await assert.rejects(j.compareAndSet(before, { ...p.signed, envelope: other.signed.envelope }));
    before = await j.compareAndSet(before, p.signed);
    for (const change of [{ reviewed_intent: other.intentReserved.reviewed_intent }, { owner_session_id: crypto.randomUUID() }, { interval_id: crypto.randomUUID() }])
      await assert.rejects(j.compareAndSet(before, { ...p.intentReserved, ...change }));
    before = await j.compareAndSet(before, p.intentReserved); before = await j.compareAndSet(before, p.complete); before = await j.compareAndSet(before, p.submitted);
    for (const change of [{ envelope_sha256: Buffer.alloc(32, 4).toString("base64url") }, { accepted_ms: "35000" }, { sms_ceiling: 3 }, { selection_epoch: "2" }])
      await assert.rejects(j.compareAndSet(before, { ...p.accepted, receipt: { ...p.accepted.receipt, ...change } }));
    assert.deepEqual(await j.read(before.message_id), p.submitted);
    const otherScope = await f.open({ scope: { ...f.scope, originalUserId: crypto.randomUUID() } });
    assert.equal(await otherScope.read(before.message_id), null); await assert.rejects(otherScope.compareAndSet(null, p.complete));
  } finally { f.close(); }
});
test("origin change and withdrawal during verification prevent a late write", async () => {
  for (const mode of ["origin", "abort"]) {
    const f = await setup(); try {
      let origin = f.scope.origin; const j = await f.open({ currentOrigin: () => origin }), p = await f.make();
      const before = await j.compareAndSet(null, p.first), pending = j.compareAndSet(before, p.signed);
      if (mode === "abort") f.abort.abort(); else origin = "https://other.example";
      await assert.rejects(pending);
      const cold = await f.open({ signal: undefined }); assert.deepEqual(await cold.read(p.first.message_id), p.first);
    } finally { f.close(); }
  }
});
test("bounded per-scope pages preserve more than128 original attempts without a lifetime cap", async () => {
  const f = await setup(); try {
    const j = await f.open(), originals = new Map();
    for (let i = 0; i < 130; i++) {
      const p = await f.make(); let r = await j.compareAndSet(null, p.first); r = await j.compareAndSet(r, { ...r, closed: true }); originals.set(r.message_id, r);
    }
    let afterMessageId = null; const seen = new Set();
    do {
      const page = await j.page({ afterMessageId, limit: 13 }); assert(page.attempts.length <= 13);
      for (const r of page.attempts) { assert.deepEqual(r, originals.get(r.message_id)); assert(!seen.has(r.message_id)); seen.add(r.message_id); }
      afterMessageId = page.nextMessageId;
    } while (afterMessageId !== null);
    assert.equal(seen.size, 130); await assert.rejects(j.page({ afterMessageId: null, limit: 17 }));
    const other = await f.open({ scope: { ...f.scope, originalUserId: crypto.randomUUID() } }); assert.deepEqual((await other.page()).attempts, []);
  } finally { f.close(); }
});
