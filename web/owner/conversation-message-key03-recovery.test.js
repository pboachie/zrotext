// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), { fixture } = require("./message-key03-test-fixture.cjs");
function scope(f) { const h = f.helpers; return { origin: f.origin, accountId: h.text(f.account), originalUserId: h.text(f.user), deviceId: h.text(f.device), lineId: h.text(f.line), rootFingerprint: Buffer.from(f.fingerprint).toString("hex") }; }
test("actual IndexedDB transaction abort preserves the original public proposal and excludes factors", async () => {
  const f = await fixture(); let journal; try {
    const { c } = await f.create(); await c.prepare({ operation: "enroll", retain: true, newKey: true }); journal = await f.openAttempts({ scope: scope(f), currentOrigin: () => f.origin });
    const before = await journal.read(); assert.equal(JSON.stringify(before).includes("password"), false);
    await assert.rejects(journal.compareAndSet(before, { ...before, password: "synthetic-password" }));
    const put = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function (...args) { const request = put.apply(this, args); this.transaction.abort(); return request; };
    try { await assert.rejects(journal.compareAndSet(before, { ...before, proposal: { ...before.proposal, packet: "AQ" } })); }
    finally { IDBObjectStore.prototype.put = put; }
    assert.deepEqual(await journal.read(), before);
  } finally { journal?.close(); f.close(); }
});
test("two real connections cannot replace an original attempt from a stale public snapshot", async () => {
  const f = await fixture(); let a, b; try {
    const { c } = await f.create(), p = await c.prepare({ operation: "enroll", retain: true, newKey: true });
    a = await f.openAttempts({ scope: scope(f), currentOrigin: () => f.origin }); b = await f.openAttempts({ scope: scope(f), currentOrigin: () => f.origin });
    const old = await b.read(); await c.authorize(await f.signedOutput(p.proposal)); const actual = await a.read();
    assert.notEqual(actual.original, null); await assert.rejects(b.compareAndSet(old, old)); assert.deepEqual(await b.read(), actual);
  } finally { a?.close(); b?.close(); f.close(); }
});
