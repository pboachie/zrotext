// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), path = require("node:path"), { createRequire } = require("node:module");
createRequire(path.join(__dirname, "../../sdk/typescript/package.json"))("fake-indexeddb/auto");
const recovery = require("./conversation-interval03-recovery.js");
const b64 = (n, v = 1) => Buffer.alloc(n, v).toString("base64url");
function fixture() {
  const name = "interval-recovery-test-" + crypto.randomUUID(), abort = new AbortController(), connections = [];
  const scope = { origin: "https://owner.example", accountId: crypto.randomUUID(), originalUserId: crypto.randomUUID(), deviceId: crypto.randomUUID(), lineId: crypto.randomUUID(), rootFingerprint: "01".repeat(32), peer: "+" + "123456789" };
  const make = () => ({ v: 1, owner_session_id: crypto.randomUUID(), command: { v: 1, opening_id: crypto.randomUUID(), line_id: scope.lineId, peer: scope.peer,
    archive_reader_key_id: b64(32, 1), phone_signer_key_id: b64(32, 2), browser_signer_key_id: b64(32, 3), interval_expires_ms: "900000", integration_readers: [] },
    original: null, receipt: null, reserve_submitted: false, request_submitted: false, stop_submitted: false });
  const receipt = (r, phase = "reserved") => ({ v: 1, opening_id: r.command.opening_id, interval_id: crypto.randomUUID(), receipt_id: crypto.randomUUID(), statement: b64(695),
    owner_signature: null, phone_signature: null, installed_signature: null, requested_ms: null, approved_ms: null, installed_ms: null, phase });
  const open = async (extra = {}) => { const j = await recovery.open({ scope, signal: abort.signal, currentOrigin: () => scope.origin, name, ...extra }); connections.push(j); return j; };
  return { scope, make, receipt, open, abort, close: () => connections.forEach(c => c.close()) };
}
test("committed consent recovery owns nested public commands and excludes all credential fields", async () => {
  const f = fixture(); try {
    const j = await f.open(), candidate = f.make(); candidate.command.integration_readers = [{ connector_id: crypto.randomUUID(), read_grant_id: crypto.randomUUID(), key_id: b64(32) }];
    const pending = j.compareAndSet(null, candidate); candidate.command.integration_readers[0].key_id = b64(32, 8);
    const actual = await pending; assert.equal(actual.command.integration_readers[0].key_id, b64(32)); assert(Object.isFrozen(actual.command.integration_readers[0]));
    await assert.rejects(j.compareAndSet(actual, { ...actual, password: "synthetic" }));
    await assert.rejects(j.compareAndSet(actual, { ...actual, command: { ...actual.command, privateKey: {} } }));
    assert.equal(JSON.stringify(await j.read()).includes("password"), false);
  } finally { f.close(); }
});
test("two actual IndexedDB connections refuse stale original snapshots", async () => {
  const f = fixture(); try {
    const a = await f.open(), b = await f.open(), original = await a.compareAndSet(null, f.make());
    const old = await b.read(), sent = await a.compareAndSet(original, { ...original, reserve_submitted: true });
    await assert.rejects(b.compareAndSet(old, { ...old, reserve_submitted: true })); assert.deepEqual(await b.read(), sent);
  } finally { f.close(); }
});
test("an actual transaction abort cannot publish a replacement head or lose the saved attempt", async () => {
  const f = fixture(); try {
    const j = await f.open(), first = await j.compareAndSet(null, f.make()), ended = await j.compareAndSet(first, { ...first, reserve_submitted: true, receipt: f.receipt(first, "expired") });
    const put = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function (...args) { const r = Reflect.apply(put, this, args); if (this.name === "heads") this.transaction.abort(); return r; };
    try { await assert.rejects(j.compareAndSet(ended, f.make())); } finally { IDBObjectStore.prototype.put = put; }
    assert.deepEqual(await j.read(), ended); assert.deepEqual((await j.page()).attempts, [ended]);
  } finally { f.close(); }
});
test("a new terminal replacement retains every original and cannot reuse a prior opening", async () => {
  const f = fixture(); try {
    const j = await f.open(), first = await j.compareAndSet(null, f.make());
    const ended = await j.compareAndSet(first, { ...first, reserve_submitted: true, receipt: f.receipt(first, "stopped") });
    const second = await j.compareAndSet(ended, f.make()); assert.equal((await j.page()).attempts.length, 2);
    const endSecond = await j.compareAndSet(second, { ...second, reserve_submitted: true, receipt: f.receipt(second, "expired") });
    await assert.rejects(j.compareAndSet(endSecond, first)); assert.deepEqual(await j.read(), endSecond); assert.equal((await j.page()).attempts.length, 2);
  } finally { f.close(); }
});
test("lost reservation responses retain their original opening and cannot become a new attempt", async () => {
  const f = fixture(); try {
    const j = await f.open(), first = await j.compareAndSet(null, f.make()), unknown = await j.compareAndSet(first, { ...first, reserve_submitted: true });
    await assert.rejects(j.compareAndSet(unknown, f.make()));
    await assert.rejects(j.compareAndSet(unknown, { ...unknown, reserve_submitted: false }));
    assert.equal((await j.read()).command.opening_id, first.command.opening_id);
  } finally { f.close(); }
});
test("saved signatures and later receipt proofs are immutable across explicit reconciliation", async () => {
  const f = fixture(); try {
    const j = await f.open(), first = await j.compareAndSet(null, f.make()), r = f.receipt(first);
    const reserved = await j.compareAndSet(first, { ...first, reserve_submitted: true, receipt: r });
    const original = { v: 1, opening_id: r.opening_id, interval_id: r.interval_id, statement: r.statement, owner_signature: b64(64) };
    const signed = await j.compareAndSet(reserved, { ...reserved, original });
    const sent = await j.compareAndSet(signed, { ...signed, request_submitted: true, receipt: { ...r, owner_signature: original.owner_signature, requested_ms: "1000", phase: "requested" } });
    await assert.rejects(j.compareAndSet(sent, { ...sent, original: { ...original, owner_signature: b64(64, 2) } }));
    await assert.rejects(j.compareAndSet(sent, { ...sent, receipt: r }));
    await assert.rejects(j.compareAndSet(sent, { ...sent, owner_session_id: crypto.randomUUID() }));
    assert.deepEqual(await j.read(), sent);
  } finally { f.close(); }
});
test("scope isolation, withdrawal and malformed recovery cannot supply authority", async () => {
  const f = fixture(); try {
    const j = await f.open(), original = await j.compareAndSet(null, f.make()), other = await f.open({ scope: { ...f.scope, peer: "+" + "987654321" } });
    assert.equal(await other.read(), null); assert.deepEqual((await other.page()).attempts, []);
    await assert.rejects(j.compareAndSet(original, { ...original, request_submitted: true }));
    await assert.rejects(j.compareAndSet(original, { ...original, receipt: f.receipt(original) }));
    await assert.rejects(j.compareAndSet(original, { ...original, command: { ...original.command, interval_expires_ms: "00" } }));
    f.abort.abort(); await assert.rejects(async () => j.read()); await assert.rejects(async () => j.page());
  } finally { f.close(); }
});
test("retained history cannot impose a global lifetime cap and every scoped page stays bounded", async () => {
  const f = fixture(); try {
    const j = await f.open(), originals = new Map(); let head = null;
    for (let i = 0; i < 130; i++) {
      head = await j.compareAndSet(head, f.make());
      head = await j.compareAndSet(head, { ...head, reserve_submitted: true, receipt: f.receipt(head, "expired") });
      originals.set(head.command.opening_id, head);
    }
    const otherScope = { ...f.scope, accountId: crypto.randomUUID(), originalUserId: crypto.randomUUID(), peer: "+" + "987654321" };
    const other = await f.open({ scope: otherScope }), fresh = f.make(); fresh.command.peer = otherScope.peer;
    assert.equal(await other.read(), null); await other.compareAndSet(null, fresh);
    assert.equal((await other.read()).command.opening_id, fresh.command.opening_id);
    let afterOpeningId = null; const seen = new Set();
    do {
      const page = await j.page({ afterOpeningId, limit: 17 }); assert(page.attempts.length <= 17);
      for (const r of page.attempts) { assert.deepEqual(r, originals.get(r.command.opening_id)); assert(!seen.has(r.command.opening_id)); seen.add(r.command.opening_id); }
      afterOpeningId = page.nextOpeningId;
    } while (afterOpeningId !== null);
    assert.equal(seen.size, 130); assert.deepEqual(await j.read(), head);
    assert.throws(() => j.page({ afterOpeningId: null, limit: 1000 })); assert.throws(() => j.page({ afterOpeningId: "invalid", limit: 1 }));
  } finally { f.close(); }
});
