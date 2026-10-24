// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), path = require("node:path");
const { createRequire } = require("node:module");
createRequire(path.join(__dirname, "../../sdk/typescript/package.json"))("fake-indexeddb/auto");
const recovery = require("./conversation-manifest03-recovery.js"), id = () => crypto.randomUUID();
function fixture() {
  const origin = "https://owner.example.test", scope = { origin, account: id(), user: id(), device: id(), line: id(),
    rootFingerprint: "ab".repeat(32), pairedFingerprint: "cd".repeat(32), priorVersion: "1", priorDigest: "ef".repeat(32) };
  const value = { v: 1, binding_id: id(), original_identity: "ba".repeat(32), version: "3", digest: "dc".repeat(32), ancestry_sha256: "fe".repeat(32) };
  return { origin, scope, value, options: { scope, currentOrigin: () => origin, name: "manifest-recovery-test-" + id() } };
}
test("actual committed highwater survives reopening and refuses decreasing version or changed same-version prefix", async () => {
  const f = fixture(), first = await recovery.open(f.options); await first.compareAndSet(null, f.value); first.close();
  const second = await recovery.open(f.options); try {
    assert.deepEqual(await second.read(), f.value);
    for (const change of [{ version: "2" }, { ancestry_sha256: "ab".repeat(32) }, { binding_id: id() }, { original_identity: "cd".repeat(32) }])
      await assert.rejects(second.compareAndSet(f.value, { ...f.value, ...change }));
    assert.deepEqual(await second.read(), f.value);
    const advanced = { ...f.value, version: "4", digest: "ac".repeat(32), ancestry_sha256: "de".repeat(32) };
    await second.compareAndSet(f.value, advanced); assert.deepEqual(await second.read(), advanced);
  } finally { second.close(); }
});
test("competing actual IndexedDB transactions cannot overwrite an unseen other-tab checkpoint", async () => {
  const f = fixture(), a = await recovery.open(f.options), b = await recovery.open(f.options);
  try {
    const other = { ...f.value, digest: "aa".repeat(32) };
    const outcomes = await Promise.allSettled([a.compareAndSet(null, f.value), b.compareAndSet(null, other)]);
    assert.equal(outcomes.filter(v => v.status === "fulfilled").length, 1); assert.deepEqual(await a.read(), await b.read());
  } finally { a.close(); b.close(); }
});
test("request success followed by actual transaction abort never publishes a durable checkpoint", async () => {
  const f = fixture(), store = await recovery.open(f.options), add = IDBObjectStore.prototype.add; let wrote = false;
  try {
    IDBObjectStore.prototype.add = function (...args) { const req = add.apply(this, args); req.addEventListener("success", () => { wrote = true; req.transaction.abort(); }, { once: true }); return req; };
    await assert.rejects(store.compareAndSet(null, f.value)); assert.equal(wrote, true); assert.equal(await store.read(), null);
  } finally { IDBObjectStore.prototype.add = add; store.close(); }
});
test("accessor secrets changed origin and abort refuse without changing the committed public record", async () => {
  const f = fixture(), abort = new AbortController(); let origin = f.origin;
  const store = await recovery.open({ ...f.options, signal: abort.signal, currentOrigin: () => origin });
  try {
    const value = { ...f.value }; let called = false; Object.defineProperty(value, "digest", { enumerable: true, get() { called = true; return f.value.digest; } });
    await assert.rejects(store.compareAndSet(null, value)); assert.equal(called, false);
    await assert.rejects(store.compareAndSet(null, { ...f.value, password: "synthetic" }));
    origin = "https://elsewhere.example.test"; await assert.rejects(async () => store.read()); origin = f.origin;
    abort.abort(); await assert.rejects(async () => store.read());
  } finally { store.close(); }
});
