// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), path = require("node:path");
const { createRequire } = require("node:module");
createRequire(path.join(__dirname, "../../sdk/typescript/package.json"))("fake-indexeddb/auto");
const recovery = require("./conversation-profile03-recovery.js");
const origin = "https://owner.example.test", id = () => crypto.randomUUID();
function fixture() {
  const scope = { origin, account: id(), user: id(), device: id(), line: id(), rootFingerprint: "ab".repeat(32), pairedFingerprint: "cd".repeat(32), manifestVersion: "1", manifestDigest: "ef".repeat(32) };
  const opening = { v: 1, origin, account_id: scope.account, user_id: scope.user, owner_session_id: id(), device_id: scope.device, root_fingerprint: "public-root", opening_id: id(), line_id: scope.line, successor_manifest03: "public-signed-successor" };
  return { scope, opening, options: { scope, name: "profile-recovery-test-" + id(), currentOrigin: () => origin } };
}
test("completed public recovery survives close and same-original-user reopening with no secrets or overwrite", async () => {
  const f = fixture(), first = await recovery.open(f.options);
  await first.append(f.opening.opening_id, "opening", f.opening); first.close();
  const second = await recovery.open(f.options);
  try {
    assert.deepEqual(await second.list(), [f.opening.opening_id]); assert.deepEqual(await second.read(f.opening.opening_id, "opening"), f.opening);
    await second.append(f.opening.opening_id, "opening", { ...f.opening });
    await assert.rejects(second.append(f.opening.opening_id, "opening", { ...f.opening, owner_session_id: id() }));
    for (const secret of ["password", "factor", "privateKey", "recoveryCode"]) await assert.rejects(second.append(f.opening.opening_id, "opening", { ...f.opening, [secret]: "synthetic" }));
    assert.deepEqual(await second.read(f.opening.opening_id, "opening"), f.opening);
  } finally { second.close(); }
});
test("competing tabs retain one immutable public bundle and never replace an unknown original", async () => {
  const f = fixture(), a = await recovery.open(f.options), b = await recovery.open(f.options);
  try {
    const results = await Promise.allSettled([a.append(f.opening.opening_id, "bundle", { bundle: "original-public-bundle" }), b.append(f.opening.opening_id, "bundle", { bundle: "different-public-bundle" })]);
    assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
    const winner = await a.read(f.opening.opening_id, "bundle"); assert.deepEqual(await b.read(f.opening.opening_id, "bundle"), winner);
  } finally { a.close(); b.close(); }
});
test("request success followed by transaction abort never publishes durable recovery", async () => {
  const f = fixture(), store = await recovery.open(f.options), add = IDBObjectStore.prototype.add;
  let requestSucceeded = false;
  try {
    IDBObjectStore.prototype.add = function (...args) {
      const req = add.apply(this, args); req.addEventListener("success", () => { requestSucceeded = true; req.transaction.abort(); }, { once: true }); return req;
    };
    await assert.rejects(store.append(f.opening.opening_id, "opening", f.opening)); assert.equal(requestSucceeded, true);
    assert.equal(await store.read(f.opening.opening_id, "opening"), null); assert.deepEqual(await store.list(), []);
  } finally { IDBObjectStore.prototype.add = add; store.close(); }
});
test("a different original owner, device or compared checkpoint cannot select stored recovery", async () => {
  const f = fixture(), original = await recovery.open(f.options); await original.append(f.opening.opening_id, "opening", f.opening); original.close();
  for (const change of [{ user: id() }, { device: id() }, { manifestDigest: "aa".repeat(32) }]) {
    const other = await recovery.open({ ...f.options, scope: { ...f.scope, ...change } });
    try { assert.deepEqual(await other.list(), []); assert.equal(await other.read(f.opening.opening_id, "opening"), null); } finally { other.close(); }
  }
});
test("abort, changed origin and accessor input refuse before publishing public bytes", async () => {
  const f = fixture(), abort = new AbortController(); let selectedOrigin = origin;
  const store = await recovery.open({ ...f.options, signal: abort.signal, currentOrigin: () => selectedOrigin });
  try {
    let called = false; const value = { ...f.opening }; Object.defineProperty(value, "origin", { get() { called = true; return origin; } });
    await assert.rejects(store.append(f.opening.opening_id, "opening", value)); assert.equal(called, false);
    selectedOrigin = "https://elsewhere.example.test"; await assert.rejects(store.append(f.opening.opening_id, "opening", f.opening));
    selectedOrigin = origin; abort.abort(); await assert.rejects(store.list());
  } finally { store.close(); }
});
