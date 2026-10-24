// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  const scopeFields = ["origin", "account", "user", "device", "line", "rootFingerprint", "pairedFingerprint", "priorVersion", "priorDigest"];
  const fields = ["v", "binding_id", "original_identity", "version", "digest", "ancestry_sha256"];
  const fail = () => { throw Error("Saved manifest checkpoint unavailable"); };
  function closed(value, names) {
    if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
    const d = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(d).length !== names.length || names.some(k => !d[k] || !("value" in d[k]) || !d[k].enumerable)) fail();
    return Object.fromEntries(names.map(k => [k, d[k].value]));
  }
  function id(v) { if (typeof v !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(v)) fail(); }
  function hash(v) { if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v) || /^0+$/.test(v)) fail(); }
  function number(v) { if (typeof v !== "string" || !/^[1-9][0-9]{0,18}$/.test(v) || BigInt(v) > (1n << 63n) - 1n) fail(); }
  function checkpoint(value) {
    const r = closed(value, fields);
    if (r.v !== 1) fail(); id(r.binding_id); number(r.version);
    for (const k of ["original_identity", "digest", "ancestry_sha256"]) hash(r[k]);
    return Object.freeze(r);
  }
  async function open({ scope, signal, currentOrigin = () => root.location.origin,
    indexedDB = root.indexedDB, name = "zrotext-manifest-history03" }) {
    scope = Object.freeze(closed(scope, scopeFields));
    for (const k of ["account", "user", "device", "line"]) id(scope[k]);
    for (const k of ["rootFingerprint", "pairedFingerprint", "priorDigest"]) hash(scope[k]); number(scope.priorVersion);
    if (typeof scope.origin !== "string" || new URL(scope.origin).protocol !== "https:" || new URL(scope.origin).origin !== scope.origin) fail();
    let stopped = false, db;
    const transactions = new Set(), key = JSON.stringify(scopeFields.map(k => scope[k]));
    function guard() { if (stopped || signal?.aborted || currentOrigin() !== scope.origin) fail(); }
    function close() { stopped = true; for (const tx of transactions) try { tx.abort(); } catch {} db?.close(); signal?.removeEventListener("abort", close); }
    signal?.addEventListener("abort", close, { once: true }); guard();
    try {
      db = await new Promise((resolve, reject) => {
        const request = indexedDB.open(name, 1); let refused = false;
        const abort = () => { refused = true; clearTimeout(timer); reject(Error("Manifest checkpoint storage unavailable")); };
        const timer = setTimeout(abort, 5000);
        request.onerror = request.onblocked = abort;
        request.onupgradeneeded = () => { if (refused || stopped || signal?.aborted) request.transaction.abort(); else request.result.createObjectStore("checkpoints"); };
        request.onsuccess = () => { clearTimeout(timer); if (refused || stopped || signal?.aborted) { request.result.close(); reject(Error("Manifest checkpoint storage closed")); } else resolve(request.result); };
      });
      guard(); if (db.objectStoreNames.length !== 1 || !db.objectStoreNames.contains("checkpoints")) fail(); db.onversionchange = close;
    } catch (e) { close(); throw e; }
    function decode(raw) {
      if (raw === undefined) return null;
      if (typeof raw !== "string" || raw.length > 1024) fail();
      const value = checkpoint(JSON.parse(raw)); if (JSON.stringify(value) !== raw) fail(); return value;
    }
    function transaction(mode, run) {
      guard();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("checkpoints", mode); transactions.add(tx); let result;
        const finish = () => { clearTimeout(timer); transactions.delete(tx); };
        const timer = setTimeout(() => { try { tx.abort(); } catch {} reject(Error("Manifest checkpoint commit timed out")); }, 5000);
        tx.oncomplete = () => { finish(); try { guard(); resolve(result); } catch (e) { reject(e); } };
        tx.onerror = tx.onabort = () => { finish(); reject(Error("Manifest checkpoint transaction refused")); };
        const safe = fn => (...args) => { try { guard(); fn(...args); } catch { try { tx.abort(); } catch {} } };
        try { run(tx.objectStore("checkpoints"), v => { result = v; }, tx, safe); } catch { tx.abort(); }
      });
    }
    const read = () => transaction("readonly", (store, done, _tx, safe) => { const req = store.get(key); req.onsuccess = safe(() => done(decode(req.result))); });
    async function compareAndSet(expected, candidate) {
      expected = expected === null ? null : checkpoint(expected); candidate = checkpoint(candidate);
      const before = expected === null ? null : JSON.stringify(expected), after = JSON.stringify(candidate);
      if (expected && (candidate.binding_id !== expected.binding_id || candidate.original_identity !== expected.original_identity
          || BigInt(candidate.version) < BigInt(expected.version) || candidate.version === expected.version && after !== before)) fail();
      await transaction("readwrite", (store, done, tx, safe) => {
        const req = store.get(key);
        req.onsuccess = safe(() => {
          const actual = decode(req.result); if ((actual === null ? null : JSON.stringify(actual)) !== before) { tx.abort(); return; }
          if (actual !== null) { store.put(after, key); done(); return; }
          const count = store.count(); count.onsuccess = safe(() => { if (count.result >= 128) tx.abort(); else store.add(after, key); });
        });
      });
      const retained = await read(); guard(); if (JSON.stringify(retained) !== after) fail();
      return retained;
    }
    // Public saved selectors are never proof. Reverify originals and every
    // accepted link before comparing/promoting this local monotonic checkpoint.
    return Object.freeze({ read, compareAndSet, close });
  }
  const api = Object.freeze({ open });
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ZtManifest03Recovery = api;
})(globalThis);
