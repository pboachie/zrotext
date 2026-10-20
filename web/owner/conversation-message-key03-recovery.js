// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  const scopes = ["origin", "accountId", "originalUserId", "deviceId", "lineId", "rootFingerprint"];
  const originals = ["v", "origin", "account_id", "user_id", "owner_session_id", "device_id", "root_fingerprint", "opening_id", "line_id", "statement", "signature", "successor_manifest03"];
  const receipts = ["v", "opening_id", "line_id", "binding_id", "election_digest", "statement", "signature", "successor_manifest03", "accepted_ms", "predecessor_version", "predecessor_digest", "successor_version", "successor_digest", "operation", "predecessor_ancestry_sha256", "ancestry_sha256"];
  function closed(value, names) {
    if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw Error("Public message-key record refused");
    const d = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(d).length !== names.length || names.some(k => !d[k] || !("value" in d[k]) || !d[k].enumerable)) throw Error("Closed public message-key record required");
    return Object.fromEntries(names.map(k => [k, d[k].value]));
  }
  function strings(value, names) {
    const r = closed(value, names);
    for (const k of names) if (k === "v" ? r[k] !== 1 : typeof r[k] !== "string" || !r[k].length || r[k].length > 32768) throw Error("Public recovery value refused");
    return r;
  }
  function record(value) {
    const r = closed(value, ["v", "proposal", "original", "submitted", "predecessor", "receipt"]);
    if (r.v !== 1 || typeof r.submitted !== "boolean") throw Error("Public recovery version refused");
    if (r.original === null && (r.receipt !== null || r.submitted) || r.receipt !== null && !r.submitted) throw Error("Original attempt required");
    return Object.freeze({ v: 1, proposal: Object.freeze(strings(r.proposal, ["operation", "issued_ms", "expires_ms", "key_id", "public_point", "unsigned", "packet"])),
      original: r.original === null ? null : Object.freeze(strings(r.original, originals)),
      submitted: r.submitted,
      predecessor: Object.freeze(strings(r.predecessor, ["version", "digest", "ancestry_sha256"])),
      receipt: r.receipt === null ? null : Object.freeze(strings(r.receipt, receipts)) });
  }
  async function open({ scope, signal, currentOrigin = () => root.location.origin, indexedDB = root.indexedDB, name = "zrotext-browser-message-key03-recovery" }) {
    scope = Object.freeze(strings(scope, scopes));
    if (new URL(scope.origin).origin !== scope.origin || new URL(scope.origin).protocol !== "https:") throw Error("Recovery origin refused");
    const key = JSON.stringify(scopes.map(k => scope[k])), transactions = new Set(); let db, stopped = false;
    function guard() { if (stopped || signal?.aborted || currentOrigin() !== scope.origin) throw Error("Public recovery closed"); }
    function close() { stopped = true; for (const tx of transactions) try { tx.abort(); } catch {} db?.close(); signal?.removeEventListener("abort", close); }
    signal?.addEventListener("abort", close, { once: true }); guard();
    try {
      db = await new Promise((resolve, reject) => {
        const request = indexedDB.open(name, 1); let refused = false;
        const fail = () => { refused = true; clearTimeout(timer); reject(Error("Message-key recovery unavailable")); };
        const timer = setTimeout(fail, 5000); request.onerror = request.onblocked = fail;
        request.onupgradeneeded = () => { if (refused || stopped || signal?.aborted) request.transaction.abort(); else request.result.createObjectStore("attempts"); };
        request.onsuccess = () => { clearTimeout(timer); if (refused || stopped || signal?.aborted) { request.result.close(); fail(); } else resolve(request.result); };
      });
      guard(); if (db.objectStoreNames.length !== 1 || !db.objectStoreNames.contains("attempts")) throw Error("Recovery schema refused"); db.onversionchange = close;
    } catch (e) { close(); throw e; }
    function decode(raw) {
      if (raw === undefined) return null;
      if (typeof raw !== "string" || raw.length > 131072) throw Error("Bounded recovery required");
      const r = record(JSON.parse(raw)); if (JSON.stringify(r) !== raw) throw Error("Canonical recovery required"); return r;
    }
    function transaction(mode, run) {
      guard(); return new Promise((resolve, reject) => {
        const tx = db.transaction("attempts", mode); transactions.add(tx); let result;
        const finish = () => { clearTimeout(timer); transactions.delete(tx); };
        const timer = setTimeout(() => { try { tx.abort(); } catch {} reject(Error("Recovery commit timed out")); }, 5000);
        tx.oncomplete = () => { finish(); try { guard(); resolve(result); } catch (e) { reject(e); } };
        tx.onerror = tx.onabort = () => { finish(); reject(Error("Recovery transaction refused")); };
        const safe = fn => () => { try { guard(); fn(); } catch { try { tx.abort(); } catch {} } };
        try { run(tx.objectStore("attempts"), v => { result = v; }, tx, safe); } catch { tx.abort(); }
      });
    }
    const read = () => transaction("readonly", (store, done, _tx, safe) => { const r = store.get(key); r.onsuccess = safe(() => done(decode(r.result))); });
    async function compareAndSet(expected, candidate) {
      const before = expected === null ? null : JSON.stringify(record(expected)), after = JSON.stringify(record(candidate));
      if (after.length > 131072) throw Error("Bounded public recovery required");
      await transaction("readwrite", (store, done, tx, safe) => {
        const r = store.get(key); r.onsuccess = safe(() => {
          const actual = decode(r.result); if ((actual === null ? null : JSON.stringify(actual)) !== before) { tx.abort(); return; }
          if (actual !== null) { store.put(after, key); done(); return; }
          const count = store.count(); count.onsuccess = safe(() => { if (count.result >= 128) tx.abort(); else store.add(after, key); });
        });
      });
      const actual = await read(); guard(); if (JSON.stringify(actual) !== after) throw Error("Recovery readback refused"); return actual;
    }
    // One current public attempt per scope. The controller permits replacement
    // only after genuine accepted-history confirmation; UNKNOWN is never cleared.
    return Object.freeze({ read, compareAndSet, close });
  }
  const api = Object.freeze({ open }); if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ZtMessageKey03Recovery = api;
})(globalThis);
