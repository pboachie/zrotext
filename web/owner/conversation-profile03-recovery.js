// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  const names = ["origin", "account", "user", "device", "line", "rootFingerprint", "pairedFingerprint", "manifestVersion", "manifestDigest"];
  const fields = {
    opening: ["v", "origin", "account_id", "user_id", "owner_session_id", "device_id", "root_fingerprint", "opening_id", "line_id", "successor_manifest03"],
    reservation: ["challenge_id", "new_binding_id", "core", "issued_ms", "expires_ms", "successor_manifest03"],
    bundle: ["bundle"],
    receipt: ["opening_id", "challenge_id", "binding_id", "binding_generation", "election_digest", "bundle_sha256", "accepted_ms", "selection_epoch"]
  };
  function closed(value, keys) {
    if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw Error("Public recovery record required");
    const ds = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(ds).length !== keys.length || keys.some(k => !ds[k] || !("value" in ds[k]))) throw Error("Closed public recovery record required");
    const out = {};
    for (const k of keys) {
      const v = ds[k].value;
      if (k === "v" ? v !== 1 : typeof v !== "string" || v.length < 1 || v.length > 32768) throw Error("Public recovery value refused");
      out[k] = v;
    }
    return out;
  }
  async function open({ scope, signal, currentOrigin = () => root.location.origin, indexedDB = root.indexedDB, name = "zrotext-profile03-public-recovery" }) {
    scope = Object.freeze(closed(scope, names));
    if (new URL(scope.origin).protocol !== "https:" || new URL(scope.origin).origin !== scope.origin) throw Error("Recovery origin refused");
    let db, stopped = false;
    const transactions = new Set();
    function guard() { if (stopped || signal?.aborted || currentOrigin() !== scope.origin) throw Error("Public recovery closed"); }
    function close() { stopped = true; for (const tx of transactions) try { tx.abort(); } catch {} db?.close(); signal?.removeEventListener("abort", close); }
    signal?.addEventListener("abort", close, { once: true });
    guard();
    try {
      db = await new Promise((resolve, reject) => {
        const req = indexedDB.open(name, 1);
        let refused = false;
        const timer = setTimeout(() => { refused = true; reject(Error("Recovery storage unavailable")); }, 5000);
        req.onblocked = req.onerror = () => { refused = true; clearTimeout(timer); reject(Error("Recovery storage unavailable")); };
        req.onupgradeneeded = () => { if (refused || signal?.aborted) req.transaction.abort(); else req.result.createObjectStore("public"); };
        req.onsuccess = () => { clearTimeout(timer); if (refused || stopped || signal?.aborted) { req.result.close(); reject(Error("Recovery storage closed")); } else resolve(req.result); };
      });
      guard();
      if (db.objectStoreNames.length !== 1 || !db.objectStoreNames.contains("public")) throw Error("Recovery schema refused");
      db.onversionchange = close;
    } catch (error) { close(); throw error; }
    const scopeKey = JSON.stringify(names.map(k => scope[k]));
    function identity(opening) { if (typeof opening !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(opening) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(opening)) throw Error("Recovery identity refused"); return opening; }
    function transaction(mode, run) {
      guard();
      return new Promise((resolve, reject) => {
        const tx = db.transaction("public", mode); transactions.add(tx); let result;
        const timer = setTimeout(() => { try { tx.abort(); } catch {} reject(Error("Recovery transaction timed out")); }, 5000);
        tx.oncomplete = () => { clearTimeout(timer); transactions.delete(tx); try { guard(); resolve(result); } catch (error) { reject(error); } };
        tx.onabort = tx.onerror = () => { clearTimeout(timer); transactions.delete(tx); reject(Error("Recovery transaction refused")); };
        const safe = fn => (...args) => { try { guard(); fn(...args); } catch { try { tx.abort(); } catch {} } };
        try { run(tx.objectStore("public"), value => { result = value; }, tx, safe); } catch { tx.abort(); }
      });
    }
    async function append(opening, kind, input) {
      identity(opening); if (!Object.hasOwn(fields, kind)) throw Error("Recovery kind refused");
      const value = closed(input, fields[kind]), data = JSON.stringify(value), key = [scopeKey, opening, kind];
      if (data.length > 65536 || kind === "opening" && (value.opening_id !== opening || value.origin !== scope.origin || value.account_id !== scope.account || value.user_id !== scope.user || value.device_id !== scope.device || value.line_id !== scope.line)) throw Error("Recovery scope refused");
      await transaction("readwrite", (store, done, tx, safe) => {
        const existing = store.get(key);
        existing.onsuccess = safe(() => {
          guard();
          if (existing.result !== undefined) { if (existing.result !== data) tx.abort(); else done(); return; }
          const count = store.count();
          count.onsuccess = safe(() => { if (count.result >= 512) tx.abort(); else store.add(data, key); });
        });
      });
    }
    async function read(opening, kind) {
      identity(opening); if (!Object.hasOwn(fields, kind)) throw Error("Recovery kind refused");
      return transaction("readonly", (store, done, _tx, safe) => { const req = store.get([scopeKey, opening, kind]); req.onsuccess = safe(() => done(req.result === undefined ? null : Object.freeze(closed(JSON.parse(req.result), fields[kind])))); });
    }
    async function list() {
      return transaction("readonly", (store, done, _tx, safe) => {
        const rows = [], req = store.openCursor(); let total = 0;
        req.onsuccess = safe(() => {
          guard(); const c = req.result;
          if (!c) { done(Object.freeze(rows)); return; }
          if (++total > 512) throw Error("Recovery capacity refused");
          if (Array.isArray(c.key) && c.key[0] === scopeKey && c.key[2] === "opening") rows.push(identity(c.key[1]));
          c.continue();
        });
      });
    }
    return Object.freeze({ append, read, list, close });
  }
  const api = Object.freeze({ open });
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ZtProfile03Recovery = api;
})(globalThis);
