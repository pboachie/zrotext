// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  const scopes = ["origin", "accountId", "originalUserId", "deviceId", "lineId", "rootFingerprint", "peer"];
  const commands = ["v", "opening_id", "line_id", "peer", "archive_reader_key_id", "phone_signer_key_id", "browser_signer_key_id", "interval_expires_ms", "integration_readers"];
  const originals = ["v", "opening_id", "interval_id", "statement", "owner_signature"];
  const receipts = ["v", "opening_id", "interval_id", "receipt_id", "statement", "owner_signature", "phone_signature", "installed_signature", "requested_ms", "approved_ms", "installed_ms", "phase"];
  const fields = ["v", "owner_session_id", "command", "original", "receipt", "reserve_submitted", "request_submitted", "stop_submitted"];
  const phases = ["reserved", "requested", "install_pending", "active", "stopped", "expired"];
  const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  function closed(value, names) {
    if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw Error("Closed consent recovery required");
    const ds = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(ds).length !== names.length || names.some(k => !ds[k] || !("value" in ds[k]) || !ds[k].enumerable)) throw Error("Closed consent recovery required");
    return Object.fromEntries(names.map(k => [k, ds[k].value]));
  }
  function id(v) { if (typeof v !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(v)) throw Error("Original identity required"); return v; }
  function text(v) { if (typeof v !== "string" || !v.length || v.length > 4096) throw Error("Bounded public packet required"); return v; }
  function number(v) { text(v); if (!/^[1-9][0-9]{0,18}$/.test(v) || BigInt(v) >= 1n << 63n) throw Error("Original time required"); return v; }
  function binary(v, min, max = min) {
    text(v); if (!/^[A-Za-z0-9_-]+$/.test(v)) throw Error("Canonical public bytes required");
    const raw = atob(v.replaceAll("-", "+").replaceAll("_", "/"));
    if (raw.length < min || raw.length > max || btoa(raw).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "") !== v) throw Error("Canonical public bytes required"); return v;
  }
  function command(value) {
    const r = closed(value, commands); if (r.v !== 1) throw Error("Recovery version refused");
    id(r.opening_id); id(r.line_id); if (typeof r.peer !== "string" || !/^\+[1-9][0-9]{1,14}$/.test(r.peer)) throw Error("Compared peer required");
    number(r.interval_expires_ms); for (const k of commands.slice(4, 7)) binary(r[k], 32);
    const mappings = r.integration_readers;
    if (!Array.isArray(mappings) || Object.getPrototypeOf(mappings) !== Array.prototype || mappings.length > 6
        || Reflect.ownKeys(mappings).length !== mappings.length + 1) throw Error("Closed reader selection required");
    r.integration_readers = Object.freeze(Array.from({ length: mappings.length }, (_, i) => {
      const d = Object.getOwnPropertyDescriptor(mappings, String(i)); if (!d || !("value" in d)) throw Error("Owned reader selection required");
      const m = closed(d.value, ["connector_id", "read_grant_id", "key_id"]); id(m.connector_id); id(m.read_grant_id); binary(m.key_id, 32); return Object.freeze(m);
    })); return Object.freeze(r);
  }
  function packet(value, names) {
    const r = closed(value, names); if (r.v !== 1) throw Error("Recovery version refused");
    id(r.opening_id); id(r.interval_id); binary(r.statement, 695, 1092);
    if (names === originals) binary(r.owner_signature, 64);
    else {
      id(r.receipt_id); if (!phases.includes(r.phase)) throw Error("Original phase required");
      let count = 0;
      for (const [signature, time] of [["owner_signature", "requested_ms"], ["phone_signature", "approved_ms"], ["installed_signature", "installed_ms"]]) {
        if (r[signature] === null && r[time] === null) continue;
        if (count !== ["owner_signature", "phone_signature", "installed_signature"].indexOf(signature)) throw Error("Receipt proof gap refused");
        binary(r[signature], 64); number(r[time]); count++;
      }
      if (phases.indexOf(r.phase) < 4 && count !== phases.indexOf(r.phase)) throw Error("Original phase proof required");
    } return Object.freeze(r);
  }
  function record(value, scope) {
    const r = closed(value, fields); if (r.v !== 1) throw Error("Recovery version refused"); id(r.owner_session_id);
    r.command = command(r.command); r.original = r.original === null ? null : packet(r.original, originals); r.receipt = r.receipt === null ? null : packet(r.receipt, receipts);
    for (const k of fields.slice(5)) if (typeof r[k] !== "boolean") throw Error("Original submission state required");
    if (r.command.line_id !== scope.lineId || r.command.peer !== scope.peer || !r.reserve_submitted && (r.request_submitted || r.stop_submitted || r.receipt !== null)
        || r.original === null && r.request_submitted || r.receipt === null && r.stop_submitted) throw Error("Original attempt required");
    for (const p of [r.original, r.receipt]) if (p && p.opening_id !== r.command.opening_id) throw Error("Original opening changed");
    if (r.original && r.receipt && (r.original.interval_id !== r.receipt.interval_id || r.original.statement !== r.receipt.statement
        || r.receipt.owner_signature !== null && r.original.owner_signature !== r.receipt.owner_signature)) throw Error("Original signed packet changed");
    return Object.freeze(r);
  }
  function transition(before, after) {
    if (!equal(before.command, after.command) || before.owner_session_id !== after.owner_session_id) throw Error("Original reservation cannot change");
    for (const k of fields.slice(5)) if (before[k] && !after[k]) throw Error("Submission history cannot reset");
    if (before.original && !equal(before.original, after.original) || before.receipt && !after.receipt) throw Error("Original proof cannot change");
    if (before.receipt) {
      for (const k of receipts.filter(k => k !== "phase")) if (before.receipt[k] !== null && before.receipt[k] !== after.receipt[k]) throw Error("Receipt history cannot change");
      if (phases.indexOf(after.receipt.phase) < phases.indexOf(before.receipt.phase) && !(before.receipt.phase === "expired" && after.receipt.phase === "stopped")) throw Error("Receipt cannot reopen");
    }
  }
  async function open({ scope, signal, currentOrigin = () => root.location.origin, indexedDB = root.indexedDB, name = "zrotext-conversation-interval03-recovery" }) {
    scope = Object.freeze(closed(scope, scopes));
    if (typeof scope.origin !== "string" || typeof scope.rootFingerprint !== "string" || new URL(scope.origin).origin !== scope.origin || new URL(scope.origin).protocol !== "https:" || !/^[0-9a-f]{64}$/.test(scope.rootFingerprint)
        || /^0+$/.test(scope.rootFingerprint) || typeof scope.peer !== "string" || !/^\+[1-9][0-9]{1,14}$/.test(scope.peer)) throw Error("Compared recovery scope required");
    for (const k of scopes.slice(1, 5)) id(scope[k]);
    const key = JSON.stringify(scopes.map(k => scope[k])), transactions = new Set(); let db, stopped = false;
    function guard() { if (stopped || signal?.aborted || currentOrigin() !== scope.origin) throw Error("Consent recovery closed"); }
    function close() { stopped = true; for (const tx of transactions) try { tx.abort(); } catch {} db?.close(); signal?.removeEventListener("abort", close); }
    signal?.addEventListener("abort", close, { once: true }); guard();
    try {
      db = await new Promise((resolve, reject) => {
        const request = indexedDB.open(name, 1); let refused = false;
        const fail = () => { refused = true; clearTimeout(timer); reject(Error("Consent recovery unavailable")); };
        const timer = setTimeout(fail, 5000); request.onerror = request.onblocked = fail;
        request.onupgradeneeded = () => { if (refused || stopped || signal?.aborted) request.transaction.abort(); else { request.result.createObjectStore("heads"); request.result.createObjectStore("attempts"); } };
        request.onsuccess = () => { clearTimeout(timer); if (refused || stopped || signal?.aborted) { request.result.close(); fail(); } else resolve(request.result); };
      });
      guard(); if (db.objectStoreNames.length !== 2 || !db.objectStoreNames.contains("heads") || !db.objectStoreNames.contains("attempts")) throw Error("Recovery schema refused"); db.onversionchange = close;
    } catch (e) { close(); throw e; }
    function decode(raw) {
      if (typeof raw !== "string" || raw.length > 32768) throw Error("Bounded consent recovery required");
      const r = record(JSON.parse(raw), scope); if (JSON.stringify(r) !== raw) throw Error("Canonical consent recovery required"); return r;
    }
    function transaction(mode, run) {
      guard(); return new Promise((resolve, reject) => {
        const tx = db.transaction(["heads", "attempts"], mode); transactions.add(tx); let result;
        const finish = () => { clearTimeout(timer); transactions.delete(tx); };
        const timer = setTimeout(() => { try { tx.abort(); } catch {} reject(Error("Consent recovery commit timed out")); }, 5000);
        tx.oncomplete = () => { finish(); try { guard(); resolve(result); } catch (e) { reject(e); } };
        tx.onerror = tx.onabort = () => { finish(); reject(Error("Consent recovery transaction refused")); };
        const safe = fn => () => { try { guard(); fn(); } catch { try { tx.abort(); } catch {} } };
        try { run(tx.objectStore("heads"), tx.objectStore("attempts"), v => { result = v; }, tx, safe); } catch { tx.abort(); }
      });
    }
    const read = () => transaction("readonly", (heads, attempts, done, _tx, safe) => {
      const h = heads.get(key); h.onsuccess = safe(() => {
        if (h.result === undefined) { done(null); return; } const opening = id(h.result), r = attempts.get([key, opening]);
        r.onsuccess = safe(() => { const value = decode(r.result); if (value.command.opening_id !== opening) throw Error("Original head changed"); done(value); });
      });
    });
    const list = () => transaction("readonly", (_heads, attempts, done, _tx, safe) => {
      const r = attempts.getAll(IDBKeyRange.bound([key, ""], [key, "\uffff"]), 129);
      r.onsuccess = safe(() => { if (r.result.length > 128) throw Error("Consent history bounded"); done(Object.freeze(r.result.map(decode))); });
    });
    async function compareAndSet(expected, candidate) {
      const before = expected === null ? null : record(expected, scope), after = record(candidate, scope), serialized = JSON.stringify(after);
      if (serialized.length > 32768) throw Error("Consent record bounded");
      await transaction("readwrite", (heads, attempts, done, tx, safe) => {
        const h = heads.get(key); h.onsuccess = safe(() => {
          if ((h.result ?? null) !== (before?.command.opening_id ?? null)) { tx.abort(); return; }
          const write = () => {
            if (before && before.command.opening_id === after.command.opening_id) { transition(before, after); attempts.put(serialized, [key, after.command.opening_id]); done(); return; }
            if (before && !["stopped", "expired"].includes(before.receipt?.phase) || after.original !== null || after.receipt !== null || fields.slice(5).some(k => after[k])) throw Error("Reconcile original consent before a new opening");
            const count = attempts.count(); count.onsuccess = safe(() => {
              if (count.result >= 128) { tx.abort(); return; } attempts.add(serialized, [key, after.command.opening_id]); heads.put(after.command.opening_id, key); done();
            });
          };
          if (before === null) { write(); return; }
          const r = attempts.get([key, before.command.opening_id]); r.onsuccess = safe(() => { if (!equal(decode(r.result), before)) { tx.abort(); return; } write(); });
        });
      });
      const actual = await read(); guard(); if (!equal(actual, after)) throw Error("Consent recovery readback refused"); return actual;
    }
    // Records are local recovery only. Callers must freshly verify actual
    // original receipts and current permission; persisted phase proves neither.
    return Object.freeze({ read, list, compareAndSet, close });
  }
  const api = Object.freeze({ open }); if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ZtInterval03Recovery = api;
})(globalThis);
