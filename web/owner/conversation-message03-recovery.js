// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  const scopes = ["origin", "accountId", "originalUserId", "deviceId", "lineId", "rootFingerprint", "peer"];
  const fields = ["v", "message_id", "interval_id", "owner_session_id", "unsigned_envelope", "envelope", "reviewed_intent", "reviewed_signature", "stage", "closed", "receipt"];
  const stages = ["envelope_sign_reserved", "envelope_signed", "intent_sign_reserved", "intent_signed", "submit_reserved", "accepted"];
  const receiptFields = ["v", "message_id", "interval_id", "accepted_ms", "expires_ms", "selection_epoch", "envelope_sha256", "reviewed_intent_sha256", "reviewed_signature_sha256", "sms_ceiling"];
  const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  const hex = b => Array.from(b, v => v.toString(16).padStart(2, "0")).join("");
  const uuid = b => hex(b).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
  const sha = async b => new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(b).buffer));
  function closed(value, names) {
    if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw Error("Closed message recovery required");
    const ds = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(ds).length !== names.length || names.some(k => !ds[k] || !("value" in ds[k]) || !ds[k].enumerable)) throw Error("Closed message recovery required");
    return Object.fromEntries(names.map(k => [k, ds[k].value]));
  }
  function id(v) { if (typeof v !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(v)) throw Error("Original identity required"); return v; }
  function decimal(v) { if (typeof v !== "string" || !/^[1-9][0-9]{0,18}$/.test(v) || BigInt(v) >= 1n << 63n) throw Error("Original time required"); return BigInt(v); }
  function binary(v, min, max = min) {
    if (typeof v !== "string" || v.length > 46000 || !/^[A-Za-z0-9_-]+$/.test(v)) throw Error("Bounded canonical public bytes required");
    const raw = atob(v.replaceAll("-", "+").replaceAll("_", "/"));
    if (raw.length < min || raw.length > max || btoa(raw).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "") !== v) throw Error("Canonical public bytes required");
    return Uint8Array.from(raw, c => c.charCodeAt(0));
  }
  function capture(value, scope) {
    const r = closed(value, fields), stage = stages.indexOf(r.stage);
    if (r.v !== 1 || stage < 0 || typeof r.closed !== "boolean") throw Error("Original message stage required");
    for (const k of ["message_id", "interval_id", "owner_session_id"]) id(r[k]);
    const unsigned = binary(r.unsigned_envelope, 493, 34149), v = new DataView(unsigned.buffer), end = 10 + v.getUint16(8);
    if (!same(unsigned.slice(0, 8), Uint8Array.of(90, 84, 83, 69, 3, 1, 0, 0)) || end !== 164 + scope.peer.length
        || uuid(unsigned.slice(10, 26)) !== scope.accountId || uuid(unsigned.slice(26, 42)) !== r.message_id
        || uuid(unsigned.slice(42, 58)) !== scope.deviceId || uuid(unsigned.slice(58, 74)) !== scope.lineId
        || unsigned[162] !== 1 || unsigned[163] !== scope.peer.length
        || new TextDecoder("utf-8", { fatal: true }).decode(unsigned.slice(164, end)) !== scope.peer) throw Error("Original ciphertext scope changed");
    if (unsigned.length < end + 34) throw Error("Ciphertext framing required");
    const bodySize = v.getUint32(end + 12), bodyEnd = end + 16 + bodySize, count = unsigned[bodyEnd];
    if (bodySize < 17 || bodySize > 32784 || count < 2 || count > 8 || bodyEnd + 1 + 146 * count !== unsigned.length) throw Error("Ciphertext bounds required");
    for (const [k, at, min, max] of [["envelope", 1, 557, 34213], ["reviewed_intent", 2, 592, 803], ["reviewed_signature", 3, 64, 64]]) {
      if (stage < at ? r[k] !== null : r[k] === null) throw Error("Original signing order required");
      if (r[k] !== null) binary(r[k], min, max);
    }
    if (r.envelope !== null) {
      const envelope = binary(r.envelope, 557, 34213);
      if (envelope.length !== unsigned.length + 64 || !same(envelope.slice(0, -64), unsigned)) throw Error("Original unsigned ciphertext cannot change");
    }
    if (stage === 5 ? r.receipt === null : r.receipt !== null) throw Error("Original receipt stage required");
    if (r.receipt !== null) {
      r.receipt = closed(r.receipt, receiptFields); const p = r.receipt;
      if (p.v !== 1 || p.message_id !== r.message_id || p.interval_id !== r.interval_id || !Number.isInteger(p.sms_ceiling) || p.sms_ceiling < 1 || p.sms_ceiling > 6) throw Error("Original receipt required");
      for (const k of ["accepted_ms", "expires_ms", "selection_epoch"]) decimal(p[k]);
      for (const k of receiptFields.slice(6, 9)) binary(p[k], 32);
      Object.freeze(p);
    }
    return Object.freeze(r);
  }
  async function open({ scope, signal, currentOrigin = () => root.location.origin, indexedDB = root.indexedDB, name = "zrotext-conversation-message03-recovery",
    importSdk = n => import("/v1/owner/conversation-sdk/sdk/" + n + ".js") }) {
    scope = Object.freeze(closed(scope, scopes));
    if (typeof scope.origin !== "string" || scope.origin.length > 512 || new URL(scope.origin).origin !== scope.origin || new URL(scope.origin).protocol !== "https:"
        || typeof scope.rootFingerprint !== "string" || !/^[0-9a-f]{64}$/.test(scope.rootFingerprint) || /^0+$/.test(scope.rootFingerprint)
        || typeof scope.peer !== "string" || !/^\+[1-9][0-9]{1,14}$/.test(scope.peer)) throw Error("Compared message scope required");
    for (const k of scopes.slice(1, 5)) id(scope[k]);
    const key = JSON.stringify(scopes.map(k => scope[k])), transactions = new Set(); let db, stopped = false;
    function guard() { if (stopped || signal?.aborted || currentOrigin() !== scope.origin) throw Error("Message recovery closed"); }
    function close() { stopped = true; for (const tx of transactions) try { tx.abort(); } catch {} db?.close(); signal?.removeEventListener("abort", close); }
    signal?.addEventListener("abort", close, { once: true }); guard();
    let sdk;
    try {
      sdk = Object.assign({}, ...await Promise.all(["reviewed-intent03", "owner-reviewed-send03", "accepted-manifest-history03", "draft01"].map(importSdk))); guard();
      db = await new Promise((resolve, reject) => {
        const request = indexedDB.open(name, 1); let refused = false;
        const fail = () => { refused = true; clearTimeout(timer); reject(Error("Message recovery unavailable")); };
        const timer = setTimeout(fail, 5000); request.onerror = request.onblocked = fail;
        request.onupgradeneeded = () => { if (refused || stopped || signal?.aborted) request.transaction.abort(); else { request.result.createObjectStore("attempts"); request.result.createObjectStore("pending"); } };
        request.onsuccess = () => { clearTimeout(timer); if (refused || stopped || signal?.aborted) { request.result.close(); fail(); } else resolve(request.result); };
      });
      guard(); if (db.objectStoreNames.length !== 2 || !db.objectStoreNames.contains("attempts") || !db.objectStoreNames.contains("pending")) throw Error("Message recovery schema refused"); db.onversionchange = close;
    } catch (e) { close(); throw e; }
    function recovery(r) {
      if (stages.indexOf(r.stage) < 3) throw Error("Original completed public packet required");
      return Object.freeze({ v: 1, origin: scope.origin, account_id: scope.accountId, user_id: scope.originalUserId, owner_session_id: r.owner_session_id,
        device_id: scope.deviceId, line_id: scope.lineId, root_fingerprint: sdk.manifestHistoryBase64url03(Uint8Array.from(scope.rootFingerprint.match(/../g), n => parseInt(n, 16))),
        packet: Object.freeze({ v: 1, envelope: r.envelope, reviewed_intent: r.reviewed_intent, reviewed_signature: r.reviewed_signature }) });
    }
    async function validate(r) {
      guard(); const stage = stages.indexOf(r.stage);
      if (stage >= 1 && !sdk.isCanonicalP256Signature(binary(r.envelope, 557, 34213).slice(-64))) throw Error("Canonical original envelope signature required");
      if (stage >= 2) {
        const f = sdk.decodeReviewedIntent03V2(binary(r.reviewed_intent, 592, 803)), envelope = binary(r.envelope, 557, 34213);
        for (const [value, wanted] of [[f.accountId, scope.accountId], [f.ownerUserId, scope.originalUserId], [f.ownerSessionId, r.owner_session_id], [f.deviceId, scope.deviceId], [f.lineId, scope.lineId], [f.messageId, r.message_id], [f.intervalId, r.interval_id]])
          if (uuid(value) !== wanted) throw Error("Original reviewed identity changed");
        if (hex(f.rootFingerprint) !== scope.rootFingerprint || new TextDecoder().decode(f.peer) !== scope.peer
            || !same(f.envelopeDigest, await sha(envelope)) || !same(f.unsignedDigest, await sha(envelope.slice(0, -64)))
            || !same(f.originDigest, await sha(new TextEncoder().encode(scope.origin)))) throw Error("Original reviewed commitments changed");
        if (r.receipt) {
          const p = r.receipt;
          if (p.sms_ceiling !== f.smsCeiling || decimal(p.expires_ms) !== f.messageExpiresMs || decimal(p.selection_epoch) !== f.accountSelectionEpoch
              || decimal(p.accepted_ms) < f.reviewIssuedMs || decimal(p.accepted_ms) >= f.reviewExpiresMs
              || p.envelope_sha256 !== sdk.manifestHistoryBase64url03(f.envelopeDigest)
              || p.reviewed_intent_sha256 !== sdk.manifestHistoryBase64url03(await sha(binary(r.reviewed_intent, 592, 803)))
              || p.reviewed_signature_sha256 !== sdk.manifestHistoryBase64url03(await sha(binary(r.reviewed_signature, 64)))) throw Error("Original receipt commitments changed");
        }
      }
      if (stage >= 3) await sdk.captureReviewedSendRecovery03(recovery(r)); guard(); return r;
    }
    function decode(raw) {
      if (typeof raw !== "string" || raw.length > 96000) throw Error("Bounded message recovery required");
      const r = capture(JSON.parse(raw), scope); if (JSON.stringify(r) !== raw) throw Error("Canonical message recovery required"); return r;
    }
    function transaction(mode, run) {
      guard(); return new Promise((resolve, reject) => {
        const tx = db.transaction(["attempts", "pending"], mode); transactions.add(tx); let result;
        const finish = () => { clearTimeout(timer); transactions.delete(tx); };
        const timer = setTimeout(() => { try { tx.abort(); } catch {} reject(Error("Message commit timed out")); }, 5000);
        tx.oncomplete = () => { finish(); try { guard(); resolve(result); } catch (e) { reject(e); } };
        tx.onerror = tx.onabort = () => { finish(); reject(Error("Message recovery transaction refused")); };
        const safe = fn => () => { try { guard(); fn(); } catch { try { tx.abort(); } catch {} } };
        try { run(tx.objectStore("attempts"), v => { result = v; }, tx, safe, tx.objectStore("pending")); } catch { tx.abort(); }
      });
    }
    async function read(messageId) {
      id(messageId); const r = await transaction("readonly", (store, done, _tx, safe) => {
        const request = store.get([key, messageId]); request.onsuccess = safe(() => { const value = request.result === undefined ? null : decode(request.result);
          if (value && value.message_id !== messageId) throw Error("Original message index changed"); done(value); });
      }); return r === null ? null : validate(r);
    }
    async function page(options = { afterMessageId: null, limit: 16 }) {
      const o = closed(options, ["afterMessageId", "limit"]); if (o.afterMessageId !== null) id(o.afterMessageId);
      if (!Number.isInteger(o.limit) || o.limit < 1 || o.limit > 16) throw Error("Bounded message page required");
      const rows = await transaction("readonly", (store, done, _tx, safe) => {
        const request = store.getAll(IDBKeyRange.bound([key, o.afterMessageId ?? ""], [key, "\uffff"], o.afterMessageId !== null), o.limit + 1);
        request.onsuccess = safe(() => done(request.result));
      });
      const values = Object.freeze(await Promise.all(rows.slice(0, o.limit).map(raw => validate(decode(raw))))); guard();
      return Object.freeze({ attempts: values, nextMessageId: rows.length > o.limit ? values.at(-1).message_id : null });
    }
    async function compareAndSet(expected, candidate) {
      // Own all descriptors and nested public fields before the first await.
      const before = expected === null ? null : capture(expected, scope), after = capture(candidate, scope), serialized = JSON.stringify(after);
      if (serialized.length > 96000) throw Error("Message record bounded"); await validate(after); guard();
      if (before) {
        if (before.message_id !== after.message_id || before.interval_id !== after.interval_id || before.owner_session_id !== after.owner_session_id
            || before.unsigned_envelope !== after.unsigned_envelope || before.closed && !after.closed) throw Error("Original message cannot change");
        for (const k of ["envelope", "reviewed_intent", "reviewed_signature", "receipt"]) if (before[k] !== null && !equal(before[k], after[k])) throw Error("Original public proof cannot change");
        const a = stages.indexOf(before.stage), b = stages.indexOf(after.stage);
        const closing = !before.closed && after.closed && a === b;
        if (!closing && (b !== a + 1 || before.closed && !(a === 4 && b === 5))) throw Error("Signing or submission cannot restart");
      } else if (after.stage !== stages[0] || after.closed) throw Error("Reserve original signing before use");
      await transaction("readwrite", (store, done, tx, safe, pending) => {
        const request = store.get([key, after.message_id]); request.onsuccess = safe(() => {
          if (before === null ? request.result !== undefined : request.result !== JSON.stringify(before)) { tx.abort(); return; }
          const write = () => {
            if (before === null) store.add(serialized, [key, after.message_id]); else store.put(serialized, [key, after.message_id]);
            if (after.stage === "submit_reserved") pending.put(true, [key, after.message_id]);
            if (after.stage === "accepted") pending.delete([key, after.message_id]); done();
          };
          if (after.stage === "submit_reserved" && before.stage !== "submit_reserved") {
            const unresolved = pending.getAllKeys(IDBKeyRange.bound([key, ""], [key, "\uffff"]), 1);
            unresolved.onsuccess = safe(() => { if (unresolved.result.length) { tx.abort(); return; } write(); });
          } else write();
        });
      });
      const actual = await read(after.message_id); guard(); if (!equal(actual, after)) throw Error("Message commit readback refused"); return actual;
    }
    function hasUnresolvedSubmission() {
      return transaction("readonly", (_store, done, _tx, safe, pending) => {
        const request = pending.getAllKeys(IDBKeyRange.bound([key, ""], [key, "\uffff"]), 1); request.onsuccess = safe(() => done(request.result.length !== 0));
      });
    }
    // Durable records are public recovery, never a permission or a restorable
    // signing handle. A cold record may only be inspected/reconciled. Callers
    // must burn before each effect, retain RAM-only authority, and never retry
    // an uncertain signature, submission or radio operation.
    return Object.freeze({ read, page, compareAndSet, hasUnresolvedSubmission, recovery: r => recovery(capture(r, scope)), close });
  }
  const api = Object.freeze({ open }); if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ZtMessage03Recovery = api;
})(globalThis);
