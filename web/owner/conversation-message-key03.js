// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  const enc = new TextEncoder(), modules = ["browser-message-signer-store03", "profile03-manifest-proposal", "manifest-install03", "owner-profile-election-client", "draft01", "accepted-manifest-history03"];
  const hex = b => Array.from(b, v => v.toString(16).padStart(2, "0")).join("");
  const bytes = h => { if (typeof h !== "string" || !/^(?:[0-9a-f]{2})+$/.test(h)) throw Error("Compared identity required"); return Uint8Array.from(h.match(/../g), v => parseInt(v, 16)); };
  const uuid = h => { const out = bytes(h.replaceAll("-", "")); if (out.length !== 16 || !out.some(v => v)) throw Error("Original identity required"); return out; };
  const text = b => hex(b).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
  const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  const sha = async b => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
  const cat = (...xs) => { const b = new Uint8Array(xs.reduce((n, x) => n + x.length, 0)); let at = 0; for (const x of xs) { b.set(x, at); at += x.length; } return b; };
  const frame = (label, b) => { const n = new Uint8Array(4); new DataView(n.buffer).setUint32(0, b.length); return cat(enc.encode(label + "\0"), n, b); };
  function create({ enabled = false, history, document = root.document, window = root.window, fetch = root.fetch,
    monotonic = () => performance.now(), importSdk = name => import("/v1/owner/conversation-sdk/sdk/" + name + ".js"),
    openRecovery = options => root.ZtMessageKey03Recovery.open(options), openKeyStore, timeoutMs = 15000 } = {}) {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw Error("Bounded setup operation required");
    const lifetime = new AbortController(), listeners = new Set();
    let closed = !enabled, busy = false, phase = "unprepared", sdk, store, journal, lease, client, selected, token, keyScope, metadata, saved, input, original;
    let clock = 0n, clockTick = 0, observedClock = 0n, lastTick = 0, timer, confirmed = false, acceptedVerified = false, requestedTarget = null;
    function csrf() {
      const values = document.cookie.split(";").map(s => s.trim()).filter(s => s.startsWith("__Host-zrotext_csrf="));
      if (values.length !== 1) throw Error("Current owner session required");
      const value = decodeURIComponent(values[0].slice(20));
      if (!/^ztc_[A-Za-z0-9_-]{43}$/.test(value) || !/^[AEIMQUYcgkosw048]$/.test(value.slice(-1))) throw Error("Current owner session required"); return value;
    }
    function close() {
      if (closed) return; closed = true; phase = "closed"; lifetime.abort(); clearTimeout(timer);
      for (const release of [() => client?.close(), () => lease?.close(), () => store?.close(), () => journal?.close()]) try { release(); } catch {}
      input = original = null; window.removeEventListener?.("pagehide", close); document.removeEventListener?.("visibilitychange", hidden);
      for (const fn of listeners) try { fn(); } catch {} listeners.clear();
    }
    function guard() {
      try {
        const n = monotonic();
        history.assertOpen();
        if (!Number.isFinite(n) || n < lastTick || closed || document.hidden || lifetime.signal.aborted || history.state().closed
            || selected && (window.location.origin !== selected.origin || csrf() !== token)) throw Error("Browser message setup withdrawn");
        lastTick = n;
      } catch (e) { close(); throw e; }
    }
    const hidden = () => { if (document.hidden) close(); };
    if (enabled) { history.onClose(close); window.addEventListener?.("pagehide", close); document.addEventListener?.("visibilitychange", hidden); }
    function now() { guard(); if (!clock) throw Error("Current service time required"); return clock + BigInt(Math.floor(monotonic() - clockTick)); }
    async function context(target = false) {
      guard(); const started = monotonic(), c = await history.proposalContext(target); guard();
      if (selected && JSON.stringify(c.scope) !== JSON.stringify(selected)) { close(); throw Error("Original sign-in changed"); }
      const prior = clock ? now() : 0n;
      if (c.nowMs < observedClock) throw Error("Setup clock regressed"); observedClock = c.nowMs; clock = c.nowMs; clockTick = started;
      if (now() < prior) { clock = prior; clockTick = monotonic(); } return c;
    }
    function snapshot() { return Object.freeze({ phase, closed, busy, keyId: metadata?.keyId ?? null, openingId: saved?.original?.opening_id ?? null,
      hasProposal: !!saved, hasOriginal: !!saved?.original, hasReceipt: !!saved?.receipt,
      canResumeInstall: !!saved?.original && saved.submitted === false && !saved.receipt, confirmed }); }
    async function action(run) {
      guard(); if (busy) throw Error("Browser message setup pending"); busy = true;
      let withdraw; const stopped = new Promise((_, reject) => { withdraw = () => reject(Error("Browser message action withdrawn")); lifetime.signal.addEventListener("abort", withdraw, { once: true }); });
      timer = setTimeout(close, timeoutMs);
      try { return await Promise.race([run(), stopped]); }
      catch (e) { if (!closed && !["unknown", "saved_accepted", "history_required", "ready_install"].includes(phase)) phase = e?.outcome === "unknown" ? "unknown" : "interrupted"; throw e; }
      finally { clearTimeout(timer); lifetime.signal.removeEventListener("abort", withdraw); busy = false; }
    }
    const position = p => ({ version: BigInt(p.version), digest: bytes(p.digest), ancestry: bytes(p.ancestry_sha256) });
    const wirePosition = p => ({ version: String(p.version), digest: hex(p.digest), ancestry_sha256: hex(p.ancestry) });
    function equalPosition(a, b) { return a.version === b.version && same(a.digest, b.digest) && same(a.ancestry, b.ancestry); }
    function proposalInput(c, p) {
      return { predecessor: c.historicalManifest, originalSigned03: c.signedManifest, nowMs: c.nowMs,
        scope: { operation: p.operation, accountId: uuid(selected.account), deviceId: uuid(selected.device), lineId: uuid(selected.line), origin: selected.origin,
          rootFingerprint: bytes(selected.rootFingerprint), predecessorVersion: c.position.version, predecessorDigest: c.position.digest,
          predecessorAcceptedMs: c.acceptedMs, phoneReaderKeyId: c.election.selectedReaderKeyId, browserPoint: bytes(p.public_point), browserKeyId: bytes(p.key_id),
          issuedMs: BigInt(p.issued_ms), expiresMs: BigInt(p.expires_ms) } };
    }
    async function targetContext() {
      const c = await context();
      if (equalPosition(c.position, position(saved.predecessor))) return c;
      const prior = await context(true);
      if (!equalPosition(prior.position, position(saved.predecessor))) throw Error("Recheck the saved attempt's original history checkpoint"); return prior;
    }
    async function restoreInput() {
      const c = await targetContext(), p = saved.proposal, value = proposalInput(c, p);
      // Historical proposal reconstruction is not present permission. The
      // genuine full-chain checkpoint supplies the retained predecessor token.
      const regenerated = await sdk.encodeProfile03ManifestProposal({ ...value, nowMs: BigInt(p.issued_ms) }); guard();
      if (!same(regenerated.proposal, sdk.manifestHistoryBinary03(p.packet, 1, 20480))
          || !same(regenerated.unsigned, sdk.manifestHistoryBinary03(p.unsigned, 302, 9689))) throw Error("Original public proposal changed");
      input = value; return c;
    }
    function transport() {
      client?.close(); client = new sdk.OwnerProfileElectionClient03({ origin: selected.origin, accountId: selected.account, userId: selected.user, ownerSessionId: selected.session,
        deviceId: selected.device, rootFingerprint: bytes(selected.rootFingerprint), currentCsrf: csrf, signal: lifetime.signal, fetchImpl: fetch, timeoutMs,
        saveRecovery: async () => { throw Error("Election mutation unavailable in message-key setup"); } }); return client;
    }
    async function open() { return action(async () => {
      if (selected) throw Error("Browser message setup already opened");
      const c = await context(); selected = c.scope; token = csrf(); guard();
      sdk = Object.assign({}, ...await Promise.all(modules.map(importSdk))); guard();
      keyScope = Object.freeze({ origin: selected.origin, accountId: selected.account, originalUserId: selected.user, deviceId: selected.device, lineId: selected.line, rootFingerprint: selected.rootFingerprint });
      store = await (openKeyStore ? openKeyStore({ signal: lifetime.signal, currentOrigin: () => window.location.origin }) : sdk.BrowserMessageSigner03KeyStore.open({ signal: lifetime.signal, currentOrigin: () => window.location.origin })); guard();
      journal = await openRecovery({ scope: keyScope, signal: lifetime.signal, currentOrigin: () => window.location.origin }); guard();
      metadata = await store.metadata(keyScope); guard(); saved = await journal.read(); guard();
      phase = saved ? "saved_attempt" : "key_selected"; return snapshot();
    }); }
    async function prepare({ operation, retain = false, newKey = false } = {}) { return action(async () => {
      if (!store || saved && !confirmed || !["enroll", "renew", "replace"].includes(operation)) throw Error("Reconcile the saved original attempt first");
      const c = await context();
      if (!metadata) {
        if (!retain || !newKey || operation === "renew") throw Error("Explicit new retained key approval required");
        metadata = await store.create(keyScope, { retain: true, newEnrollment: true }); guard();
      }
      const p = { operation, issued_ms: String(c.nowMs), expires_ms: String(c.nowMs + 86400000n), key_id: metadata.keyId, public_point: metadata.publicPoint };
      const candidate = proposalInput(c, p), encoded = await sdk.encodeProfile03ManifestProposal(candidate); guard();
      const record = { v: 1, proposal: { ...p, unsigned: sdk.manifestHistoryBase64url03(encoded.unsigned), packet: sdk.manifestHistoryBase64url03(encoded.proposal) },
        predecessor: wirePosition(c.position), original: null, submitted: false, receipt: null };
      saved = await journal.compareAndSet(saved, record); guard(); input = candidate; confirmed = acceptedVerified = false; requestedTarget = null; original = null; phase = "awaiting_offline_approval";
      return Object.freeze({ proposal: Uint8Array.from(encoded.proposal), keyId: metadata.keyId });
    }); }
    async function resumeProposal() { return action(async () => {
      if (!saved || saved.original) throw Error("Original unsigned proposal required");
      await restoreInput(); guard(); phase = "awaiting_offline_approval";
      return Object.freeze({ proposal: sdk.manifestHistoryBinary03(saved.proposal.packet, 1, 20480), keyId: saved.proposal.key_id });
    }); }
    async function recoverHistory() { return action(async () => {
      if (!saved) throw Error("Saved original attempt required"); await history.restart(position(saved.predecessor)); guard(); phase = "history_required"; return snapshot();
    }); }
    async function authorize(file) { return action(async () => {
      if (!saved || saved.original || !metadata || metadata.keyId !== saved.proposal.key_id || !file || file.size < 366 || file.size > 9753) throw Error("Original retained key and signed public output required");
      const signed = new Uint8Array(await file.arrayBuffer()); guard(); if (signed.length !== file.size) throw Error("Signed output changed");
      let c = await restoreInput();
      await sdk.verifyProfile03ManifestOutput({ ...input, nowMs: now(), signed03: signed }); guard();
      c = await context(); if (!equalPosition(c.position, position(saved.predecessor))) throw Error("Accepted predecessor changed");
      const issued = now(), expires = issued + 300000n, e = c.election;
      const statement = await sdk.encodeManifestInstall03({ accountId: e.accountId, ownerUserId: uuid(selected.user), ownerSessionId: uuid(selected.session),
        deviceId: e.deviceId, lineId: e.lineId, bindingId: e.newBindingId, electionChallengeId: c.electionChallengeId, openingId: uuid(crypto.randomUUID()),
        bindingGeneration: e.newBindingGeneration, vaultGeneration: 1n, selectionEpoch: 1n, predecessorVersion: c.position.version, successorVersion: c.position.version + 1n,
        issuedMs: issued, expiresMs: expires, rootFingerprint: e.rootFingerprint, electionCommitment: e.electionCommitment, electionBundleSha256: e.electionBundleSha256,
        originDigest: await sha(enc.encode(selected.origin)), ownerSessionDigest: await sha(frame("ZTSE/line/payload-profile/owner-session/v1", cat(e.accountId, uuid(selected.user), uuid(selected.session)))),
        predecessorDigest: c.position.digest, signedSuccessorSha256: await sha(signed), signerKeyId: bytes(metadata.keyId), signerPoint: bytes(metadata.publicPoint) }); guard();
      lease?.close(); lease = await store.load(keyScope, metadata.keyId); guard();
      const transcript = await sdk.manifestInstallSigningBytes03(statement); guard();
      const signature = await lease.withKey(keyScope, metadata.keyId, async key => {
        guard(); if (now() >= expires) throw Error("Possession approval expired");
        const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, transcript)); guard();
        if (now() >= expires) throw Error("Possession approval expired"); return sdk.canonicalP256Signature(raw);
      }); guard();
      const possession = await sdk.verifyManifestInstallPossession03(statement, signature); guard();
      const record = { v: 1, origin: selected.origin, account_id: selected.account, user_id: selected.user, owner_session_id: selected.session, device_id: selected.device,
        root_fingerprint: sdk.manifestHistoryBase64url03(bytes(selected.rootFingerprint)), opening_id: text(possession.openingId), line_id: selected.line,
        statement: sdk.manifestHistoryBase64url03(statement), signature: sdk.manifestHistoryBase64url03(signature), successor_manifest03: sdk.manifestHistoryBase64url03(signed) };
      saved = await journal.compareAndSet(saved, { ...saved, original: record }); guard(); original = record; phase = "ready_install"; return snapshot();
    }); }
    async function verifyOriginal() {
      const c = await restoreInput(), r = saved.original;
      if (!r || r.account_id !== selected.account || r.user_id !== selected.user || r.device_id !== selected.device || r.line_id !== selected.line || r.origin !== selected.origin) throw Error("Original attempt scope changed");
      const statement = await sdk.verifyManifestInstallPossession03(sdk.manifestHistoryBinary03(r.statement, 513), sdk.manifestHistoryBinary03(r.signature, 64)); guard();
      await sdk.verifyProfile03ManifestOutput({ ...input, nowMs: statement.issuedMs, signed03: sdk.manifestHistoryBinary03(r.successor_manifest03, 366, 9753) }); guard();
      const e = c.election;
      for (const [actual, expected] of [[statement.accountId, e.accountId], [statement.deviceId, e.deviceId], [statement.lineId, e.lineId],
        [statement.bindingId, e.newBindingId], [statement.electionChallengeId, c.electionChallengeId], [statement.rootFingerprint, e.rootFingerprint],
        [statement.electionCommitment, e.electionCommitment], [statement.electionBundleSha256, e.electionBundleSha256],
        [statement.predecessorDigest, c.position.digest], [statement.signerPoint, bytes(saved.proposal.public_point)]]) if (!same(actual, expected)) throw Error("Original statement scope changed");
      if (statement.bindingGeneration !== e.newBindingGeneration || statement.vaultGeneration !== 1n || statement.selectionEpoch !== 1n
          || statement.predecessorVersion !== c.position.version || statement.successorVersion !== c.position.version + 1n
          || hex(statement.signerKeyId) !== saved.proposal.key_id) throw Error("Original signer changed");
      original = r; return statement;
    }
    async function retainReceipt(receipt) {
      const before = position(saved.predecessor);
      if (receipt.predecessor_version !== String(before.version) || receipt.predecessor_digest !== sdk.manifestHistoryBase64url03(before.digest)
          || receipt.predecessor_ancestry_sha256 !== sdk.manifestHistoryBase64url03(before.ancestry) || receipt.operation !== saved.proposal.operation) throw Error("Accepted attempt ancestry changed");
      // Acceptance already occurred. A failed local commit is UNKNOWN; it must
      // never reopen a mutation control or discard the exact original attempt.
      phase = "unknown"; saved = await journal.compareAndSet(saved, { ...saved, receipt }); guard(); acceptedVerified = true; phase = "saved_accepted";
    }
    async function install(factor) { return action(async () => {
      if (!original || phase !== "ready_install" || saved.submitted || saved.receipt) throw Error("Original unsent approval required");
      const statement = await verifyOriginal(); await context(); guard();
      if (original.owner_session_id !== selected.session || now() >= statement.expiresMs) throw Error("Original approval needs status reconciliation");
      try {
        const receipt = await transport().installManifest(original, factor, async record => {
          const actual = await journal.read(); guard();
          if (!actual?.original || Object.keys(actual.original).length !== Object.keys(record).length
              || Object.keys(record).some(k => actual.original[k] !== record[k])) throw Error("Committed original readback required");
          if (actual.submitted || actual.receipt) throw Error("Check the original submission status");
          saved = await journal.compareAndSet(actual, { ...actual, submitted: true }); guard();
        }); guard(); await retainReceipt(receipt); return snapshot();
      } catch (e) {
        phase = "unknown";
        if (e?.outcome === "refused") {
          const actual = await journal.read(); guard();
          if (actual?.original?.opening_id === original.opening_id && !actual.receipt) {
            saved = actual.submitted ? await journal.compareAndSet(actual, { ...actual, submitted: false }) : actual;
            guard(); phase = "ready_install";
          }
        }
        throw e;
      }
    }); }
    async function resumeInstall() { return action(async () => {
      if (!saved?.original || saved.submitted || saved.receipt || !metadata || metadata.keyId !== saved.proposal.key_id) throw Error("Original unsent retained approval required");
      const statement = await verifyOriginal(); await context(); guard();
      if (saved.original.owner_session_id !== selected.session || now() >= statement.expiresMs) throw Error("Original approval requires status and fresh explicit recovery");
      phase = "ready_install"; return snapshot();
    }); }
    async function check() { return action(async () => {
      if (!saved?.original) throw Error("Saved original possession approval required"); await verifyOriginal(); await context(); guard();
      const receipt = await transport().manifestStatus(saved.original); guard(); await retainReceipt(receipt); return snapshot();
    }); }
    async function confirm() { return action(async () => {
      if (!saved?.receipt || !acceptedVerified) throw Error("Check the accepted original receipt with the service first");
      const r = saved.receipt, target = { version: BigInt(r.successor_version), digest: sdk.manifestHistoryBinary03(r.successor_digest, 32), ancestry: sdk.manifestHistoryBinary03(r.ancestry_sha256, 32) };
      if (!requestedTarget) { await history.restart(target); guard(); requestedTarget = target; phase = "history_required"; return snapshot(); }
      const c = await context(true);
      if (!equalPosition(c.position, target) || c.acceptedMs !== BigInt(r.accepted_ms) || !same(c.signedManifest, sdk.manifestHistoryBinary03(r.successor_manifest03, 366, 9753))) throw Error("Exact accepted chain confirmation required");
      metadata = await store.metadata(keyScope); guard();
      if (!metadata || metadata.keyId !== saved.proposal.key_id) { phase = "accepted_key_missing"; return snapshot(); }
      confirmed = true; phase = "confirmed"; return snapshot();
    }); }
    return Object.freeze({ open, prepare, resumeProposal, recoverHistory, authorize, resumeInstall, install, check, confirm, state: snapshot, close,
      onClose: fn => { if (typeof fn !== "function") throw Error("Close callback required"); listeners.add(fn); } });
  }
  const api = Object.freeze({ create }); if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ZtBrowserMessageEnrollment03 = api;
})(globalThis);
