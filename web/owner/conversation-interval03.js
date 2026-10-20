// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  const modules = ["owner-conversation-interval03", "conversation-interval03", "browser-message-signer-store03", "accepted-manifest-history03", "draft01"];
  const hex = b => Array.from(b, v => v.toString(16).padStart(2, "0")).join("");
  const bytes = s => { if (typeof s !== "string" || !/^(?:[0-9a-f]{2})+$/.test(s) || /^0+$/.test(s)) throw Error("Compared public identity required"); return Uint8Array.from(s.match(/../g), v => parseInt(v, 16)); };
  const id = s => { if (typeof s !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(s)) throw Error("Original identity required"); return s; };
  const uuid = s => bytes(id(s).replaceAll("-", ""));
  const text = b => hex(b).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
  const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  function closed(v, names) {
    if (!v || ![Object.prototype, null].includes(Object.getPrototypeOf(v))) throw Error("Explicit conversation selection required");
    const ds = Object.getOwnPropertyDescriptors(v);
    if (Reflect.ownKeys(ds).length !== names.length || names.some(k => !ds[k] || !("value" in ds[k]))) throw Error("Closed conversation selection required");
    return Object.fromEntries(names.map(k => [k, ds[k].value]));
  }
  async function contentChoices(history) {
    const c = await history.proposalContext(), raw = c.signedManifest, archives = [], phones = [];
    history.assertOpen();
    if (!(raw instanceof Uint8Array) || raw.length !== 153 + 149 * raw[152] + 64) throw Error("Verified content key history required");
    for (let i = 0; i < raw[152]; i++) {
      const r = raw.slice(153 + i * 149, 153 + (i + 1) * 149), view = new DataView(r.buffer);
      if (r[148] !== 1 || c.nowMs < view.getBigUint64(132) || c.nowMs >= view.getBigUint64(140)) continue;
      const key = Object.freeze({ keyId: hex(r.slice(1, 33)), validUntilMs: String(view.getBigUint64(140)) });
      if (r[0] === 2) archives.push(key);
      if (r[0] === 4 && text(r.slice(98, 114)) === c.scope.device && text(r.slice(114, 130)) === c.scope.line) phones.push(key);
    }
    // Root-verified public choices only; no current lease, registry, private
    // custody, installed ACK or content permission is inferred by discovery.
    return Object.freeze({ archives: Object.freeze(archives), phones: Object.freeze(phones) });
  }
  function create({ enabled = false, history, readSelection, document = root.document, window = root.window, fetch = root.fetch,
    monotonic = () => performance.now(), importSdk = name => import("/v1/owner/conversation-sdk/sdk/" + name + ".js"),
    openRecovery = options => root.ZtInterval03Recovery.open(options), openKeyStore, timeoutMs = 15000 } = {}) {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw Error("Bounded consent action required");
    const lifetime = new AbortController(), listeners = new Set();
    let closedState = !enabled, busy = false, phase = "unprepared", sdk, selected, choice, checkpoint, token, store, journal, client, saved, lease, keyScope;
    let tick = 0, primary = 0n, primaryTick = 0, observed = 0n, parentObserved = 0n, timer, reconciled = false, verified = false, verifiedDeadline = 0n, localStopped = false, transportAbort, activeDone, stopping;
    const position = p => JSON.stringify([String(p.position.version), hex(p.position.digest), hex(p.position.ancestry)]);
    function capture() {
      const s = closed(readSelection(), ["peer", "archiveReaderKeyId", "phoneSignerKeyId", "integrationReaders", "retentionConsent"]);
      if (s.retentionConsent !== true || typeof s.peer !== "string" || !/^\+[1-9][0-9]{1,14}$/.test(s.peer)) throw Error("Explicit retained conversation selection required");
      for (const k of ["archiveReaderKeyId", "phoneSignerKeyId"]) if (bytes(s[k]).length !== 32) throw Error("Compared content key required");
      if (!Array.isArray(s.integrationReaders) || Object.getPrototypeOf(s.integrationReaders) !== Array.prototype || s.integrationReaders.length > 6
          || Reflect.ownKeys(s.integrationReaders).length !== s.integrationReaders.length + 1) throw Error("Closed selected readers required");
      s.integrationReaders = Object.freeze(Array.from({ length: s.integrationReaders.length }, (_, i) => {
        const d = Object.getOwnPropertyDescriptor(s.integrationReaders, String(i)); if (!d || !("value" in d)) throw Error("Owned selected readers required");
        const m = closed(d.value, ["connectorId", "readGrantId", "keyId"]); id(m.connectorId); id(m.readGrantId);
        if (bytes(m.keyId).length !== 32) throw Error("Compared reader key required"); return Object.freeze(m);
      })); return Object.freeze(s);
    }
    function csrf() {
      const values = document.cookie.split(";").map(v => v.trim()).filter(v => v.startsWith("__Host-zrotext_csrf="));
      if (values.length !== 1) throw Error("Current owner session required");
      const value = decodeURIComponent(values[0].slice(20));
      if (!/^ztc_[A-Za-z0-9_-]{43}$/.test(value) || !/^[AEIMQUYcgkosw048]$/.test(value.slice(-1))) throw Error("Current owner session required"); return value;
    }
    function close() {
      if (closedState) return; closedState = true; phase = "closed"; verified = false; lifetime.abort(); transportAbort?.abort(); clearTimeout(timer);
      for (const release of [() => lease?.close(), () => store?.close(), () => journal?.close()]) try { release(); } catch {}
      window.removeEventListener?.("pagehide", close); document.removeEventListener?.("visibilitychange", hidden);
      for (const fn of listeners) try { fn(); } catch {} listeners.clear();
    }
    function guard() {
      try {
        const n = monotonic(); history.assertOpen();
        if (!Number.isFinite(n) || n < tick || closedState || document.hidden || lifetime.signal.aborted
            || selected && (window.location.origin !== selected.origin || csrf() !== token || !history.state().durable
              || position(history.checkpoint()) !== checkpoint || JSON.stringify(capture()) !== JSON.stringify(choice))) throw Error("Conversation consent withdrawn");
        tick = n;
      } catch (e) { close(); throw e; }
    }
    const hidden = () => { if (document.hidden) close(); };
    if (enabled) { history.onClose(close); window.addEventListener?.("pagehide", close); document.addEventListener?.("visibilitychange", hidden); }
    function now() { guard(); if (!primary) throw Error("Current service time required"); return primary + BigInt(Math.floor(monotonic() - primaryTick)); }
    function observe(value, started, comparison = false) {
      const before = primary ? now() : 0n;
      // A parent's elapsed/RTT-conservative clock can be ahead of a later
      // actual primary comparison. Keep both monotone floors independently;
      // neither source may lower the conservative local expiry clock.
      if (comparison) { if (value < observed) throw Error("Primary time regressed"); observed = value; }
      else { if (value < parentObserved) throw Error("Parent clock regressed"); parentObserved = value; }
      primary = value; primaryTick = started;
      if (now() < before) { primary = before; primaryTick = monotonic(); }
    }
    async function actualScope() {
      guard(); const started = monotonic(), c = await history.proposalContext(); guard();
      if (selected && JSON.stringify(c.scope) !== JSON.stringify(selected)) { close(); throw Error("Original owner sign-in changed"); }
      observe(c.nowMs, started); return c;
    }
    function snapshot() {
      if (verified) try { if (now() >= verifiedDeadline) { verified = false; phase = "permission_expired"; } } catch { verified = false; }
      let canPrepareFresh = false;
      if (saved && !closedState && !saved.reserve_submitted && !saved.original && !saved.receipt) try { canPrepareFresh = now() >= BigInt(saved.command.interval_expires_ms); } catch {}
      return Object.freeze({ phase, closed: closedState, busy, openingId: saved?.command.opening_id ?? null,
      intervalId: saved?.receipt?.interval_id ?? null, originalSaved: !!saved?.original, submitted: !!saved?.request_submitted,
      reserveSubmitted: !!saved?.reserve_submitted, hasReceipt: !!saved?.receipt, localStopped,
      peer: choice?.peer ?? null, expiresMs: saved?.command.interval_expires_ms ?? null, readerCount: choice?.integrationReaders.length ?? 0,
      canPrepareFresh,
      historical: !!saved && saved.owner_session_id !== selected?.session, reconciled, verifiedActive: verified }); }
    async function action(run) {
      guard(); if (busy) throw Error("Consent action pending"); busy = true;
      let releaseIdle; activeDone = new Promise(resolve => { releaseIdle = resolve; });
      let withdraw; const stopped = new Promise((_, reject) => { withdraw = () => reject(Error("Consent action withdrawn")); lifetime.signal.addEventListener("abort", withdraw, { once: true }); });
      timer = setTimeout(close, timeoutMs);
      try { return await Promise.race([run(), stopped]); }
      catch (e) { verified = false; if (!closedState) phase = localStopped ? "stopping" : e?.outcome === "unknown" ? "unknown" : "interrupted"; throw e; }
      finally { clearTimeout(timer); lifetime.signal.removeEventListener("abort", withdraw); busy = false; releaseIdle(); }
    }
    function writable() { guard(); if (localStopped) throw Error("Local consent withdrawn"); }
    async function save(candidate) { const result = await journal.compareAndSet(saved ?? null, candidate); guard(); saved = result; return result; }
    async function publicRecovery(r) {
      guard(); if (!saved || r.origin !== selected.origin || r.account_id !== selected.account || r.user_id !== selected.user
          || r.owner_session_id !== selected.session || r.device_id !== selected.device || r.line_id !== selected.line) throw Error("Original transport scope changed");
      if (r.kind !== "stop") writable();
      if (r.kind === "reservation" && JSON.stringify(r.packet) === JSON.stringify(saved.command)) await save({ ...saved, reserve_submitted: true });
      else if (r.kind === "request" && JSON.stringify(r.packet) === JSON.stringify(saved.original)) await save({ ...saved, request_submitted: true });
      else if (r.kind === "stop" && r.packet.interval_id === saved.receipt?.interval_id) await save({ ...saved, stop_submitted: true });
      else throw Error("Original public transport packet changed");
    }
    function transport() {
      transportAbort?.abort(); transportAbort = new AbortController();
      client = new sdk.OwnerConversationIntervalClient03({ origin: selected.origin, accountId: selected.account, userId: selected.user, ownerSessionId: selected.session,
        deviceId: selected.device, lineId: selected.line, rootFingerprint: bytes(selected.rootFingerprint), currentCsrf: csrf, signal: transportAbort.signal, fetchImpl: fetch, timeoutMs, saveRecovery: publicRecovery });
    }
    function selection() {
      return { peer: new TextEncoder().encode(choice.peer), archiveReaderKeyId: bytes(choice.archiveReaderKeyId), phoneSignerKeyId: bytes(choice.phoneSignerKeyId),
        browserSignerKeyId: sdk.manifestHistoryBinary03(saved.command.browser_signer_key_id, 32),
        integrationReaders: choice.integrationReaders.map(m => ({ connectorId: uuid(m.connectorId), readGrantId: uuid(m.readGrantId), keyId: bytes(m.keyId) })) };
    }
    async function match(r) {
      const s = await sdk.decodeConversationStatement03(sdk.manifestHistoryBinary03(r.statement, 695, 1092)); guard(); const c = saved.command;
      if (r.opening_id !== c.opening_id || text(s.ownerSessionId) !== saved.owner_session_id || new TextDecoder().decode(s.peer) !== c.peer
          || String(s.intervalUntilMs) !== c.interval_expires_ms || sdk.manifestHistoryBase64url03(s.archiveReaderKeyId) !== c.archive_reader_key_id
          || sdk.manifestHistoryBase64url03(s.phoneSignerKeyId) !== c.phone_signer_key_id || sdk.manifestHistoryBase64url03(s.browserSignerKeyId) !== c.browser_signer_key_id
          || s.integrationReaders.length !== c.integration_readers.length || s.integrationReaders.some((m, i) => text(m.connectorId) !== c.integration_readers[i].connector_id
            || text(m.readGrantId) !== c.integration_readers[i].read_grant_id || sdk.manifestHistoryBase64url03(m.keyId) !== c.integration_readers[i].key_id)) throw Error("Original reservation changed");
      if (saved.receipt && (r.interval_id !== saved.receipt.interval_id || r.statement !== saved.receipt.statement)
          || saved.original && (r.statement !== saved.original.statement || r.owner_signature !== null && r.owner_signature !== saved.original.owner_signature)) throw Error("Original signed consent changed"); return s;
    }
    async function current(r, pending) {
      await actualScope(); const started = monotonic();
      const checked = await history.conversationContext({ openingId: r.opening_id, intervalId: r.interval_id,
        statement: sdk.manifestHistoryBinary03(r.statement, 695, 1092), selection: selection() }); guard();
      observe(checked.comparedMs, started, true);
      const at = now(); if (at >= checked.permissionExpiresMs || pending && at >= checked.statement.setupExpiresMs) throw Error("Current consent window ended");
      return checked;
    }
    async function possession(keyId) {
      lease?.close(); lease = await store.load(keyScope, keyId); guard();
      if (lease.keyId !== keyId) throw Error("Retained browser signer unavailable"); return lease;
    }
    async function accept(r) {
      const s = await match(r); guard(); await save({ ...saved, receipt: r }); verified = false;
      if (["stopped", "expired"].includes(r.phase)) { reconciled = true; phase = r.phase; return snapshot(); }
      if (localStopped) { phase = "stopping"; return snapshot(); }
      if (saved.owner_session_id !== selected.session) { reconciled = true; phase = "historical_only"; return snapshot(); }
      const c = await current(r, false), signature = (proof, time) => r[proof] === null ? null : { signature: sdk.manifestHistoryBinary03(r[proof], 64), timeMs: BigInt(r[time]) };
      await sdk.verifyConversationReceipts03({ context: c.context, statement: sdk.manifestHistoryBinary03(r.statement, 695, 1092), request: signature("owner_signature", "requested_ms"),
        approval: signature("phone_signature", "approved_ms"), installed: signature("installed_signature", "installed_ms"), nowMs: now(), pending: false }); guard();
      await possession(hex(s.browserSignerKeyId)); guard();
      if (now() >= c.permissionExpiresMs || now() >= s.intervalUntilMs) throw Error("Current consent window ended");
      reconciled = true; verifiedDeadline = c.permissionExpiresMs < s.intervalUntilMs ? c.permissionExpiresMs : s.intervalUntilMs;
      verified = r.phase === "active" && !saved.stop_submitted && !localStopped; phase = saved.stop_submitted || localStopped ? "stopping" : verified ? "active_verified" : r.phase; return snapshot();
    }
    async function open() { return action(async () => {
      if (selected) throw Error("Consent already opened"); choice = capture();
      const c = await actualScope(); selected = c.scope; checkpoint = position(c); token = csrf(); guard();
      sdk = Object.assign({}, ...await Promise.all(modules.map(importSdk))); guard();
      keyScope = Object.freeze({ origin: selected.origin, accountId: selected.account, originalUserId: selected.user, deviceId: selected.device, lineId: selected.line, rootFingerprint: selected.rootFingerprint });
      store = await (openKeyStore ? openKeyStore({ signal: lifetime.signal, currentOrigin: () => window.location.origin }) : sdk.BrowserMessageSigner03KeyStore.open({ signal: lifetime.signal, currentOrigin: () => window.location.origin })); guard();
      journal = await openRecovery({ scope: { ...keyScope, peer: choice.peer }, signal: lifetime.signal, currentOrigin: () => window.location.origin }); guard();
      saved = await journal.read(); guard();
      localStopped = !!saved?.stop_submitted; transport();
      phase = saved ? "saved_attempt" : "ready"; return snapshot();
    }); }
    async function begin({ durationMs } = {}) { return action(async () => {
      if (!journal) throw Error("Original consent journal required");
      await actualScope();
      const expiredUnsent = saved && !saved.reserve_submitted && !saved.original && !saved.receipt && now() >= BigInt(saved.command.interval_expires_ms);
      if (saved && !(expiredUnsent || reconciled && ["stopped", "expired"].includes(saved.receipt?.phase))) throw Error("Reconcile original consent first");
      if (!Number.isSafeInteger(durationMs) || durationMs < 1000 || durationMs > 86400000) throw Error("Explicit bounded interval required");
      localStopped = false;
      const metadata = await store.metadata(keyScope); guard(); if (!metadata) throw Error("Recover existing browser message key first");
      const b64 = sdk.manifestHistoryBase64url03;
      const command = { v: 1, opening_id: crypto.randomUUID(), line_id: selected.line, peer: choice.peer, archive_reader_key_id: b64(bytes(choice.archiveReaderKeyId)),
        phone_signer_key_id: b64(bytes(choice.phoneSignerKeyId)), browser_signer_key_id: b64(bytes(metadata.keyId)), interval_expires_ms: String(now() + BigInt(durationMs)),
        integration_readers: choice.integrationReaders.map(m => ({ connector_id: m.connectorId, read_grant_id: m.readGrantId, key_id: b64(bytes(m.keyId)) })) };
      await save({ v: 1, owner_session_id: selected.session, command, original: null, receipt: null, reserve_submitted: false, request_submitted: false, stop_submitted: false });
      reconciled = verified = false; const r = await client.reserve(saved.command); guard(); return accept(r);
    }); }
    async function check() { return action(async () => {
      if (!saved?.reserve_submitted) throw Error("Original submitted reservation required");
      const r = saved.receipt ? await client.status(saved.command.opening_id, saved.receipt.interval_id) : await client.openingStatus(saved.command.opening_id); guard(); return accept(r);
    }); }
    async function resumeReservation() { return action(async () => {
      if (!saved || saved.reserve_submitted || saved.receipt || localStopped || saved.owner_session_id !== selected.session) throw Error("Check the original submitted reservation first");
      await actualScope(); if (now() >= BigInt(saved.command.interval_expires_ms)) throw Error("Prepare a fresh explicit request for the expired unsent reservation");
      const metadata = await store.metadata(keyScope); writable();
      if (!metadata || sdk.manifestHistoryBase64url03(bytes(metadata.keyId)) !== saved.command.browser_signer_key_id) throw Error("Original retained browser key required");
      if (now() >= BigInt(saved.command.interval_expires_ms)) throw Error("Original unsent reservation expired");
      reconciled = false; const r = await client.reserve(saved.command); guard(); return accept(r);
    }); }
    async function review({ disclosure = false } = {}) { return action(async () => {
      if (localStopped || !disclosure || !saved?.receipt || saved.original || saved.owner_session_id !== selected.session || saved.stop_submitted
          || !reconciled || saved.receipt.phase !== "reserved") throw Error("Explicit original consent review required");
      const r = saved.receipt, c = await current(r, true), raw = sdk.manifestHistoryBinary03(r.statement, 695, 1092);
      const statement = await sdk.checkConversationStatement03(raw, c.context, now()); writable(); const keyId = hex(statement.browserSignerKeyId), retained = await possession(keyId);
      const signature = await retained.withKey(keyScope, keyId, async key => {
        writable(); if (now() >= c.permissionExpiresMs || now() >= statement.setupExpiresMs) throw Error("Consent review expired");
        const value = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, sdk.conversationRequestTranscript03(raw)); writable(); return sdk.canonicalP256Signature(new Uint8Array(value));
      }); writable();
      const publicKey = await crypto.subtle.importKey("raw", bytes(retained.publicPoint), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]); guard();
      if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature, sdk.conversationRequestTranscript03(raw))) throw Error("Retained key proof refused"); guard();
      writable(); if (now() >= c.permissionExpiresMs || now() >= statement.setupExpiresMs) throw Error("Consent review expired");
      await save({ ...saved, original: { v: 1, opening_id: r.opening_id, interval_id: r.interval_id, statement: r.statement, owner_signature: sdk.manifestHistoryBase64url03(signature) } });
      if (now() >= c.permissionExpiresMs || now() >= statement.setupExpiresMs) throw Error("Consent review expired");
      phase = "signed_request"; return snapshot();
    }); }
    async function request(credentials) {
      const factors = closed(credentials, ["password", "factor"]);
      for (const k of ["password", "factor"]) if (typeof factors[k] !== "string" || !factors[k].length || factors[k].length > 1024) throw Error("Explicit current owner factors required");
      return action(async () => {
      if (localStopped || !saved?.original || saved.owner_session_id !== selected.session || saved.stop_submitted || !reconciled || saved.receipt?.phase !== "reserved") throw Error("Reconcile the saved signed consent first");
      const c = await current(saved.receipt, true), retained = await possession(hex(c.statement.browserSignerKeyId)); writable();
      const key = await crypto.subtle.importKey("raw", bytes(retained.publicPoint), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]); writable();
      if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sdk.manifestHistoryBinary03(saved.original.owner_signature, 64),
        sdk.conversationRequestTranscript03(sdk.manifestHistoryBinary03(saved.original.statement, 695, 1092)))) throw Error("Original browser signature refused"); writable();
      if (now() >= c.permissionExpiresMs || now() >= c.statement.setupExpiresMs) throw Error("Consent request expired");
      reconciled = verified = false; const r = await client.request(saved.original, factors); guard(); return accept(r);
    }); }
    function stop() {
      verified = false; reconciled = false; localStopped = true; phase = "stopping"; transportAbort?.abort();
      if (stopping) return stopping;
      const idle = activeDone;
      stopping = (async () => {
        if (busy) await idle;
        if (closedState) return snapshot();
        transport(); return action(async () => {
          if (!saved?.receipt) throw Error("Check the original reservation before stopping it on the service");
          await client.stop(saved.receipt.interval_id); guard(); phase = "stopping"; return snapshot();
        });
      })().finally(() => { stopping = null; }); return stopping;
    }
    return Object.freeze({ open, begin, resumeReservation, check, review, request, stop, state: snapshot, close,
      onClose: fn => { if (typeof fn !== "function") throw Error("Close callback required"); listeners.add(fn); } });
  }
  const api = Object.freeze({ create, contentChoices }); if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ZtConversationInterval03 = api;
})(globalThis);
