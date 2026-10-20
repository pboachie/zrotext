// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  const hex = b => Array.from(b, v => v.toString(16).padStart(2, "0")).join("");
  const bytes = h => { if (typeof h !== "string" || !/^(?:[0-9a-f]{2})+$/.test(h)) throw Error("Compared identity required"); return Uint8Array.from(h.match(/../g), v => parseInt(v, 16)); };
  const id = v => { if (typeof v !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(v)) throw Error("Compared identity required"); return v; };
  const number = v => { if (typeof v !== "string" || !/^[1-9][0-9]{0,18}$/.test(v) || BigInt(v) >= 1n << 63n) throw Error("Compared checkpoint required"); return BigInt(v); };
  const sha = async b => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
  function create({ enabled = false, readSelection, document = root.document, window = root.window, fetch = root.fetch,
    monotonic = () => performance.now(), importSdk = name => import("/v1/owner/conversation-sdk/sdk/" + name + ".js"),
    openRecovery = options => root.ZtManifest03Recovery.open(options), timeoutMs = 15000 } = {}) {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw Error("Bounded history operation required");
    const abort = new AbortController(), listeners = new Set();
    let closed = !enabled, busy = false, phase = "unprepared", selected, owner, token, client, sdk, journal, original, history, retained, bindingId;
    let tick = 0, primary = 0n, primaryTick = 0, lastPrimary = 0n, durable = false, timer;
    function capture() {
      const s = readSelection(), origin = window.location.origin;
      if (s.enabled !== true || s.retentionConsent !== true || s.compared !== true || s.origin !== origin
          || new URL(origin).protocol !== "https:" || new URL(origin).origin !== origin) throw Error("Explicit compared history setup required");
      for (const k of ["rootFingerprint", "pairedFingerprint", "manifestDigest"]) if (typeof s[k] !== "string" || !/^[0-9a-f]{64}$/.test(s[k]) || /^0+$/.test(s[k])) throw Error("Independent compared checkpoint required");
      number(s.manifestVersion);
      return Object.freeze({ origin, account: id(s.account_id), device: id(s.device_id), line: id(s.line_id),
        rootFingerprint: s.rootFingerprint, pairedFingerprint: s.pairedFingerprint, priorVersion: s.manifestVersion, priorDigest: s.manifestDigest });
    }
    function csrf() {
      const values = document.cookie.split(";").map(s => s.trim()).filter(s => s.startsWith("__Host-zrotext_csrf="));
      if (values.length !== 1) throw Error("Current owner session required");
      const value = decodeURIComponent(values[0].slice(20));
      if (!/^ztc_[A-Za-z0-9_-]{43}$/.test(value) || !/^[AEIMQUYcgkosw048]$/.test(value.slice(-1))) throw Error("Current owner session required"); return value;
    }
    function close() {
      if (closed) return; closed = true; phase = "closed"; abort.abort(); clearTimeout(timer); journal?.close(); history = original = null; durable = false;
      window.removeEventListener?.("pagehide", close); document.removeEventListener?.("visibilitychange", hidden);
      for (const fn of listeners) try { fn(); } catch {} listeners.clear();
    }
    function guard() {
      try {
        const n = monotonic();
        if (!Number.isFinite(n) || closed || abort.signal.aborted || document.hidden || n < tick
            || selected && (JSON.stringify(capture()) !== JSON.stringify(selected) || csrf() !== token)) throw Error("History setup no longer current");
        tick = n;
      } catch (e) { close(); throw e; }
    }
    const hidden = () => { if (document.hidden) close(); };
    if (enabled) { window.addEventListener?.("pagehide", close); document.addEventListener?.("visibilitychange", hidden); }
    function now() { guard(); if (!primary) throw Error("Current service time unavailable"); return primary + BigInt(Math.floor(monotonic() - primaryTick)); }
    function observe(value, started) {
      const prior = primary ? now() : 0n;
      if (value < lastPrimary) throw Error("Service time regressed");
      primary = value; primaryTick = started; lastPrimary = value;
      if (now() < prior) { primary = prior; primaryTick = monotonic(); }
    }
    async function session() {
      guard(); const r = await fetch("/v1/auth/session", { credentials: "same-origin", mode: "same-origin", redirect: "error", cache: "no-store", signal: abort.signal }); guard();
      if (r.status !== 200 || r.redirected || r.headers.get("content-type")?.split(";")[0] !== "application/json" || !r.body) throw Error("Current owner session unavailable");
      const reader = r.body.getReader(), chunks = []; let length = 0;
      const cancel = () => { void reader.cancel().catch(() => {}); }; abort.signal.addEventListener("abort", cancel, { once: true });
      try { for (;;) { const part = await reader.read(); guard(); if (part.done) break; length += part.value.length; if (length > 8192) throw Error("Owner session response bounded"); chunks.push(part.value); } }
      finally { abort.signal.removeEventListener("abort", cancel); cancel(); reader.releaseLock(); }
      const all = new Uint8Array(length); let at = 0; for (const part of chunks) { all.set(part, at); at += part.length; }
      const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(all));
      if (value.role !== "owner" || value.account_id !== selected.account || owner && (value.user_id !== owner.user || value.session_id !== owner.session)) throw Error("Owner sign-in changed");
      return Object.freeze({ user: id(value.user_id), session: id(value.session_id) });
    }
    async function operation(run) {
      guard(); if (busy) throw Error("History action pending"); busy = true;
      let withdraw;
      const stopped = new Promise((_, reject) => { withdraw = () => reject(Error("History action withdrawn")); abort.signal.addEventListener("abort", withdraw, { once: true }); });
      timer = setTimeout(close, timeoutMs);
      try { return await Promise.race([run(), stopped]); } catch (e) { if (!closed) phase = "interrupted"; throw e; }
      finally { clearTimeout(timer); abort.signal.removeEventListener("abort", withdraw); busy = false; }
    }
    function snapshot() { return Object.freeze({ phase, busy, closed, durable, version: history ? String(sdk.acceptedManifestHistoryCursor03(history).after.version) : null,
      complete: history ? sdk.acceptedManifestHistoryCursor03(history).complete : false }); }
    async function open(file) { return operation(async () => {
      if (selected) throw Error("History setup already opened"); selected = capture(); token = csrf(); guard();
      if (!file || file.size !== 65) throw Error("Existing paired public point required");
      const paired = new Uint8Array(await file.arrayBuffer()); guard();
      if (paired.length !== 65 || paired[0] !== 4 || hex(await sha(paired)) !== selected.pairedFingerprint) throw Error("Independently paired phone changed"); guard();
      owner = await session();
      const parts = await Promise.all(["accepted-manifest-history03", "original-manifest-history03", "payload-profile-election03"].map(importSdk)); guard(); sdk = Object.assign({}, ...parts);
      client = new sdk.OwnerManifestHistoryClient03({ origin: selected.origin, accountId: selected.account, userId: owner.user, ownerSessionId: owner.session,
        currentCsrf: csrf, signal: abort.signal, fetchImpl: fetch, timeoutMs });
      const candidate = await client.original(selected.line); guard(); bindingId = candidate.binding_id;
      original = await sdk.verifyOriginalManifestHistory03(candidate, { accountId: bytes(selected.account.replaceAll("-", "")), deviceId: bytes(selected.device.replaceAll("-", "")),
        lineId: bytes(selected.line.replaceAll("-", "")), rootFingerprint: bytes(selected.rootFingerprint), pairedSigningPoint: paired, origin: selected.origin,
        priorVersion: number(selected.priorVersion), priorDigest: bytes(selected.priorDigest) }); guard();
      if (original.originalUserHex !== owner.user.replaceAll("-", "")) throw Error("Original owner custody belongs to another user");
      journal = await openRecovery({ scope: { ...selected, user: owner.user }, signal: abort.signal, currentOrigin: () => window.location.origin }); guard();
      retained = await journal.read(); guard();
      if (retained && (retained.original_identity !== original.originalIdentity || retained.binding_id !== candidate.binding_id)) throw Error("Original saved setup changed");
      history = await sdk.startAcceptedManifestHistory03({ ...original.seed, ...(retained ? { minimum: { version: number(retained.version), digest: bytes(retained.digest), ancestry: bytes(retained.ancestry_sha256) } } : {}) }); guard();
      phase = "reading_history"; return snapshot();
    }); }
    async function next() { return operation(async () => {
      if (!history || durable) throw Error("Unfinished original history required"); await session(); guard();
      const started = monotonic(), verified = await client.next(history); guard();
      const checkpoint = sdk.acceptedManifestHistoryCheckpoint03(verified); observe(checkpoint.comparedMs, started); guard();
      if (sdk.acceptedManifestHistoryCursor03(verified).complete) {
        const candidate = { v: 1, binding_id: bindingId,
          original_identity: original.originalIdentity, version: String(checkpoint.position.version), digest: hex(checkpoint.position.digest), ancestry_sha256: hex(checkpoint.position.ancestry) };
        retained = await journal.compareAndSet(retained, candidate); guard(); durable = true;
      }
      history = verified; phase = durable ? "verified_history" : "reading_history"; return snapshot();
    }); }
    async function current() { return operation(async () => {
      if (!history || !durable) throw Error("Committed complete history required"); await session(); guard();
      const value = await client.current(history, now); guard(); phase = "current_selection"; return value;
    }); }
    function checkpoint() { guard(); if (!durable || !history) throw Error("Committed complete history required"); return sdk.acceptedManifestHistoryCheckpoint03(history); }
    async function proposalContext(target = false) { return operation(async () => {
      checkpoint(); await session(); guard();
      const value = target ? sdk.acceptedManifestHistoryRequiredCheckpoint03(history) : checkpoint();
      return Object.freeze({ ...value, nowMs: now(), scope: Object.freeze({ ...selected, user: owner.user, session: owner.session }),
        election: sdk.verifiedAcceptedElectionIdentity03(original.seed.acceptedElection),
        electionChallengeId: sdk.manifestHistoryBinary03(original.seed.originalEvidence.bundle, 628).slice(56, 72) });
    }); }
    async function restart(required) { return operation(async () => {
      checkpoint(); await session(); guard();
      const next = await sdk.startAcceptedManifestHistory03({ ...original.seed,
        minimum: { version: number(retained.version), digest: bytes(retained.digest), ancestry: bytes(retained.ancestry_sha256) },
        ...(required ? { required } : {}) }); guard();
      history = next; durable = false; phase = "reading_history"; return snapshot();
    }); }
    return Object.freeze({ open, next, current, checkpoint, proposalContext, restart, assertOpen: guard, state: snapshot, close, onClose: fn => { if (typeof fn !== "function") throw Error("Close callback required"); listeners.add(fn); } });
  }
  const api = Object.freeze({ create }); if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ZtManifest03History = api;
})(globalThis);
