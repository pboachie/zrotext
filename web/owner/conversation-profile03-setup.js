// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  const enc = new TextEncoder();
  const modules = ["owner-profile-election-client", "original-line-evidence03", "draft01", "draft02-manifest", "draft03-manifest", "payload-profile-election03", "payload-profile-upgrade-proposal", "sealed-approval-key-store"];
  const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  const hex = b => Array.from(b, v => v.toString(16).padStart(2, "0")).join("");
  const fromHex = h => { if (typeof h !== "string" || !/^(?:[0-9a-f]{2})+$/.test(h)) throw Error("Compared public identity refused"); return Uint8Array.from(h.match(/../g), v => parseInt(v, 16)); };
  const uuid = b => { if (b.length !== 16 || !b.some(v => v)) throw Error("Profile identity refused"); return hex(b).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5"); };
  const id = s => { if (typeof s !== "string" || uuid(fromHex(s.replaceAll("-", ""))) !== s) throw Error("Canonical profile identity required"); return s; };
  const number = s => { if (typeof s !== "string" || !/^[1-9][0-9]{0,18}$/.test(s) || BigInt(s) >= 1n << 63n) throw Error("Profile time refused"); return BigInt(s); };
  const cat = (...xs) => { const b = new Uint8Array(xs.reduce((n, x) => n + x.length, 0)); let at = 0; for (const x of xs) { b.set(x, at); at += x.length; } return b; };
  const sha = async b => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
  const frame = (label, b) => { const n = new Uint8Array(4); new DataView(n.buffer).setUint32(0, b.length); return cat(enc.encode(label + "\0"), n, b); };
  const b64 = b => { let s = ""; for (const v of b) s += String.fromCharCode(v); return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, ""); };
  function binary(s, minimum, maximum = minimum) {
    if (typeof s !== "string" || !/^[A-Za-z0-9_-]+$/.test(s) || s.length > Math.ceil(maximum * 4 / 3)) throw Error("Profile public encoding refused");
    const b = Uint8Array.from(atob(s.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - s.length % 4) % 4)), c => c.charCodeAt(0));
    if (b.length < minimum || b.length > maximum || b64(b) !== s) throw Error("Profile public size refused"); return b;
  }
  async function fileBytes(file, minimum, maximum = minimum) {
    if (!file || file.size < minimum || file.size > maximum) throw Error("Existing public file required");
    const b = new Uint8Array(await file.arrayBuffer()); if (b.length !== file.size) throw Error("Public file changed"); return b;
  }
  function create({ enabled = false, readSelection, document = root.document, window = root.window, fetch = root.fetch,
    monotonic = () => performance.now(), importSdk = name => import("/v1/owner/conversation-sdk/sdk/" + name + ".js"),
    openRecovery = options => root.ZtProfile03Recovery.open(options), openApprovalStore } = {}) {
    const lifetime = new AbortController(), listeners = new Set();
    let closed = !enabled, phase = "unprepared", busy = false, selected, owner, token, sdk, paired, journal, store, lease, leaseScope;
    let client, original, scope, proposal, opening, reservation, deadline = 0, clock = 0n, clockTick = 0, lastTick = 0, timer;
    const capture = () => {
      const s = readSelection(), origin = window.location.origin;
      if (s.enabled !== true || s.retentionConsent !== true || s.compared !== true || s.origin !== origin || new URL(origin).protocol !== "https:" || new URL(origin).origin !== origin) throw Error("Explicit compared profile setup required");
      for (const k of ["rootFingerprint", "pairedFingerprint", "manifestDigest"]) if (typeof s[k] !== "string" || !/^[0-9a-f]{64}$/.test(s[k]) || /^0+$/.test(s[k])) throw Error("Independent public checkpoint required");
      number(s.manifestVersion);
      return Object.freeze({ account: id(s.account_id), device: id(s.device_id), line: id(s.line_id), origin,
        rootFingerprint: s.rootFingerprint, pairedFingerprint: s.pairedFingerprint, manifestVersion: s.manifestVersion, manifestDigest: s.manifestDigest });
    };
    function csrf() {
      const cookies = document.cookie.split(";").map(s => s.trim()).filter(s => s.startsWith("__Host-zrotext_csrf="));
      if (cookies.length !== 1) throw Error("Current owner session required");
      const t = decodeURIComponent(cookies[0].slice(20));
      if (!/^ztc_[A-Za-z0-9_-]{43}$/.test(t) || b64(binary(t.slice(4), 32)) !== t.slice(4)) throw Error("Current owner session required"); return t;
    }
    function guard() {
      try {
        const tick = monotonic();
        if (closed || lifetime.signal.aborted || document.hidden || tick < lastTick || selected && (JSON.stringify(capture()) !== JSON.stringify(selected) || csrf() !== token) || deadline && tick >= deadline) throw Error("Profile setup no longer current");
        lastTick = tick;
      } catch (error) { close(); throw error; }
    }
    function close() {
      if (closed) return; closed = true; phase = "closed"; lifetime.abort(); clearTimeout(timer);
      for (const release of [() => client?.close(), () => lease?.close(), () => store?.close(), () => journal?.close()]) try { release(); } catch {}
      owner = original = proposal = scope = paired = null;
      window.removeEventListener?.("pagehide", close); document.removeEventListener?.("visibilitychange", hidden);
      for (const fn of listeners) try { fn(); } catch {} listeners.clear();
    }
    const hidden = () => { if (document.hidden) close(); };
    if (enabled) { window.addEventListener?.("pagehide", close); document.addEventListener?.("visibilitychange", hidden); }
    function now() { guard(); if (!clock) throw Error("Primary time required"); return clock + BigInt(Math.floor(monotonic() - clockTick)); }
    function compareTime(value, started) {
      const n = number(value.compared_ms), prior = clock ? now() : 0n;
      if (clock && n < clock) throw Error("Primary time regressed");
      clock = n; clockTick = started;
      if (now() < prior) { clock = prior; clockTick = monotonic(); }
      const end = monotonic() + Number(number(value.permission_expires_ms) - now());
      deadline = deadline ? Math.min(deadline, end) : end; guard();
      clearTimeout(timer); timer = setTimeout(close, Math.max(0, deadline - monotonic()));
    }
    async function session() {
      guard();
      const response = await fetch("/v1/auth/session", { credentials: "same-origin", mode: "same-origin", redirect: "error", cache: "no-store", signal: AbortSignal.any([lifetime.signal, AbortSignal.timeout(15000)]) });
      guard();
      if (response.status !== 200 || response.redirected || response.headers.get("content-type")?.split(";")[0] !== "application/json" || !response.body) throw Error("Owner session unavailable");
      const reader = response.body.getReader(), parts = []; let total = 0;
      try { for (;;) { const { value, done } = await reader.read(); guard(); if (done) break; total += value.length; if (total > 8192) throw Error("Owner response bounded"); parts.push(value); } }
      finally { try { await reader.cancel(); } finally { reader.releaseLock(); } }
      const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(cat(...parts)));
      if (value.role !== "owner" || value.account_id !== selected.account || owner && (value.user_id !== owner.user || value.session_id !== owner.session)) throw Error("Owner session changed");
      const result = Object.freeze({ user: id(value.user_id), session: id(value.session_id) }); guard(); return result;
    }
    function newClient() {
      client?.close();
      client = new sdk[0].OwnerProfileElectionClient03({ origin: selected.origin, accountId: selected.account, userId: owner.user, ownerSessionId: owner.session, deviceId: selected.device,
        rootFingerprint: fromHex(selected.rootFingerprint), currentCsrf: csrf, signal: lifetime.signal,
        saveRecovery: value => journal.append(value.opening_id, "opening", value), fetchImpl: fetch });
      if (opening) client.observeOpening(opening);
    }
    async function init(file) {
      if (selected) throw Error("Profile setup already opened");
      selected = capture(); token = csrf(); guard();
      paired = await fileBytes(file, 65); guard();
      if (paired[0] !== 4 || hex(await sha(paired)) !== selected.pairedFingerprint) throw Error("Independently paired phone point changed");
      owner = await session();
      sdk = await Promise.all(modules.map(importSdk)); guard();
      await crypto.subtle.importKey("raw", paired, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]); guard();
      journal = await openRecovery({ scope: { ...selected, user: owner.user }, signal: lifetime.signal, currentOrigin: () => window.location.origin }); guard();
      newClient();
    }
    async function verifyOriginal(value) {
      const e = value.evidence, at = now(), pin = binary(e.root_pin, 94), signed02 = binary(e.prior_manifest02, 364, 9751);
      const enrolled = binary(e.device_signing_point, 65);
      if (!same(enrolled, paired) || value.root_fingerprint !== b64(fromHex(selected.rootFingerprint)) || value.device_id !== selected.device || value.line_id !== selected.line || value.manifest_profile === 2 && (value.manifest_version !== selected.manifestVersion || value.manifest_digest !== b64(fromHex(selected.manifestDigest)))) throw Error("Original compared selection changed");
      const trust = await sdk[3].enrollRootPin02(pin, fromHex(selected.rootFingerprint)); guard();
      const predecessor = await sdk[3].verifyManifest02(signed02, { ...trust, version: number(selected.manifestVersion), digest: fromHex(selected.manifestDigest) }, at); guard();
      const registered = await sdk[1].verifyOriginalRegistrationSignatures03(binary(e.registration_evidence, 1, 98304), {
        accountId: fromHex(selected.account.replaceAll("-", "")), deviceId: fromHex(selected.device.replaceAll("-", "")), lineId: fromHex(selected.line.replaceAll("-", "")),
        generation: number(value.old_binding_generation), comparedRootFingerprint: fromHex(selected.rootFingerprint), pairedSigningPoint: paired, origin: selected.origin, trustedNowMs: at }); guard();
      const points = sdk[1].originalRegistrationPublicKeys03(registered);
      if (uuid(fromHex(registered.originalUserHex)) !== owner.user || !same(points.approvalPoint, binary(e.owner_approval_point, 65))) throw Error("Original owner approval custody changed");
      const activated = await sdk[1].verifyOriginalActivationSignatures03(binary(e.activation_evidence, 1, 98304), registered, {
        oldBindingId: fromHex(value.old_binding_id.replaceAll("-", "")), selectedReaderKeyId: binary(value.reader_key_id, 32), trustedNowMs: at }); guard();
      if (activated.oldBindingDigestHex !== hex(binary(value.old_binding_proof_digest, 32)) || !same(await sdk[2].keyId(0x101, paired), binary(value.device_signing_key_id, 32)) || !same(await sdk[2].keyId(0x101, points.approvalPoint), binary(value.approval_key_id, 32))) throw Error("Original election identities changed");
      guard(); return { value, e, predecessor, signed02, registered, activated, points };
    }
    async function originalCurrent() {
      await session(); const started = monotonic(), value = await client.bootstrap(selected.line); guard(); compareTime(value, started);
      const next = await verifyOriginal(value);
      if (original) for (const key of ["old_binding_id", "old_binding_generation", "old_binding_proof_digest", "device_session_digest", "reader_key_id", "approval_key_id", "manifest_digest"]) if (original.value[key] !== value[key]) throw Error("Original current scope changed");
      original = next; return next;
    }
    function reservedWire(r) { return { challenge_id: r.challengeId, new_binding_id: r.newBindingId, core: b64(r.core), issued_ms: String(r.issuedMs), expires_ms: String(r.expiresMs), successor_manifest03: b64(r.successorManifest03) }; }
    async function verifyReservation(r) {
      const c = r.core, v = new DataView(c.buffer, c.byteOffset, c.byteLength), s = original.value;
      for (const [offset, value] of [[72, fromHex(s.old_binding_id.replaceAll("-", ""))], [104, binary(s.old_binding_proof_digest, 32)], [136, fromHex(selected.rootFingerprint)], [184, fromHex(selected.manifestDigest)], [256, binary(s.reader_key_id, 32)], [288, binary(s.device_signing_key_id, 32)], [320, binary(s.approval_key_id, 32)], [464, binary(s.device_session_digest, 32)]]) if (!same(c.subarray(offset, offset + value.length), value)) throw Error("Reserved original selection changed");
      if (v.getBigUint64(88) !== number(s.old_binding_generation) || v.getBigUint64(176) !== number(selected.manifestVersion) || !same(r.successorManifest03, binary(opening.successor_manifest03, 366, 9753))) throw Error("Reserved predecessor changed");
      await journal.append(opening.opening_id, "reservation", reservedWire(r)); guard(); return r;
    }
    async function loadCustody() {
      const point = original.points.approvalPoint, fingerprint = hex(await sha(point)); guard();
      leaseScope = { origin: selected.origin, accountId: selected.account, originalUserId: owner.user, deviceId: selected.device, lineId: selected.line, rootFingerprint: selected.rootFingerprint };
      store ??= await (openApprovalStore ? openApprovalStore({ signal: lifetime.signal }) : sdk[7].SealedApprovalKeyStore.open({ signal: lifetime.signal, currentOrigin: () => window.location.origin })); guard();
      lease?.close(); lease = await store.load(leaseScope, fingerprint); guard();
      if (lease.publicPoint !== hex(point)) throw Error("Original retained key changed");
      return fingerprint;
    }
    async function acceptedCurrent(r) {
      const started = monotonic(), value = await client.current(selected.line); guard(); compareTime(value, started);
      const o = await verifyOriginal(value), e = value.evidence, bundle = binary(e.bundle, 628), core = bundle.slice(0, 500), v = new DataView(core.buffer);
      if (value.binding_id !== r.newBindingId || !same(core, r.core) || value.evidence.accepted_manifest03 !== opening.successor_manifest03) throw Error("Accepted original reservation changed");
      const retained = await journal.read(opening.opening_id, "bundle"); if (retained && retained.bundle !== b64(bundle)) throw Error("Accepted original bundle changed");
      const record = { accountId: fromHex(selected.account.replaceAll("-", "")), deviceId: fromHex(selected.device.replaceAll("-", "")), lineId: fromHex(selected.line.replaceAll("-", "")), rootFingerprint: fromHex(selected.rootFingerprint), vaultGeneration: 1n,
        oldBindingId: fromHex(value.old_binding_id.replaceAll("-", "")), oldBindingGeneration: number(value.old_binding_generation), oldBindingProofDigest: binary(value.old_binding_proof_digest, 32), newBindingId: fromHex(value.binding_id.replaceAll("-", "")), newBindingGeneration: number(value.binding_generation), selectedReaderKeyId: binary(value.reader_key_id, 32),
        priorManifestVersion: v.getBigUint64(176), priorManifestDigest: core.slice(184, 216), priorSignedManifestSha256: await sha(o.signed02), acceptedManifestVersion: number(value.manifest_version), acceptedManifestDigest: binary(value.manifest_digest, 32), acceptedSignedManifestSha256: await sha(binary(e.accepted_manifest03, 366, 9753)), electionCoreSha256: await sha(core), electionCommitment: binary(value.election_digest, 32), electionBundleSha256: binary(value.election_bundle_sha256, 32), acceptedAtMs: number(e.accepted_ms) };
      const proof = await sdk[5].verifyAcceptedPayloadProfileElection03({ bundle, expectedCore: r.core, acceptedRecord: record, predecessor02: o.predecessor, priorSignedManifest02: o.signed02, acceptedSignedManifest03: binary(e.accepted_manifest03, 366, 9753), deviceSigningPointAtAcceptance: paired, ownerApprovalPointAtAcceptance: o.points.approvalPoint }); guard();
      const manifest = await sdk[4].verifyManifest03From02(binary(e.accepted_manifest03, 366, 9753), o.predecessor, o.signed02, record.acceptedAtMs); guard();
      sdk[5].requireCurrentElection03(proof, manifest, { profile: 3, manifestProfile: 3, accountId: record.accountId, deviceId: record.deviceId, lineId: record.lineId, bindingId: record.newBindingId, bindingGeneration: record.newBindingGeneration, selectedReaderKeyId: record.selectedReaderKeyId, rootFingerprint: record.rootFingerprint, vaultGeneration: 1n, manifestVersion: record.acceptedManifestVersion, manifestDigest: record.acceptedManifestDigest, electionCommitment: record.electionCommitment, electionBundleSha256: record.electionBundleSha256, comparedAtMs: number(value.compared_ms), permissionExpiresAtMs: number(value.permission_expires_ms) }, now());
      guard(); phase = "accepted"; lease?.close(); return snapshot();
    }
    async function operation(run) {
      guard(); if (busy) throw Error("Profile action already pending"); busy = true;
      try { return await run(); } catch (error) { phase = error.outcome === "unknown" ? "outcome_unknown" : error.code === "not_found" && reservation ? "awaiting_phone" : "refused"; throw error; } finally { busy = false; }
    }
    function snapshot() { return Object.freeze({ phase, busy, closed, openingId: opening?.opening_id ?? null, challengeId: reservation?.challengeId ?? null, expiresMs: reservation ? String(reservation.expiresMs) : null }); }
    async function begin(file) { return operation(async () => {
      await init(file); await originalCurrent(); await loadCustody();
      scope = { accountId: fromHex(selected.account.replaceAll("-", "")), deviceId: fromHex(selected.device.replaceAll("-", "")), lineId: fromHex(selected.line.replaceAll("-", "")), origin: selected.origin, rootFingerprint: fromHex(selected.rootFingerprint), predecessorVersion: number(selected.manifestVersion), predecessorDigest: fromHex(selected.manifestDigest), phoneReaderKeyId: binary(original.value.reader_key_id, 32), phoneSigningKeyId: binary(original.value.device_signing_key_id, 32), issuedMs: now() };
      proposal = await sdk[6].encodePayloadProfileUpgradeProposal03({ scope, predecessor: original.predecessor, originalSigned02: original.signed02, nowMs: now() }); guard();
      phase = "awaiting_offline_approval"; return Object.freeze({ ...snapshot(), proposal: proposal.proposal.slice() });
    }); }
    async function reserve(file, credentials) { return operation(async () => {
      if (phase !== "awaiting_offline_approval" || opening) throw Error("Exact existing proposal required");
      await originalCurrent();
      const signed03 = await fileBytes(file, 366, 9753); guard();
      await sdk[6].verifyPayloadProfileUpgradeOutput03({ scope, predecessor: original.predecessor, originalSigned02: original.signed02, signed03, nowMs: now() }); guard();
      opening = client.createOpening(selected.line, signed03);
      reservation = await client.reserve(opening, credentials); guard();
      await verifyReservation(reservation); phase = "awaiting_phone"; return snapshot();
    }); }
    async function check() { return operation(async () => {
      if (!opening) throw Error("Original recovery record required");
      await session(); newClient(); const r = await client.status(opening); guard();
      const stored = await journal.read(opening.opening_id, "reservation");
      if (stored && JSON.stringify(stored) !== JSON.stringify(reservedWire(r))) throw Error("Original reservation changed");
      reservation = r;
      if (r.status === "accepted") return acceptedCurrent(r);
      if (opening.owner_session_id !== owner.session) { phase = "historical_only"; return snapshot(); }
      await originalCurrent(); await verifyReservation(r);
      if (now() >= r.expiresMs) { phase = "expired"; return snapshot(); }
      const p = await client.deviceProof(opening, r.challengeId); guard();
      if (!sdk[2].isCanonicalP256Signature(p.signature)) throw Error("Strict phone signature required");
      const key = await crypto.subtle.importKey("raw", paired, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, p.signature, frame("ZTSE/line/payload-profile/device/v1", r.core))) throw Error("Actual paired phone approval refused");
      reservation = Object.freeze({ ...r, signature: p.signature.slice() }); phase = "awaiting_owner"; return snapshot();
    }); }
    async function approve(credentials) { return operation(async () => {
      if (phase !== "awaiting_owner" || !reservation?.signature || opening.owner_session_id !== owner.session) throw Error("Actual current phone proof required");
      await originalCurrent(); await verifyReservation(reservation);
      if (now() >= reservation.expiresMs) throw Error("Original challenge expired");
      const saved = await journal.read(opening.opening_id, "bundle"); let bundle;
      if (saved) { bundle = binary(saved.bundle, 628); if (!same(bundle.subarray(0, 500), reservation.core) || !same(bundle.subarray(500, 564), reservation.signature)) throw Error("Original prepared bundle changed"); }
      else {
        const fingerprint = await loadCustody();
        const signature = await lease.withKey(leaseScope, fingerprint, async key => {
          guard(); const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, frame("ZTSE/line/payload-profile/owner/v1", cat(reservation.core, await sha(reservation.signature))))); guard();
          return sdk[2].canonicalP256Signature(raw);
        }); guard(); bundle = cat(reservation.core, reservation.signature, signature);
        await journal.append(opening.opening_id, "bundle", { bundle: b64(bundle) }); guard();
      }
      const ownerPoint = original.points.approvalPoint, ownerKey = await crypto.subtle.importKey("raw", ownerPoint, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      if (!sdk[2].isCanonicalP256Signature(bundle.subarray(564)) || !await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, ownerKey, bundle.subarray(564), frame("ZTSE/line/payload-profile/owner/v1", cat(reservation.core, await sha(reservation.signature))))) throw Error("Retained original owner signature refused");
      guard();
      const receipt = await client.commit(opening, reservation.challengeId, bundle, credentials); guard();
      await journal.append(opening.opening_id, "receipt", { opening_id: receipt.openingId, challenge_id: receipt.challengeId, binding_id: receipt.bindingId, binding_generation: String(receipt.bindingGeneration), election_digest: b64(receipt.electionDigest), bundle_sha256: b64(receipt.bundleSha256), accepted_ms: String(receipt.acceptedMs), selection_epoch: String(receipt.selectionEpoch) }); guard();
      phase = "accepted_pending_current"; return snapshot();
    }); }
    async function find(file) { return operation(async () => { await init(file); const ids = await journal.list(); phase = "choose_recovery"; return Object.freeze({ ...snapshot(), openings: ids }); }); }
    async function recover(openingId) { return operation(async () => {
      if (phase !== "choose_recovery") throw Error("Choose retained recovery first");
      const value = await journal.read(id(openingId), "opening"); if (!value) throw Error("Original recovery missing; reconcile without restarting");
      opening = client.observeOpening(value); phase = "recovery_loaded"; return snapshot();
    }); }
    return Object.freeze({ begin, reserve, check, approve, find, recover, close, state: snapshot,
      onClose(fn) { if (closed) fn(); else listeners.add(fn); } });
  }
  const api = Object.freeze({ create });
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ZtProfile03Setup = api;
})(globalThis);
