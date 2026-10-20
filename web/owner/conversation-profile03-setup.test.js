// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), path = require("node:path");
const { pathToFileURL } = require("node:url"), { createRequire } = require("node:module");
createRequire(path.join(__dirname, "../../sdk/typescript/package.json"))("fake-indexeddb/auto");
const setup = require("./conversation-profile03-setup.js"), recovery = require("./conversation-profile03-recovery.js"), line = require("./conversation-line-setup.js");
const loadSdk = name => import(pathToFileURL(path.join(__dirname, "../../sdk/typescript/dist", name + ".js")).href);
const enc = new TextEncoder(), origin = "https://owner.example.test";
const cat = (...xs) => Uint8Array.from(Buffer.concat(xs)), hex = b => Buffer.from(b).toString("hex"), b64 = b => Buffer.from(b).toString("base64url");
const sha = async b => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
const num = (n, size = 8) => { const b = new Uint8Array(size), v = new DataView(b.buffer); if (size === 8) v.setBigUint64(0, BigInt(n)); else if (size === 4) v.setUint32(0, Number(n)); else v.setUint16(0, Number(n)); return b; };
const text = s => cat(num(enc.encode(s).length, 2), enc.encode(s));
const frame = (label, body) => cat(enc.encode(label + "\0"), num(body.length, 4), body);
const bytes = id => Uint8Array.from(Buffer.from(id.replaceAll("-", ""), "hex"));
const id = () => crypto.randomUUID(), publicFile = b => ({ size: b.length, arrayBuffer: async () => b.slice().buffer });
const reply = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const sdkNames = ["owner-profile-election-client", "original-line-evidence03", "draft01", "draft02-manifest", "draft03-manifest", "payload-profile-election03", "payload-profile-upgrade-proposal", "sealed-approval-key-store"];
async function fixture() {
  const sdk = await Promise.all(sdkNames.map(loadSdk)), d = sdk[2], f = { sdk, account: id(), user: id(), session: id(), device: id(), line: id(), registration: id(), oldChallenge: id(), oldBinding: id(), calls: [], time: 4000n, mono: 0, phoneConfirmed: false, accepted: false, lostCommit: false };
  const makeKey = async () => { const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]); return { pair, point: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) }; };
  f.root = await makeKey(); f.phone = await makeKey();
  const rawSign = async (key, message) => d.canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, message)));
  f.pin = cat(enc.encode("ZTRP\x02"), bytes(f.account), num(1), f.root.point); f.rootFingerprint = await sha(cat(enc.encode("ZTSE/root-pin/v2\0"), f.pin));
  f.pairedFingerprint = await sha(f.phone.point);
  f.storeName = "profile-test-key-" + id(); f.journalName = "profile-test-public-" + id();
  f.keyScope = { origin, accountId: f.account, originalUserId: f.user, deviceId: f.device, lineId: f.line, rootFingerprint: hex(f.rootFingerprint) };
  const initialStore = await sdk[7].SealedApprovalKeyStore.open({ name: f.storeName, currentOrigin: () => origin });
  f.approvalMetadata = await initialStore.create(f.keyScope, { retain: true, newRegistration: true });
  const approval = await initialStore.load(f.keyScope, f.approvalMetadata.fingerprint);
  f.approvalPoint = Uint8Array.from(Buffer.from(f.approvalMetadata.publicPoint, "hex"));
  const signApproval = message => approval.withKey(f.keyScope, f.approvalMetadata.fingerprint, key => rawSign(key, message));
  f.enrollmentId = await d.keyId(0x101, f.phone.point); f.approvalId = await d.keyId(0x101, f.approvalPoint);
  const transcript = cat(enc.encode("ZTSE/line/owner-key/register/v1\0"), ...[f.account, f.user, f.session, f.device, f.line].map(bytes), num(1), bytes(f.registration), new Uint8Array(32).fill(7), num(1000), num(60000), f.pin, f.rootFingerprint, f.approvalPoint, await sha(f.approvalPoint), f.pairedFingerprint, num(1), num(1), text("fixture-site"), text("fixture-instance"), text(origin));
  f.registrationEvidence = frame("ZTSE/line/payload-profile/registration-evidence/v1", cat(num(transcript.length, 4), transcript, await rawSign(f.root.pair.privateKey, transcript), await signApproval(transcript), f.approvalPoint, await sha(f.approvalPoint), f.pairedFingerprint, num(1000), num(60000), num(2000)));
  const observation = Uint8Array.from(Buffer.from(require("../../protocol/v2/vectors/line-activation.json").encodings.find(v => v.purpose === "sealed").observation_hex, "hex"));
  const deviceStatement = cat(enc.encode("ZTSE/line/device-confirm/v2\0"), Uint8Array.of(2, 2), bytes(f.account), bytes(f.line), bytes(f.device), num(1), bytes(f.oldChallenge), new Uint8Array(32).fill(8), observation);
  const deviceDer = line.derFromRaw(await rawSign(f.phone.pair.privateKey, deviceStatement));
  const ownerStatement = cat(enc.encode("ZTSE/line/owner-approve/v2\0"), deviceStatement, await sha(deviceDer));
  const ownerDer = line.derFromRaw(await signApproval(ownerStatement));
  f.activationEvidence = frame("ZTSE/line/payload-profile/activation-evidence/v1", cat(bytes(f.registration), bytes(f.oldBinding), f.phone.point, f.approvalPoint, deviceStatement, num(deviceDer.length, 2), deviceDer, ownerStatement, num(ownerDer.length, 2), ownerDer, num(3000)));
  const records = [];
  for (let role = 1; role <= 6; role++) {
    const k = role === 6 ? f.root : await makeKey(), keyId = await d.keyId(role <= 3 ? 0x10 : 0x101, k.point);
    if (role === 1) f.readerId = keyId;
    records.push(cat(Uint8Array.of(role), keyId, k.point, [1, 4].includes(role) ? bytes(f.device) : new Uint8Array(16), [1, 4, 5].includes(role) ? bytes(f.line) : new Uint8Array(16), num([0, 4, 12, 12, 2, 1, 0][role], 2), num(1000), num(100000), Uint8Array.of(1)));
  }
  const oldBody = cat(enc.encode("ZTMA\x02"), bytes(f.account), num(1), num(1), num(1000), num(100000), new Uint8Array(32), f.root.point, Uint8Array.of(records.length), ...records);
  f.old = cat(oldBody, await rawSign(f.root.pair.privateKey, frame("ZTSE/manifest/v2", oldBody))); f.oldDigest = await sha(oldBody);
  const originalReg = await sdk[1].verifyOriginalRegistrationSignatures03(f.registrationEvidence, { accountId: bytes(f.account), deviceId: bytes(f.device), lineId: bytes(f.line), generation: 1n, comparedRootFingerprint: f.rootFingerprint, pairedSigningPoint: f.phone.point, origin, trustedNowMs: f.time });
  f.oldProof = (await sdk[1].verifyOriginalActivationSignatures03(f.activationEvidence, originalReg, { oldBindingId: bytes(f.oldBinding), selectedReaderKeyId: f.readerId, trustedNowMs: f.time })).oldBindingDigestHex;
  f.deviceDigest = await sha(frame("ZTSE/line/payload-profile/device-session/v1", cat(bytes(f.account), bytes(f.device), num(12, 4), enc.encode("fixture-site"), num(16, 4), enc.encode("fixture-instance"), num(1), num(1), num(2, 2), f.enrollmentId)));
  const sessionDigest = session => sha(frame("ZTSE/line/payload-profile/owner-session/v1", cat(bytes(f.account), bytes(f.user), bytes(session))));
  f.actualSession = f.session;
  async function originalProjection() {
    return { v: 1, envelope_profile: 2, manifest_profile: 2, account_id: f.account, user_id: f.user, owner_session_id: f.actualSession, device_id: f.device, line_id: f.line,
      selection_epoch: "0", origin_digest: b64(await sha(enc.encode(origin))), owner_session_digest: b64(await sessionDigest(f.actualSession)), device_session_digest: b64(f.deviceDigest), site_id: "fixture-site", instance_id: "fixture-instance", connection_epoch: "1", deployment_epoch: "1",
      old_binding_id: f.oldBinding, old_binding_generation: "1", old_binding_proof_digest: b64(Buffer.from(f.oldProof, "hex")), reader_key_id: b64(f.readerId), device_signing_key_id: b64(f.enrollmentId), approval_key_id: b64(f.approvalId), root_fingerprint: b64(f.rootFingerprint), trust_generation: "1", manifest_version: "1", manifest_digest: b64(f.oldDigest), compared_ms: String(f.time), permission_expires_ms: "100000",
      evidence: { root_pin: b64(f.pin), prior_manifest02: b64(f.old), prior_accepted_ms: "1000", device_signing_point: b64(f.phone.point), owner_approval_point: b64(f.approvalPoint), registration_evidence: b64(f.registrationEvidence), activation_evidence: b64(f.activationEvidence) } };
  }
  f.selection = { enabled: true, retentionConsent: true, compared: true, account_id: f.account, device_id: f.device, line_id: f.line, rootFingerprint: hex(f.rootFingerprint), pairedFingerprint: hex(f.pairedFingerprint), manifestVersion: "1", manifestDigest: hex(f.oldDigest), origin };
  f.document = { hidden: false, cookie: "__Host-zrotext_csrf=ztc_" + b64(new Uint8Array(32).fill(11)), addEventListener() {}, removeEventListener() {} };
  f.window = { location: { origin }, addEventListener() {}, removeEventListener() {} };
  f.fetch = async (url, init = {}) => {
    const route = new URL(url, origin).pathname, body = init.body ? JSON.parse(init.body) : null; f.calls.push({ route, body });
    if (route === "/v1/auth/session") return reply({ role: "owner", account_id: f.account, user_id: f.user, session_id: f.actualSession });
    if (route.endsWith("/bootstrap")) return reply(await originalProjection());
    if (route.endsWith("/challenges")) {
      assert.deepEqual(await f.journal.read(body.opening_id, "opening"), f.opening());
      f.challenge = id(); f.newBinding = id(); f.signed03 = Uint8Array.from(Buffer.from(body.successor_manifest03, "base64url"));
      f.core = cat(enc.encode("ZTPE\x03\x01\x02\x03"), bytes(f.account), bytes(f.device), bytes(f.line), bytes(f.challenge), bytes(f.oldBinding), num(1), num(2), Buffer.from(f.oldProof, "hex"), f.rootFingerprint, num(1), num(1), f.oldDigest, num(2), await sha(f.signed03.subarray(0, -64)), f.readerId, f.enrollmentId, f.approvalId, new Uint8Array(32).fill(9), num(f.time), num(f.time + 60000n), await sha(enc.encode(origin)), await sessionDigest(f.actualSession), f.deviceDigest, new Uint8Array(4));
      f.savedOpeningId = body.opening_id; f.reserved = { v: 1, opening_id: body.opening_id, challenge_id: f.challenge, new_binding_id: f.newBinding, core: b64(f.core), successor_manifest03: body.successor_manifest03, issued_ms: String(f.time), expires_ms: String(f.time + 60000n), status: "reserved", closed_unaccepted: [] };
      return reply(f.reserved, 201);
    }
    if (route.endsWith("/challenges/status")) return reply({ ...f.reserved, status: f.accepted ? "accepted" : "reserved" });
    if (route.endsWith("/challenges/proof")) {
      if (!f.phoneConfirmed) return reply({ error: "not_found" }, 404);
      f.phoneSignature ??= await rawSign(f.phone.pair.privateKey, frame("ZTSE/line/payload-profile/device/v1", f.core));
      const signature = f.badPhone ? new Uint8Array(64).fill(1) : f.phoneSignature;
      return reply({ v: 1, opening_id: f.savedOpeningId, challenge_id: f.challenge, device_signature: b64(signature) });
    }
    if (route.endsWith("/elections")) {
      const bundle = Uint8Array.from(Buffer.from(body.bundle, "base64url"));
      assert.equal((await f.journal.read(body.opening_id, "bundle")).bundle, body.bundle);
      if (f.failCommitBeforeAcceptance) return reply({ error: "temporarily_unavailable" }, 503);
      f.bundle = bundle; f.accepted = true;
      if (f.lostCommit) { f.lostCommit = false; throw Error("Synthetic response lost after commit"); }
      return reply({ v: 1, opening_id: f.savedOpeningId, challenge_id: f.challenge, binding_id: f.newBinding, binding_generation: "2", election_digest: b64(await sha(frame("ZTSE/line/payload-profile/commitment/v1", f.core))), bundle_sha256: b64(await sha(bundle)), accepted_ms: String(f.time), selection_epoch: "1" }, 201);
    }
    if (route.endsWith("/current")) {
      const r = await originalProjection();
      return reply({ ...r, envelope_profile: 3, manifest_profile: 3, selection_epoch: "1", binding_id: f.newBinding, binding_generation: "2", manifest_version: "2", manifest_digest: b64(await sha(f.signed03.subarray(0, -64))), election_digest: b64(await sha(frame("ZTSE/line/payload-profile/commitment/v1", f.core))), election_bundle_sha256: b64(await sha(f.bundle)),
        evidence: { ...r.evidence, accepted_manifest03: b64(f.signed03), accepted_ms: String(f.time), bundle: b64(f.bundle) } });
    }
    throw Error("Unexpected synthetic endpoint");
  };
  f.controllers = []; f.ownerSignOperations = 0;
  f.create = (extra = {}) => {
    const controller = setup.create({ enabled: true, document: f.document, window: f.window, fetch: f.fetch, monotonic: () => f.mono, readSelection: () => f.selection, importSdk: loadSdk,
      openApprovalStore: async () => {
        const store = await sdk[7].SealedApprovalKeyStore.open({ name: f.storeName, currentOrigin: () => origin });
        return { close: () => store.close(), load: async (...args) => { const lease = await store.load(...args); return { ...lease, withKey: (...input) => { f.ownerSignOperations++; return lease.withKey(...input); } }; } };
      },
      openRecovery: async options => { const result = await recovery.open({ ...options, name: f.journalName }); f.journal = result; return result; }, ...extra });
    f.controllers.push(controller); return controller;
  };
  f.opening = () => ({ v: 1, origin, account_id: f.account, user_id: f.user, owner_session_id: f.session, device_id: f.device, root_fingerprint: b64(f.rootFingerprint), opening_id: f.savedOpeningId ?? f.calls.findLast(c => c.route.endsWith("/challenges"))?.body.opening_id, line_id: f.line, successor_manifest03: f.reserved?.successor_manifest03 ?? f.calls.findLast(c => c.route.endsWith("/challenges"))?.body.successor_manifest03 });
  f.prepare = async c => {
    const prepared = await c.begin(publicFile(f.phone.point));
    const p = prepared.proposal, originLength = new DataView(p.buffer, p.byteOffset).getUint16(53), oldLengthAt = 55 + originLength + 32 + 8 + 32 + 32 + 32 + 8;
    const oldLength = new DataView(p.buffer, p.byteOffset).getUint16(oldLengthAt), unsignedLengthAt = oldLengthAt + 2 + oldLength;
    const unsignedLength = new DataView(p.buffer, p.byteOffset).getUint16(unsignedLengthAt), unsigned = p.slice(unsignedLengthAt + 2);
    assert.equal(unsigned.length, unsignedLength);
    const signed = cat(unsigned, await rawSign(f.root.pair.privateKey, frame("ZTSE/manifest/v3", unsigned)));
    await c.reserve(publicFile(signed), { password: "synthetic", factor: "123456" }); return c.state().openingId;
  };
  f.close = () => { for (const c of f.controllers) c.close(); approval.close(); initialStore.close(); };
  return f;
}

test("actual SDK crypto, retained nonextractable key and committed public journal compose the complete browser election", async () => {
  const f = await fixture(); try {
    const c = f.create(); await f.prepare(c); assert.equal(c.state().phase, "awaiting_phone");
    await assert.rejects(c.check(), e => e.code === "not_found"); assert.equal(c.state().phase, "awaiting_phone");
    assert.equal(f.calls.filter(c => c.route.endsWith("/elections")).length, 0);
    f.phoneConfirmed = true; await c.check(); assert.equal(c.state().phase, "awaiting_owner");
    await c.approve({ password: "synthetic", factor: "654321" }); assert.equal(c.state().phase, "accepted_pending_current");
    await c.check(); assert.equal(c.state().phase, "accepted");
    assert.equal(f.calls.filter(c => c.route.endsWith("/challenges")).length, 1); assert.equal(f.calls.filter(c => c.route.endsWith("/elections")).length, 1);
    const record = await f.journal.read(c.state().openingId, "opening"); assert.equal("password" in record, false); assert.equal("factor" in record, false);
  } finally { f.close(); }
});

test("lost committed approval recovers after a fresh same-user sign-in without new signing, factor or mutation", async () => {
  const f = await fixture(); try {
    const c = f.create(), opening = await f.prepare(c); f.phoneConfirmed = true; await c.check(); f.lostCommit = true;
    await assert.rejects(c.approve({ password: "synthetic", factor: "654321" }), e => e.outcome === "unknown");
    assert.equal(c.state().phase, "outcome_unknown"); const originalBundle = f.bundle.slice(); c.close();
    f.actualSession = id(); const restored = f.create(); const found = await restored.find(publicFile(f.phone.point)); assert.deepEqual(found.openings, [opening]);
    await restored.recover(opening); await restored.check(); assert.equal(restored.state().phase, "accepted");
    assert.deepEqual(f.bundle, originalBundle); assert.equal(f.calls.filter(c => c.route.endsWith("/elections")).length, 1);
  } finally { f.close(); }
});

test("fresh sign-in observes an unfinished original attempt but cannot upgrade its old session-bound approval", async () => {
  const f = await fixture(); try {
    const c = f.create(), opening = await f.prepare(c); c.close(); f.actualSession = id(); f.phoneConfirmed = true;
    const restored = f.create(); await restored.find(publicFile(f.phone.point)); await restored.recover(opening); await restored.check();
    assert.equal(restored.state().phase, "historical_only");
    await assert.rejects(restored.approve({ password: "synthetic", factor: "654321" }));
    assert.equal(f.calls.filter(c => c.route.endsWith("/elections")).length, 0);
  } finally { f.close(); }
});

test("an ambiguous503 preserves the original owner bundle and only explicit same-request retry can proceed", async () => {
  const f = await fixture(); try {
    const c = f.create(), opening = await f.prepare(c); f.phoneConfirmed = true; await c.check(); f.failCommitBeforeAcceptance = true;
    await assert.rejects(c.approve({ password: "synthetic", factor: "654321" }), e => e.outcome === "unknown");
    const original = await f.journal.read(opening, "bundle"); assert.equal(f.ownerSignOperations, 1);
    await c.check(); assert.equal(c.state().phase, "awaiting_owner"); assert.equal(f.ownerSignOperations, 1);
    f.failCommitBeforeAcceptance = false;
    await c.approve({ password: "synthetic", factor: "543210" });
    assert.equal(f.ownerSignOperations, 1); assert.equal(b64(f.bundle), original.bundle);
    assert.equal(f.calls.filter(c => c.route.endsWith("/challenges")).length, 1);
  } finally { f.close(); }
});

test("forged phone proof cannot create an owner bundle or acceptance request", async () => {
  const f = await fixture(); try {
    const c = f.create(), opening = await f.prepare(c); f.phoneConfirmed = true; f.badPhone = true;
    await assert.rejects(c.check()); assert.equal(await f.journal.read(opening, "bundle"), null);
    await assert.rejects(c.approve({ password: "synthetic", factor: "654321" }));
    assert.equal(f.calls.filter(c => c.route.endsWith("/elections")).length, 0);
  } finally { f.close(); }
});

test("failed durable recovery save reaches neither challenge admission nor a factor-bearing request", async () => {
  const f = await fixture(); try {
    const c = f.create({ openRecovery: async () => ({ append: async () => { throw Error("Synthetic storage failure"); }, close() {} }) });
    await assert.rejects(f.prepare(c)); assert.equal(f.calls.filter(c => c.body?.password).length, 0);
  } finally { f.close(); }
});

test("changed comparison, CSRF, foreground or monotonic clock withdraws before a new approval", async () => {
  for (const change of [f => f.selection.rootFingerprint = "aa".repeat(32), f => f.document.cookie = "", f => f.document.hidden = true, f => f.mono = -1]) {
    const f = await fixture(); try { const c = f.create(); await f.prepare(c); change(f); await assert.rejects(c.check()); assert.equal(c.state().closed, true); assert.equal(f.calls.filter(c => c.route.endsWith("/elections")).length, 0); } finally { f.close(); }
  }
});

test("disabled setup performs no network, storage or key access", async () => {
  const c = setup.create({ enabled: false, document: {}, window: {}, readSelection: () => { throw Error("No selection access"); } });
  await assert.rejects(c.begin(publicFile(new Uint8Array(65)))); assert.equal(c.state().closed, true);
});
