// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { captureTrustedReviewContext03, encodeReviewedIntent03, decodeReviewedIntent03, prepareReviewedIntent03,
  reviewedIntentTranscript03, verifyReviewedIntent03, verifiedReviewedIntentSnapshot03,
  encodeReviewedIntent03V2, decodeReviewedIntent03V2, prepareReviewedIntent03V2, reviewedIntentTranscript03V2,
  verifyReviewedIntent03V2, verifiedReviewedIntentSnapshot03V2 } from "../dist/reviewed-intent03.js";
import { fixture, clone, uuid, enc, present, inputFor, composeSealedOutboundEnvelope03, canonicalP256Signature,
  sha, join, frame, verifyAndOpen } from "./fixtures/profile03-outbound-fixture.mjs";

function contextFor(f) {
  return { currentAuthority: clone(f.authority), manifest: f.currentManifest, acceptedElection: f.proof,
    accountSelectionEpoch: 1n, ownerUserId: uuid(140), ownerSessionId: uuid(160), canonicalOrigin: "https://example.test",
    intervalId: uuid(180), intervalFromMs: 20_000n, intervalUntilMs: 60_000n, peer: enc.encode("+12"),
    signerKeyId: f.records[4].id.slice(), recipients: f.records.slice(0, 3).map(r => ({ role: r.role, keyId: r.id.slice() })), nowMs: present };
}
async function sign(f, transcript) {
  return canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" },
    f.records[4].k.pair.privateKey, transcript)));
}
async function packet(f, overrides = {}) {
  const composition = inputFor(f), out = await composeSealedOutboundEnvelope03(composition);
  const context = await captureTrustedReviewContext03(contextFor(f));
  const preparation = { context, envelope: out.envelope, reviewIssuedMs: present, reviewExpiresMs: 35_000n,
    smsCeiling: 1, nowMs: present, ...overrides };
  const intent = await prepareReviewedIntent03V2(preparation);
  return { context, envelope: out.envelope, intent, signature: await sign(f, reviewedIntentTranscript03V2(intent)), nowMs: present };
}

test("V2 authenticates the actual encrypted composer packet with no plaintext commitment", async () => {
  const f = await fixture();
  for (const smsCeiling of [1, 6]) {
    const p = await packet(f, { smsCeiling }), proof = await verifyReviewedIntent03V2(p), snapshot = verifiedReviewedIntentSnapshot03V2(proof);
    await verifyAndOpen(f, { envelope: p.envelope, envelopeDigest: await sha(p.envelope), unsignedDigest: await sha(p.envelope.subarray(0, -64)) }, inputFor(f).content);
    assert.equal(snapshot.fields.smsCeiling, smsCeiling); assert.equal(Object.hasOwn(snapshot.fields, "bodyDigest"), false);
    assert.equal(Buffer.from(p.intent).includes(await sha(enc.encode(inputFor(f).content))), false);
    assert.deepEqual(snapshot.fields.envelopeDigest, await sha(p.envelope));
    assert.deepEqual(snapshot.fields.unsignedDigest, await sha(p.envelope.subarray(0, -64)));
    assert.deepEqual(snapshot.fields.ownerSessionDigest, await sha(frame("ZTSE/line/payload-profile/owner-session/v1", join(f.authority.accountId, uuid(140), uuid(160)))));
    assert.deepEqual(snapshot.fields.originDigest, await sha(enc.encode("https://example.test")));
    assert.deepEqual(encodeReviewedIntent03V2(decodeReviewedIntent03V2(p.intent)), p.intent);
    for (const name of ["accountId", "peer"]) snapshot.fields[name].fill(0);
    snapshot.fields.recipients[0].keyId.fill(0); snapshot.intent.fill(0); snapshot.signature.fill(0); snapshot.envelope.fill(0);
    assert.deepEqual(verifiedReviewedIntentSnapshot03V2(proof).intent, p.intent);
    assert.throws(() => verifiedReviewedIntentSnapshot03(proof));
  }
  assert.throws(() => verifiedReviewedIntentSnapshot03V2({}));
});

test("explicit V2 entry points never reinterpret V1 bytes or accept a V1 proof", async () => {
  const f = await fixture(), p = await packet(f);
  const old = await prepareReviewedIntent03({ context: p.context, envelope: p.envelope, body: inputFor(f).content,
    reviewIssuedMs: present, reviewExpiresMs: 35_000n, smsCeiling: 1, nowMs: present });
  const oldPacket = { ...p, intent: old, signature: await sign(f, reviewedIntentTranscript03(old)) };
  const oldProof = await verifyReviewedIntent03(oldPacket);
  assert.throws(() => verifiedReviewedIntentSnapshot03V2(oldProof));
  assert.throws(() => decodeReviewedIntent03V2(old)); assert.throws(() => decodeReviewedIntent03(p.intent));
  await assert.rejects(verifyReviewedIntent03V2(oldPacket)); await assert.rejects(verifyReviewedIntent03(p));
  assert.throws(() => encodeReviewedIntent03V2(decodeReviewedIntent03(old)), /closed/);
  assert.throws(() => encodeReviewedIntent03(decodeReviewedIntent03V2(p.intent)), /closed/);
  const rewritten = old.slice(); rewritten[4] = 2;
  assert.throws(() => decodeReviewedIntent03V2(rewritten));
  // The first ten commitments stay in place; the V1 plaintext field is absent.
  assert.deepEqual(old.subarray(8, 520), p.intent.subarray(8, 520));
  assert.deepEqual(old.subarray(552), p.intent.subarray(520)); assert.equal(old.length - p.intent.length, 32);
});

test("V2 refuses body inputs, placeholder fields, forged context and unsupported counters", async () => {
  const f = await fixture(), p = await packet(f), fields = decodeReviewedIntent03V2(p.intent);
  const prep = { context: p.context, envelope: p.envelope, reviewIssuedMs: present, reviewExpiresMs: 35_000n, smsCeiling: 1, nowMs: present };
  for (const extra of [{ body: "Synthetic" }, { bodyDigest: new Uint8Array(32) }, { bodyDigest: fields.envelopeDigest }, { permission: true }]) {
    await assert.rejects(prepareReviewedIntent03V2({ ...prep, ...extra }), /closed/);
    assert.throws(() => encodeReviewedIntent03V2({ ...fields, ...extra }), /closed/);
  }
  await assert.rejects(prepareReviewedIntent03V2({ ...prep, context: {} }));
  await assert.rejects(verifyReviewedIntent03V2({ ...p, context: {} }));
  for (const name of ["vaultGeneration", "accountSelectionEpoch"]) {
    assert.throws(() => encodeReviewedIntent03V2({ ...fields, [name]: 2n }), /unsupported/);
  }
  for (const smsCeiling of [undefined, null, false, 0, 7, 1.5, "1", 1n, NaN, Infinity]) {
    assert.throws(() => encodeReviewedIntent03V2({ ...fields, smsCeiling }));
  }
  const absent = { ...fields }; delete absent.smsCeiling; assert.throws(() => encodeReviewedIntent03V2(absent));
  for (const name of ["bindingGeneration", "vaultGeneration", "manifestVersion", "accountSelectionEpoch", "observedMs", "messageExpiresMs", "reviewIssuedMs", "reviewExpiresMs"]) {
    for (const value of [0n, -1n, 1n << 63n, 1, "1", true]) assert.throws(() => encodeReviewedIntent03V2({ ...fields, [name]: value }));
  }
  const getter = { ...fields }; Object.defineProperty(getter, "peer", { get() { throw Error("must not run"); } });
  assert.throws(() => encodeReviewedIntent03V2(getter), /accessor/);
});

test("V2 grammar pins shifted tail and exact592/803 boundaries without suffix or digest slots", async () => {
  const p = await packet(await fixture()), f = decodeReviewedIntent03V2(p.intent);
  for (let n = 0; n < p.intent.length; n++) assert.throws(() => decodeReviewedIntent03V2(p.intent.slice(0, n)));
  for (const bytes of [join(p.intent, Uint8Array.of(0)), join(p.intent, new Uint8Array(32))]) assert.throws(() => decodeReviewedIntent03V2(bytes));
  for (const [at, value] of [[4, 1], [5, 2], [6, 2], [7, 1], [520, 0], [524, 0], [p.intent.length - 1, 0], [p.intent.length - 1, 7]]) {
    const bytes = p.intent.slice(); bytes[at] = value; assert.throws(() => decodeReviewedIntent03V2(bytes));
  }
  const minimum = encodeReviewedIntent03V2({ ...f, recipients: f.recipients.slice(0, 2) });
  assert.equal(minimum.length, 592); assert.equal(minimum[520], 3); assert.equal(minimum[524], 2);
  const peer = new Uint8Array(16).fill(49); peer[0] = 43;
  const recipients = [...f.recipients.slice(0, 2), ...Array.from({ length: 6 }, (_, i) => ({ role: 3, keyId: new Uint8Array(32).fill(80 + i) }))];
  const maximum = encodeReviewedIntent03V2({ ...f, peer, recipients });
  assert.equal(maximum.length, 803); assert.deepEqual(encodeReviewedIntent03V2(decodeReviewedIntent03V2(maximum)), maximum);
  for (const changed of [{ ...f, recipients: [...recipients, { role: 3, keyId: new Uint8Array(32).fill(99) }] },
    { ...f, recipients: [...f.recipients].reverse() }, { ...f, recipients: [f.recipients[0], f.recipients[0]] },
    { ...f, peer: enc.encode("+01") }]) assert.throws(() => encodeReviewedIntent03V2(changed));
});

test("each V2 immutable field and original trusted scope is independently bound", async () => {
  const f = await fixture(), p = await packet(f), original = decodeReviewedIntent03V2(p.intent);
  for (const [name, value] of Object.entries(original)) {
    const changed = clone(original);
    if (value instanceof Uint8Array) changed[name][0] ^= 1;
    else if (typeof value === "bigint") changed[name] += 1n;
    else if (name === "smsCeiling") changed[name] = 6;
    else changed.recipients[2].keyId[0] ^= 1;
    let intent; try { intent = encodeReviewedIntent03V2(changed); } catch { continue; }
    await assert.rejects(verifyReviewedIntent03V2({ ...p, intent }), undefined, name);
  }
  for (const change of [c => c.accountSelectionEpoch++, c => c.ownerUserId[0] ^= 1, c => c.ownerSessionId[0] ^= 1,
    c => c.intervalId[0] ^= 1, c => c.peer = enc.encode("+13"), c => c.canonicalOrigin = "https://other.test"]) {
    const c = contextFor(f); change(c);
    await assert.rejects(verifyReviewedIntent03V2({ ...p, context: await captureTrustedReviewContext03(c) }));
  }
});

test("valid V2 intent cannot rescue substituted ciphertext, bad envelope signature, domain or high-S", async () => {
  const f = await fixture(), p = await packet(f);
  const other = await packet(f); await assert.rejects(verifyReviewedIntent03V2({ ...p, envelope: other.envelope }));
  const envelope = p.envelope.slice(); envelope[envelope.length - 1] ^= 1;
  const intent = encodeReviewedIntent03V2({ ...decodeReviewedIntent03V2(p.intent), envelopeDigest: await sha(envelope) });
  const signature = await sign(f, reviewedIntentTranscript03V2(intent));
  await assert.rejects(verifyReviewedIntent03V2({ ...p, envelope, intent, signature }), /signature/);
  for (const domain of ["zrotext/conversation/reviewed-send03/v1", "ZTSE/sign/v3", "zrotext/conversation/confirm-send/v1"]) {
    await assert.rejects(verifyReviewedIntent03V2({ ...p, signature: await sign(f, frame(domain, p.intent)) }), /signature/);
  }
  for (const signature of [new Uint8Array(64), new Uint8Array(63), new Uint8Array(65), new Uint8Array(64).fill(255)])
    await assert.rejects(verifyReviewedIntent03V2({ ...p, signature }));
  const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const s = BigInt("0x" + Buffer.from(p.signature.subarray(32)).toString("hex"));
  const high = p.signature.slice(); high.set(Buffer.from((order - s).toString(16).padStart(64, "0"), "hex"), 32);
  await assert.rejects(verifyReviewedIntent03V2({ ...p, signature: high }), /low-S/);
  const wrong = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const wrongSig = canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, wrong.privateKey, reviewedIntentTranscript03V2(p.intent))));
  await assert.rejects(verifyReviewedIntent03V2({ ...p, signature: wrongSig }), /signature/);
});

test("V2 original review window, captured floor and whole-message bounds cannot renew", async () => {
  const f = await fixture(), p = await packet(f);
  await verifyReviewedIntent03V2({ ...p, nowMs: 34_999n });
  for (const nowMs of [35_000n, present - 1n]) await assert.rejects(verifyReviewedIntent03V2({ ...p, nowMs }));
  for (const overrides of [{ reviewIssuedMs: present + 1n }, { reviewExpiresMs: present }, { reviewExpiresMs: 60_001n },
    { reviewIssuedMs: 29_999n }, { nowMs: 40_000n }]) await assert.rejects(packet(f, overrides));
  const later = contextFor(f); later.nowMs++;
  await assert.rejects(verifyReviewedIntent03V2({ ...p, context: await captureTrustedReviewContext03(later) }), /context clock regressed/);
  const shorter = contextFor(f); shorter.currentAuthority.permissionExpiresAtMs = 39_999n;
  await assert.rejects(verifyReviewedIntent03V2({ ...p, context: await captureTrustedReviewContext03(shorter) }));
  const laterStart = contextFor(f); laterStart.intervalFromMs = present + 1n; laterStart.nowMs = present + 2n;
  await assert.rejects(verifyReviewedIntent03V2({ ...p, nowMs: present + 2n, context: await captureTrustedReviewContext03(laterStart) }), /whole-message/);
});

test("V2 snapshots all packet arrays and scalars before asynchronous work", async () => {
  const f = await fixture(), p = await packet(f), expected = p.intent.slice(), verifying = verifyReviewedIntent03V2(p);
  p.intent.fill(0); p.signature.fill(0); p.envelope.fill(0); p.nowMs = 1n; p.context = {};
  assert.deepEqual(verifiedReviewedIntentSnapshot03V2(await verifying).intent, expected);
  const out = await composeSealedOutboundEnvelope03(inputFor(f));
  const prep = { context: await captureTrustedReviewContext03(contextFor(f)), envelope: out.envelope,
    reviewIssuedMs: present, reviewExpiresMs: 35_000n, smsCeiling: 1, nowMs: present };
  const preparing = prepareReviewedIntent03V2(prep); prep.envelope.fill(0); prep.smsCeiling = 6; prep.reviewExpiresMs = 1n;
  const captured = decodeReviewedIntent03V2(await preparing);
  assert.equal(captured.smsCeiling, 1); assert.equal(captured.reviewExpiresMs, 35_000n);
  const shared = new SharedArrayBuffer(expected.length), disguised = new Uint8Array(shared); disguised.set(expected);
  Object.setPrototypeOf(shared, ArrayBuffer.prototype); assert.throws(() => decodeReviewedIntent03V2(disguised));
});

test("independent V2 struct vectors pin bytes, transcript and actual public low-S signatures", async () => {
  const vectors = JSON.parse(readFileSync(new URL("../../../protocol/v1/vectors/reviewed-intent03-v2.json", import.meta.url)));
  const bytes = hex => Uint8Array.from(Buffer.from(hex, "hex"));
  const numbers = new Set("bindingGeneration vaultGeneration manifestVersion accountSelectionEpoch observedMs messageExpiresMs reviewIssuedMs reviewExpiresMs".split(" "));
  for (const vector of vectors.cases) {
    const fields = Object.fromEntries(Object.entries(vector.fields).map(([k, v]) => [k, numbers.has(k) ? BigInt(v) :
      k === "recipients" ? v.map(r => ({ role: r.role, keyId: bytes(r.keyId) })) : k === "smsCeiling" ? v : bytes(v)]));
    const intent = encodeReviewedIntent03V2(fields); assert.equal(Buffer.from(intent).toString("hex"), vector.intent_hex);
    assert.equal(Buffer.from(await sha(intent)).toString("hex"), vector.intent_sha256);
    const transcript = reviewedIntentTranscript03V2(intent);
    assert.equal(Buffer.from(await sha(transcript)).toString("hex"), vector.transcript_sha256);
    const key = await crypto.subtle.importKey("raw", bytes(vector.signer_point_hex), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, bytes(vector.signature_hex), transcript), true);
    assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, bytes(vector.signature_hex), frame("zrotext/conversation/reviewed-send03/v1", intent)), false);
  }
});
