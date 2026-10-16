// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { captureTrustedReviewContext03, encodeReviewedIntent03, decodeReviewedIntent03, prepareReviewedIntent03,
  reviewedIntentTranscript03, verifyReviewedIntent03, verifiedReviewedIntentSnapshot03 } from "../dist/reviewed-intent03.js";
import { fixture, clone, uuid, enc, present, inputFor, composeSealedOutboundEnvelope03, canonicalP256Signature,
  sha, join, frame } from "./fixtures/profile03-outbound-fixture.mjs";

function contextFor(f) {
  return { currentAuthority: clone(f.authority), manifest: f.currentManifest, acceptedElection: f.proof,
    accountSelectionEpoch: 1n, ownerUserId: uuid(140), ownerSessionId: uuid(160), canonicalOrigin: "https://example.test",
    intervalId: uuid(180), intervalFromMs: 20_000n, intervalUntilMs: 60_000n, peer: enc.encode("+12"),
    signerKeyId: f.records[4].id.slice(), recipients: f.records.slice(0, 3).map(r => ({ role: r.role, keyId: r.id.slice() })), nowMs: present };
}

test("trusted context requires genuine accepted election and manifest handles with current selection", async () => {
  const f = await fixture();
  assert.deepEqual(Object.keys(await captureTrustedReviewContext03(contextFor(f))), []);
  for (const change of [c => c.manifest = {}, c => c.acceptedElection = {}, c => c.currentAuthority.bindingId[0] ^= 1,
    c => c.currentAuthority.permissionExpiresAtMs = present, c => c.signerKeyId.fill(9)]) {
    const c = contextFor(f); change(c); await assert.rejects(captureTrustedReviewContext03(c));
  }
});

test("closed context rejects arbitrary digest substitutes, accessors, prototype fields and bad scalar types", async () => {
  const f = await fixture();
  const changes = [c => c.originDigest = new Uint8Array(32), c => c.ownerSessionDigest = new Uint8Array(32),
    c => delete c.ownerSessionId, c => Object.defineProperty(c, "ownerUserId", { get() { throw Error("getter invoked"); } }),
    c => Object.setPrototypeOf(c, { role: "owner" }), c => c.accountSelectionEpoch = true,
    c => c.accountSelectionEpoch = 0n, c => c.accountSelectionEpoch = 1n << 63n,
    c => c.intervalId.fill(0), c => c.ownerSessionId.fill(0), c => c.nowMs = Number(present)];
  for (const change of changes) { const c = contextFor(f); change(c); await assert.rejects(captureTrustedReviewContext03(c)); }
});

test("origin is exact configured canonical HTTPS and interval/peer must be approved-shaped", async () => {
  const f = await fixture();
  for (const origin of ["http://example.test", "https://example.test/", "https://example.test/path", "https://EXAMPLE.test", "https://u@example.test", "https://example.test:443"]) {
    const c = contextFor(f); c.canonicalOrigin = origin; await assert.rejects(captureTrustedReviewContext03(c));
  }
  for (const change of [c => c.intervalFromMs = present + 1n, c => c.intervalUntilMs = present,
    c => c.intervalUntilMs = c.intervalFromMs, c => c.peer = enc.encode("+01"), c => c.peer = enc.encode("+1x")]) {
    const c = contextFor(f); change(c); await assert.rejects(captureTrustedReviewContext03(c));
  }
});

test("recipient selection is canonical and enforces exact existing one-device/one-archive policy", async () => {
  const f = await fixture();
  for (const change of [c => c.recipients.reverse(), c => c.recipients.push(c.recipients[2]),
    c => c.recipients[0].keyId.fill(4), c => c.recipients.splice(1, 1), c => c.recipients[1].role = 3,
    c => c.recipients[2].role = 4, c => delete c.recipients[1], c => c.recipients.extra = "bad",
    c => Object.defineProperty(c.recipients, "0", { get() { throw Error("getter invoked"); } }),
    c => c.recipients[0].extra = "bad"]) {
    const c = contextFor(f); change(c); await assert.rejects(captureTrustedReviewContext03(c));
  }
});

test("byte capture refuses shared/disguised storage and captures caller changes before async hashing", async () => {
  const f = await fixture();
  for (const field of ["ownerUserId", "ownerSessionId", "intervalId", "peer", "signerKeyId"]) {
    const c = contextFor(f), shared = new SharedArrayBuffer(c[field].length), bytes = new Uint8Array(shared); bytes.set(c[field]);
    Object.setPrototypeOf(shared, ArrayBuffer.prototype); c[field] = bytes;
    await assert.rejects(captureTrustedReviewContext03(c));
  }
  const c = contextFor(f), pending = captureTrustedReviewContext03(c);
  c.ownerUserId.fill(0); c.ownerSessionId.fill(0); c.currentAuthority.bindingId.fill(0); c.peer.fill(0);
  c.signerKeyId.fill(0); c.recipients.forEach(r => r.keyId.fill(0)); c.recipients.length = 0;
  c.canonicalOrigin = "https://changed.test";
  assert.deepEqual(Object.keys(await pending), []);
});

async function packet(f, overrides = {}) {
  const composition = inputFor(f), out = await composeSealedOutboundEnvelope03(composition);
  const context = await captureTrustedReviewContext03(contextFor(f));
  const preparation = { context, envelope: out.envelope, body: composition.content, reviewIssuedMs: present,
    reviewExpiresMs: 35_000n, smsCeiling: 1, nowMs: present, ...overrides };
  const intent = await prepareReviewedIntent03(preparation);
  const signature = canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" },
    f.records[4].k.pair.privateKey, reviewedIntentTranscript03(intent))));
  return { context, envelope: out.envelope, intent, signature, nowMs: present };
}

test("real composer ciphertext and role5 intent signatures verify with ceiling1 and6 and independent commitments", async () => {
  const f = await fixture();
  for (const smsCeiling of [1, 6]) {
    const p = await packet(f, { smsCeiling }), proof = await verifyReviewedIntent03(p), snapshot = verifiedReviewedIntentSnapshot03(proof);
    assert.equal(snapshot.fields.smsCeiling, smsCeiling);
    assert.deepEqual(snapshot.fields.envelopeDigest, await sha(p.envelope));
    assert.deepEqual(snapshot.fields.unsignedDigest, await sha(p.envelope.subarray(0, -64)));
    assert.deepEqual(snapshot.fields.bodyDigest, await sha(enc.encode(inputFor(f).content)));
    assert.deepEqual(snapshot.fields.ownerSessionDigest, await sha(frame("ZTSE/line/payload-profile/owner-session/v1", join(f.authority.accountId, uuid(140), uuid(160)))));
    assert.deepEqual(snapshot.fields.originDigest, await sha(enc.encode("https://example.test")));
    assert.deepEqual(encodeReviewedIntent03(decodeReviewedIntent03(p.intent)), p.intent);
    snapshot.fields.accountId.fill(0); snapshot.intent.fill(0); snapshot.signature.fill(0); snapshot.envelope.fill(0);
    assert.deepEqual(verifiedReviewedIntentSnapshot03(proof).intent, p.intent);
  }
  assert.throws(() => verifiedReviewedIntentSnapshot03({}));
  await assert.rejects(verifyReviewedIntent03({ ...(await packet(f)), context: {} }));
});

test("closed fields enforce mandatory canonical ceiling and counters with no coercion or extras", async () => {
  const f = await fixture(), fields = decodeReviewedIntent03((await packet(f)).intent);
  for (const smsCeiling of [undefined, null, false, 0, 7, 1.5, "1", 1n, NaN, Infinity])
    assert.throws(() => encodeReviewedIntent03({ ...fields, smsCeiling }));
  const absent = { ...fields }; delete absent.smsCeiling; assert.throws(() => encodeReviewedIntent03(absent));
  for (const name of ["bindingGeneration", "vaultGeneration", "manifestVersion", "accountSelectionEpoch", "observedMs", "messageExpiresMs", "reviewIssuedMs", "reviewExpiresMs"]) {
    for (const value of [0n, -1n, 1n << 63n, 1, "1", true]) assert.throws(() => encodeReviewedIntent03({ ...fields, [name]: value }));
  }
  assert.throws(() => encodeReviewedIntent03({ ...fields, unsignedCeiling: 6 }));
  assert.throws(() => encodeReviewedIntent03({ ...fields, profile: 2 }));
  const getter = { ...fields }; Object.defineProperty(getter, "smsCeiling", { get() { throw Error("getter invoked"); } });
  assert.throws(() => encodeReviewedIntent03(getter), /accessor/);
});

test("any signed immutable field mutation refuses against original signature or trusted replay context", async () => {
  const f = await fixture(), p = await packet(f), original = decodeReviewedIntent03(p.intent);
  for (const [name, value] of Object.entries(original)) {
    const changed = clone(original);
    if (value instanceof Uint8Array) changed[name][0] ^= 1;
    else if (typeof value === "bigint") changed[name] += 1n;
    else if (name === "smsCeiling") changed[name] = 6;
    else changed.recipients[2].keyId[0] ^= 1;
    let intent; try { intent = encodeReviewedIntent03(changed); } catch { continue; }
    await assert.rejects(verifyReviewedIntent03({ ...p, intent }), undefined, name);
  }
  for (const change of [c => c.accountSelectionEpoch++, c => c.ownerUserId[0] ^= 1, c => c.ownerSessionId[0] ^= 1,
    c => c.intervalId[0] ^= 1, c => c.peer = enc.encode("+13"), c => c.canonicalOrigin = "https://other.test"]) {
    const c = contextFor(f); change(c);
    await assert.rejects(verifyReviewedIntent03({ ...p, context: await captureTrustedReviewContext03(c) }));
  }
});

test("exact envelope bytes, framing, real envelope signature and intent domain all independently matter", async () => {
  const f = await fixture(), p = await packet(f);
  for (const at of [4, 5, 6, 7, 10, 26, 74, 104, 146, 154, 162, p.envelope.length - 65, p.envelope.length - 1]) {
    const envelope = p.envelope.slice(); envelope[at] ^= 1;
    await assert.rejects(verifyReviewedIntent03({ ...p, envelope }));
  }
  // Even freshly signed intent commitments cannot bless a bad envelope signature.
  const envelope = p.envelope.slice(); envelope[envelope.length - 1] ^= 1;
  const fields = { ...decodeReviewedIntent03(p.intent), envelopeDigest: await sha(envelope) };
  const intent = encodeReviewedIntent03(fields), signature = canonicalP256Signature(new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, f.records[4].k.pair.privateKey, reviewedIntentTranscript03(intent))));
  await assert.rejects(verifyReviewedIntent03({ ...p, envelope, intent, signature }), /signature/);
  for (const domain of ["ZTSE/sign/v3", "zrotext/conversation/confirm-send/v1", "zrotext/conversation/reviewed-send03/v2"]) {
    const signature = canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, f.records[4].k.pair.privateKey, frame(domain, p.intent))));
    await assert.rejects(verifyReviewedIntent03({ ...p, signature }), /signature/);
  }
  for (const signature of [new Uint8Array(64), new Uint8Array(63), new Uint8Array(65), new Uint8Array(64).fill(255)])
    await assert.rejects(verifyReviewedIntent03({ ...p, signature }));
  const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const s = BigInt("0x" + Buffer.from(p.signature.subarray(32)).toString("hex"));
  const high = p.signature.slice(); high.set(Buffer.from((order - s).toString(16).padStart(64, "0"), "hex"), 32);
  await assert.rejects(verifyReviewedIntent03({ ...p, signature: high }), /low-S/);
  const wrong = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const wrongSignature = canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, wrong.privateKey, reviewedIntentTranscript03(p.intent))));
  await assert.rejects(verifyReviewedIntent03({ ...p, signature: wrongSignature }));
});

test("binary grammar rejects all truncations, suffixes, reserved/profile mutations and malformed recipient framing", async () => {
  const p = await packet(await fixture());
  for (let n = 0; n < p.intent.length; n++) assert.throws(() => decodeReviewedIntent03(p.intent.slice(0, n)));
  for (const bytes of [join(p.intent, Uint8Array.of(0)), join(p.intent, new Uint8Array(33))]) assert.throws(() => decodeReviewedIntent03(bytes));
  for (const [at, value] of [[4, 2], [5, 2], [6, 2], [7, 1], [552, 0], [556, 0], [p.intent.length - 1, 0], [p.intent.length - 1, 7]]) {
    const bytes = p.intent.slice(); bytes[at] = value; assert.throws(() => decodeReviewedIntent03(bytes));
  }
  const fields = decodeReviewedIntent03(p.intent), peer = new Uint8Array(16).fill(49); peer[0] = 43;
  const recipients = [...fields.recipients.slice(0, 2), ...Array.from({ length: 6 }, (_, i) => ({ role: 3, keyId: new Uint8Array(32).fill(80 + i) }))];
  const maximum = encodeReviewedIntent03({ ...fields, peer, recipients });
  assert.equal(maximum.length, 835); assert.deepEqual(encodeReviewedIntent03(decodeReviewedIntent03(maximum)), maximum);
  assert.throws(() => encodeReviewedIntent03({ ...fields, recipients: [...recipients, { role: 3, keyId: new Uint8Array(32).fill(99) }] }));
});

test("review clock is original signing/admission clock, separate from900s message TTL and later delivery", async () => {
  const f = await fixture(), p = await packet(f);
  await verifyReviewedIntent03({ ...p, nowMs: 34_999n });
  await assert.rejects(verifyReviewedIntent03({ ...p, nowMs: 35_000n }));
  await assert.rejects(verifyReviewedIntent03({ ...p, nowMs: present - 1n }));
  for (const overrides of [{ reviewIssuedMs: present + 1n }, { reviewExpiresMs: present }, { reviewExpiresMs: 60_001n },
    { reviewIssuedMs: 29_999n }, { nowMs: 40_000n }]) await assert.rejects(packet(f, overrides));
  const refresh = contextFor(f); refresh.currentAuthority.permissionExpiresAtMs = 90_000n;
  await assert.rejects(verifyReviewedIntent03({ ...p, context: await captureTrustedReviewContext03(refresh), nowMs: 35_000n }));
  const shorter = contextFor(f); shorter.currentAuthority.permissionExpiresAtMs = 39_999n;
  await assert.rejects(verifyReviewedIntent03({ ...p, context: await captureTrustedReviewContext03(shorter) }));
  const later = contextFor(f); later.nowMs = present + 1n;
  const laterContext = await captureTrustedReviewContext03(later);
  // Still >= authority.comparedAtMs: this isolates the captured-context floor.
  await assert.rejects(verifyReviewedIntent03({ ...p, context: laterContext }), /context clock regressed/);
  await assert.rejects(prepareReviewedIntent03({ context: laterContext, envelope: p.envelope, body: inputFor(f).content,
    reviewIssuedMs: present, reviewExpiresMs: 35_000n, smsCeiling: 1, nowMs: present }), /context clock regressed/);
  const openedLater = contextFor(f); openedLater.intervalFromMs = present + 1n; openedLater.nowMs = present + 2n;
  const laterInterval = await captureTrustedReviewContext03(openedLater);
  // The live comparison is inside the interval, while the observation predates it.
  await assert.rejects(verifyReviewedIntent03({ ...p, context: laterInterval, nowMs: present + 2n }), /whole-message permission/);
  await assert.rejects(prepareReviewedIntent03({ context: laterInterval, envelope: p.envelope, body: inputFor(f).content,
    reviewIssuedMs: present + 2n, reviewExpiresMs: 35_000n, smsCeiling: 1, nowMs: present + 2n }), /whole-message permission/);
});

test("preparation rejects invalid plaintext and does not send or independently authenticate its opaque body commitment", async () => {
  const f = await fixture();
  for (const body of ["", "\ufeffbad", "\ud800", "a\0b", "a".repeat(32769), null]) await assert.rejects(packet(f, { body }));
  const a = await packet(f), b = await packet(f, { body: "Different synthetic owner-attested body" });
  // This is intentional: no decryptor/UI confirmation exists in this pure component.
  await verifyReviewedIntent03(b);
  assert.notDeepEqual(decodeReviewedIntent03(a.intent).bodyDigest, decodeReviewedIntent03(b.intent).bodyDigest);
});

test("candidate long message TTL is explicit, bounded separately from review and has no new manifest-issued floor", async () => {
  const f = await fixture(); f.authority.permissionExpiresAtMs = 1_000_000n;
  const current = contextFor(f); current.intervalUntilMs = 1_000_000n;
  const context = await captureTrustedReviewContext03(current), composition = inputFor(f); composition.expiresMs = 930_000n;
  const envelope = (await composeSealedOutboundEnvelope03(composition)).envelope;
  const intent = await prepareReviewedIntent03({ context, envelope, body: composition.content, reviewIssuedMs: present,
    reviewExpiresMs: 60_000n, smsCeiling: 6, nowMs: present });
  assert.equal(decodeReviewedIntent03(intent).messageExpiresMs - present, 900_000n);
  const signature = canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, f.records[4].k.pair.privateKey, reviewedIntentTranscript03(intent))));
  await verifyReviewedIntent03({ context, envelope, intent, signature, nowMs: 59_999n });
  await assert.rejects(verifyReviewedIntent03({ context, envelope, intent, signature, nowMs: 60_000n }));
  const issuedLater = await fixture({ issued_ms: 35_000, key_from_ms: 7_000 });
  await verifyReviewedIntent03(await packet(issuedLater));
});

test("independent struct vectors pin canonical bytes, transcript SHA and actual public ECDSA signatures", async () => {
  const vectors = JSON.parse(readFileSync(new URL("../../../protocol/v1/vectors/reviewed-intent03.json", import.meta.url)));
  const bytes = hex => Uint8Array.from(Buffer.from(hex, "hex"));
  const numbers = new Set("bindingGeneration vaultGeneration manifestVersion accountSelectionEpoch observedMs messageExpiresMs reviewIssuedMs reviewExpiresMs".split(" "));
  for (const vector of vectors.cases) {
    const fields = Object.fromEntries(Object.entries(vector.fields).map(([k, v]) => [k, numbers.has(k) ? BigInt(v) :
      k === "recipients" ? v.map(r => ({ role: r.role, keyId: bytes(r.keyId) })) : k === "smsCeiling" ? v : bytes(v)]));
    const intent = encodeReviewedIntent03(fields); assert.equal(Buffer.from(intent).toString("hex"), vector.intent_hex);
    assert.equal(Buffer.from(await sha(intent)).toString("hex"), vector.intent_sha256);
    const transcript = reviewedIntentTranscript03(intent);
    assert.equal(Buffer.from(await sha(transcript)).toString("hex"), vector.transcript_sha256);
    const key = await crypto.subtle.importKey("raw", bytes(vector.signer_point_hex), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, bytes(vector.signature_hex), transcript), true);
    assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, bytes(vector.signature_hex), frame("zrotext/conversation/confirm-send/v1", intent)), false);
  }
});

test("async verification and preparation capture private context, packet bytes and scalar inputs before awaits", async () => {
  const f = await fixture(), p = await packet(f), expected = p.intent.slice();
  const verifying = verifyReviewedIntent03(p);
  p.intent.fill(0); p.signature.fill(0); p.envelope.fill(0); p.nowMs = 1n; p.context = {};
  assert.deepEqual(verifiedReviewedIntentSnapshot03(await verifying).intent, expected);
  const composition = inputFor(f), envelope = (await composeSealedOutboundEnvelope03(composition)).envelope;
  const inputs = { context: await captureTrustedReviewContext03(contextFor(f)), envelope, body: composition.content,
    reviewIssuedMs: present, reviewExpiresMs: 35_000n, smsCeiling: 1, nowMs: present };
  const preparing = prepareReviewedIntent03(inputs); envelope.fill(0); inputs.body = "changed"; inputs.smsCeiling = 6; inputs.reviewExpiresMs = 1n;
  const captured = decodeReviewedIntent03(await preparing);
  assert.equal(captured.smsCeiling, 1); assert.equal(captured.reviewExpiresMs, 35_000n);
  assert.deepEqual(captured.bodyDigest, await sha(enc.encode(composition.content)));
});
