// Test-only profile-02 envelope preparation checks. All keys below are public synthetic
// test material with fixed scalars/IKMs, so every byte except ECDSA signatures is stable
// across runs: the manifest digest covers only unsigned manifest fields, and the pinned
// constants below prove the exact unsigned envelope transcript is reproducible.
import assert from "node:assert/strict";
import { createECDH, createHash, webcrypto } from "node:crypto";
import { test } from "node:test";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { canonicalSignature02, verifyManifest02 } from "../dist/draft02-manifest.js";
import { keyId } from "../dist/draft01.js";
import { prepareInboundEnvelope02, prepareOutboundEnvelope02 } from "../dist/draft02-envelope-prep.js";

globalThis.crypto ??= webcrypto;
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const maxSigned = (1n << 63n) - 1n;

const enc = new TextEncoder();
const hex = (value) => Buffer.from(value).toString("hex");
const ascii = (value) => enc.encode(value);
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((part) => Buffer.from(part))));
const repeat = (value, count) => Uint8Array.from({ length: count }, () => value);
const sha256 = (value) => Uint8Array.from(createHash("sha256").update(value).digest());
const u16 = (value) => Uint8Array.of(value >> 8, value & 255);
const u32 = (value) => Uint8Array.of(value >>> 24, value >>> 16 & 255, value >>> 8, value & 255);
const u64 = (value) => { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, BigInt(value), false); return out; };
const buffer = (value) => Uint8Array.from(value).buffer;
const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);

const now = 1_893_500_000_000n;
const fixed = {
  account: repeat(0xa1, 16), device: repeat(0xd1, 16), line: repeat(0xb1, 16),
  message: repeat(0x31, 16), peer: ascii("+12"),
  outboundText: "Draft02 prep ✉", inboundText: "Draft02 prep ✓",
  outboundCek: repeat(0xc1, 32), inboundCek: repeat(0xc2, 32),
  outboundNonce: repeat(0xa5, 12), inboundNonce: repeat(0xa6, 12),
  deviceEkm: repeat(0x51, 32), archiveEkm: repeat(0x52, 32), readerEkm: repeat(0x53, 32),
};

async function signingKey(scalarByte) {
  const scalar = new Uint8Array(32);
  scalar[31] = scalarByte;
  const ec = createECDH("prime256v1");
  ec.setPrivateKey(scalar);
  const point = Uint8Array.from(ec.getPublicKey(undefined, "uncompressed"));
  const b64url = (value) => Buffer.from(value).toString("base64url");
  const privateKey = await crypto.subtle.importKey("jwk", {
    kty: "EC", crv: "P-256", x: b64url(point.subarray(1, 33)), y: b64url(point.subarray(33)),
    d: b64url(scalar), ext: true, key_ops: ["sign"],
  }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  return { privateKey, point };
}

// A key that can never produce an ECDSA signature, to prove authorization runs first.
async function unusableSigningKey() {
  return crypto.subtle.importKey("raw", buffer(repeat(0x0e, 32)), "AES-GCM", false, ["encrypt"]);
}

async function kemKey(ikmByte) {
  const ikm = repeat(ikmByte, 32);
  const pair = await suite.kem.deriveKeyPair(ikm);
  const point = new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  return { ikm, pair, point, keyId: await keyId(0x0010, point) };
}

async function manifestFixture(options = {}) {
  const root = await signingKey(7);
  const outboundSigner = await signingKey(5);
  const inboundSigner = await signingKey(6);
  const device = await kemKey(0x11);
  const archive = await kemKey(0x22);
  const reader = await kemKey(0x33);
  const issued = now - 1_000n;
  const expires = now + 3_600_000n;
  const records = [
    { role: 1, id: device.keyId, point: device.point, device: fixed.device, line: fixed.line, scope: 4, state: 1 },
    { role: 2, id: archive.keyId, point: archive.point, device: new Uint8Array(16), line: new Uint8Array(16), scope: 12, state: 1 },
    { role: 3, id: reader.keyId, point: reader.point, device: new Uint8Array(16), line: new Uint8Array(16), scope: options.readerScope ?? 12, state: 1 },
    { role: 4, id: await keyId(0x0101, inboundSigner.point), point: inboundSigner.point, device: fixed.device, line: fixed.line, scope: 2, state: options.inboundState ?? 1 },
    { role: 5, id: await keyId(0x0101, outboundSigner.point), point: outboundSigner.point, device: new Uint8Array(16), line: options.signerLine ?? fixed.line, scope: 1, state: options.outboundState ?? 1 },
    { role: 6, id: await keyId(0x0101, root.point), point: root.point, device: new Uint8Array(16), line: new Uint8Array(16), scope: 0, state: 1 },
  ];
  const unsigned = concat(ascii("ZTMA"), Uint8Array.of(2), fixed.account, u64(1n), u64(1n),
    u64(issued), u64(expires), new Uint8Array(32), root.point, Uint8Array.of(records.length),
    ...records.map((record) => concat(Uint8Array.of(record.role), record.id, record.point, record.device, record.line,
      u16(record.scope), u64(issued), u64(expires), Uint8Array.of(record.state))));
  const transcript = concat(ascii("ZTSE/manifest/v2\0"), u32(unsigned.length), unsigned);
  const signature = canonicalSignature02(new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, root.privateKey, transcript)));
  const pin = { accountId: fixed.account, generation: 1n, rootPoint: root.point,
    version: 0n, digest: new Uint8Array(32), anchorDigest: new Uint8Array(32) };
  const manifest = await verifyManifest02(concat(unsigned, signature), pin, now);
  return { manifest, device, archive, reader, outboundSigner, inboundSigner };
}

function outboundInput(fixture, overrides = {}) {
  return {
    kind: 1, manifest: fixture.manifest, nowMs: now,
    messageId: fixed.message, deviceId: fixed.device, lineId: fixed.line, peer: fixed.peer,
    observedMs: now, expiresMs: now + 300_000n, content: fixed.outboundText,
    cek: fixed.outboundCek, nonce: fixed.outboundNonce,
    signer: { privateKey: fixture.outboundSigner.privateKey, publicPoint: fixture.outboundSigner.point },
    recipients: [
      { role: 1, keyId: fixture.device.keyId, point: fixture.device.point, ekm: fixed.deviceEkm },
      { role: 2, keyId: fixture.archive.keyId, point: fixture.archive.point, ekm: fixed.archiveEkm },
    ],
    ...overrides,
  };
}

function inboundInput(fixture, overrides = {}) {
  return {
    kind: 2, manifest: fixture.manifest, nowMs: now,
    messageId: fixed.message, deviceId: fixed.device, lineId: fixed.line, peer: fixed.peer,
    observedMs: now, eventId: fixed.message, localSequence: 7n, content: fixed.inboundText,
    cek: fixed.inboundCek, nonce: fixed.inboundNonce,
    signer: { privateKey: fixture.inboundSigner.privateKey, publicPoint: fixture.inboundSigner.point },
    recipients: [
      { role: 2, keyId: fixture.archive.keyId, point: fixture.archive.point, ekm: fixed.archiveEkm },
    ],
    ...overrides,
  };
}

// Independent structural walk mirroring the dormant Rust reader bounds, so a prepared
// envelope always satisfies the grammar the candidate profile's verifier expects.
function structuralWalk(prepared, kind) {
  const value = Buffer.from(prepared.envelope);
  const maxTotal = kind === 1 ? 34_213 : 34_082;
  assert.ok(value.length >= 426 && value.length <= 36_864 && value.length <= maxTotal, "envelope size");
  assert.deepEqual(Uint8Array.from(value.subarray(0, 5)), Uint8Array.of(0x5a, 0x54, 0x53, 0x45, 2), "magic/profile");
  assert.equal(value[5], kind);
  assert.deepEqual(Uint8Array.from(value.subarray(6, 8)), Uint8Array.of(0, 0), "flags");
  const protectedLen = value.readUInt16BE(8);
  const baseLen = kind === 1 ? 154 : 169;
  const peerLenAt = kind === 1 ? 153 : 168;
  const peerLen = value[10 + peerLenAt];
  assert.equal(protectedLen, baseLen + peerLen, "canonical protected length");
  const bodyLen = value.readUInt32BE(10 + protectedLen + 12);
  assert.equal(value.length, 10 + protectedLen + 16 + bodyLen + 1 + prepared.wraps.length * 146 + 64, "exact envelope width");
  assert.equal(bodyLen, 16 + Buffer.byteLength(kind === 1 ? fixed.outboundText : fixed.inboundText), "body length field");
  let previous = null;
  let deviceCount = 0;
  let archiveCount = 0;
  for (const wrap of prepared.wraps) {
    if (previous) assert.ok(wrap.role > previous.role || (wrap.role === previous.role && Buffer.compare(Buffer.from(wrap.keyId), Buffer.from(previous.keyId)) > 0), "wrap order");
    previous = wrap;
    assert.ok([1, 2, 3].includes(wrap.role), "wrap role");
    deviceCount += wrap.role === 1 ? 1 : 0;
    archiveCount += wrap.role === 2 ? 1 : 0;
  }
  assert.equal(deviceCount, kind === 1 ? 1 : 0, "device wraps");
  assert.equal(archiveCount, 1, "archive wraps");
  assert.equal(prepared.signature.length, 64, "signature width");
  assert.equal(prepared.unsigned.length, value.length - 64, "unsigned span");
  assert.ok(equal(prepared.unsignedSha256, sha256(prepared.unsigned)), "unsigned digest");
}

// Independent consumer: reopen a prepared wrap exactly as the Rust/Android readers do.
async function openWrapAndBody(prepared, role, recipientPrivateKey, expectedContent) {
  const wrap = prepared.wraps.find((item) => item.role === role);
  const recipient = await suite.createRecipientContext({
    recipientKey: recipientPrivateKey, enc: buffer(wrap.enc), info: buffer(wrap.info),
  });
  const cek = new Uint8Array(await recipient.open(buffer(wrap.ct), new ArrayBuffer(0)));
  assert.equal(cek.length, 32, "recovered CEK width");
  const bodyKey = await crypto.subtle.importKey("raw", buffer(cek), "AES-GCM", false, ["decrypt"]);
  const body = new Uint8Array(await crypto.subtle.decrypt({
    name: "AES-GCM", iv: buffer(prepared.envelope.subarray(10 + prepared.protected.length, 10 + prepared.protected.length + 12)),
    additionalData: buffer(prepared.bodyAad), tagLength: 128,
  }, bodyKey, buffer(prepared.envelope.subarray(10 + prepared.protected.length + 16, prepared.envelope.length - 64 - 1 - prepared.wraps.length * 146))));
  assert.equal(new TextDecoder().decode(body), expectedContent, "recovered body text");
}

async function verifyOriginSignature(prepared, signerPoint) {
  const transcript = concat(ascii("ZTSE/sign/v2\0"), u32(prepared.unsigned.length), prepared.unsigned);
  const key = await crypto.subtle.importKey("raw", buffer(signerPoint), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  assert.ok(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, buffer(prepared.signature), buffer(transcript)), "origin signature");
  assert.deepEqual(prepared.signature, canonicalSignature02(prepared.signature), "low-s signature");
}

const pinnedOutboundUnsignedHex = "5a54534502010000009da1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a131313131313131313131313131313131d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b10000000000000001f936214792324059253d35168fe67b9cbbb877d5641d4d12772b88e539c950ca225778922ad1f5921f1561095dff1dd8f3d316dcb59736f48631697880c723ae000001b8dd651700000001b8dd69aae001032b3132a5a5a5a5a5a5a5a5a5a5a5a5000000203b4b0e6b7c4ddcaa6bd9635a093ff6b73924adc0282dc4953008e33aab71fe930201864d167d204c1d7f15de43a1d48c10a0cb787af5ca0b28f58e0c5f62bef6bb1c0427988a1f8a5af2269603b0fb5114ab016701fb1468212d97c01b3566038fb63b37f9b4aa356d888b0fad09cb147f6c5e306dac65aaa7e02f94c7b52c7f62a2571e3c4b9d0a2a4bdce3b9adad64f8cc7a23db5c92a5778d8d002c3e1ac7e942b5234071db4a4c7553336f2b0b09978c6602077d873e1ff06750695653ea83dd16e2058de174a06092e6d23576946f57816404b671da8b6b1eb95671ba7448536c1910930df4caa9cd64888eab61f06fecb889c3d07ab85e8600a6a8f6d5e2808727ce018bbbdb2b7ce5c173228cc8a52aa01d4f25a108a513f830ad1157cc39f280cb92b4720ebdedce891fdc43923446f552ab9ce35f60a840457da4a878fea16786";
const pinnedOutboundShaHex = "a086fca090da5b0ad36b11f7538ad9e8de113a01f4ccd9388025c736f4ca9504";
const pinnedInboundUnsignedHex = "5a5453450202000000aca1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a131313131313131313131313131313131d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b10000000000000001f936214792324059253d35168fe67b9cbbb877d5641d4d12772b88e539c950ca6fe6495d5585dfccbda051ac36f9af1f1c011b2967985d898892f9e3de881554000001b8dd651700313131313131313131313131313131310000000000000007032b3132a6a6a6a6a6a6a6a6a6a6a6a6000000209c0ef45fd63cc9b7e71f6a1779127e597b5dc6541a32a6f759d890ade0ebf1760102077d873e1ff06750695653ea83dd16e2058de174a06092e6d23576946f57816404b671da8b6b1eb95671ba7448536c1910930df4caa9cd64888eab61f06fecb889c3d07ab85e8600a6a8f6d5e2808727ce018bbbdb2b7ce5c173228cc8a52aa01d6d22f4ad93bb94da0ad1e6d2aebe727c595212e95d4a8cec4bad234b12ee6c2ae5085a89586ced63f32c1f1c22a1ec46";
const pinnedInboundShaHex = "be2435720b8bbf291f6a991d8d2377f17cb2096e0e29e23f80f4a7e0bc1e39f7";

test("outbound preparation reproduces the pinned profile-02 unsigned transcript exactly", async () => {
  const fixture = await manifestFixture();
  const prepared = await prepareOutboundEnvelope02(outboundInput(fixture));
  assert.equal(hex(prepared.unsigned), pinnedOutboundUnsignedHex);
  assert.equal(hex(prepared.unsignedSha256), pinnedOutboundShaHex);
  structuralWalk(prepared, 1);
  await verifyOriginSignature(prepared, fixture.outboundSigner.point);
  await openWrapAndBody(prepared, 2, fixture.archive.pair.privateKey, fixed.outboundText);
  // The wrap info and body AAD must be the exact profile-02 transcript bytes.
  const header = concat(ascii("ZTSE"), Uint8Array.of(2, 1, 0, 0), u16(prepared.protected.length));
  assert.deepEqual(prepared.bodyAad, concat(ascii("ZTSE/body/v2\0"), header, prepared.protected));
  for (const wrap of prepared.wraps) {
    assert.deepEqual(wrap.info, concat(ascii("ZTSE/wrap/v2\0"), header, prepared.protected, Uint8Array.of(wrap.role), wrap.keyId));
  }
});

test("inbound preparation reproduces the pinned profile-02 unsigned transcript exactly", async () => {
  const fixture = await manifestFixture();
  const prepared = await prepareInboundEnvelope02(inboundInput(fixture));
  assert.equal(hex(prepared.unsigned), pinnedInboundUnsignedHex);
  assert.equal(hex(prepared.unsignedSha256), pinnedInboundShaHex);
  structuralWalk(prepared, 2);
  await verifyOriginSignature(prepared, fixture.inboundSigner.point);
  await openWrapAndBody(prepared, 2, fixture.archive.pair.privateKey, fixed.inboundText);
});

test("preparation is deterministic for identical inputs and varies with the wrap ekm", async () => {
  const fixture = await manifestFixture();
  const first = await prepareOutboundEnvelope02(outboundInput(fixture));
  const second = await prepareOutboundEnvelope02(outboundInput(fixture));
  assert.deepEqual(second.unsigned, first.unsigned);
  assert.deepEqual(second.unsignedSha256, first.unsignedSha256);
  const changedEkm = await prepareOutboundEnvelope02(outboundInput(fixture, {
    recipients: outboundInput(fixture).recipients.map((recipient, index) =>
      index === 0 ? { ...recipient, ekm: repeat(0x61, 32) } : recipient),
  }));
  assert.notEqual(hex(changedEkm.unsigned), hex(first.unsigned));
  assert.notEqual(hex(changedEkm.wraps[0].enc), hex(first.wraps[0].enc));
  const changedContent = await prepareInboundEnvelope02(inboundInput(fixture, { content: "different body" }));
  const baseline = await prepareInboundEnvelope02(inboundInput(fixture));
  assert.notEqual(hex(changedContent.unsigned), hex(baseline.unsigned));
});

test("outbound authorization is consulted before any crypto and fails closed", async () => {
  const fixture = await manifestFixture();
  const unusable = await unusableSigningKey();
  // Control: this key really cannot produce an ECDSA signature.
  await assert.rejects(prepareOutboundEnvelope02(outboundInput(fixture, {
    signer: { privateKey: unusable, publicPoint: fixture.outboundSigner.point },
  })));
  // Ordering: with a revoked signer the authorization error surfaces, not a signing failure.
  const revoked = await manifestFixture({ outboundState: 2 });
  await assert.rejects(prepareOutboundEnvelope02(outboundInput(revoked, {
    signer: { privateKey: unusable, publicPoint: fixture.outboundSigner.point },
  })), /outbound signer authority/);
  await assert.rejects(prepareOutboundEnvelope02(outboundInput(fixture, { manifest: { ...fixture.manifest } })), /just-verified/);
  await assert.rejects(prepareOutboundEnvelope02(outboundInput(fixture, { nowMs: now + 3_600_000n })), /stale or future/);
  await assert.rejects(prepareOutboundEnvelope02(outboundInput(fixture, { recipients: [outboundInput(fixture).recipients[1]] })), /reader set/);
  const wrongLine = await manifestFixture({ signerLine: fixed.device });
  await assert.rejects(prepareOutboundEnvelope02(outboundInput(wrongLine)), /outbound signer authority/);
  const outboundBlindReader = await manifestFixture({ readerScope: 8 });
  await assert.rejects(prepareOutboundEnvelope02(outboundInput(outboundBlindReader, {
    recipients: [...outboundInput(outboundBlindReader).recipients,
      { role: 3, keyId: outboundBlindReader.reader.keyId, point: outboundBlindReader.reader.point, ekm: fixed.readerEkm }],
  })), /reader authority/);
});

test("inbound authorization is consulted before any crypto and fails closed", async () => {
  const fixture = await manifestFixture();
  const unusable = await unusableSigningKey();
  await assert.rejects(prepareInboundEnvelope02(inboundInput(fixture, {
    signer: { privateKey: unusable, publicPoint: fixture.inboundSigner.point },
  })));
  const revoked = await manifestFixture({ inboundState: 2 });
  await assert.rejects(prepareInboundEnvelope02(inboundInput(revoked, {
    signer: { privateKey: unusable, publicPoint: fixture.inboundSigner.point },
  })), /inbound signer authority/);
  await assert.rejects(prepareInboundEnvelope02(inboundInput(fixture, {
    signer: { privateKey: fixture.outboundSigner.privateKey, publicPoint: fixture.outboundSigner.point },
  })), /inbound signer authority/);
  await assert.rejects(prepareInboundEnvelope02(inboundInput(fixture, { manifest: { ...fixture.manifest } })), /just-verified/);
  // The device key exists in the manifest but its scope has no inbound bit, and a
  // device wrap is not an inbound reader at all: both paths fail closed.
  await assert.rejects(prepareInboundEnvelope02(inboundInput(fixture, {
    recipients: [...inboundInput(fixture).recipients, { role: 1, keyId: fixture.device.keyId, point: fixture.device.point, ekm: fixed.deviceEkm }],
  })), /inbound reader authority/);
  const inboundBlindReader = await manifestFixture({ readerScope: 4 });
  await assert.rejects(prepareInboundEnvelope02(inboundInput(inboundBlindReader, {
    recipients: [{ role: 3, keyId: inboundBlindReader.reader.keyId, point: inboundBlindReader.reader.point, ekm: fixed.readerEkm }],
  })), /inbound reader authority/);
});

test("manifest role/scope mutations are rejected at verification time, before preparation", async () => {
  await assert.rejects(manifestFixture({ readerScope: 5 }), /role\/scope/);
});

test("Q9 body content rules reject empty, oversized, BOM, NUL and non-strict UTF-8", async () => {
  const fixture = await manifestFixture();
  for (const [content, why] of [
    ["", "empty"],
    ["A".repeat(32_769), "too long"],
    ["\uFEFFhello", "BOM"],
    ["a\0b", "NUL"],
    ["lone surrogate \uD800 here", "surrogate"],
  ]) {
    await assert.rejects(prepareOutboundEnvelope02(outboundInput(fixture, { content })), /content/, why);
  }
  await prepareOutboundEnvelope02(outboundInput(fixture, { content: "A".repeat(32_768) }));
});

test("kind-specific identity rules: outbound expiry window and inbound event/sequence", async () => {
  const fixture = await manifestFixture();
  await assert.rejects(prepareOutboundEnvelope02(outboundInput(fixture, { expiresMs: now })), /intent\/expiry/);
  await assert.rejects(prepareOutboundEnvelope02(outboundInput(fixture, { expiresMs: now + 900_001n })), /intent\/expiry/);
  await prepareOutboundEnvelope02(outboundInput(fixture, { expiresMs: now + 900_000n }));
  await assert.rejects(prepareInboundEnvelope02(inboundInput(fixture, { eventId: fixed.device })), /identity\/sequence/);
  await assert.rejects(prepareInboundEnvelope02(inboundInput(fixture, { localSequence: 0n })), /identity\/sequence/);
  await assert.rejects(prepareInboundEnvelope02(inboundInput(fixture, { localSequence: 1n << 63n })), /identity\/sequence/);
});

test("peer must be a bounded E.164 string and recipient wraps must match their manifest key id", async () => {
  const fixture = await manifestFixture();
  for (const peer of [ascii("12"), ascii("+012"), ascii("+12a"), ascii("+" + "1".repeat(16))]) {
    await assert.rejects(prepareOutboundEnvelope02(outboundInput(fixture, { peer })), /peer/);
  }
  await assert.rejects(prepareOutboundEnvelope02(outboundInput(fixture, {
    recipients: outboundInput(fixture).recipients.map((recipient, index) =>
      index === 1 ? { ...recipient, point: fixture.device.point } : recipient),
  })), /recipient key id/);
});

test("signatures are always canonical low-s and scalar range is enforced", async () => {
  const fixture = await manifestFixture();
  for (let index = 0; index < 6; index++) {
    const prepared = await prepareOutboundEnvelope02(outboundInput(fixture));
    assert.deepEqual(prepared.signature, canonicalSignature02(prepared.signature), "module output stays low-s");
  }
  const prepared = await prepareOutboundEnvelope02(outboundInput(fixture));
  const r = prepared.signature.subarray(0, 32);
  const s = prepared.signature.subarray(32);
  const scalar = (value) => value.reduce((n, b) => (n << 8n) | BigInt(b), 0n);
  const fixed32 = (value) => { const out = new Uint8Array(32); for (let i = 31; i >= 0; i--) { out[i] = Number(value & 255n); value >>= 8n; } return out; };
  const highTwin = concat(r, fixed32(order - scalar(s)));
  assert.deepEqual(canonicalSignature02(highTwin), prepared.signature, "high-s twin converts to the low-s form");
  const zeroS = concat(r, new Uint8Array(32));
  assert.throws(() => canonicalSignature02(zeroS), /signature scalar range/);
  const oversizeR = concat(fixed32(order), s);
  assert.throws(() => canonicalSignature02(oversizeR), /signature scalar range/);
  assert.throws(() => canonicalSignature02(new Uint8Array(63)), /signature width/);
});

test("integration reader wraps are accepted in both directions with the dual scope", async () => {
  const fixture = await manifestFixture();
  const outbound = await prepareOutboundEnvelope02(outboundInput(fixture, {
    recipients: [...outboundInput(fixture).recipients,
      { role: 3, keyId: fixture.reader.keyId, point: fixture.reader.point, ekm: fixed.readerEkm }],
  }));
  structuralWalk(outbound, 1);
  const inbound = await prepareInboundEnvelope02(inboundInput(fixture, {
    recipients: [...inboundInput(fixture).recipients,
      { role: 3, keyId: fixture.reader.keyId, point: fixture.reader.point, ekm: fixed.readerEkm }],
  }));
  structuralWalk(inbound, 2);
  await openWrapAndBody(inbound, 3, fixture.reader.pair.privateKey, fixed.inboundText);
});

test("localSequence and observedMs must stay inside signed u64 storage", async () => {
  const fixture = await manifestFixture();
  await prepareInboundEnvelope02(inboundInput(fixture, { localSequence: maxSigned }));
  await assert.rejects(prepareOutboundEnvelope02(outboundInput(fixture, { observedMs: -1n, expiresMs: 299_999n })), /u64 exceeds/);
  await assert.rejects(prepareInboundEnvelope02(inboundInput(fixture, { localSequence: maxSigned + 1n })), /identity\/sequence/);
});
