// SPDX-License-Identifier: AGPL-3.0-only
// Production sealed-envelope composition corpus (issue #537 slice A). The
// structural walk below mirrors the dormant Rust parser rules byte for byte
// (crates/server/src/sealed_envelope, sealed_body), the signature check uses
// the existing draft-02 helpers, and the cross-client test regenerates the
// fixture through the real generator the Rust CI lane consumes. All key
// material is public synthetic test data.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createECDH, createHash, webcrypto } from "node:crypto";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { canonicalSignature02, verifyManifest02 } from "../dist/draft02-manifest.js";
import { keyId } from "../dist/draft01.js";
import { composeSealedOutboundEnvelope, SEALED_CONTENT_TYPE, SealedEnvelopeError } from "../dist/sealed-envelope.js";
// Test seam only: pinned vector material never travels through the production input type.
import { composeSealedOutboundEnvelopeForVectors } from "../dist/sealed-envelope-vectors.js";

globalThis.crypto ??= webcrypto;
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
const maxSigned = (1n << 63n) - 1n;

const enc = new TextEncoder();
const hex = (value) => Buffer.from(value).toString("hex");
const fromHex = (value) => Uint8Array.from(Buffer.from(value, "hex"));
const ascii = (value) => enc.encode(value);
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((part) => Buffer.from(part))));
const repeat = (value, count) => Uint8Array.from({ length: count }, () => value);
const sha256 = (value) => Uint8Array.from(createHash("sha256").update(value).digest());
const u16 = (value) => Uint8Array.of(value >> 8, value & 255);
const u32 = (value) => Uint8Array.of(value >>> 24, value >>> 16 & 255, value >>> 8 & 255, value & 255);
const u64 = (value) => { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, BigInt(value), false); return out; };
const view = (bytes) => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
const u16be = (bytes, at) => view(bytes).getUint16(at, false);
const u32be = (bytes, at) => view(bytes).getUint32(at, false);
const u64be = (bytes, at) => view(bytes).getBigUint64(at, false);
const buffer = (value) => Uint8Array.from(value).buffer;
const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);

const now = 1_893_456_000_000n;
const fixed = {
  account: repeat(0x9a, 16), device: repeat(0xd4, 16), line: repeat(0xb7, 16),
  message: Uint8Array.from({ length: 16 }, (_, index) => index * 3 + 1), peer: ascii("+12"),
  text: "Slice A production envelope ✓",
  cek: repeat(0x7c, 32), nonce: repeat(0x4e, 12),
  deviceEkm: repeat(0x0d, 32), archiveEkm: repeat(0x0e, 32),
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

async function kemKey(ikmByte) {
  const ikm = repeat(ikmByte, 32);
  const pair = await suite.kem.deriveKeyPair(ikm);
  const point = new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  return { ikm, pair, point, keyId: await keyId(0x0010, point) };
}

// A verified profile-02 manifest fixture with up to six integration readers.
async function manifestFixture(options = {}) {
  const integrations = options.integrations ?? 0;
  assert.ok(integrations >= 0 && integrations <= 6);
  const root = await signingKey(0x19);
  const outboundSigner = await signingKey(0x1a);
  const device = await kemKey(0x21);
  const archive = await kemKey(0x22);
  const readers = [];
  for (let index = 0; index < integrations; index++) readers.push(await kemKey(0x30 + index));
  const issued = now - 1_000n;
  const expires = now + 3_600_000n;
  const zero16 = new Uint8Array(16);
  const records = [
    { role: 1, id: device.keyId, point: device.point, device: fixed.device, line: fixed.line, scope: 4, state: 1 },
    { role: 2, id: archive.keyId, point: archive.point, device: zero16, line: zero16, scope: 12, state: 1 },
    ...readers.map((reader) => ({ role: 3, id: reader.keyId, point: reader.point, device: zero16, line: zero16,
      scope: options.readerScope ?? 12, state: 1 })),
    { role: 5, id: await keyId(0x0101, outboundSigner.point), point: outboundSigner.point, device: zero16,
      line: options.signerLine ?? fixed.line, scope: 1, state: options.outboundState ?? 1 },
    { role: 6, id: await keyId(0x0101, root.point), point: root.point, device: zero16, line: zero16, scope: 0, state: 1 },
  ].sort((a, b) => a.role - b.role || Buffer.compare(Buffer.from(a.id), Buffer.from(b.id)));
  const unsigned = concat(ascii("ZTMA"), Uint8Array.of(2), fixed.account, u64(1n), u64(1n),
    u64(issued), u64(expires), new Uint8Array(32), root.point, Uint8Array.of(records.length),
    ...records.map((record) => concat(Uint8Array.of(record.role), record.id, record.point, record.device, record.line,
      u16(record.scope), u64(issued), u64(expires), Uint8Array.of(record.state))));
  const transcript = concat(ascii("ZTSE/manifest/v2\0"), u32(unsigned.length), unsigned);
  const signature = canonicalSignature02(new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, root.privateKey, buffer(transcript))));
  const pin = { accountId: fixed.account, generation: 1n, rootPoint: root.point,
    version: 0n, digest: new Uint8Array(32), anchorDigest: new Uint8Array(32) };
  const manifest = await verifyManifest02(concat(unsigned, signature), pin, now);
  return { manifest, device, archive, readers, outboundSigner };
}

function composeInput(fixture, overrides = {}) {
  return {
    manifest: fixture.manifest, nowMs: now,
    messageId: fixed.message, deviceId: fixed.device, lineId: fixed.line, peer: fixed.peer,
    observedMs: now, expiresMs: now + 300_000n, content: fixed.text,
    signer: { privateKey: fixture.outboundSigner.privateKey, publicPoint: fixture.outboundSigner.point },
    recipients: [
      { role: 1, keyId: fixture.device.keyId, point: fixture.device.point },
      { role: 2, keyId: fixture.archive.keyId, point: fixture.archive.point },
    ],
    ...overrides,
  };
}

// Pinned vector material for the test seam; the production entry point has no
// field for this and refuses it when handed one.
function pinnedMaterial(ekms = [fixed.deviceEkm, fixed.archiveEkm]) {
  return { cek: fixed.cek, nonce: fixed.nonce, ekms };
}

function pinnedInput(fixture, overrides = {}) {
  const { deterministicKeyMaterial = pinnedMaterial(), ...rest } = overrides;
  return { ...composeInput(fixture, rest), deterministicKeyMaterial };
}

/** Composes reproducible vector bytes through the clearly-marked test seam. */
function composePinned(fixture, overrides = {}) {
  return composeSealedOutboundEnvelopeForVectors(pinnedInput(fixture, overrides));
}

// Byte-structure walk mirroring crates/server/src/sealed_envelope parse() for
// kind 01 under Profile::Draft02Candidate, plus the sealed_body Q9 bounds.
function parserWalk(envelope, expected) {
  assert.ok(envelope.length >= 426 && envelope.length <= 36_864, "pre-allocation cap");
  assert.ok(envelope.length <= 34_213, "kind envelope size");
  assert.deepEqual(Uint8Array.from(envelope.subarray(0, 4)), ascii("ZTSE"), "magic");
  assert.equal(envelope[4], 2, "profile");
  assert.equal(envelope[5], 1, "kind");
  assert.deepEqual(Uint8Array.from(envelope.subarray(6, 8)), Uint8Array.of(0, 0), "flags");
  const protectedLen = u16be(envelope, 8);
  assert.ok(protectedLen >= 157 && protectedLen <= 170, "protected length range");
  const protectedBytes = envelope.subarray(10, 10 + protectedLen);
  const peerLen = protectedBytes[153];
  assert.ok(peerLen >= 3 && peerLen <= 16, "peer length");
  assert.equal(protectedLen, 154 + peerLen, "canonical protected length");
  const peer = protectedBytes.subarray(154);
  assert.ok(peer[0] === 0x2b && peer[1] >= 49 && peer[1] <= 57 &&
    peer.subarray(2).every((byte) => byte >= 48 && byte <= 57), "peer is E.164");
  assert.equal(new TextDecoder().decode(peer), expected.peer, "peer value");
  assert.deepEqual(Uint8Array.from(protectedBytes.subarray(0, 16)), expected.account, "account");
  assert.deepEqual(Uint8Array.from(protectedBytes.subarray(16, 32)), expected.message, "message");
  assert.deepEqual(Uint8Array.from(protectedBytes.subarray(32, 48)), expected.device, "device");
  assert.deepEqual(Uint8Array.from(protectedBytes.subarray(48, 64)), expected.line, "line");
  assert.ok(u64be(protectedBytes, 64) > 0n, "keyset version");
  assert.deepEqual(Uint8Array.from(protectedBytes.subarray(72, 104)), expected.manifestDigest, "manifest digest");
  const observedMs = u64be(protectedBytes, 136);
  const expiresMs = u64be(protectedBytes, 144);
  assert.equal(protectedBytes[152], 1, "intent tag");
  assert.ok(expiresMs > observedMs && expiresMs - observedMs <= 900_000n, "intent/expiry window");
  assert.equal(observedMs, expected.observedMs, "observed value");
  assert.equal(expiresMs, expected.expiresMs, "expires value");
  const nonceAt = 10 + protectedLen;
  const bodyLen = u32be(envelope, nonceAt + 12);
  assert.ok(bodyLen >= 17 && bodyLen <= 32_784, "body length range");
  assert.equal(bodyLen, 16 + expected.contentByteLength, "body length value");
  const bodyEnd = nonceAt + 16 + bodyLen;
  const count = envelope[bodyEnd];
  assert.ok(count >= 2 && count <= 8, "wrap count range");
  assert.equal(count, expected.wrapCount, "wrap count value");
  assert.equal(envelope.length, 10 + protectedLen + 16 + bodyLen + 1 + count * 146 + 64, "exact width");
  let previous = null;
  let deviceCount = 0;
  let archiveCount = 0;
  for (let index = 0; index < count; index++) {
    const start = bodyEnd + 1 + index * 146;
    const role = envelope[start];
    assert.ok(role >= 1 && role <= 3, "wrap role");
    const wrapKeyId = envelope.subarray(start + 1, start + 33);
    if (previous) {
      assert.ok(role > previous.role ||
        (role === previous.role && Buffer.compare(Buffer.from(wrapKeyId), Buffer.from(previous.keyId)) > 0), "wrap order");
    }
    previous = { role, keyId: wrapKeyId };
    assert.equal(envelope[start + 33], 4, "enc point prefix");
    deviceCount += role === 1 ? 1 : 0;
    archiveCount += role === 2 ? 1 : 0;
  }
  assert.equal(deviceCount, 1, "device wraps");
  assert.equal(archiveCount, 1, "archive wraps");
  const signature = envelope.subarray(envelope.length - 64);
  assert.doesNotThrow(() => canonicalSignature02(signature), "signature scalar range");
  assert.deepEqual(canonicalSignature02(signature), signature, "low-s signature");
  return { protectedBytes, protectedLen, bodyEnd };
}

async function verifyOriginSignature(envelope, signerPoint) {
  const unsigned = envelope.subarray(0, envelope.length - 64);
  const transcript = concat(ascii("ZTSE/sign/v2\0"), u32(unsigned.length), unsigned);
  const key = await crypto.subtle.importKey("raw", buffer(signerPoint), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key,
    buffer(envelope.subarray(envelope.length - 64)), buffer(transcript));
}

// Independent consumer: rebuild every transcript input from envelope bytes only.
async function openWrapAndBody(envelope, role, wrapKeyId, recipientPrivateKey, expectedContent) {
  const protectedLen = u16be(envelope, 8);
  const header = envelope.subarray(0, 10);
  const protectedBytes = envelope.subarray(10, 10 + protectedLen);
  const info = concat(ascii("ZTSE/wrap/v2\0"), header, protectedBytes, Uint8Array.of(role), wrapKeyId);
  const nonceAt = 10 + protectedLen;
  const bodyLen = u32be(envelope, nonceAt + 12);
  const bodyEnd = nonceAt + 16 + bodyLen;
  const count = envelope[bodyEnd];
  let wrap = null;
  for (let index = 0; index < count; index++) {
    const start = bodyEnd + 1 + index * 146;
    if (envelope[start] === role && equal(envelope.subarray(start + 1, start + 33), wrapKeyId)) {
      wrap = { enc: envelope.subarray(start + 33, start + 98), ct: envelope.subarray(start + 98, start + 146) };
      break;
    }
  }
  assert.ok(wrap, "wrap present");
  const recipient = await suite.createRecipientContext({ recipientKey: recipientPrivateKey, enc: buffer(wrap.enc), info: buffer(info) });
  const cek = new Uint8Array(await recipient.open(buffer(wrap.ct), new ArrayBuffer(0)));
  assert.equal(cek.length, 32, "recovered CEK width");
  const bodyKey = await crypto.subtle.importKey("raw", buffer(cek), "AES-GCM", false, ["decrypt"]);
  const bodyAad = concat(ascii("ZTSE/body/v2\0"), header, protectedBytes);
  const body = new Uint8Array(await crypto.subtle.decrypt({
    name: "AES-GCM", iv: buffer(envelope.subarray(nonceAt, nonceAt + 12)), additionalData: buffer(bodyAad), tagLength: 128,
  }, bodyKey, buffer(envelope.subarray(nonceAt + 16, bodyEnd))));
  assert.equal(new TextDecoder().decode(body), expectedContent, "recovered body text");
  return cek;
}

function runGenerator(setupJson) {
  const script = fileURLToPath(new URL("./support/generate-cross-client.mjs", import.meta.url));
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], { stdio: ["pipe", "pipe", "pipe"] });
    const out = [];
    const err = [];
    child.stdout.on("data", (chunk) => out.push(chunk));
    child.stderr.on("data", (chunk) => err.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => code === 0
      ? resolve(Buffer.concat(out))
      : reject(new Error(`generator failed (${code}): ${Buffer.concat(err)}`)));
    child.stdin.end(setupJson);
  });
}

test("composes a parser-legal kind-01 profile-02 envelope from explicit inputs", async () => {
  const fixture = await manifestFixture();
  const result = await composePinned(fixture);
  assert.equal(SEALED_CONTENT_TYPE, "application/vnd.zrotext.sealed.v1");
  // The result carries only ciphertext bytes and the Q6 digest identity.
  assert.deepEqual(Object.keys(result).sort(), ["envelope", "unsignedDigest"]);
  const { protectedBytes } = parserWalk(result.envelope, {
    account: fixed.account, message: fixed.message, device: fixed.device, line: fixed.line,
    peer: "+12", manifestDigest: fixture.manifest.digest, observedMs: now, expiresMs: now + 300_000n,
    contentByteLength: Buffer.byteLength(fixed.text), wrapCount: 2,
  });
  // The protected signer key ID is derived from the signer point, not caller text.
  assert.deepEqual(Uint8Array.from(protectedBytes.subarray(104, 136)), await keyId(0x0101, fixture.outboundSigner.point));
  // Q6 identity: SHA-256 over the exact unsigned bytes, computed independently.
  const unsigned = result.envelope.subarray(0, result.envelope.length - 64);
  assert.deepEqual(result.unsignedDigest, sha256(unsigned));
  assert.ok(await verifyOriginSignature(result.envelope, fixture.outboundSigner.point));
});

test("deterministic material reproduces identical unsigned bytes; default randomness does not", async () => {
  const fixture = await manifestFixture();
  const first = await composePinned(fixture);
  const second = await composePinned(fixture);
  const unsignedOf = (value) => value.envelope.subarray(0, value.envelope.length - 64);
  assert.deepEqual(unsignedOf(second), unsignedOf(first), "same material, same unsigned bytes");
  assert.deepEqual(second.unsignedDigest, first.unsignedDigest, "same material, same digest");
  // ekms bind to the recipient array the caller passed, not to wire order, so
  // the same (recipient, ekm) pairs in a permuted input compose identical bytes.
  const permuted = await composePinned(fixture, {
    recipients: [
      { role: 2, keyId: fixture.archive.keyId, point: fixture.archive.point },
      { role: 1, keyId: fixture.device.keyId, point: fixture.device.point },
    ],
    deterministicKeyMaterial: pinnedMaterial([fixed.archiveEkm, fixed.deviceEkm]),
  });
  assert.deepEqual(unsignedOf(permuted), unsignedOf(first), "input order must not change bytes");
  // Without the override, the production entry point draws fresh material and
  // the identity changes; and the override itself is refused on that surface.
  const fresh = await composeSealedOutboundEnvelope(composeInput(fixture));
  assert.notEqual(hex(unsignedOf(fresh)), hex(unsignedOf(first)));
  assert.notEqual(hex(fresh.unsignedDigest), hex(first.unsignedDigest));
  await assert.rejects(
    composeSealedOutboundEnvelope(pinnedInput(fixture)),
    (error) => error instanceof SealedEnvelopeError && error.code === "key_material",
  );
  // Caller-held buffers are copied, never written back into or zeroed.
  const cek = repeat(0x7c, 32);
  const ekm = repeat(0x0d, 32);
  await composePinned(fixture, {
    deterministicKeyMaterial: { cek, nonce: repeat(0x4e, 12), ekms: [ekm, repeat(0x0e, 32)] },
  });
  assert.equal(cek[0], 0x7c);
  assert.equal(ekm[0], 0x0d);
});

// The production path must draw fresh CSPRNG bytes for the content key, body
// nonce and every HPKE ephemeral IKM. An all-zero RNG (the audit's mutant)
// would compose valid-looking envelopes whose key material is entirely zero;
// every assertion below is a red line for exactly that mutant.
test("production path draws fresh CSPRNG key material on every composition", async () => {
  const fixture = await manifestFixture();
  const first = await composeSealedOutboundEnvelope(composeInput(fixture));
  const second = await composeSealedOutboundEnvelope(composeInput(fixture));
  // Correct widths: exact envelope size for this input shape, 65-byte KEM
  // points, 32-byte digest (the CEK width is asserted inside openWrapAndBody).
  const width = 10 + 157 + 16 + (Buffer.byteLength(fixed.text) + 16) + 1 + 2 * 146 + 64;
  assert.equal(first.envelope.length, width, "exact envelope width");
  assert.equal(second.envelope.length, width, "exact envelope width");
  assert.equal(first.unsignedDigest.length, 32, "digest width");
  // Same message, fresh material: the envelope bytes and the Q6 digest must
  // differ, because the digest is SHA-256 over the FULL unsigned bytes and the
  // unsigned bytes contain the key-dependent nonce, body ciphertext and wrap
  // records. That is why retries must resend composed bytes instead of
  // recomposing, and why "the digest is identical across fresh compositions"
  // would be wrong to assert: nothing key-dependent is excluded from it.
  assert.notEqual(hex(first.envelope), hex(second.envelope), "fresh material changes the envelope");
  assert.notEqual(hex(first.unsignedDigest), hex(second.unsignedDigest), "fresh material changes the Q6 identity");
  assert.deepEqual(first.unsignedDigest, sha256(first.envelope.subarray(0, first.envelope.length - 64)));
  // What IS invariant across compositions of the same message is exactly the
  // caller-derived, key-independent prefix: header || protected record.
  const prefixOf = (result) => {
    const protectedLen = u16be(result.envelope, 8);
    return Uint8Array.from(result.envelope.subarray(0, 10 + protectedLen));
  };
  assert.deepEqual(prefixOf(first), prefixOf(second), "caller-derived header+protected prefix is invariant");
  // The body nonce travels in the clear right after the protected record: it
  // must be nonzero and must differ between compositions.
  const nonceOf = (result) => {
    const at = 10 + u16be(result.envelope, 8);
    return result.envelope.subarray(at, at + 12);
  };
  const notAllZero = (bytes, what) => assert.ok(!bytes.every((value) => value === 0), `${what} must not be all zero`);
  notAllZero(nonceOf(first), "body nonce");
  notAllZero(nonceOf(second), "body nonce");
  assert.notEqual(hex(nonceOf(first)), hex(nonceOf(second)), "fresh body nonce per composition");
  // The content key is recovered by opening the device wrap as an independent
  // consumer: never all-zero, never reused across compositions.
  const cekOf = async (result) => openWrapAndBody(result.envelope, 1, fixture.device.keyId, fixture.device.pair.privateKey, fixed.text);
  const firstCek = await cekOf(first);
  const secondCek = await cekOf(second);
  notAllZero(firstCek, "content key");
  notAllZero(secondCek, "content key");
  assert.notEqual(hex(firstCek), hex(secondCek), "fresh content key per composition");
  // Each HPKE ephemeral IKM is secret, but its derived public point is on the
  // wire at wrap offset 33..98. The all-zero-IKM point is precisely what the
  // all-zero RNG mutant emits, and fresh compositions must never show it or
  // reuse a point.
  const zeroIkmPoint = new Uint8Array(
    await suite.kem.serializePublicKey((await suite.kem.deriveKeyPair(new Uint8Array(32))).publicKey),
  );
  const wrapEncPointsOf = (result) => {
    const protectedLen = u16be(result.envelope, 8);
    const bodyLen = u32be(result.envelope, 10 + protectedLen + 12);
    const countAt = 10 + protectedLen + 16 + bodyLen;
    const count = result.envelope[countAt];
    return Array.from({ length: count }, (_, index) =>
      result.envelope.subarray(countAt + 1 + index * 146 + 33, countAt + 1 + index * 146 + 98));
  };
  for (const [label, result] of [["first", first], ["second", second]]) {
    const points = wrapEncPointsOf(result);
    assert.equal(points.length, 2, "wrap count");
    for (const [index, point] of points.entries()) {
      assert.equal(point.length, 65, "KEM point width");
      assert.notEqual(hex(point), hex(zeroIkmPoint), `${label} wrap ${index} must not use the all-zero-IKM ephemeral point`);
    }
  }
  assert.notEqual(hex(wrapEncPointsOf(first)[0]), hex(wrapEncPointsOf(second)[0]), "fresh device-wrap ephemeral");
  assert.notEqual(hex(wrapEncPointsOf(first)[1]), hex(wrapEncPointsOf(second)[1]), "fresh archive-wrap ephemeral");
});

test("refuses every inadmissible input with a typed error and no partial output", async () => {
  const fixture = await manifestFixture();
  const refuses = async (code, build, compose = composeSealedOutboundEnvelope) => {
    const input = build();
    await assert.rejects(compose(input), (error) => {
      assert.ok(error instanceof SealedEnvelopeError, `not typed for ${code}: ${String(error)}`);
      assert.equal(error.code, code);
      assert.match(error.message, /ZTSE sealed envelope:/);
      return true;
    });
  };
  const over = (overrides) => () => composeInput(fixture, overrides);
  await refuses("identity", over({ messageId: fixed.message.subarray(0, 15) }));
  await refuses("identity", over({ messageId: concat(fixed.message, Uint8Array.of(1)) }));
  await refuses("identity", over({ deviceId: new Uint8Array(15) }));
  await refuses("identity", over({ lineId: new Uint8Array(17) }));
  for (const peer of [ascii("12"), ascii("+012"), ascii("+12a"), ascii("+" + "1".repeat(16))]) {
    await refuses("peer", over({ peer }));
  }
  await refuses("time_range", over({ nowMs: -1n }));
  await refuses("time_range", over({ observedMs: maxSigned + 1n }));
  await refuses("time_range", over({ expiresMs: 1n << 64n }));
  await refuses("intent_expiry", over({ expiresMs: now }));
  await refuses("intent_expiry", over({ expiresMs: now + 900_001n }));
  for (const [content] of [
    [""], ["A".repeat(32_769)], ["✓".repeat(32_768)], ["\uFEFFhello"], ["a\0b"], ["lone surrogate \uD800 here"],
  ]) {
    await refuses("content", over({ content }));
  }
  const readerFixture = await manifestFixture({ integrations: 1 });
  const readerRecipient = { role: 3, keyId: readerFixture.readers[0].keyId, point: readerFixture.readers[0].point };
  await refuses("recipient", () => composeInput(readerFixture, {
    recipients: [composeInput(readerFixture).recipients[1], readerRecipient],
  }));
  await refuses("recipient", over({ recipients: [...composeInput(fixture).recipients, composeInput(fixture).recipients[0]] }));
  await refuses("recipient", over({ recipients: [composeInput(fixture).recipients[0], composeInput(fixture).recipients[0]] }));
  await refuses("recipient", over({ recipients: [
    composeInput(fixture).recipients[0],
    { role: 4, keyId: fixture.archive.keyId, point: fixture.archive.point },
  ] }));
  await refuses("recipient", over({ recipients: [
    composeInput(fixture).recipients[0],
    { role: 2, keyId: fixture.archive.keyId, point: fixture.archive.point.subarray(0, 64) },
  ] }));
  const stranger = sha256(ascii("fabricated-recipient"));
  await refuses("wrap_count", over({ recipients: [
    composeInput(fixture).recipients[0], composeInput(fixture).recipients[1],
    ...Array.from({ length: 7 }, (_, index) => ({ role: 3, keyId: sha256(ascii(`fabricated-${index}`)), point: fixture.archive.point })),
  ] }));
  await refuses("wrap_count", over({ recipients: [composeInput(fixture).recipients[0]] }));
  await refuses("recipient_key_id", over({ recipients: [
    composeInput(fixture).recipients[0],
    { role: 2, keyId: stranger, point: fixture.archive.point },
  ] }));
  await refuses("signer", over({ signer: { privateKey: fixture.outboundSigner.privateKey, publicPoint: fixture.archive.point.subarray(0, 64) } }));
  // Vector-material width refusals are reachable only through the test seam;
  // on the production surface the field itself is the refusal.
  const pinnedOver = (overrides) => () => pinnedInput(fixture, overrides);
  await refuses("key_material", pinnedOver({ deterministicKeyMaterial: { cek: repeat(0x7c, 31), nonce: fixed.nonce, ekms: [fixed.deviceEkm, fixed.archiveEkm] } }), composeSealedOutboundEnvelopeForVectors);
  await refuses("key_material", pinnedOver({ deterministicKeyMaterial: { cek: fixed.cek, nonce: repeat(0x4e, 11), ekms: [fixed.deviceEkm, fixed.archiveEkm] } }), composeSealedOutboundEnvelopeForVectors);
  await refuses("key_material", pinnedOver({ deterministicKeyMaterial: { cek: fixed.cek, nonce: fixed.nonce, ekms: [fixed.deviceEkm] } }), composeSealedOutboundEnvelopeForVectors);
  await refuses("key_material", pinnedOver({ deterministicKeyMaterial: { cek: fixed.cek, nonce: fixed.nonce, ekms: [repeat(0x0d, 31), fixed.archiveEkm] } }), composeSealedOutboundEnvelopeForVectors);
  await refuses("key_material", over({ deterministicKeyMaterial: pinnedMaterial() }));
  // Authorization refusals stay typed, not silent coercions.
  await refuses("authorization", over({ manifest: { ...fixture.manifest } }));
  await refuses("authorization", over({ nowMs: now + 3_600_000n }));
  const revoked = await manifestFixture({ outboundState: 2 });
  await refuses("authorization", () => composeInput(revoked));
  const wrongLine = await manifestFixture({ signerLine: fixed.device });
  await refuses("authorization", () => composeInput(wrongLine));
  const blindReader = await manifestFixture({ integrations: 1, readerScope: 8 });
  await refuses("authorization", () => pinnedInput(blindReader, {
    recipients: [...composeInput(blindReader).recipients,
      { role: 3, keyId: blindReader.readers[0].keyId, point: blindReader.readers[0].point }],
    deterministicKeyMaterial: pinnedMaterial([fixed.deviceEkm, fixed.archiveEkm, repeat(0x0f, 32)]),
  }), composeSealedOutboundEnvelopeForVectors);
});

test("minimum and maximum admissible compositions stay inside the parser bounds", async () => {
  const min = await manifestFixture();
  const minimum = await composePinned(min, { content: "x", peer: ascii("+12") });
  assert.ok(minimum.envelope.length >= 426);
  parserWalk(minimum.envelope, {
    account: fixed.account, message: fixed.message, device: fixed.device, line: fixed.line,
    peer: "+12", manifestDigest: min.manifest.digest, observedMs: now, expiresMs: now + 300_000n,
    contentByteLength: 1, wrapCount: 2,
  });
  const max = await manifestFixture({ integrations: 6 });
  const maximum = await composePinned(max, {
    content: "A".repeat(32_768), peer: ascii("+" + "1".repeat(15)),
    recipients: [
      { role: 1, keyId: max.device.keyId, point: max.device.point },
      { role: 2, keyId: max.archive.keyId, point: max.archive.point },
      ...max.readers.map((reader) => ({ role: 3, keyId: reader.keyId, point: reader.point })),
    ],
    deterministicKeyMaterial: pinnedMaterial([
      fixed.deviceEkm, fixed.archiveEkm, ...Array.from({ length: 6 }, (_, index) => repeat(0x60 + index, 32)),
    ]),
  });
  assert.equal(maximum.envelope.length, 34_213, "exact maximum kind-01 width");
  parserWalk(maximum.envelope, {
    account: fixed.account, message: fixed.message, device: fixed.device, line: fixed.line,
    peer: "+" + "1".repeat(15), manifestDigest: max.manifest.digest, observedMs: now, expiresMs: now + 300_000n,
    contentByteLength: 32_768, wrapCount: 8,
  });
});

test("signature covers the exact unsigned bytes and stays canonical low-s", async () => {
  const fixture = await manifestFixture();
  const result = await composePinned(fixture);
  assert.ok(await verifyOriginSignature(result.envelope, fixture.outboundSigner.point));
  const tampered = Uint8Array.from(result.envelope);
  tampered[tampered.length - 65] ^= 1; // Last unsigned byte: last wrap ciphertext.
  assert.ok(!(await verifyOriginSignature(tampered, fixture.outboundSigner.point)));
  // The unsigned digest is the Q6 identity: one flipped unsigned byte changes it.
  assert.notEqual(hex(sha256(tampered.subarray(0, tampered.length - 64))), hex(result.unsignedDigest));
});

test("an independent consumer opens the wraps and body from envelope bytes alone", async () => {
  const fixture = await manifestFixture();
  const result = await composePinned(fixture);
  const deviceCek = await openWrapAndBody(result.envelope, 1, fixture.device.keyId, fixture.device.pair.privateKey, fixed.text);
  const archiveCek = await openWrapAndBody(result.envelope, 2, fixture.archive.keyId, fixture.archive.pair.privateKey, fixed.text);
  assert.deepEqual(deviceCek, fixed.cek, "device wrap recovers the deterministic CEK");
  assert.deepEqual(archiveCek, fixed.cek, "archive wrap recovers the same CEK");
});

test("cross-client generator fixture bytes are reproduced exactly by the production composer", async () => {
  const clock = 1_893_456_000_000;
  const account = repeat(0x6f, 16);
  const device = repeat(0x7a, 16);
  const line = repeat(0x5c, 16);
  const message = Uint8Array.from({ length: 16 }, (_, index) => index * 3 + 1);
  const event = Uint8Array.from({ length: 16 }, (_, index) => index * 5 + 2);
  const rootScalar = repeat(0x3d, 32);
  const signerScalar = repeat(0x2e, 32);
  const rootEc = createECDH("prime256v1");
  rootEc.setPrivateKey(rootScalar);
  const rootPoint = Uint8Array.from(rootEc.getPublicKey(undefined, "uncompressed"));
  const rootPin = concat(ascii("ZTRP"), Uint8Array.of(2), account, u64(1n), rootPoint);
  const previousDigest = sha256(ascii("synthetic-slice-a-previous-digest"));
  const cek = repeat(0xc7, 32);
  const nonce = repeat(0x37, 12);
  const deviceEkm = repeat(0x1d, 32);
  const archiveEkm = repeat(0x2d, 32);
  const setup = JSON.stringify({
    now: clock, account: hex(account), device: hex(device), line: hex(line),
    message: hex(message), event: hex(event), rootPin: hex(rootPin), rootScalar: hex(rootScalar),
    outboundSignerScalar: hex(signerScalar), previousVersion: 1, previousDigest: hex(previousDigest),
    outboundCek: hex(cek), outboundNonce: hex(nonce), deviceEkm: hex(deviceEkm), archiveEkm: hex(archiveEkm),
  });
  assert.ok(Buffer.byteLength(setup) <= 8192, "setup within the generator bound");
  const fixture = JSON.parse(await runGenerator(setup));
  assert.equal(fixture.fixtureVersion, 1);
  // Rebuild the trust pin and re-verify the manifest exactly like a consumer.
  const pin = { accountId: account, generation: 1n, rootPoint: fromHex(fixture.rootPin).subarray(29),
    version: 1n, digest: previousDigest, anchorDigest: new Uint8Array(32) };
  const manifest = await verifyManifest02(fromHex(fixture.manifest), pin, BigInt(clock));
  const signerEc = createECDH("prime256v1");
  signerEc.setPrivateKey(signerScalar);
  const signerPoint = Uint8Array.from(signerEc.getPublicKey(undefined, "uncompressed"));
  const b64url = (value) => Buffer.from(value).toString("base64url");
  const signerPrivate = await crypto.subtle.importKey("jwk", {
    kty: "EC", crv: "P-256", x: b64url(signerPoint.subarray(1, 33)), y: b64url(signerPoint.subarray(33)),
    d: b64url(signerScalar), ext: true, key_ops: ["sign"],
  }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const produced = await composeSealedOutboundEnvelopeForVectors({
    manifest, nowMs: BigInt(clock), messageId: message, deviceId: device, lineId: line,
    peer: ascii("+12"), observedMs: BigInt(clock), expiresMs: BigInt(clock) + 60_000n,
    content: fixture.expectedText, signer: { privateKey: signerPrivate, publicPoint: signerPoint },
    recipients: [
      { role: 1, keyId: fromHex(fixture.deviceKeyId), point: fromHex(fixture.devicePoint) },
      { role: 2, keyId: fromHex(fixture.archiveKeyId), point: fromHex(fixture.archivePoint) },
    ],
    deterministicKeyMaterial: { cek, nonce, ekms: [deviceEkm, archiveEkm] },
  });
  const fixtureEnvelope = fromHex(fixture.outboundEnvelope);
  // ECDSA signatures vary per run; every unsigned byte and the digest are pinned.
  assert.equal(produced.envelope.length, fixtureEnvelope.length);
  assert.deepEqual(Uint8Array.from(produced.envelope.subarray(0, produced.envelope.length - 64)),
    fixtureEnvelope.subarray(0, fixtureEnvelope.length - 64), "unsigned bytes match the fixture");
  assert.deepEqual(produced.unsignedDigest, fromHex(fixture.outboundUnsignedDigest));
  assert.deepEqual(produced.unsignedDigest, fromHex(fixture.outboundProductionUnsignedDigest));
  // The fixture bytes the Rust CI lane feeds to admission pass the parser mirror
  // and the signature check under the same signer.
  parserWalk(fixtureEnvelope, {
    account, message, device, line, peer: "+12", manifestDigest: manifest.digest,
    observedMs: BigInt(clock), expiresMs: BigInt(clock) + 60_000n,
    contentByteLength: Buffer.byteLength(fixture.expectedText), wrapCount: 2,
  });
  assert.ok(await verifyOriginSignature(fixtureEnvelope, signerPoint));
});

test("the production path draws every key byte from the platform CSPRNG", async () => {
  const fixture = await manifestFixture();
  const input = composeInput(fixture);
  const calls = [];
  const original = globalThis.crypto.getRandomValues;
  globalThis.crypto.getRandomValues = (view) => {
    calls.push(view.length);
    return original.call(globalThis.crypto, view);
  };
  try {
    await composeSealedOutboundEnvelope(input);
    await composeSealedOutboundEnvelope(composeInput(fixture, { messageId: fixed.message.map((b, i) => b ^ (i + 1)) }));
  } finally {
    globalThis.crypto.getRandomValues = original;
  }
  // One 32-byte CEK, one 12-byte nonce, and one 32-byte EKM per wrap, per composition.
  const widths = calls.slice().sort((a, b) => a - b).join(",");
  assert.ok(calls.length >= 8, `expected CSPRNG calls for CEK/nonce/EKMs, saw ${calls.length}`);
  assert.ok(widths.includes("12") && widths.includes("32"), `nonce/CEK widths expected among ${widths}`);
});

test("a missing platform CSPRNG fails closed instead of weakening key material", async () => {
  const fixture = await manifestFixture();
  const original = globalThis.crypto;
  Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true });
  try {
    await assert.rejects(
      composeSealedOutboundEnvelope(composeInput(fixture)),
      (error) => error instanceof SealedEnvelopeError && error.code === "key_material",
    );
  } finally {
    Object.defineProperty(globalThis, "crypto", { value: original, configurable: true });
  }
});

test("an options object inheriting deterministicKeyMaterial is refused, not honored", async () => {
  const fixture = await manifestFixture();
  const inherited = Object.create({ deterministicKeyMaterial: pinnedMaterial() });
  Object.assign(inherited, composeInput(fixture));
  await assert.rejects(
    composeSealedOutboundEnvelope(inherited),
    (error) => error instanceof SealedEnvelopeError && error.code === "key_material",
  );
});
