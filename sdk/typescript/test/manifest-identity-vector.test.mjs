// Cross-client ZT-009 Q6 vector for the manifest identity correction.
// Consumes the same public fixture as crates/server/tests/zt_manifest_identity_digest_vectors.rs;
// both clients must compute identical digests and reach identical verdicts.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { canonicalSignature02 } from "../dist/draft02-manifest.js";

const vector = JSON.parse(readFileSync(
  new URL("../../../protocol/v1/vectors/ztse-manifest-identity-01.json", import.meta.url),
  "utf8",
));
const bytes = (field) => new Uint8Array(Buffer.from(field, "hex"));
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const halfOrder = order >> 1n;
const sha = (data) => Uint8Array.from(createHash("sha256").update(data).digest());
const join = (...parts) => Uint8Array.from(Buffer.concat(parts.map((part) => Buffer.from(part))));
const scalar = (data) => data.reduce((n, b) => (n << 8n) | BigInt(b), 0n);
const u32 = (length) => Uint8Array.of(length >>> 24, length >>> 16, length >>> 8, length);
const unsigned = bytes(vector.unsignedHex);
const rootPoint = bytes(vector.rootPublicPointHex);
const transcript = (body) => join(new TextEncoder().encode("ZTSE/manifest/v2\0"), u32(body.length), body);

async function verifyRaw(signature, signed) {
  const key = await crypto.subtle.importKey("raw", rootPoint, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, signed);
}

/** Scalar-range and low-s policy must pass before any ECDSA verification. */
function strictRawRanges(raw) {
  if (raw.length !== 64) throw new Error("signature width");
  const r = scalar(raw.subarray(0, 32));
  const s = scalar(raw.subarray(32));
  if (r === 0n || r >= order || s === 0n || s >= order) throw new Error("signature scalar range");
  if (s > halfOrder) throw new Error("high-s signature");
  return raw;
}

/** Strict DER-to-raw conversion; mirrors the Rust converter, normalizes nothing. */
function derToRaw(input) {
  if (input.length < 8 || input[0] !== 0x30) throw new Error("der sequence tag");
  if (input[1] >= 0x80) throw new Error("der long-form length");
  if (input.length !== 2 + input[1]) throw new Error("der sequence length");
  const scalars = [];
  let at = 2;
  for (let index = 0; index < 2; index++) {
    if (input.length < at + 2 || input[at] !== 0x02) throw new Error("der integer tag");
    const length = input[at + 1];
    if (length >= 0x80 || length === 0) throw new Error("der integer length");
    const end = at + 2 + length;
    if (end > input.length) throw new Error("der integer truncated");
    let value = input.subarray(at + 2, end);
    if (value[0] & 0x80) throw new Error("negative der integer");
    if (value[0] === 0) {
      if (value.length === 1) throw new Error("zero der integer");
      if (!(value[1] & 0x80)) throw new Error("nonminimal der integer");
      value = value.subarray(1);
    }
    if (value.length > 32) throw new Error("der integer width");
    const fixed = new Uint8Array(32);
    fixed.set(value, 32 - value.length);
    scalars.push(fixed);
    at = end;
  }
  if (at !== input.length) throw new Error("der trailing content");
  return strictRawRanges(join(scalars[0], scalars[1]));
}

test("two canonical low-s signatures share one semantic manifest identity", async () => {
  // The fixture must remain a valid single-record Manifest02 unsigned prefix.
  assert.equal(unsigned.length, 300);
  assert.deepEqual(unsigned.subarray(0, 5), Uint8Array.of(0x5a, 0x54, 0x4d, 0x41, 2));
  assert.equal(unsigned[150], 1);
  assert.equal(unsigned[151], 6);
  assert.deepEqual(unsigned.subarray(85, 150), rootPoint);
  assert.deepEqual(unsigned.subarray(184, 249), rootPoint);
  const ownerId = sha(join(new TextEncoder().encode("ZTSE/key/v1\0"), Uint8Array.of(1, 1), rootPoint));
  assert.deepEqual(unsigned.subarray(152, 184), ownerId);
  assert.deepEqual(ownerId, bytes(vector.ownerIdHex));

  const signed = transcript(unsigned);
  const raws = [];
  const completeDigests = [];
  for (const entry of vector.signatures) {
    assert.equal(entry.canonicalLowS, true);
    assert.equal(entry.verifies, true);
    const raw = bytes(entry.rawHex);
    strictRawRanges(raw);
    assert.equal(await verifyRaw(raw, signed), true);
    assert.deepEqual(raw, canonicalSignature02(raw), "shipped canonicalizer agrees");
    const complete = sha(join(unsigned, raw));
    assert.deepEqual(complete, bytes(entry.completeSignedDigestHex));
    raws.push(raw);
    completeDigests.push(complete);
  }
  assert.notDeepEqual(raws[0], raws[1]);
  assert.notDeepEqual(completeDigests[0], completeDigests[1]);
  assert.deepEqual(sha(unsigned), bytes(vector.semanticDigestHex));
});

test("high-s twin verifies under plain ECDSA but the strict rule rejects it", async () => {
  const twin = vector.highSTwinOfA;
  assert.equal(twin.verifiesUnderPlainEcdsa, true);
  assert.equal(twin.strictVerdict, "reject");
  const high = bytes(twin.rawHex);
  assert.equal(await verifyRaw(high, transcript(unsigned)), true);
  assert.throws(() => strictRawRanges(high), /high-s signature/);
  assert.notDeepEqual(canonicalSignature02(high), high, "sender-side normalization maps it low");
});

test("strict der conversion accepts only the exact canonical encoding", async () => {
  const signatureA = bytes(vector.signatures[0].rawHex);
  const signed = transcript(unsigned);
  for (const testCase of vector.derCases) {
    const der = bytes(testCase.derHex);
    if (testCase.expected === "accept") {
      const raw = derToRaw(der);
      assert.deepEqual(raw, signatureA, testCase.name);
      assert.equal(await verifyRaw(raw, signed), true, testCase.name);
    } else if (testCase.expected === "reject") {
      assert.throws(() => derToRaw(der), undefined, testCase.name);
    } else {
      assert.fail(`unknown fixture verdict ${testCase.expected}`);
    }
  }
});

test("mutated unsigned field changes identity and fails signature verification", async () => {
  const mutation = vector.mutatedUnsigned;
  const mutated = bytes(mutation.unsignedHex);
  assert.equal(mutation.signatureAVerifies, false);
  assert.equal(mutation.field, "keyset_version u64 at offset 29, byte 36: 1 -> 2");
  assert.deepEqual(sha(mutated), bytes(mutation.semanticDigestHex));
  assert.notDeepEqual(mutation.semanticDigestHex, vector.semanticDigestHex);
  const signatureA = bytes(vector.signatures[0].rawHex);
  assert.equal(await verifyRaw(signatureA, transcript(mutated)), false);
});
