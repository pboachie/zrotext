import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, createPrivateKey, sign } from "node:crypto";
import test from "node:test";
import { canonicalSignature02 } from "../dist/draft02-manifest.js";
import { verifyPublishedRootBundle } from "../dist/root-custody.js";

const read = (name) => JSON.parse(readFileSync(new URL(`../../../protocol/v1/vectors/${name}.json`, import.meta.url)));
const backupVector = read("root-backup-01"), kit = read("recovery-kit-01"), enrollment = read("root-enrollment-01");
const hash = (bytes) => createHash("sha256").update(bytes).digest();
function fixture() {
  const rootPin = Buffer.from(kit.rootPinHex, "hex"), fingerprint = Buffer.from(kit.fingerprintHex, "hex");
  const backup = Buffer.from(backupVector.ciphertextHex, "hex"), card = Buffer.from(kit.cardHex, "hex");
  const u = Buffer.from(enrollment.unsignedHex, "hex"); fingerprint.copy(u, 101);
  // Same derivable synthetic key as the already published Rust backup corpus.
  // No real key or literal private scalar is stored in this fixture/test file.
  const scalar = hash(Buffer.from("ZROtext synthetic root-backup test root"));
  const key = createPrivateKey({ format: "jwk", key: { kty: "EC", crv: "P-256",
    x: rootPin.subarray(30, 62).toString("base64url"), y: rootPin.subarray(62, 94).toString("base64url"),
    d: scalar.toString("base64url") } });
  scalar.fill(0);
  const length = Buffer.alloc(4); length.writeUInt32BE(u.length);
  const statement = Buffer.concat([Buffer.from("ZTSE/root-custody/v1\0"), length, u, hash(backup), hash(card), fingerprint]);
  const signature = canonicalSignature02(sign("sha256", statement, { key, dsaEncoding: "ieee-p1363" }));
  return { pin: Buffer.from(rootPin), fingerprint, published: { rootPin, encryptedBackup: backup,
    publicCard: card, unsignedEnrollment: u, custodySignature: signature } };
}
const verify = (v, origin = "https://example.test") => verifyPublishedRootBundle(v.pin, v.fingerprint, origin, v.published);

test("published root custody binds the independently intended pin and exact signed bundle", async () => {
  const v = fixture(), result = await verify(v);
  assert.equal(result.trust.generation, 1n);
  assert.deepEqual(Buffer.from(result.encryptedBackup), v.published.encryptedBackup);
  assert.deepEqual(Buffer.from(result.rootPin), v.pin);
  assert.notEqual(result.encryptedBackup, v.published.encryptedBackup);
  assert.equal("privateKey" in result, false);
});

test("SDK verifies the shared custody signature corpus also consumed by Rust", async () => {
  const vector = read("root-custody-01"), v = fixture();
  v.published.unsignedEnrollment = Buffer.from(vector.unsignedHex, "hex");
  v.published.custodySignature = Buffer.from(vector.signatureHex, "hex");
  assert.equal((await verify(v)).trust.generation, 1n);
});

test("root custody rejects substitution even when the attacker rewrites the public digest", async () => {
  const v = fixture();
  v.published.encryptedBackup[v.published.encryptedBackup.length - 1] ^= 1;
  const n = v.published.publicCard.readUInt16BE(5);
  hash(v.published.encryptedBackup).copy(v.published.publicCard, 101 + n);
  await assert.rejects(verify(v));
  for (const field of ["rootPin", "unsignedEnrollment", "custodySignature"]) {
    const altered = fixture(); altered.published[field][0] ^= 1;
    await assert.rejects(verify(altered));
  }
  const wrong = fixture(); wrong.fingerprint[0] ^= 1;
  await assert.rejects(verify(wrong));
  await assert.rejects(verify(fixture(), "https://foreign.test"));
  await assert.rejects(verify(fixture(), "https://example.test/"));
});

test("root custody captures every input before asynchronous public-key verification", async () => {
  const v = fixture(), intended = Buffer.from(v.pin), backup = Buffer.from(v.published.encryptedBackup);
  const pending = verify(v);
  v.pin.fill(0); v.fingerprint.fill(0);
  for (const value of Object.values(v.published)) value.fill(0);
  const result = await pending;
  assert.deepEqual(Buffer.from(result.rootPin), intended);
  assert.deepEqual(Buffer.from(result.encryptedBackup), backup);
});
