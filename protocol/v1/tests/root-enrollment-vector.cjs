// SPDX-License-Identifier: AGPL-3.0-only
// Independent Node/OpenSSL check of the Rust candidate's public wire fixture.
const assert = require("node:assert/strict");
const { createHash, createPublicKey, verify } = require("node:crypto");
const v = require("../vectors/root-enrollment-01.json");
const field = name => Buffer.from(v[name], "hex");
const pin = field("rootPinHex"), unsigned = field("unsignedHex");
assert.equal(v.status, "PROPOSED_ROOT_ENROLLMENT_01");
assert.equal(pin.length, 94);
assert.equal(pin.subarray(0, 5).toString("hex"), "5a54525002");
assert.equal(pin.readBigUInt64BE(21), 1n);
assert.equal(pin[29], 4);
assert.equal(unsigned.subarray(0, 5).toString("hex"), "5a54524501");
for (let i = 0; i < 4; i++) assert.deepEqual(unsigned.subarray(5 + i * 16, 21 + i * 16), Buffer.alloc(16, i + 1));
assert.deepEqual(unsigned.subarray(5, 21), pin.subarray(5, 21));
assert.equal(unsigned.readBigUInt64BE(133), 1000000n);
assert.equal(unsigned.readBigUInt64BE(141), 1300000n);
const origin = unsigned.subarray(151).toString("ascii");
assert.equal(origin, "https://example.test");
assert.equal(new URL(origin).origin, origin);
assert.equal(unsigned.readUInt16BE(149), Buffer.byteLength(origin));
assert.equal(unsigned.length, 151 + Buffer.byteLength(origin));
const fingerprint = createHash("sha256").update(Buffer.concat([Buffer.from("ZTSE/root-pin/v2\0"), pin])).digest();
assert.deepEqual(fingerprint, field("fingerprintHex"));
assert.deepEqual(fingerprint, unsigned.subarray(101, 133));
const length = Buffer.alloc(4); length.writeUInt32BE(unsigned.length);
const transcript = Buffer.concat([Buffer.from("ZTSE/root-enroll/v1\0"), length, unsigned]);
assert.deepEqual(transcript, field("transcriptHex"));
const key = createPublicKey({ format: "jwk", key: {
  kty: "EC", crv: "P-256", x: pin.subarray(30, 62).toString("base64url"), y: pin.subarray(62, 94).toString("base64url"),
} });
const order = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
function strict(signature, message = transcript) {
  if (signature.length !== 64) return false;
  const r = BigInt("0x" + signature.subarray(0, 32).toString("hex"));
  const s = BigInt("0x" + signature.subarray(32).toString("hex"));
  return r > 0n && r < order && s > 0n && s <= order / 2n &&
    verify("sha256", message, { key, dsaEncoding: "ieee-p1363" }, signature);
}
assert.equal(strict(field("signatureHex")), true);
assert.equal(strict(field("highSignatureHex")), false);
// OpenSSL accepts the mathematical twin; the candidate policy must reject it.
assert.equal(verify("sha256", transcript, { key, dsaEncoding: "ieee-p1363" }, field("highSignatureHex")), true);
for (const offset of [0, 19, 23, 29, 45, 61, 77, 93, 125, 164, 172, 183]) {
  const changed = Buffer.from(transcript); changed[offset] ^= 1;
  assert.equal(strict(field("signatureHex"), changed), false);
}
assert.equal(strict(field("signatureHex"), transcript.subarray(24)), false);
assert.equal(strict(field("signatureHex"), Buffer.concat([transcript, Buffer.from([0])])), false);
