// SPDX-License-Identifier: AGPL-3.0-only
// Independent Node/OpenSSL candidate-format checker. All secret inputs are
// derived synthetic test material, never stored credentials or real roots.
const assert = require("node:assert/strict");
const { createHash, createECDH, hkdfSync, createCipheriv, createDecipheriv } = require("node:crypto");
const vector = require("../vectors/root-backup-01.json");
const hash = value => createHash("sha256").update(value).digest();
const root = hash("ZROtext synthetic root-backup test root");
const recovery = hash("ZROtext synthetic root-backup test recovery");
const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const randomBlock = (i, n) => hash(Buffer.concat([Buffer.from("ZROtext synthetic root-backup randomness"), u32(i)])).subarray(0, n);
const account = Buffer.alloc(16, 1), generation = u64(1);
const ec = createECDH("prime256v1"); ec.setPrivateKey(root);
const pin = Buffer.concat([Buffer.from("ZTRP"), Buffer.from([2]), account, generation, ec.getPublicKey(null, "uncompressed")]);
const fingerprint = hash(Buffer.concat([Buffer.from("ZTSE/root-pin/v2\0"), pin]));
const origin = Buffer.from("https://example.test");
const originLength = Buffer.alloc(2); originLength.writeUInt16BE(origin.length);
const h = Buffer.concat([Buffer.from("ZTRB"), Buffer.from([1, 1]), randomBlock(0,16), account, generation, fingerprint, originLength, origin]);
assert.equal(h.length, 80 + origin.length);
const vault = randomBlock(1,32), salt = randomBlock(2,32), wrapNonce = randomBlock(3,12), bodyNonce = randomBlock(4,12);
const info = Buffer.concat([Buffer.from("ZTSE/vault-wrap/v1\0"), account, generation]);
const key = Buffer.from(hkdfSync("sha256", recovery, salt, info, 32));
function encrypt(key, nonce, aad, plaintext) {
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}
function decrypt(key, nonce, aad, ciphertext) {
  const cipher = createDecipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(aad); cipher.setAuthTag(ciphertext.subarray(-16));
  return Buffer.concat([cipher.update(ciphertext.subarray(0,-16)), cipher.final()]);
}
const wrapPrefix = Buffer.concat([h,salt,wrapNonce]);
const wrapAad = Buffer.concat([Buffer.from("ZTSE/vault-key-wrap/v1\0"),wrapPrefix]);
const wrapped = encrypt(key, wrapNonce, wrapAad, vault);
const bodyPrefix = Buffer.concat([wrapPrefix, wrapped, bodyNonce, u32(48)]);
const bodyAad = Buffer.concat([Buffer.from("ZTSE/root-backup/v1\0"),bodyPrefix]);
const body = encrypt(vault, bodyNonce, bodyAad, root);
const complete = Buffer.concat([bodyPrefix,body]);
assert.equal(vector.status, "PROPOSED_ROOT_BACKUP_01");
assert.equal(complete.length, 236 + origin.length);
assert.equal(complete.toString("hex"), vector.ciphertextHex);
assert.equal(fingerprint.toString("hex"), vector.fingerprintHex);
assert.equal(pin.toString("hex"), vector.rootPinHex);
assert(decrypt(key,wrapNonce,wrapAad,wrapped).equals(vault));
assert(decrypt(vault,bodyNonce,bodyAad,body).equals(root));
for (const [aeadKey,nonce,aad,ct] of [[key,wrapNonce,wrapAad,wrapped],[vault,bodyNonce,bodyAad,body]]) {
  for (const at of [0,31,32,47]) {
    const changed = Buffer.from(ct); changed[at] ^= 1;
    assert.throws(() => decrypt(aeadKey,nonce,aad,changed));
  }
  const changed = Buffer.from(aad); changed[0] ^= 1;
  assert.throws(() => decrypt(aeadKey,nonce,changed,ct));
}
root.fill(0); recovery.fill(0); vault.fill(0); key.fill(0);
