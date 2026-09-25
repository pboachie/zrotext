// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const assert = require("node:assert/strict");
const { createPublicKey, verify, webcrypto } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const test = require("node:test");
const signing = require("./sms-line-signing.js");

const vector = (name) => JSON.parse(readFileSync(join(__dirname, "../../protocol/v1", name), "utf8"));
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const fromHex = (text) => Uint8Array.from(Buffer.from(text, "hex"));

test("registration statement matches the published owner-key vector", async () => {
  const v = vector("sms-owner-key-registration.vector.json");
  const publicKeySec1 = signing.fromBase64(v.signing_key_sec1_b64);
  const statement = await signing.registrationStatement({
    accountId: v.account_id, userId: v.user_id, sessionId: v.session_id,
    challengeId: v.challenge_id, nonce: signing.fromBase64(v.nonce_b64), publicKeySec1,
  });
  assert.equal(hex(statement), v.statement_hex);
  assert.equal(hex(await signing.sha256(statement)), v.statement_sha256_hex);
  assert.equal(signing.base64url(await signing.sha256(publicKeySec1)), v.fingerprint_b64url);
  await assert.rejects(signing.registrationStatement({ ...v, accountId: v.account_id,
    userId: v.user_id, sessionId: v.session_id, challengeId: "00000000-0000-0000-0000-000000000000",
    nonce: new Uint8Array(32), publicKeySec1 }));
});

test("device statement parses the published activation vector and owner statement binds its signature", async () => {
  const v = vector("sms-line-activation.vector.json");
  const statement = fromHex(v.device_statement_hex);
  const parsed = signing.parseDeviceStatement(statement);
  assert.equal(parsed.accountId, v.account_id);
  assert.equal(parsed.lineId, v.line_id);
  assert.equal(parsed.deviceId, v.device_id);
  assert.equal(parsed.generation, BigInt(v.generation));
  assert.equal(parsed.challengeId, v.challenge_id);
  assert.equal(hex(parsed.nonce), v.nonce_hex);
  assert.equal(parsed.androidApiLevel, v.android_api_level);
  assert.equal(parsed.activeSubscriptionCount, v.active_subscription_count);
  assert.equal(parsed.selectedSubscriptionId, v.selected_subscription_id);
  assert.throws(() => signing.parseDeviceStatement(statement.slice(1)));
  const deviceSignature = Uint8Array.of(0x30, 6, 2, 1, 1, 2, 1, 1);
  const owner = await signing.ownerApprovalStatement(statement, deviceSignature);
  assert.equal(Buffer.from(owner.slice(0, 28)).toString("latin1"), "ZTSMS/line/owner-approve/v1\0");
  assert.deepEqual(owner.slice(28, 28 + statement.length), statement);
  assert.deepEqual(owner.slice(-32), await signing.sha256(deviceSignature));
});

test("WebCrypto P-256 signatures become canonical DER that verifies", async () => {
  const keys = await webcrypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const sec1 = new Uint8Array(await webcrypto.subtle.exportKey("raw", keys.publicKey));
  const publicKey = createPublicKey({ key: await webcrypto.subtle.exportKey("jwk", keys.publicKey), format: "jwk" });
  let paddedSeen = false;
  let shortSeen = false;
  for (let round = 0; round < 64; round += 1) {
    const message = Uint8Array.of(round, 7, 9);
    const raw = new Uint8Array(await webcrypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, message));
    const der = signing.p1363ToDer(raw);
    assert.equal(sec1.length, 65);
    assert.ok(verify("sha256", message, { key: publicKey, dsaEncoding: "der" }, der));
    // Minimal INTEGER encodings: a padding zero only before a high bit.
    const rLength = der[3];
    const r = der.slice(4, 4 + rLength);
    assert.ok(r[0] !== 0 || (r[1] & 0x80) !== 0);
    paddedSeen ||= r[0] === 0;
    shortSeen ||= rLength < 32;
  }
  assert.ok(paddedSeen, "exercised a high-bit scalar");
  assert.throws(() => signing.p1363ToDer(new Uint8Array(63)));
  // Leading zero bytes are stripped and a set high bit is padded.
  const scalar = new Uint8Array(64);
  scalar[1] = 0x80;
  scalar[63] = 1;
  assert.deepEqual(signing.p1363ToDer(scalar),
    Uint8Array.of(0x30, 0x25, 0x02, 0x20, 0x00, 0x80, ...new Uint8Array(30), 0x02, 0x01, 0x01));
  void shortSeen;
});

test("base64 decoding is canonical", () => {
  assert.deepEqual(signing.fromBase64("AAE="), Uint8Array.of(0, 1));
  assert.throws(() => signing.fromBase64("AAF="));
  assert.throws(() => signing.fromBase64("AA-_"));
});
