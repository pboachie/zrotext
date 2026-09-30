// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { createECDH, webcrypto } from "node:crypto";
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes128Gcm } from "@hpke/core";
import { openFixtureWrap } from "./conversation-simulator-wrap.mjs";

for (const [scalarByte, parity] of [[1, 1], [3, 0]]) {
  test(`fixture reader opens a nonextractable archive key with Y parity ${parity}`, async () => {
    const scalar = Buffer.alloc(32); scalar[31] = scalarByte;
    const curve = createECDH("prime256v1"); curve.setPrivateKey(scalar);
    const point = curve.getPublicKey(); assert.equal(point[64] & 1, parity);
    const privateKey = await webcrypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256",
      x: point.subarray(1,33).toString("base64url"), y: point.subarray(33).toString("base64url"),
      d: scalar.toString("base64url"), ext: false }, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    assert.equal(privateKey.extractable, false);
    const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
    const info = new TextEncoder().encode("Fixture exact archive wrap");
    const expected = new Uint8Array(32).fill(7);
    const sender = await suite.createSenderContext({ recipientPublicKey: await suite.kem.deserializePublicKey(Uint8Array.from(point).buffer), info,
      ekm: new Uint8Array(32).fill(8) });
    const ct = new Uint8Array(await sender.seal(expected.buffer, new ArrayBuffer(0)));
    assert.deepEqual(await openFixtureWrap(privateKey, point, new Uint8Array(sender.enc), info, ct), expected);
    const wrong = info.slice(); wrong[0] ^= 1;
    await assert.rejects(openFixtureWrap(privateKey, point, new Uint8Array(sender.enc), wrong, ct));
  });
}
