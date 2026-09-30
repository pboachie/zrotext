// SPDX-License-Identifier: AGPL-3.0-only
// Fixture-only HPKE consumer. Caller must authenticate the exact point and wrap first.
import { webcrypto } from "node:crypto";
import { CipherSuite, DhkemP256HkdfSha256, HkdfSha256, Aes128Gcm } from "@hpke/core";

const ab = (value) => Uint8Array.from(value).buffer;
export async function openFixtureWrap(privateKey, point, enc, info, ciphertext) {
  const publicKey = await webcrypto.subtle.importKey("raw", ab(point),
    { name: "ECDH", namedCurve: "P-256" }, true, []);
  const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
  // A bare nonextractable private key cannot reconstruct the actual point's Y parity.
  const context = await suite.createRecipientContext({ recipientKey: { privateKey, publicKey },
    enc: ab(enc), info: ab(info) });
  return new Uint8Array(await context.open(ab(ciphertext), new ArrayBuffer(0)));
}
