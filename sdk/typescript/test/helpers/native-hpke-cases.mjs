// Test-only producer. Never import this module into a production custody path.
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { CipherSuite, Aes128Gcm, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';

const hex = bytes => Buffer.from(bytes).toString('hex');
const label = text => Buffer.from(text + '\0');
export const suite = () => new CipherSuite({
  kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm(),
});

export async function createNativeHpkeCases() {
  const v1 = JSON.parse(await readFile(new URL('../../../../protocol/v1/vectors/ztse-draft-01.json', import.meta.url), 'utf8'));
  const v3 = JSON.parse(await readFile(new URL('../../../../protocol/v1/vectors/sealed-profile03-contract-01.json', import.meta.url), 'utf8'));
  const header2 = Buffer.from(v1.outbound.unsignedHex, 'hex').subarray(0, 10);
  header2[4] = 2;
  const contexts = [
    { profile: 2, header: header2, protectedBytes: Buffer.from(v1.outbound.protectedHex, 'hex') },
    { profile: 3, header: Buffer.from(v3.hpkeContext.headerHex, 'hex'), protectedBytes: Buffer.from(v3.hpkeContext.protectedHex, 'hex') },
  ];
  const cases = [];
  for (const context of contexts) for (const role of [1, 2, 3]) {
    const hpke = suite();
    const recipient = await hpke.kem.generateKeyPair();
    const publicPoint = Buffer.from(await hpke.kem.serializePublicKey(recipient.publicKey));
    const privateScalar = Buffer.from(await hpke.kem.serializePrivateKey(recipient.privateKey));
    const plaintext = webcrypto.getRandomValues(new Uint8Array(32));
    try {
      const identity = Buffer.from(await webcrypto.subtle.digest('SHA-256',
        Buffer.concat([label('ZTSE/key/v1'), Buffer.from([0, 16]), publicPoint])));
      const suffix = Buffer.concat([context.header, context.protectedBytes, Buffer.from([role]), identity]);
      const info = Buffer.concat([label(`ZTSE/wrap/v${context.profile}`), suffix]);
      const aad = context.profile === 2 ? Buffer.alloc(0)
        : Buffer.concat([label('ZTSE/wrap-aad/v3'), suffix]);
      const sender = await hpke.createSenderContext({ recipientPublicKey: recipient.publicKey, info });
      const ciphertext = await sender.seal(plaintext, aad);
      cases.push({ name: `profile${context.profile}-role${role}`, profile: context.profile, role,
        recipient_private_hex: hex(privateScalar), recipient_public_hex: hex(publicPoint),
        recipient_key_id_hex: hex(identity), enc_hex: hex(sender.enc), info_hex: hex(info),
        aad_hex: hex(aad), ciphertext_hex: hex(ciphertext), plaintext_hex: hex(plaintext) });
    } finally { privateScalar.fill(0); plaintext.fill(0); }
  }
  return { format: 'zrotext-native-hpke-interop-v1',
    scope: 'Ephemeral component cases only. Context bytes do not authorize a manifest, recipient, envelope, or protected custody. Never use test keys for application data.', cases };
}
