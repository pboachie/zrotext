import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeHpkeCases, suite } from './helpers/native-hpke-cases.mjs';

const bytes = value => Buffer.from(value, 'hex');
const changed = input => { const result = Buffer.from(input); result[0] ^= 1; return result; };

test('fresh HPKE component corpus opens exact CEKs and refuses altered contexts', async () => {
  const corpus = await createNativeHpkeCases();
  assert.equal(corpus.cases.length, 6);
  assert.equal(new Set(corpus.cases.map(row => row.recipient_public_hex)).size, 6);
  for (const row of corpus.cases) {
    const hpke = suite(), info = bytes(row.info_hex), aad = bytes(row.aad_hex);
    const scalarBytes = bytes(row.recipient_private_hex), ct = bytes(row.ciphertext_hex);
    try {
      assert.equal(scalarBytes.length, 32);
      assert.equal(bytes(row.recipient_public_hex).length, 65);
      assert.equal(bytes(row.enc_hex).length, 65);
      assert.equal(ct.length, 48);
      assert.equal(aad.length === 0, row.profile === 2);
      const key = await hpke.kem.deserializePrivateKey(scalarBytes);
      const open = async (i, a, c) => {
        const receiver = await hpke.createRecipientContext({ recipientKey: key, enc: bytes(row.enc_hex), info: i });
        return Buffer.from(await receiver.open(c, a));
      };
      assert.equal((await open(info, aad, ct)).toString('hex'), row.plaintext_hex);
      await assert.rejects(open(changed(info), aad, ct));
      await assert.rejects(open(info, aad.length ? changed(aad) : Buffer.from([1]), ct));
      await assert.rejects(open(info, aad, changed(ct)));
      await assert.rejects(open(info, aad, ct.subarray(0, ct.length - 1)));
      if (row.profile === 3) await assert.rejects(open(info, Buffer.alloc(0), ct));
    } finally { scalarBytes.fill(0); }
  }
});
