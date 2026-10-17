// SPDX-License-Identifier: AGPL-3.0-only
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { webcrypto } = require('node:crypto');
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const api = import('../review/root-material.mjs');
const vector = (name) => JSON.parse(fs.readFileSync(path.join(__dirname, '../../protocol/v1/vectors', name), 'utf8'));
const backup = vector('root-backup-01.json'), card = vector('recovery-kit-01.json'), custody = vector('root-custody-01.json');
const bytes = (value) => Uint8Array.from(Buffer.from(value, 'hex'));
const id = (value) => value.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
const file = (value) => ({ size: value.length, arrayBuffer: async () => value.slice().buffer });
const identity = { origin: card.origin, account: id(card.accountIdHex), bundle: id(card.backupIdHex), fingerprint: card.fingerprintHex };
const prepared = { request_id: '11111111-1111-4111-8111-111111111111', preparation_id: '22222222-2222-4222-8222-222222222222', generation: '1' };

test('retained backup and card require independent account, origin, bundle and full fingerprint', async () => {
  const m = await api;
  const kit = await m.readArtifacts(file(bytes(backup.ciphertextHex)), file(bytes(card.cardHex)), identity);
  assert.equal(m.hex(kit.pin), card.rootPinHex);
  for (const change of [{ account: prepared.request_id }, { bundle: prepared.request_id }, { origin: 'https://other.test' }, { fingerprint: '11'.repeat(32) }]) {
    await assert.rejects(m.readArtifacts(file(bytes(backup.ciphertextHex)), file(bytes(card.cardHex)), { ...identity, ...change }));
  }
  for (const offset of [0, 6, 22, 38, 46, 78, 184 + Buffer.byteLength(card.origin), bytes(backup.ciphertextHex).length - 1]) {
    const changed = bytes(backup.ciphertextHex); changed[offset] ^= 1;
    await assert.rejects(m.readArtifacts(file(changed), file(bytes(card.cardHex)), identity));
  }
  await assert.rejects(m.readArtifacts({ size: 999999, arrayBuffer: () => assert.fail('must bound before read') }, file(bytes(card.cardHex)), identity));
});

test('real custody vector binds exact proposal, current review session and both retained-file digests', async () => {
  const m = await api, kit = await m.readArtifacts(file(bytes(backup.ciphertextHex)), file(bytes(card.cardHex)), identity);
  const context = { ...identity, owner_user: id('02'.repeat(16)), review_owner_session: id('03'.repeat(16)) };
  const view = { version: 1, ...prepared, root_challenge_id: id('04'.repeat(16)), reauth_challenge_id: prepared.request_id,
    reauth_nonce_b64: m.base64(new Uint8Array(32).fill(1)), unsigned_enrollment_b64: m.base64(bytes(custody.unsignedHex)),
    custody_statement_b64: m.base64(bytes(custody.transcriptHex)), root_pin_b64: m.base64(kit.pin),
    request_commitment_b64: m.base64(new Uint8Array(32).fill(2)), expires_ms: '1300000', server_now_ms: '1000000' };
  const challenge = await m.inspectChallenge(view, prepared, context, kit);
  assert.equal(m.hex(challenge.statement), custody.transcriptHex);
  for (const change of [{ generation: '2' }, { request_id: prepared.preparation_id }, { server_now_ms: '1300000' }, { expires_ms: '1300001' }, { authority: true }]) {
    await assert.rejects(m.inspectChallenge({ ...view, ...change }, prepared, context, kit));
  }
  await assert.rejects(m.inspectChallenge(view, prepared, { ...context, review_owner_session: prepared.request_id }, kit));
  const changed = bytes(custody.transcriptHex); changed[changed.length - 1] ^= 1;
  await assert.rejects(m.inspectChallenge({ ...view, custody_statement_b64: m.base64(changed) }, prepared, context, kit));
});

test('both public signatures use their actual separated transcripts and strict raw low-S encoding', async () => {
  const m = await api;
  const key = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  async function sign(message) {
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, message));
    const s = BigInt('0x' + m.hex(raw.subarray(32)));
    if (s > order / 2n) raw.set(bytes((order - s).toString(16).padStart(64, '0')), 32);
    return m.hex(raw);
  }
  const challenge = { unsigned: bytes(custody.unsignedHex), statement: bytes(custody.transcriptHex) };
  const length = new Uint8Array(4); new DataView(length.buffer).setUint32(0, challenge.unsigned.length);
  const enrollment = await sign(m.concat(new TextEncoder().encode('ZTSE/root-enroll/v1\0'), length, challenge.unsigned));
  const encrypted = await sign(challenge.statement);
  const response = `Enrollment signature: ${enrollment}\nCustody signature: ${encrypted}\n`;
  const checked = await m.verifySignatures(response, challenge, { publicKey: key.publicKey });
  assert.equal(m.decode(checked.enrollment_signature_b64, 64, true).length, 64);
  for (const bad of [response.toUpperCase(), response + 'extra', `Enrollment signature: ${encrypted}\nCustody signature: ${enrollment}\n`, response.replace(enrollment, '00'.repeat(64))]) {
    await assert.rejects(m.verifySignatures(bad, challenge, { publicKey: key.publicKey }));
  }
  const highS = enrollment.slice(0, 64) + (order - BigInt('0x' + enrollment.slice(64))).toString(16).padStart(64, '0');
  await assert.rejects(m.verifySignatures(response.replace(enrollment, highS), challenge, { publicKey: key.publicKey }));
});

test('completion receipt binds the original actor as well as account, challenge, key and time', async () => {
  const m = await api, kit = await m.readArtifacts(file(bytes(backup.ciphertextHex)), file(bytes(card.cardHex)), identity);
  const context = { account: identity.account, owner_user: id('02'.repeat(16)), review_owner_session: id('03'.repeat(16)) };
  const challenge = { view: { root_challenge_id: id('04'.repeat(16)) }, issued: 1000000n, expires: 1300000n };
  const receipt = { version: 1, request_id: prepared.request_id, account: identity.account, actor_owner_user: context.owner_user,
    actor_review_owner_session: context.review_owner_session, root_challenge_id: challenge.view.root_challenge_id,
    root_pin_b64: m.base64(kit.pin), root_fingerprint_b64: m.base64(kit.fingerprint), completed_ms: '1000001', server_now_ms: '1000002' };
  assert.equal(m.inspectReceipt(receipt, prepared, context, kit, challenge), receipt);
  for (const change of [{ actor_owner_user: prepared.request_id }, { actor_review_owner_session: prepared.request_id }, { actor_owner_user: 'malformed' },
    { account: prepared.request_id }, { root_challenge_id: prepared.request_id }, { completed_ms: '1300000' }, { request_id: prepared.preparation_id }, { root_fingerprint_b64: m.base64(new Uint8Array(32).fill(1)) }]) {
    assert.throws(() => m.inspectReceipt({ ...receipt, ...change }, prepared, context, kit, challenge));
  }
});
