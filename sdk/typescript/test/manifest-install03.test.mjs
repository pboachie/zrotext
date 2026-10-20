// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { encodeManifestInstall03, decodeManifestInstall03, manifestInstallSigningBytes03, verifyManifestInstallPossession03 } from '../dist/manifest-install03.js';
import { browserSignerKeyId02, canonicalSignature02 } from '../dist/draft02-manifest.js';
import { enrollRootPin02, verifyManifest02 } from '../dist/draft02-manifest.js';
import { verifyManifest03From02, verifyManifest03Successor, verifiedManifestIdentity03, authorizeOutbound03 } from '../dist/draft03-manifest.js';

const uuids = ['accountId', 'ownerUserId', 'ownerSessionId', 'deviceId', 'lineId', 'bindingId', 'electionChallengeId', 'openingId'];
const numbers = ['bindingGeneration', 'vaultGeneration', 'selectionEpoch', 'predecessorVersion', 'successorVersion', 'issuedMs', 'expiresMs'];
const digests = ['rootFingerprint', 'electionCommitment', 'electionBundleSha256', 'originDigest', 'ownerSessionDigest', 'predecessorDigest', 'signedSuccessorSha256', 'signerKeyId'];
async function fixture() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const s = Object.fromEntries(uuids.map((k, i) => [k, new Uint8Array(16).fill(i + 1)]));
  Object.assign(s, { bindingGeneration: 2n, vaultGeneration: 1n, selectionEpoch: 1n, predecessorVersion: 2n, successorVersion: 3n, issuedMs: 7000n, expiresMs: 12000n });
  for (const [i, k] of digests.entries()) s[k] = new Uint8Array(32).fill(i + 11);
  s.signerPoint = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  s.signerKeyId = await browserSignerKeyId02(s.signerPoint);
  return { s, pair };
}
function independentBytes(s) {
  const out = Buffer.alloc(513); out.write('ZTMS', 0, 'ascii'); out.set([1, 3, 3, 0], 4);
  uuids.forEach((k, i) => out.set(s[k], 8 + i * 16));
  numbers.forEach((k, i) => out.writeBigUInt64BE(s[k], 136 + i * 8));
  digests.forEach((k, i) => out.set(s[k], 192 + i * 32)); out.set(s.signerPoint, 448);
  return Uint8Array.from(out);
}
async function signed(s, pair) {
  const bytes = await encodeManifestInstall03(s), transcript = await manifestInstallSigningBytes03(bytes);
  const signature = canonicalSignature02(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, transcript)));
  return { bytes, signature };
}

test('exact513 offsets and framed domain match independently laid out public bytes', async () => {
  const { s } = await fixture(), bytes = await encodeManifestInstall03(s);
  assert.deepEqual(bytes, independentBytes(s)); assert.deepEqual(await decodeManifestInstall03(bytes), s);
  const label = Buffer.from('ZTSE/line/payload-profile/manifest-install03/v1\0'), length = Buffer.alloc(4); length.writeUInt32BE(513);
  assert.deepEqual(await manifestInstallSigningBytes03(bytes), Uint8Array.from(Buffer.concat([label, length, bytes])));
});

test('genuine role5 possession binds every independent scope field and exact domain', async () => {
  const { s, pair } = await fixture(), { bytes, signature } = await signed(s, pair);
  assert.deepEqual(await verifyManifestInstallPossession03(bytes, signature), s);
  for (const at of [8, 24, 40, 56, 72, 88, 104, 120, 143, 150, 158, 167, 175, 183, 191, 192, 224, 256, 288, 320, 352, 384, 416, 448, 512]) {
    const changed = bytes.slice(); changed[at] ^= 1;
    await assert.rejects(verifyManifestInstallPossession03(changed, signature), `offset ${at}`);
  }
  const wrong = canonicalSignature02(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, bytes)));
  await assert.rejects(verifyManifestInstallPossession03(bytes, wrong));
  assert.equal('ownerSessionLive' in s, false);
});

test('received signature aliases are refused without normalization or trailing bytes', async () => {
  const { s, pair } = await fixture(), { bytes, signature } = await signed(s, pair);
  const high = signature.slice(), order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const scalar = BigInt('0x' + Buffer.from(signature.subarray(32)).toString('hex'));
  high.set(Buffer.from((order - scalar).toString(16).padStart(64, '0'), 'hex'), 32);
  for (const bad of [high, new Uint8Array(64), signature.slice(1), Uint8Array.from([...signature, 0])]) await assert.rejects(verifyManifestInstallPossession03(bytes, bad));
  for (const bad of [bytes.slice(0, -1), Uint8Array.from([...bytes, 0])]) await assert.rejects(decodeManifestInstall03(bad));
  for (let at = 0; at < 8; at++) { const bad = bytes.slice(); bad[at] ^= 1; await assert.rejects(decodeManifestInstall03(bad)); }
});

test('nonzero identities strict integers and successor ceremony bounds cannot be coerced', async () => {
  const { s } = await fixture();
  for (const k of [...uuids, ...digests]) await assert.rejects(encodeManifestInstall03({ ...s, [k]: new Uint8Array(s[k].length) }));
  for (const k of numbers) for (const bad of [0n, -1n, 1n << 63n, 1, '1']) await assert.rejects(encodeManifestInstall03({ ...s, [k]: bad }));
  for (const change of [{ vaultGeneration: 2n }, { selectionEpoch: 2n }, { successorVersion: 4n }, { expiresMs: s.issuedMs }, { expiresMs: s.issuedMs + 300001n }]) await assert.rejects(encodeManifestInstall03({ ...s, ...change }));
  await encodeManifestInstall03({ ...s, expiresMs: s.issuedMs + 300000n });
});

test('wrong key identity and genuine off-curve public material cannot encode possession', async () => {
  const { s } = await fixture();
  await assert.rejects(encodeManifestInstall03({ ...s, signerKeyId: new Uint8Array(32).fill(99) }));
  const point = new Uint8Array(65); point[0] = 4;
  const domain = Buffer.from('ZTSE/key/v1\0');
  const id = new Uint8Array(await crypto.subtle.digest('SHA-256', Buffer.concat([domain, Buffer.from([1, 1]), point])));
  await assert.rejects(encodeManifestInstall03({ ...s, signerPoint: point, signerKeyId: id }));
});

test('closed data snapshots reject accessors and shared input before async publication', async () => {
  const { s } = await fixture(); let calls = 0;
  await assert.rejects(encodeManifestInstall03({ ...s, get openingId() { calls++; return s.openingId; } }));
  assert.equal(calls, 0);
  await assert.rejects(encodeManifestInstall03({ ...s, approved: true }));
  await assert.rejects(encodeManifestInstall03({ ...s, accountId: new Uint8Array(new SharedArrayBuffer(16)) }));
  const expected = independentBytes(s), pending = encodeManifestInstall03(s);
  s.accountId.fill(99); s.signerPoint.fill(0); s.signerKeyId.fill(0);
  assert.deepEqual(await pending, expected);
});

test('independently produced root chain and three actual possession signatures match exact SDK bytes', async () => {
  const v = JSON.parse(readFileSync(new URL('../../../protocol/v1/vectors/sealed-profile03-manifest-install-01.json', import.meta.url)));
  const hex = value => Uint8Array.from(Buffer.from(value, 'hex'));
  const uuid = value => hex(value.replaceAll('-', ''));
  const sha = async value => Buffer.from(await crypto.subtle.digest('SHA-256', value)).toString('hex');
  const pin = await enrollRootPin02(hex(v.root_pin_hex), hex(v.root_fingerprint_hex));
  const original = await verifyManifest02(hex(v.prior02.signed_hex), pin, BigInt(v.first03.accepted_ms));
  assert.deepEqual(original.keys.map(k => k.role), [1, 2, 4, 6]);
  let manifest = await verifyManifest03From02(hex(v.first03.signed_hex), original, hex(v.prior02.signed_hex), BigInt(v.first03.accepted_ms));
  for (const row of v.successors) {
    const bytes = hex(row.statement_hex), statement = await verifyManifestInstallPossession03(bytes, hex(row.signature_hex));
    assert.deepEqual(await encodeManifestInstall03(statement), bytes);
    assert.equal(await sha(await manifestInstallSigningBytes03(bytes)), row.transcript_sha256);
    assert.equal(await sha(hex(row.successor_signed_hex)), row.successor_signed_sha256);
    assert.deepEqual(statement.signedSuccessorSha256, hex(row.successor_signed_sha256));
    assert.deepEqual(statement.predecessorDigest, hex(row.predecessor_semantic_sha256));
    assert.deepEqual(statement.signerKeyId, hex(row.role5_key_id_hex));
    assert.deepEqual(statement.signerPoint, hex(row.role5_point_hex));
    assert.equal(statement.successorVersion, BigInt(row.successor_version));
    manifest = await verifyManifest03Successor(hex(row.successor_signed_hex), manifest, BigInt(row.accepted_ms));
    const identity = verifiedManifestIdentity03(manifest, BigInt(row.accepted_ms));
    assert.deepEqual(identity.digest, hex(row.successor_semantic_sha256));
    const authority = authorizeOutbound03(manifest, { accountId: uuid(v.account_id), deviceId: uuid(v.device_id), lineId: uuid(v.line_id),
      generation: 1n, version: identity.version, digest: identity.digest, signerKeyId: statement.signerKeyId,
      wraps: [1, 2].map(role => ({ role, keyId: original.keys.find(k => k.role === role).keyId })) }, BigInt(row.accepted_ms));
    assert.deepEqual(authority.signerPoint, statement.signerPoint);
  }
  assert.deepEqual(v.successors.map(row => row.operation), ['enroll', 'renew', 'replace']);
});
