// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { fixture, account, device, line, present, join, frame, canonicalP256Signature, enrollRootPin02, verifyManifest02 } from './fixtures/profile03-outbound-fixture.mjs';
import { encodePayloadProfileUpgradeProposal03, verifyPayloadProfileUpgradeOutput03 } from '../dist/payload-profile-upgrade-proposal.js';
import { verifiedManifestIdentity03 } from '../dist/draft03-manifest.js';
import { keyId } from '../dist/draft01.js';
function input(f) {
  return { scope: { accountId: account.slice(), deviceId: device.slice(), lineId: line.slice(), origin: 'https://owner.invalid',
    rootFingerprint: f.fingerprint.slice(), predecessorVersion: 1n, predecessorDigest: f.old.digest.slice(),
    phoneReaderKeyId: f.records[0].id.slice(), phoneSigningKeyId: f.core.slice(288, 320), issuedMs: present },
  predecessor: f.prior, originalSigned02: f.old.bytes.slice(), nowMs: present };
}
async function signed(f, unsigned) {
  const signature = canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' },
    f.root.pair.privateKey, frame('ZTSE/manifest/v3', unsigned))));
  return join(unsigned, signature);
}
test('the first03 proposal preserves every original key and expiry and verifies returned genuine output', async () => {
  const f = await fixture(), selected = input(f);
  assert.notDeepEqual(selected.scope.phoneSigningKeyId, f.records[3].id);
  const result = await encodePayloadProfileUpgradeProposal03(selected);
  assert.deepEqual(result.proposal.slice(0, 5), Uint8Array.of(90, 84, 80, 85, 1));
  assert.deepEqual(result.unsigned.slice(153), f.old.bytes.slice(151, -64));
  assert.deepEqual(result.unsigned.slice(47, 55), f.old.bytes.slice(45, 53));
  const accepted = await verifyPayloadProfileUpgradeOutput03({ ...selected, signed03: await signed(f, result.unsigned) });
  const identity = verifiedManifestIdentity03(accepted, present);
  assert.equal(identity.version, 2n); assert.equal(identity.predecessorProfile, 2);
});
test('scope substitution, missing original checkpoint, future issuance and expired original refuse', async () => {
  const f = await fixture(), selected = input(f);
  for (const key of ['accountId', 'deviceId', 'lineId', 'rootFingerprint', 'predecessorDigest', 'phoneReaderKeyId']) {
    const changed = { ...selected.scope, [key]: selected.scope[key].slice() }; changed[key][0] ^= 1;
    await assert.rejects(encodePayloadProfileUpgradeProposal03({ ...selected, scope: changed }));
  }
  for (const scope of [{ ...selected.scope, predecessorVersion: 2n }, { ...selected.scope, issuedMs: present + 1n },
    { ...selected.scope, origin: selected.scope.origin + '/' }, { ...selected.scope, extra: true }]) {
    await assert.rejects(encodePayloadProfileUpgradeProposal03({ ...selected, scope }));
  }
  await assert.rejects(encodePayloadProfileUpgradeProposal03({ ...selected, predecessor: { ...selected.predecessor } }));
  await assert.rejects(encodePayloadProfileUpgradeProposal03({ ...selected, nowMs: 2_000_000n }));
});
test('even a genuinely signed changed successor cannot replace the preserved-record proposal', async () => {
  const f = await fixture(), selected = input(f), result = await encodePayloadProfileUpgradeProposal03(selected);
  for (const at of [4, 6, 7, 31, 39, 47, 55, 87, 153, 153 + 149]) {
    const changed = result.unsigned.slice(); changed[at] ^= 1;
    await assert.rejects(verifyPayloadProfileUpgradeOutput03({ ...selected, signed03: await signed(f, changed) }));
  }
  const corrupted = await signed(f, result.unsigned); corrupted[corrupted.length - 1] ^= 1;
  await assert.rejects(verifyPayloadProfileUpgradeOutput03({ ...selected, signed03: corrupted }));
});
test('scope accessors and shared byte storage refuse without reading caller accessors', async () => {
  const f = await fixture(), selected = input(f); let calls = 0;
  await assert.rejects(encodePayloadProfileUpgradeProposal03({ ...selected, scope: { ...selected.scope,
    get origin() { calls++; return 'https://owner.invalid'; } } }));
  assert.equal(calls, 0);
  const shared = new Uint8Array(new SharedArrayBuffer(16)); shared.set(account);
  await assert.rejects(encodePayloadProfileUpgradeProposal03({ ...selected, scope: { ...selected.scope, accountId: shared } }));
});
test('independently signed public vector matches exact proposal bytes and returned03 signature', async () => {
  const vector = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/sealed-profile03-upgrade-proposal-01.json', import.meta.url)));
  const b = value => Uint8Array.from(Buffer.from(value, 'hex')), s = vector.scope, nowMs = BigInt(s.issuedMs);
  const originalSigned02 = b(vector.predecessorSignedHex);
  assert.deepEqual(await keyId(0x101, b(vector.deviceEnrollmentSigningPointHex)), b(s.phoneSigningKeyId));
  const trust = await enrollRootPin02(b(vector.rootPinHex), b(s.rootFingerprint));
  const predecessor = await verifyManifest02(originalSigned02, trust, nowMs);
  const selected = { scope: { accountId: b(s.account), deviceId: b(s.device), lineId: b(s.line), origin: s.origin,
    rootFingerprint: b(s.rootFingerprint), predecessorVersion: BigInt(s.predecessorVersion), predecessorDigest: b(s.predecessorDigest),
    phoneReaderKeyId: b(s.phoneReaderKeyId), phoneSigningKeyId: b(s.phoneSigningKeyId), issuedMs: nowMs }, predecessor, originalSigned02, nowMs };
  const result = await encodePayloadProfileUpgradeProposal03(selected);
  assert.deepEqual(result.proposal, b(vector.proposalHex)); assert.deepEqual(result.unsigned, b(vector.unsigned03Hex));
  assert.equal(verifiedManifestIdentity03(await verifyPayloadProfileUpgradeOutput03({ ...selected, signed03: b(vector.signed03Hex) }), nowMs).version, 2n);
});
