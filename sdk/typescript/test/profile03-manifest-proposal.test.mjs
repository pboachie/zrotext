// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { enrollRootPin02, verifyManifest02 } from '../dist/draft02-manifest.js';
import { verifyManifest03From02, verifyManifest03Successor } from '../dist/draft03-manifest.js';
import { encodeProfile03ManifestProposal, verifyProfile03ManifestOutput } from '../dist/profile03-manifest-proposal.js';
const v = JSON.parse(readFileSync(new URL('../../../protocol/v1/vectors/sealed-profile03-manifest-install-01.json', import.meta.url)));
const packets = JSON.parse(readFileSync(new URL('../../../protocol/v1/vectors/sealed-profile03-manifest-proposal-01.json', import.meta.url)));
const bytes = value => Uint8Array.from(Buffer.from(value, 'hex'));
const uuid = text => bytes(text.replaceAll('-', ''));
const enc = new TextEncoder();
function join(...parts) { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } return out; }
function n64(n) { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, n); return out; }
function sized(bytes) { const prefix = new Uint8Array(2); new DataView(prefix.buffer).setUint16(0, bytes.length); return join(prefix, bytes); }
async function fixture(index) {
  const pin = await enrollRootPin02(bytes(v.root_pin_hex), bytes(v.root_fingerprint_hex));
  const old = bytes(v.prior02.signed_hex);
  const prior02 = await verifyManifest02(old, pin, BigInt(v.prior02.accepted_ms));
  let predecessor = await verifyManifest03From02(bytes(v.first03.signed_hex), prior02, old, BigInt(v.first03.accepted_ms));
  for (let i = 0; i < index; i++) predecessor = await verifyManifest03Successor(bytes(v.successors[i].successor_signed_hex), predecessor, BigInt(v.successors[i].accepted_ms));
  const row = v.successors[index], original = bytes(index ? v.successors[index - 1].successor_signed_hex : v.first03.signed_hex);
  const signed = bytes(row.successor_signed_hex), view = new DataView(signed.buffer);
  const scope = { operation: row.operation, accountId: uuid(v.account_id), deviceId: uuid(v.device_id), lineId: uuid(v.line_id),
    origin: v.canonical_origin, rootFingerprint: bytes(v.root_fingerprint_hex), predecessorVersion: BigInt(row.predecessor_version),
    predecessorDigest: bytes(row.predecessor_semantic_sha256), predecessorAcceptedMs: BigInt(row.predecessor_accepted_ms),
    phoneReaderKeyId: original.slice(154, 186), browserPoint: bytes(row.role5_point_hex), browserKeyId: bytes(row.role5_key_id_hex),
    issuedMs: view.getBigUint64(39), expiresMs: view.getBigUint64(47) };
  return { scope, predecessor, originalSigned03: original, nowMs: BigInt(row.accepted_ms), signed03: signed };
}
test('actual original02 chain builds exact enroll expired-renew and lost-key replacement proposals', async () => {
  for (let i = 0; i < 3; i++) {
    const input = await fixture(i), s = input.scope;
    const result = await encodeProfile03ManifestProposal(input);
    assert.deepEqual(result.unsigned, input.signed03.slice(0, -64));
    const expected = join(Uint8Array.of(90, 84, 77, 85, 1, i + 1), s.accountId, s.deviceId, s.lineId, sized(enc.encode(s.origin)), s.rootFingerprint,
      n64(s.predecessorVersion), s.predecessorDigest, n64(s.predecessorAcceptedMs), s.phoneReaderKeyId, s.browserPoint, s.browserKeyId,
      n64(s.issuedMs), n64(s.expiresMs), sized(input.originalSigned03), sized(result.unsigned));
    assert.deepEqual(result.proposal, expected);
    assert.deepEqual(result.proposal, bytes(packets.cases[i].proposal_hex));
    assert.equal(result.proposal.length <= 20480, true);
    await verifyProfile03ManifestOutput(input);
    if (i === 1) assert.ok(input.nowMs > new DataView(input.originalSigned03.buffer).getBigUint64(47));
  }
});
test('independent scope root historical token and original signatures are required', async () => {
  const input = await fixture(0);
  for (const change of [{ accountId: input.scope.deviceId }, { deviceId: input.scope.lineId },
    { lineId: input.scope.accountId }, { rootFingerprint: new Uint8Array(32) }, { predecessorDigest: new Uint8Array(32) },
    { predecessorVersion: 9n }, { predecessorAcceptedMs: input.scope.predecessorAcceptedMs + 1n },
    { phoneReaderKeyId: new Uint8Array(32) }, { browserKeyId: new Uint8Array(32) }, { operation: 'replace' },
    { origin: 'https://owner.invalid/path' }, { issuedMs: input.nowMs + 1n }, { extra: true }]) {
    await assert.rejects(encodeProfile03ManifestProposal({ ...input, scope: { ...input.scope, ...change } }));
  }
  await assert.rejects(encodeProfile03ManifestProposal({ ...input, predecessor: {} }));
  const original = Uint8Array.from(input.originalSigned03); original[original.length - 1] ^= 1;
  await assert.rejects(encodeProfile03ManifestProposal({ ...input, originalSigned03: original }));
});
test('bounded fresh signing window preserves historical custody instead of silently renewing operation time', async () => {
  const input = await fixture(1);
  for (const nowMs of [input.scope.predecessorAcceptedMs - 1n, input.scope.issuedMs - 1n,
    input.scope.issuedMs + 300000n, input.scope.expiresMs]) {
    await assert.rejects(encodeProfile03ManifestProposal({ ...input, nowMs }));
  }
  await assert.rejects(encodeProfile03ManifestProposal({ ...input, scope: { ...input.scope, expiresMs: input.scope.issuedMs + 86400001n } }));
});
test('returned output must retain every exact reviewed unsigned byte and a genuine root signature', async () => {
  const input = await fixture(2);
  for (const at of [6, 31, 55, 153, input.signed03.length - 1]) {
    const signed03 = Uint8Array.from(input.signed03); signed03[at] ^= 1;
    await assert.rejects(verifyProfile03ManifestOutput({ ...input, signed03 }));
  }
});
test('creation captures public input before asynchronous verification and never reads caller getters', async () => {
  const input = await fixture(0), original = Uint8Array.from(input.originalSigned03), point = Uint8Array.from(input.scope.browserPoint);
  const pending = encodeProfile03ManifestProposal(input);
  input.originalSigned03.fill(0); input.scope.browserPoint.fill(0); input.scope.accountId.fill(0);
  const result = await pending;
  assert.ok(Buffer.from(result.proposal).includes(Buffer.from(original)));
  assert.ok(Buffer.from(result.proposal).includes(Buffer.from(point)));
  let called = false; const scope = { ...(await fixture(0)).scope };
  Object.defineProperty(scope, 'origin', { enumerable: true, get() { called = true; throw Error('getter'); } });
  await assert.rejects(encodeProfile03ManifestProposal({ ...(await fixture(0)), scope })); assert.equal(called, false);
});
