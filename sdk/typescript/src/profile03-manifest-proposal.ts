// SPDX-License-Identifier: AGPL-3.0-only
/** Exact public offline proposal. No root/key creation, signing or installation. */
import { captureElectionBytes03, electionTime03 } from './payload-profile-election03.js';
import { verifyManifest03Current, verifyManifest03Successor, verifiedManifestIdentity03, type VerifiedManifest03 } from './draft03-manifest.js';

export type Profile03ManifestScope = Readonly<{
  operation: 'enroll' | 'renew' | 'replace'; accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array;
  origin: string; rootFingerprint: Uint8Array; predecessorVersion: bigint; predecessorDigest: Uint8Array;
  predecessorAcceptedMs: bigint; phoneReaderKeyId: Uint8Array; browserPoint: Uint8Array; browserKeyId: Uint8Array;
  issuedMs: bigint; expiresMs: bigint;
}>;
export type Profile03ManifestProposalInput = Readonly<{
  scope: Profile03ManifestScope;
  /** Genuine verified historical token retained at its actual accepted checkpoint. */
  predecessor: VerifiedManifest03; originalSigned03: Uint8Array; nowMs: bigint;
}>;
const enc = new TextEncoder(), max = (1n << 63n) - 1n;
const fields = ['operation', 'accountId', 'deviceId', 'lineId', 'origin', 'rootFingerprint', 'predecessorVersion',
  'predecessorDigest', 'predecessorAcceptedMs', 'phoneReaderKeyId', 'browserPoint', 'browserKeyId', 'issuedMs', 'expiresMs'];
function fail(): never { throw Error('Offline profile03 manifest proposal refused'); }
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
function join(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; } return out;
}
function u64(value: bigint): Uint8Array<ArrayBuffer> {
  electionTime03(value); const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, value); return out;
}
function sized(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  if (bytes.length > 65535) fail(); const prefix = new Uint8Array(2);
  new DataView(prefix.buffer).setUint16(0, bytes.length); return join(prefix, bytes);
}
async function sha(bytes: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', Uint8Array.from(bytes).buffer));
}
function capture(input: Profile03ManifestScope): Profile03ManifestScope {
  if (!input || Object.getPrototypeOf(input) !== Object.prototype) fail();
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (Reflect.ownKeys(descriptors).length !== fields.length || fields.some(k => !descriptors[k] || !('value' in descriptors[k]))) fail();
  const scope = Object.fromEntries(fields.map(k => [k, descriptors[k].value])) as unknown as Profile03ManifestScope;
  const out = { ...scope };
  for (const key of ['accountId', 'deviceId', 'lineId', 'rootFingerprint', 'predecessorDigest', 'phoneReaderKeyId', 'browserPoint', 'browserKeyId'] as const) {
    out[key] = captureElectionBytes03(scope[key], ['accountId', 'deviceId', 'lineId'].includes(key) ? 16 : key === 'browserPoint' ? 65 : 32);
    if (!out[key].some(v => v !== 0)) fail();
  }
  for (const key of ['predecessorVersion', 'predecessorAcceptedMs', 'issuedMs', 'expiresMs'] as const) electionTime03(scope[key]);
  if (!['enroll', 'renew', 'replace'].includes(scope.operation) || out.browserPoint[0] !== 4
      || scope.predecessorVersion >= max || typeof scope.origin !== 'string' || scope.origin.length > 512
      || !/^[\x21-\x7e]+$/.test(scope.origin) || scope.expiresMs <= scope.issuedMs
      || scope.expiresMs - scope.issuedMs > 86400000n) fail();
  const origin = new URL(scope.origin);
  if (origin.protocol !== 'https:' || origin.origin !== scope.origin || origin.username || origin.password) fail();
  return Object.freeze(out);
}
function compare(a: Uint8Array, b: Uint8Array): number {
  if (a[0] !== b[0]) return a[0] - b[0];
  for (let i = 1; i < 33; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0;
}
async function prepare(input: Profile03ManifestProposalInput) {
  // Capture every public byte before the first asynchronous operation.
  const scope = capture(input.scope), original = captureElectionBytes03(input.originalSigned03, 366, 9753);
  const predecessor = input.predecessor, now = input.nowMs; electionTime03(now);
  if (scope.issuedMs > now || now - scope.issuedMs >= 300000n || now >= scope.expiresMs || now < scope.predecessorAcceptedMs) fail();
  const checkpoint = verifiedManifestIdentity03(predecessor, scope.predecessorAcceptedMs);
  if (checkpoint.comparisonMs !== scope.predecessorAcceptedMs) fail();
  const historical = await verifyManifest03Current(original, predecessor, scope.predecessorAcceptedMs);
  const identity = verifiedManifestIdentity03(historical, scope.predecessorAcceptedMs);
  if (identity.generation !== 1n || identity.version !== scope.predecessorVersion || !same(identity.digest, scope.predecessorDigest)
      || !same(identity.accountId, scope.accountId)) fail();
  const pin = join(Uint8Array.of(90, 84, 82, 80, 2), identity.accountId, u64(1n), identity.rootPoint);
  if (!same(await sha(join(enc.encode('ZTSE/root-pin/v2\0'), pin)), scope.rootFingerprint)
      || !same(await sha(join(enc.encode('ZTSE/key/v1\0'), Uint8Array.of(1, 1), scope.browserPoint)), scope.browserKeyId)) fail();
  await crypto.subtle.importKey('raw', Uint8Array.from(scope.browserPoint).buffer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const records = Array.from({ length: original[152] }, (_, i) => original.slice(153 + i * 149, 153 + (i + 1) * 149));
  const old = records.filter(r => r[0] === 5 && r[148] === 1 && same(r.subarray(114, 130), scope.lineId));
  if (old.length > 1 || (scope.operation === 'enroll') !== (old.length === 0)) fail();
  const identical = old.length === 1 && same(old[0].subarray(1, 33), scope.browserKeyId) && same(old[0].subarray(33, 98), scope.browserPoint);
  if ((scope.operation === 'renew') !== identical) fail();
  if (scope.operation !== 'renew' && records.some(r => same(r.subarray(1, 33), scope.browserKeyId) || same(r.subarray(33, 98), scope.browserPoint))) fail();
  for (const row of records) {
    if (scope.operation === 'replace' && row === old[0]) { row[148] = 2; continue; }
    if (row[148] !== 1) continue;
    const view = new DataView(row.buffer);
    if (view.getBigUint64(140) > scope.expiresMs) fail();
    view.setBigUint64(140, scope.expiresMs);
  }
  if (scope.operation !== 'renew') {
    const row = new Uint8Array(149); row[0] = 5; row.set(scope.browserKeyId, 1); row.set(scope.browserPoint, 33);
    row.set(scope.lineId, 114); const view = new DataView(row.buffer); view.setUint16(130, 1);
    view.setBigUint64(132, scope.issuedMs); view.setBigUint64(140, scope.expiresMs); row[148] = 1; records.push(row);
  }
  if (records.length > 64) fail();
  const reader = records.filter(r => r[0] === 1 && r[148] === 1 && same(r.subarray(114, 130), scope.lineId));
  if (reader.length !== 1 || !same(reader[0].subarray(1, 33), scope.phoneReaderKeyId)
      || !same(reader[0].subarray(98, 114), scope.deviceId) || new DataView(reader[0].buffer).getBigUint64(132) > now) fail();
  const signer = records.find(r => r[0] === 5 && r[148] === 1 && same(r.subarray(114, 130), scope.lineId));
  if (!signer || new DataView(signer.buffer).getBigUint64(132) > now) fail();
  records.sort(compare); const header = original.slice(0, 153), view = new DataView(header.buffer);
  header[6] = 3; header[152] = records.length; view.setBigUint64(31, scope.predecessorVersion + 1n);
  view.setBigUint64(39, scope.issuedMs); view.setBigUint64(47, scope.expiresMs); header.set(scope.predecessorDigest, 55);
  return { scope, original, historical, unsigned: join(header, ...records), now };
}
/** Closed ZTMU01 packet for review by the existing offline owner custodian.
 * Its complete existing-key extension and optional one-key delta are displayed
 * and approved there. These public bytes authorize no network or content use. */
export async function encodeProfile03ManifestProposal(input: Profile03ManifestProposalInput): Promise<Readonly<{ proposal: Uint8Array; unsigned: Uint8Array }>> {
  const p = await prepare(input), s = p.scope;
  const packet = join(Uint8Array.of(90, 84, 77, 85, 1, { enroll: 1, renew: 2, replace: 3 }[s.operation]),
    s.accountId, s.deviceId, s.lineId, sized(enc.encode(s.origin)), s.rootFingerprint, u64(s.predecessorVersion), s.predecessorDigest,
    u64(s.predecessorAcceptedMs), s.phoneReaderKeyId, s.browserPoint, s.browserKeyId, u64(s.issuedMs), u64(s.expiresMs), sized(p.original), sized(p.unsigned));
  if (packet.length > 20480) fail(); return Object.freeze({ proposal: packet, unsigned: p.unsigned });
}
/** Exact returned public artifact verification, before any role05 signature or
 * network install. A verified manifest token supplies cryptography, not durable
 * accepted ancestry, current owner/phone selection or content permission. */
export async function verifyProfile03ManifestOutput(input: Profile03ManifestProposalInput & Readonly<{ signed03: Uint8Array }>): Promise<VerifiedManifest03> {
  const signed = captureElectionBytes03(input.signed03, 366, 9753), p = await prepare(input);
  if (!same(signed.subarray(0, -64), p.unsigned)) fail();
  return verifyManifest03Successor(signed, p.historical, p.now);
}
