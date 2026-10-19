// SPDX-License-Identifier: AGPL-3.0-only
/** Public first03 proposal for the existing offline root. No key generation or authority. */
import { verifyManifest02, verifiedManifestIdentity02, verifiedManifestTrust02, type Manifest02 } from './draft02-manifest.js';
import { verifyManifest03From02, type VerifiedManifest03 } from './draft03-manifest.js';
import { captureElectionBytes03, electionTime03 } from './payload-profile-election03.js';

export type ProfileUpgradeScope03 = Readonly<{
  accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array;
  origin: string; rootFingerprint: Uint8Array; predecessorVersion: bigint;
  predecessorDigest: Uint8Array; phoneReaderKeyId: Uint8Array; phoneSigningKeyId: Uint8Array;
  issuedMs: bigint;
}>;
const max = (1n << 63n) - 1n, enc = new TextEncoder();
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
function join(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; } return out;
}
function u64(n: bigint): Uint8Array<ArrayBuffer> { electionTime03(n); const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n); return b; }
function sized(b: Uint8Array): Uint8Array<ArrayBuffer> {
  if (b.length > 65535) throw Error('Profile upgrade public length refused');
  const n = new Uint8Array(2); new DataView(n.buffer).setUint16(0, b.length); return join(n, b);
}
function capture(input: ProfileUpgradeScope03): ProfileUpgradeScope03 {
  const keys = ['accountId', 'deviceId', 'lineId', 'origin', 'rootFingerprint', 'predecessorVersion', 'predecessorDigest', 'phoneReaderKeyId', 'phoneSigningKeyId', 'issuedMs'];
  const ds = Object.getOwnPropertyDescriptors(input);
  if (Object.getPrototypeOf(input) !== Object.prototype || Reflect.ownKeys(ds).length !== keys.length
      || keys.some(k => !ds[k] || !('value' in ds[k]))) throw Error('Profile upgrade closed scope required');
  const s = Object.fromEntries(keys.map(k => [k, ds[k].value])) as unknown as ProfileUpgradeScope03;
  const out = { ...s };
  for (const k of ['accountId', 'deviceId', 'lineId', 'rootFingerprint', 'predecessorDigest', 'phoneReaderKeyId', 'phoneSigningKeyId'] as const) {
    out[k] = captureElectionBytes03(s[k], k.endsWith('Id') && !k.endsWith('KeyId') ? 16 : 32);
    if (!out[k].some(v => v !== 0)) throw Error('Profile upgrade identity required');
  }
  electionTime03(s.predecessorVersion); electionTime03(s.issuedMs);
  if (typeof s.origin !== 'string' || s.origin.length > 512 || !/^[\x21-\x7e]+$/.test(s.origin)) throw Error('Profile upgrade canonical HTTPS origin required');
  const origin = new URL(s.origin);
  if (origin.protocol !== 'https:' || origin.origin !== s.origin) throw Error('Profile upgrade canonical HTTPS origin required');
  return Object.freeze(out);
}
async function prepare(input: ProfileUpgradeScope03, original: Manifest02, signed: Uint8Array, now: bigint) {
  const s = capture(input), originalBytes = captureElectionBytes03(signed, 364, 9751);
  electionTime03(now);
  const identity = verifiedManifestIdentity02(original, now), trust = verifiedManifestTrust02(original, now);
  const before = await verifyManifest02(originalBytes, trust, now);
  if (identity.generation !== 1n || identity.version >= max || s.predecessorVersion !== identity.version
      || !same(s.accountId, identity.accountId) || !same(s.predecessorDigest, identity.digest)
      || s.issuedMs < before.issuedMs || s.issuedMs > now || s.issuedMs >= before.expiresMs
      || trust.anchorDigest.some(v => v !== 0)) throw Error('Profile upgrade original high-water refused');
  const pin = join(Uint8Array.of(90, 84, 82, 80, 2), identity.accountId, u64(1n), identity.rootPoint);
  const actual = new Uint8Array(await crypto.subtle.digest('SHA-256', join(enc.encode('ZTSE/root-pin/v2\0'), pin)));
  if (!same(actual, s.rootFingerprint)) throw Error('Profile upgrade independent root refused');
  for (const [role, id] of [[1, s.phoneReaderKeyId], [4, s.phoneSigningKeyId]] as const) {
    const selected = before.keys.filter(k => k.role === role && k.state === 1 && k.fromMs <= now && now < k.untilMs
      && same(k.deviceId, s.deviceId) && same(k.lineId, s.lineId));
    if (selected.length !== 1 || !same(selected[0].keyId, id)) throw Error('Profile upgrade original selected key refused');
  }
  const unsigned = join(Uint8Array.of(90, 84, 77, 65, 3, 3, 2), originalBytes.subarray(5, -64));
  unsigned.set(u64(identity.version + 1n), 31); unsigned.set(u64(s.issuedMs), 39); unsigned.set(identity.digest, 55);
  return { scope: s, originalBytes, unsigned };
}
/** ZTPU01: account/device/line16, origin(u16+ASCII), rootFingerprint32, version8,
 * predecessorDigest/phoneReader/phoneSigner32, issued8, signed02(u16+bytes), unsigned03(u16+bytes).
 * The original signed expiry and every key record remain byte-identical. */
export async function encodePayloadProfileUpgradeProposal03(input: Readonly<{
  scope: ProfileUpgradeScope03; predecessor: Manifest02; originalSigned02: Uint8Array; nowMs: bigint;
}>): Promise<Readonly<{ proposal: Uint8Array; unsigned: Uint8Array }>> {
  const p = await prepare(input.scope, input.predecessor, input.originalSigned02, input.nowMs), s = p.scope;
  const proposal = join(Uint8Array.of(90, 84, 80, 85, 1), s.accountId, s.deviceId, s.lineId, sized(enc.encode(s.origin)),
    s.rootFingerprint, u64(s.predecessorVersion), s.predecessorDigest, s.phoneReaderKeyId, s.phoneSigningKeyId,
    u64(s.issuedMs), sized(p.originalBytes), sized(p.unsigned));
  if (proposal.length > 20480) throw Error('Profile upgrade proposal bound refused');
  return Object.freeze({ proposal, unsigned: p.unsigned });
}
/** Verify returned public output against the independently selected exact proposal, before reserve. */
export async function verifyPayloadProfileUpgradeOutput03(input: Readonly<{
  scope: ProfileUpgradeScope03; predecessor: Manifest02; originalSigned02: Uint8Array; signed03: Uint8Array; nowMs: bigint;
}>): Promise<VerifiedManifest03> {
  const signed = captureElectionBytes03(input.signed03, 366, 9753);
  const p = await prepare(input.scope, input.predecessor, input.originalSigned02, input.nowMs);
  if (!same(signed.subarray(0, -64), p.unsigned)) throw Error('Profile upgrade changes original authority');
  return verifyManifest03From02(signed, input.predecessor, p.originalBytes, input.nowMs);
}
