// SPDX-License-Identifier: AGPL-3.0-only
/** Public possession grammar only. No root verification, authenticated owner,
 * accepted ancestry, enrollment, current permission or installation is implied. */
import { captureElectionBytes03, electionTime03 } from './payload-profile-election03.js';
import { isCanonicalP256Signature } from './draft01.js';

const uuidFields = ['accountId', 'ownerUserId', 'ownerSessionId', 'deviceId', 'lineId', 'bindingId', 'electionChallengeId', 'openingId'] as const;
const numberFields = ['bindingGeneration', 'vaultGeneration', 'selectionEpoch', 'predecessorVersion', 'successorVersion', 'issuedMs', 'expiresMs'] as const;
const digestFields = ['rootFingerprint', 'electionCommitment', 'electionBundleSha256', 'originDigest', 'ownerSessionDigest', 'predecessorDigest', 'signedSuccessorSha256', 'signerKeyId'] as const;
const fields = [...uuidFields, ...numberFields, ...digestFields, 'signerPoint'] as const;
export type ManifestInstallStatement03 = Readonly<
  Record<typeof uuidFields[number] | typeof digestFields[number] | 'signerPoint', Uint8Array>
  & Record<typeof numberFields[number], bigint>>;
const header = Uint8Array.of(90, 84, 77, 83, 1, 3, 3, 0), enc = new TextEncoder();
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
const ab = (a: Uint8Array): ArrayBuffer => Uint8Array.from(a).buffer;
function fail(): never { throw Error('Manifest03 possession statement refused'); }
function nonzero(value: Uint8Array, length: number): Uint8Array {
  const result = captureElectionBytes03(value, length); if (!result.some(v => v !== 0)) fail(); return result;
}
function snapshot(input: ManifestInstallStatement03): ManifestInstallStatement03 {
  if (!input || Object.getPrototypeOf(input) !== Object.prototype) fail();
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (Reflect.ownKeys(descriptors).length !== fields.length || fields.some(k => !descriptors[k] || !('value' in descriptors[k]))) fail();
  const out = Object.fromEntries(fields.map(k => [k, descriptors[k].value])) as Record<string, Uint8Array | bigint>;
  for (const k of uuidFields) out[k] = nonzero(out[k] as Uint8Array, 16);
  for (const k of digestFields) out[k] = nonzero(out[k] as Uint8Array, 32);
  out.signerPoint = captureElectionBytes03(out.signerPoint as Uint8Array, 65);
  for (const k of numberFields) electionTime03(out[k] as bigint);
  const s = out as ManifestInstallStatement03;
  if (s.vaultGeneration !== 1n || s.selectionEpoch !== 1n || s.successorVersion !== s.predecessorVersion + 1n
      || s.expiresMs <= s.issuedMs || s.expiresMs - s.issuedMs > 300000n || s.signerPoint[0] !== 4) fail();
  return s;
}
async function signer(s: ManifestInstallStatement03): Promise<CryptoKey> {
  const domain = enc.encode('ZTSE/key/v1\0'), framed = new Uint8Array(domain.length + 2 + 65);
  framed.set(domain); framed.set([1, 1], domain.length); framed.set(s.signerPoint, domain.length + 2);
  if (!same(new Uint8Array(await crypto.subtle.digest('SHA-256', framed)), s.signerKeyId)) fail();
  return crypto.subtle.importKey('raw', ab(s.signerPoint), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}
export async function encodeManifestInstall03(input: ManifestInstallStatement03): Promise<Uint8Array> {
  const s = snapshot(input), out = new Uint8Array(513), view = new DataView(out.buffer);
  out.set(header); let at = 8;
  for (const k of uuidFields) { out.set(s[k], at); at += 16; }
  for (const k of numberFields) { view.setBigUint64(at, s[k]); at += 8; }
  for (const k of digestFields) { out.set(s[k], at); at += 32; }
  out.set(s.signerPoint, at); await signer(s); return out;
}
export async function decodeManifestInstall03(input: Uint8Array): Promise<ManifestInstallStatement03> {
  const bytes = captureElectionBytes03(input, 513);
  if (!same(bytes.subarray(0, 8), header)) fail();
  const view = new DataView(bytes.buffer), raw: Record<string, Uint8Array | bigint> = {}; let at = 8;
  for (const k of uuidFields) { raw[k] = bytes.slice(at, at + 16); at += 16; }
  for (const k of numberFields) { raw[k] = view.getBigUint64(at); at += 8; }
  for (const k of digestFields) { raw[k] = bytes.slice(at, at + 32); at += 32; }
  raw.signerPoint = bytes.slice(at);
  const owned = snapshot(raw as ManifestInstallStatement03); await signer(owned); return Object.freeze(owned);
}
/** Exact L framing; callers must separately approve the verified successor and
 * genuine current scope before using a retained message key for this transcript. */
export async function manifestInstallSigningBytes03(input: Uint8Array): Promise<Uint8Array> {
  const bytes = captureElectionBytes03(input, 513); await decodeManifestInstall03(bytes);
  const domain = enc.encode('ZTSE/line/payload-profile/manifest-install03/v1\0'), out = new Uint8Array(domain.length + 4 + bytes.length);
  out.set(domain); new DataView(out.buffer).setUint32(domain.length, bytes.length); out.set(bytes, domain.length + 4); return out;
}
/** Verifies the stated key's possession only. Received high-S is rejected,
 * never normalized; caller must independently verify root/current authority. */
export async function verifyManifestInstallPossession03(input: Uint8Array, signature: Uint8Array): Promise<ManifestInstallStatement03> {
  const bytes = captureElectionBytes03(input, 513), raw = captureElectionBytes03(signature, 64);
  if (!isCanonicalP256Signature(raw)) fail();
  const statement = await decodeManifestInstall03(bytes), key = await signer(statement);
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, ab(raw), ab(await manifestInstallSigningBytes03(bytes)))) fail();
  return statement;
}
