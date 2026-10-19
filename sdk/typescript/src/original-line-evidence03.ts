// SPDX-License-Identifier: AGPL-3.0-only
/** Original signature evidence only. Acceptance timestamps are server-attributed;
 * these objects never establish database acceptance or present permission. */
import { enrollRootPin02 } from './draft02-manifest.js';
import { captureElectionBytes03, electionTime03 } from './payload-profile-election03.js';
import { isCanonicalP256Signature } from './draft01.js';

const enc = new TextEncoder();
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const registrationLabel = 'ZTSE/line/payload-profile/registration-evidence/v1';
const activationLabel = 'ZTSE/line/payload-profile/activation-evidence/v1';
const registrationDomain = enc.encode('ZTSE/line/owner-key/register/v1\0');
const deviceDomain = enc.encode('ZTSE/line/device-confirm/v2\0');
const ownerDomain = enc.encode('ZTSE/line/owner-approve/v2\0');
const maxRegistration = enc.encode(registrationLabel).length + 1 + 4 + 4 + 1024 + 128 + 65 + 64 + 24;
const maxActivation = enc.encode(activationLabel).length + 1 + 4 + 32 + 130 + 255 + 2 + 80 + 314 + 2 + 80 + 8;

function fail(): never { throw new Error('Original line signature evidence refused'); }
function same(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((v, i) => v === b[i]); }
function nonzero(a: Uint8Array): Uint8Array { if (!a.some(v => v !== 0)) fail(); return a; }
function hex(a: Uint8Array): string { return Array.from(a, v => v.toString(16).padStart(2, '0')).join(''); }
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; } return out;
}
function frame(label: string, bytes: Uint8Array): Uint8Array {
  const size = new Uint8Array(4); new DataView(size.buffer).setUint32(0, bytes.length);
  return concat(enc.encode(label + '\0'), size, bytes);
}
function ab(bytes: Uint8Array): ArrayBuffer { return Uint8Array.from(bytes).buffer; }
async function sha(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', ab(bytes)));
}
function own(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== keys.length || keys.some(k => !descriptors[k] || !('value' in descriptors[k]))) fail();
  return Object.fromEntries(keys.map(k => [k, descriptors[k].value]));
}
function bytes(value: unknown, size: number): Uint8Array {
  return captureElectionBytes03(value as Uint8Array, size);
}
function positive(value: unknown): bigint { electionTime03(value as bigint); return value as bigint; }
function canonicalOrigin(value: unknown): string {
  if (typeof value !== 'string' || value.length > 255) fail();
  try { const u = new URL(value); if (u.protocol !== 'https:' || u.origin !== value) fail(); }
  catch { return fail(); } return value;
}
class Cursor {
  #at = 0;
  constructor(readonly data: Uint8Array) {}
  take(n: number): Uint8Array {
    if (!Number.isInteger(n) || n < 0 || this.#at + n > this.data.length) fail();
    const out = this.data.slice(this.#at, this.#at + n); this.#at += n; return out;
  }
  u16(): number { return new DataView(this.take(2).buffer).getUint16(0); }
  u32(): number { return new DataView(this.take(4).buffer).getUint32(0); }
  time(): bigint { return positive(new DataView(this.take(8).buffer).getBigUint64(0)); }
  id(): Uint8Array { return nonzero(this.take(16)); }
  text(max: number): string {
    const n = this.u16(); if (n < 1 || n > max) fail();
    const raw = this.take(n); if (!raw.every(v => v >= 33 && v <= 126)) fail();
    return new TextDecoder().decode(raw);
  }
  end(): void { if (this.#at !== this.data.length) fail(); }
}
function payload(input: Uint8Array, label: string, max: number): Cursor {
  const c = new Cursor(captureElectionBytes03(input, 1, max)), domain = enc.encode(label + '\0');
  if (!same(c.take(domain.length), domain)) fail();
  const raw = c.take(c.u32()); c.end(); return new Cursor(raw);
}
function scalar(raw: Uint8Array): bigint { return raw.reduce((n, v) => (n << 8n) | BigInt(v), 0n); }
/** Original v2 DER admits both S halves. Never normalize bytes used by its hash. */
function rawFromOriginalDer(der: Uint8Array): Uint8Array {
  if (der.length < 8 || der.length > 72 || der[0] !== 48 || der[1] !== der.length - 2) fail();
  let at = 2;
  function integer(): Uint8Array {
    if (der[at++] !== 2) fail(); const n = der[at++];
    if (n < 1 || n > 33 || at + n > der.length) fail();
    let part = der.slice(at, at + n); at += n;
    if (part[0] & 128 || part.length > 1 && part[0] === 0 && !(part[1] & 128)) fail();
    if (part[0] === 0) part = part.slice(1);
    if (part.length > 32) fail(); const out = new Uint8Array(32); out.set(part, 32 - part.length);
    if (scalar(out) < 1n || scalar(out) >= order) fail(); return out;
  }
  const raw = concat(integer(), integer()); if (at !== der.length) fail(); return raw;
}
async function verify(point: Uint8Array, raw: Uint8Array, message: Uint8Array): Promise<void> {
  const key = await pointKey(point);
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, ab(raw), ab(message))) fail();
}
async function pointKey(point: Uint8Array): Promise<CryptoKey> {
  if (point.length !== 65 || point[0] !== 4) fail();
  return crypto.subtle.importKey('raw', ab(point), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}

export type OriginalRegistrationSelection03 = Readonly<{
  accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array; generation: bigint;
  comparedRootFingerprint: Uint8Array; pairedSigningPoint: Uint8Array; origin: string; trustedNowMs: bigint;
}>;
/** Immutable strings/counters, not a current authorization or acceptance claim. */
export type HistoricalRegistrationSignatures03 = Readonly<{
  accountHex: string; deviceHex: string; lineHex: string; generation: bigint;
  registrationHex: string; originalUserHex: string; originalSessionHex: string;
  evidenceSha256Hex: string; completedMs: bigint;
}>;
type RegistrationState = {
  account: Uint8Array; device: Uint8Array; line: Uint8Array; generation: bigint; registration: Uint8Array;
  approvalPoint: Uint8Array; pairedPoint: Uint8Array; evidenceDigest: Uint8Array; completed: bigint; expires: bigint; observed: bigint;
};
const verifiedRegistrations = new WeakMap<HistoricalRegistrationSignatures03, RegistrationState>();

/** Copies of the verified original public points, for exact retained-key lookup.
 * This exposes no private key or present authorization; copied handles are refused. */
export function originalRegistrationPublicKeys03(
  handle: HistoricalRegistrationSignatures03,
): Readonly<{ approvalPoint: Uint8Array; pairedPoint: Uint8Array }> {
  const original = verifiedRegistrations.get(handle); if (!original) fail();
  return Object.freeze({ approvalPoint: original.approvalPoint.slice(), pairedPoint: original.pairedPoint.slice() });
}

/** Inputs must come from the existing independent root/paired-phone comparison.
 * Historical session IDs stay historical; a fresh owner sign-in must not rewrite them. */
export async function verifyOriginalRegistrationSignatures03(
  input: Uint8Array, selection: OriginalRegistrationSelection03,
): Promise<HistoricalRegistrationSignatures03> {
  const c = payload(input, registrationLabel, maxRegistration);
  const selected = own(selection, ['accountId', 'deviceId', 'lineId', 'generation', 'comparedRootFingerprint', 'pairedSigningPoint', 'origin', 'trustedNowMs']);
  const account = nonzero(bytes(selected.accountId, 16)), device = nonzero(bytes(selected.deviceId, 16)), line = nonzero(bytes(selected.lineId, 16));
  const generation = positive(selected.generation), rootFingerprint = nonzero(bytes(selected.comparedRootFingerprint, 32));
  const pairedPoint = bytes(selected.pairedSigningPoint, 65), origin = canonicalOrigin(selected.origin), now = positive(selected.trustedNowMs);
  const length = c.u32(); if (length < 1 || length > 1024) fail();
  const transcript = c.take(length), rootSignature = c.take(64), approvalSignature = c.take(64), approvalPoint = c.take(65);
  const approvalFingerprint = c.take(32), pairedFingerprint = c.take(32), issued = c.time(), expires = c.time(), completed = c.time(); c.end();
  if (expires <= issued || expires - issued > 300_000n || completed < issued || completed >= expires || completed > now
    || !isCanonicalP256Signature(rootSignature) || !isCanonicalP256Signature(approvalSignature)) fail();
  const t = new Cursor(transcript); if (!same(t.take(registrationDomain.length), registrationDomain)) fail();
  const originalAccount = t.id(), user = t.id(), session = t.id(), originalDevice = t.id(), originalLine = t.id();
  const originalGeneration = t.time(), registration = t.id(); nonzero(t.take(32));
  if (t.time() !== issued || t.time() !== expires) fail();
  const pin = t.take(94), signedRootFingerprint = t.take(32), signedApprovalPoint = t.take(65);
  const signedApprovalFingerprint = nonzero(t.take(32)), signedPairedFingerprint = nonzero(t.take(32));
  t.time(); t.time(); t.text(128); t.text(128); const signedOrigin = canonicalOrigin(t.text(255)); t.end();
  if (!same(account, originalAccount) || !same(device, originalDevice) || !same(line, originalLine) || generation !== originalGeneration
    || signedOrigin !== origin || !same(signedRootFingerprint, rootFingerprint) || !same(signedApprovalPoint, approvalPoint)
    || !same(signedApprovalFingerprint, approvalFingerprint) || !same(signedPairedFingerprint, pairedFingerprint)
    || same(approvalPoint, pairedPoint) || same(approvalFingerprint, pairedFingerprint)) fail();
  const trust = await enrollRootPin02(pin, rootFingerprint);
  if (!same(trust.accountId, account) || same(trust.rootPoint, approvalPoint) || same(trust.rootPoint, pairedPoint)
    || !same(await sha(approvalPoint), approvalFingerprint) || !same(await sha(pairedPoint), pairedFingerprint)) fail();
  await pointKey(pairedPoint);
  await verify(trust.rootPoint, rootSignature, transcript); await verify(approvalPoint, approvalSignature, transcript);
  const evidenceDigest = await sha(frame(registrationLabel, c.data));
  const result = Object.freeze({ accountHex: hex(account), deviceHex: hex(device), lineHex: hex(line), generation,
    registrationHex: hex(registration), originalUserHex: hex(user), originalSessionHex: hex(session),
    evidenceSha256Hex: hex(evidenceDigest), completedMs: completed });
  verifiedRegistrations.set(result, { account, device, line, generation, registration, approvalPoint, pairedPoint, evidenceDigest, completed, expires, observed: now });
  return result;
}

export type OriginalActivationSelection03 = Readonly<{ oldBindingId: Uint8Array; selectedReaderKeyId: Uint8Array; trustedNowMs: bigint }>;
export type HistoricalActivationSignatures03 = Readonly<{
  oldBindingHex: string; activationChallengeHex: string; registrationHex: string; generation: bigint;
  evidenceSha256Hex: string; oldBindingDigestHex: string; deviceConfirmationDigestHex: string;
  ownerApprovalDigestHex: string; acceptedMs: bigint;
}>;
/** Verifies historical signatures and derives the old-binding commitment. The
 * later E500, current selected manifest/lease and installed-reader checks remain mandatory. */
export async function verifyOriginalActivationSignatures03(
  input: Uint8Array, registration: HistoricalRegistrationSignatures03, selection: OriginalActivationSelection03,
): Promise<HistoricalActivationSignatures03> {
  const r = verifiedRegistrations.get(registration); if (!r) fail();
  const c = payload(input, activationLabel, maxActivation), s = own(selection, ['oldBindingId', 'selectedReaderKeyId', 'trustedNowMs']);
  const binding = nonzero(bytes(s.oldBindingId, 16)), reader = nonzero(bytes(s.selectedReaderKeyId, 32)), now = positive(s.trustedNowMs);
  const registrationId = c.id(), oldBinding = c.id(), devicePoint = c.take(65), ownerPoint = c.take(65), deviceStatement = c.take(255);
  const deviceDer = c.take(c.u16()), ownerStatement = c.take(314), ownerDer = c.take(c.u16()), accepted = c.time(); c.end();
  if (!same(registrationId, r.registration) || !same(binding, oldBinding) || !same(devicePoint, r.pairedPoint)
    || !same(ownerPoint, r.approvalPoint) || accepted < r.completed || accepted >= r.expires || accepted > now || now < r.observed) fail();
  const deviceRaw = rawFromOriginalDer(deviceDer), ownerRaw = rawFromOriginalDer(ownerDer), d = new Cursor(deviceStatement);
  if (!same(d.take(deviceDomain.length), deviceDomain) || !same(d.take(2), Uint8Array.of(2, 2))
    || !same(d.id(), r.account) || !same(d.id(), r.line) || !same(d.id(), r.device) || d.time() !== r.generation) fail();
  const challenge = d.id(); d.take(32); const observation = d.take(121); d.end();
  if (same(challenge, binding)) fail();
  const v = new DataView(observation.buffer), count = v.getUint16(2);
  if (v.getUint16(0) < 33 || count < 1 || count > 256 || v.getInt32(4) < 0 || ![1, 2].includes(observation[8])
    || v.getInt32(41) < 0 || v.getInt32(45) < 0) fail();
  for (const at of [9, 25, 49, 73]) nonzero(observation.subarray(at, at + 16));
  positive(v.getBigUint64(65));
  if (!same(ownerStatement, concat(ownerDomain, deviceStatement, await sha(deviceDer)))) fail();
  await verify(devicePoint, deviceRaw, deviceStatement); await verify(ownerPoint, ownerRaw, ownerStatement);
  const deviceDigest = await sha(concat(deviceStatement, deviceDer)), ownerDigest = await sha(concat(ownerStatement, ownerDer));
  const generationBytes = new Uint8Array(8); new DataView(generationBytes.buffer).setBigUint64(0, r.generation);
  const identity = frame('ZTSE/line/payload-profile/old-binding/v1', concat(Uint8Array.of(2, 2), binding, r.account,
    r.device, r.line, generationBytes, challenge, r.registration, r.evidenceDigest, ownerDigest, deviceDigest, reader));
  return Object.freeze({ oldBindingHex: hex(binding), activationChallengeHex: hex(challenge), registrationHex: hex(r.registration), generation: r.generation,
    evidenceSha256Hex: hex(await sha(frame(activationLabel, c.data))), oldBindingDigestHex: hex(await sha(identity)),
    deviceConfirmationDigestHex: hex(deviceDigest), ownerApprovalDigestHex: hex(ownerDigest), acceptedMs: accepted });
}
