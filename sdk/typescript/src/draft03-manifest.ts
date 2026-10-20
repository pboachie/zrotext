/** Experimental Manifest03 cryptographic dependency; no production caller/export.
 * Generation-one, zero-anchor chains only. This module cannot attest the owner's
 * comparison channel, original signed02 evidence/checkpoint, durable currentness,
 * a live session, elected binding, reader permission or atomic fork selection.
 * The caller supplies trusted time and must atomically persist original evidence.
 */
import {
  verifyManifest02, verifiedManifestIdentity02, verifiedManifestTrust02,
  type Manifest02, type ManifestTrust02,
} from "./draft02-manifest.js";

declare const verified03: unique symbol;
/** Runtime provenance is the private WeakMap, never this compile-time brand. */
export type VerifiedManifest03 = Readonly<{ [verified03]: true }>;
export type ManifestIdentity03 = Readonly<{
  profile: 3; predecessorProfile: 2 | 3; accountId: Uint8Array; generation: bigint;
  version: bigint; digest: Uint8Array; rootPoint: Uint8Array; issuedMs: bigint;
  expiresMs: bigint; comparisonMs: bigint;
}>;
type Key03 = Readonly<{
  role: number; keyId: Uint8Array; point: Uint8Array; deviceId: Uint8Array;
  lineId: Uint8Array; scope: number; fromMs: bigint; untilMs: bigint; state: number;
}>;
type Snapshot = ManifestIdentity03 & Readonly<{
  bytes: Uint8Array; previousDigest: Uint8Array; anchorDigest: Uint8Array;
  keys: readonly Key03[];
}>;
type Identity02 = ReturnType<typeof verifiedManifestIdentity02>;
const snapshots = new WeakMap<VerifiedManifest03, Snapshot>();
const maxSigned = (1n << 63n) - 1n;
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const zero16 = new Uint8Array(16), zero32 = new Uint8Array(32);
const enc = new TextEncoder();
const u8Prototype = Uint8Array.prototype, abPrototype = ArrayBuffer.prototype;
const ordinaryByteLength = Object.getOwnPropertyDescriptor(abPrototype, "byteLength")!.get!;
const getPrototype = Object.getPrototypeOf;
const typedPrototype = getPrototype(u8Prototype);
const elementKind = Object.getOwnPropertyDescriptor(typedPrototype, Symbol.toStringTag)!.get!;
const storage = Object.getOwnPropertyDescriptor(typedPrototype, "buffer")!.get!;
const byteLength = Object.getOwnPropertyDescriptor(typedPrototype, "byteLength")!.get!;
const typedSet = u8Prototype.set;

function fail(why: string): never { throw new Error(`ZTSE draft-03 manifest: ${why}`); }
function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}
function comparison(now: bigint): void {
  if (typeof now !== "bigint" || now < 1n || now > maxSigned) fail("comparison range/type");
}
/** Genuine Uint8Array/ArrayBuffer brands with exact local prototypes; no caller
 * iterator, species or public getters. Prototype compatibility does not attest
 * allocation history. Shared storage refuses, including prototype disguises. */
function capture(input: Uint8Array, min: number, max: number): Uint8Array {
  try {
    if (getPrototype(input) !== u8Prototype) fail("unsupported byte input");
    if (Reflect.apply(elementKind, input, []) !== "Uint8Array") fail("unsupported byte kind");
    const buffer = Reflect.apply(storage, input, []) as ArrayBuffer;
    if (getPrototype(buffer) !== abPrototype) fail("unsupported byte storage");
    // Public prototype equality is not a storage brand: callers can disguise a
    // SharedArrayBuffer. This intrinsic requires actual ArrayBuffer storage.
    Reflect.apply(ordinaryByteLength, buffer, []);
    const length = Reflect.apply(byteLength, input, []) as number;
    if (length < min || length > max) fail("byte input bounds");
    const owned = new Uint8Array(length);
    Reflect.apply(typedSet, owned, [input]);
    return owned;
  } catch { return fail("unsupported byte input or bounds"); }
}
function copy(bytes: Uint8Array): Uint8Array { return Uint8Array.from(bytes); }
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}
function ab(bytes: Uint8Array): ArrayBuffer { return Uint8Array.from(bytes).buffer; }
async function sha(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", ab(bytes)));
}
function u64(view: DataView, at: number): bigint {
  const n = view.getBigUint64(at, false);
  if (n > maxSigned) fail("signed-storage range");
  return n;
}
function scalar(bytes: Uint8Array): bigint {
  return bytes.reduce((n, b) => (n << 8n) | BigInt(b), 0n);
}
function strictSignature(raw: Uint8Array): void {
  if (raw.length !== 64) fail("signature width");
  const r = scalar(raw.subarray(0, 32)), s = scalar(raw.subarray(32));
  if (r < 1n || r >= order || s < 1n || s >= order) fail("signature scalar range");
  if (s > order / 2n) fail("high-s signature");
}
async function pointKey(point: Uint8Array): Promise<CryptoKey> {
  if (point.length !== 65 || point[0] !== 4) fail("point shape");
  try {
    return await crypto.subtle.importKey("raw", ab(point), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  } catch { return fail("point curve"); }
}
function window(issued: bigint, expires: bigint, now: bigint): void {
  if (issued < 1n || expires <= issued || expires - issued > 86_400_000n) fail("signed validity window");
  if (issued > now + 300_000n || now >= expires) fail("stale or future signed object");
}
function scope(role: number, value: number, device: Uint8Array, line: Uint8Array): void {
  if (role < 1 || role > 6) fail("unknown role");
  const allowed = [0, 4, 12, 4, 2, 1, 0][role];
  if (role === 3 ? ![4, 8, 12].includes(value) : value !== allowed) fail("role/scope");
  const deviceBound = role === 1 || role === 4;
  const lineBound = deviceBound || role === 5;
  if (deviceBound ? same(device, zero16) : !same(device, zero16)) fail("role/subject");
  if (lineBound ? same(line, zero16) : !same(line, zero16)) fail("role/subject");
}
function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}
function owned(snapshot: Snapshot): Snapshot {
  return { ...snapshot, accountId: copy(snapshot.accountId), digest: copy(snapshot.digest),
    rootPoint: copy(snapshot.rootPoint), bytes: copy(snapshot.bytes),
    previousDigest: copy(snapshot.previousDigest), anchorDigest: copy(snapshot.anchorDigest),
    keys: snapshot.keys.map(k => ({ ...k, keyId: copy(k.keyId), point: copy(k.point),
      deviceId: copy(k.deviceId), lineId: copy(k.lineId) })) };
}
function bound(token: VerifiedManifest03, now: bigint): Snapshot {
  const value = snapshots.get(token);
  if (!value) fail("requires exact verified03 token");
  if (now < value.comparisonMs) fail("comparison regression");
  return owned(value);
}
function accept(snapshot: Snapshot): VerifiedManifest03 {
  const token = Object.freeze({}) as VerifiedManifest03;
  snapshots.set(token, owned(snapshot));
  return token;
}
function same02(a: Identity02, b: Identity02): boolean {
  return a.generation === b.generation && a.version === b.version && same(a.accountId, b.accountId)
    && same(a.digest, b.digest) && same(a.rootPoint, b.rootPoint);
}
function sameTrust(a: ManifestTrust02, b: ManifestTrust02): boolean {
  return same02(a, b) && same(a.anchorDigest, b.anchorDigest);
}
function identityBinding(value: Snapshot, prior: Identity02): void {
  if (value.generation !== prior.generation || !same(value.accountId, prior.accountId)
      || !same(value.rootPoint, prior.rootPoint)) fail("predecessor identity mismatch");
}
function successor(value: Snapshot, prior: Identity02, profile: 2 | 3): void {
  identityBinding(value, prior);
  if (prior.version === maxSigned || value.version !== prior.version + 1n
      || value.predecessorProfile !== profile || !same(value.previousDigest, prior.digest)) fail("successor chain or overflow");
}

async function parse(bytes: Uint8Array, anchorDigest: Uint8Array, now: bigint): Promise<Snapshot> {
  if (!same(bytes.subarray(0, 6), Uint8Array.of(0x5a, 0x54, 0x4d, 0x41, 3, 3))) fail("magic/profile");
  const predecessorProfile = bytes[6];
  if (predecessorProfile !== 2 && predecessorProfile !== 3) fail("unsupported predecessor/genesis");
  const count = bytes[152];
  if (count < 1 || count > 64 || bytes.length !== 217 + 149 * count) fail("count or exact size");
  const view = new DataView(bytes.buffer);
  const accountId = bytes.subarray(7, 23), generation = u64(view, 23), version = u64(view, 31);
  const issuedMs = u64(view, 39), expiresMs = u64(view, 47);
  const previousDigest = bytes.subarray(55, 87), rootPoint = bytes.subarray(87, 152);
  if (same(accountId, zero16) || generation !== 1n || version < 1n) fail("unsupported identity/generation/version");
  window(issuedMs, expiresMs, now);
  const rootKey = await pointKey(rootPoint);
  const keys: Key03[] = [], seen = new Set<string>();
  let roots = 0, archives = 0;
  for (let i = 0; i < count; i++) {
    const at = 153 + 149 * i, role = bytes[at];
    const keyId = bytes.subarray(at + 1, at + 33), point = bytes.subarray(at + 33, at + 98);
    const deviceId = bytes.subarray(at + 98, at + 114), lineId = bytes.subarray(at + 114, at + 130);
    const keyScope = view.getUint16(at + 130, false);
    const fromMs = u64(view, at + 132), untilMs = u64(view, at + 140), state = bytes[at + 148];
    scope(role, keyScope, deviceId, lineId);
    if (fromMs > untilMs || state !== 1 && state !== 2) fail("key validity/state");
    if (i && (role < keys[i - 1].role || role === keys[i - 1].role && compare(keyId, keys[i - 1].keyId) <= 0)) fail("record order");
    await pointKey(point);
    const algorithm = role <= 3 ? Uint8Array.of(0, 0x10) : Uint8Array.of(1, 1);
    if (!same(keyId, await sha(concat(enc.encode("ZTSE/key/v1\0"), algorithm, point)))) fail("key id");
    const pointHex = Array.from(point, b => b.toString(16).padStart(2, "0")).join("");
    if (seen.has(pointHex)) fail("point reused");
    seen.add(pointHex);
    if (role === 6) {
      roots++;
      if (!same(point, rootPoint) || state !== 1 || fromMs > issuedMs || untilMs < expiresMs) fail("owner root record");
    }
    if (role === 2 && state === 1) archives++;
    keys.push({ role, keyId, point, deviceId, lineId, scope: keyScope, fromMs, untilMs, state });
  }
  if (roots !== 1 || archives !== 1) fail("owner/archive cardinality");
  const unsigned = bytes.subarray(0, bytes.length - 64), signature = bytes.subarray(bytes.length - 64);
  strictSignature(signature);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, unsigned.length, false);
  const transcript = concat(enc.encode("ZTSE/manifest/v3\0"), length, unsigned);
  if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, rootKey, ab(signature), ab(transcript))) fail("signature verification");
  return { profile: 3, predecessorProfile, accountId, generation, version, issuedMs, expiresMs,
    comparisonMs: now, digest: await sha(unsigned), rootPoint, previousDigest, anchorDigest, keys, bytes };
}

/** Fresh02 semantic evidence only: the old private signed bytes/comparison time
 * are inaccessible. Supplied evidence is independently reverified; this cannot
 * prove original evidence, full genesis lineage or clock nonregression versus02.
 * Expired02 and rotated/later-generation02 upgrades are unsupported. */
export async function verifyManifest03From02(input: Uint8Array, predecessor: Manifest02,
  predecessorSignedBytes: Uint8Array, comparisonMs: bigint): Promise<VerifiedManifest03> {
  comparison(comparisonMs);
  const bytes = capture(input, 366, 9753), signed02 = capture(predecessorSignedBytes, 364, 9751);
  const identity = verifiedManifestIdentity02(predecessor, comparisonMs);
  const trust = verifiedManifestTrust02(predecessor, comparisonMs);
  if (!same02(identity, trust) || identity.generation !== 1n || identity.version < 1n
      || identity.version > maxSigned || !same(trust.anchorDigest, zero32)) fail("unsupported02 identity/anchor");
  const supplied = await verifyManifest02(signed02, trust, comparisonMs);
  if (!same02(identity, verifiedManifestIdentity02(supplied, comparisonMs))
      || !sameTrust(trust, verifiedManifestTrust02(supplied, comparisonMs))) fail("supplied02 semantic mismatch");
  const value = await parse(bytes, trust.anchorDigest, comparisonMs);
  successor(value, identity, 2);
  return accept(value);
}

/** Pure historical-chain continuation, including an expired prior03 token.
 * Only the newly signed successor must be fresh. No old reader is revived.
 * Concurrent valid successors require the caller's durable atomic selection. */
export async function verifyManifest03Successor(input: Uint8Array, predecessor: VerifiedManifest03,
  comparisonMs: bigint): Promise<VerifiedManifest03> {
  comparison(comparisonMs);
  const bytes = capture(input, 366, 9753), prior = bound(predecessor, comparisonMs);
  const value = await parse(bytes, prior.anchorDigest, comparisonMs);
  successor(value, prior, 3);
  return accept(value);
}

/** Semantic currentness relative to this token only, never live durable authority.
 * Alternate valid signatures neither replace old evidence nor establish exact
 * transport replay. Always verify the received signature, even at the same digest. */
export async function verifyManifest03Current(input: Uint8Array, current: VerifiedManifest03,
  comparisonMs: bigint): Promise<VerifiedManifest03> {
  comparison(comparisonMs);
  const bytes = capture(input, 366, 9753), prior = bound(current, comparisonMs);
  const value = await parse(bytes, prior.anchorDigest, comparisonMs);
  identityBinding(value, prior);
  if (value.version !== prior.version || value.predecessorProfile !== prior.predecessorProfile
      || !same(value.digest, prior.digest)) fail("current identity fork/rollback");
  return accept(value);
}

/** Owned public metadata, not an authority context. comparisonMs in the returned
 * identity is the token's ORIGINAL verification comparison time. This accessor
 * validates laterComparisonMs but never updates that snapshot or any clock. */
export function verifiedManifestIdentity03(accepted: VerifiedManifest03, laterComparisonMs: bigint): ManifestIdentity03 {
  comparison(laterComparisonMs);
  const value = bound(accepted, laterComparisonMs);
  window(value.issuedMs, value.expiresMs, laterComparisonMs);
  return { profile: 3, predecessorProfile: value.predecessorProfile, accountId: copy(value.accountId),
    generation: value.generation, version: value.version, digest: copy(value.digest),
    rootPoint: copy(value.rootPoint), issuedMs: value.issuedMs, expiresMs: value.expiresMs,
    comparisonMs: value.comparisonMs };
}

/** Public-key authorization only. Durable current selection and permission are
 * independent inputs to the composer, never inferred from this private token. */
export function authorizeOutbound03(accepted: VerifiedManifest03, claims: Readonly<{
  accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array;
  generation: bigint; version: bigint; digest: Uint8Array; signerKeyId: Uint8Array;
  wraps: readonly Readonly<{ role: number; keyId: Uint8Array }>[];
}>, nowMs: bigint): Readonly<{
  signerPoint: Uint8Array; validFromMs: bigint; expiresMs: bigint;
  recipients: readonly Readonly<{ role: 1 | 2 | 3; keyId: Uint8Array; point: Uint8Array }>[];
}> {
  comparison(nowMs);
  const value = bound(accepted, nowMs);
  window(value.issuedMs, value.expiresMs, nowMs);
  const account = capture(claims.accountId, 16, 16), device = capture(claims.deviceId, 16, 16);
  const line = capture(claims.lineId, 16, 16), digest = capture(claims.digest, 32, 32);
  const signerId = capture(claims.signerKeyId, 32, 32);
  if (same(account, zero16) || same(device, zero16) || same(line, zero16)
      || !same(account, value.accountId) || claims.generation !== value.generation
      || claims.version !== value.version || !same(digest, value.digest)) fail("outbound manifest binding");
  const active = (key: Key03) => key.state === 1 && key.fromMs <= nowMs && nowMs < key.untilMs;
  const signer = value.keys.find(k => k.role === 5 && same(k.keyId, signerId));
  if (!signer || !active(signer) || signer.scope !== 1 || !same(signer.lineId, line)) fail("outbound signer authority");
  const requested = claims.wraps, count = requested?.length;
  if (!Array.isArray(requested) || typeof count !== "number" || !Number.isInteger(count) || count < 2 || count > 8) fail("outbound reader count");
  let devices = 0, archives = 0, integrations = 0;
  let expiresMs = value.expiresMs < signer.untilMs ? value.expiresMs : signer.untilMs;
  let validFromMs = signer.fromMs;
  const seen = new Set<string>();
  const recipients: { role: 1 | 2 | 3; keyId: Uint8Array; point: Uint8Array }[] = [];
  for (let i = 0; i < count; i++) {
    const w = requested[i];
    const id = capture(w.keyId, 32, 32), role = w.role;
    if (role !== 1 && role !== 2 && role !== 3) fail("outbound reader role");
    const identity = `${role}:${Array.from(id).join(",")}`;
    if (seen.has(identity)) fail("outbound duplicate reader");
    seen.add(identity);
    const key = value.keys.find(k => k.role === role && same(k.keyId, id));
    if (!key || !active(key) || !(key.scope & 4)) fail("outbound reader authority");
    if (role === 1) {
      if (!same(key.deviceId, device) || !same(key.lineId, line)) fail("outbound selected device/line");
      devices++;
    } else if (role === 2) archives++;
    else integrations++;
    if (key.untilMs < expiresMs) expiresMs = key.untilMs;
    if (key.fromMs > validFromMs) validFromMs = key.fromMs;
    recipients.push({ role, keyId: copy(id), point: copy(key.point) });
  }
  if (devices !== 1 || archives !== 1 || integrations > 6) fail("outbound reader set");
  return { signerPoint: copy(signer.point), validFromMs, expiresMs, recipients };
}

/** Public-key policy for type2 content. This verifies the selected manifest
 * signer/readers only; capture identity, current permission, physical custody
 * and durable one-use admission remain independent adapter obligations. */
export function authorizeInbound03(accepted: VerifiedManifest03, claims: Readonly<{
  accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array;
  generation: bigint; version: bigint; digest: Uint8Array; signerKeyId: Uint8Array;
  wraps: readonly Readonly<{ role: number; keyId: Uint8Array }>[];
}>, nowMs: bigint): Readonly<{
  signerPoint: Uint8Array; validFromMs: bigint; expiresMs: bigint;
  recipients: readonly Readonly<{ role: 2 | 3; keyId: Uint8Array; point: Uint8Array }>[];
}> {
  comparison(nowMs);
  const value = bound(accepted, nowMs);
  window(value.issuedMs, value.expiresMs, nowMs);
  const account = capture(claims.accountId, 16, 16), device = capture(claims.deviceId, 16, 16);
  const line = capture(claims.lineId, 16, 16), digest = capture(claims.digest, 32, 32);
  const signerId = capture(claims.signerKeyId, 32, 32);
  if (same(account, zero16) || same(device, zero16) || same(line, zero16)
      || !same(account, value.accountId) || claims.generation !== value.generation
      || claims.version !== value.version || !same(digest, value.digest)) fail("inbound manifest binding");
  const active = (key: Key03) => key.state === 1 && key.fromMs <= nowMs && nowMs < key.untilMs;
  const signer = value.keys.find(k => k.role === 4 && same(k.keyId, signerId));
  if (!signer || !active(signer) || signer.scope !== 2 || !same(signer.deviceId, device)
      || !same(signer.lineId, line)) fail("inbound signer authority");
  const requested = claims.wraps;
  if (!Array.isArray(requested) || requested.length < 1 || requested.length > 7) fail("inbound reader count");
  let archives = 0, validFromMs = signer.fromMs;
  let expiresMs = value.expiresMs < signer.untilMs ? value.expiresMs : signer.untilMs;
  const seen = new Set<string>(), recipients: { role: 2 | 3; keyId: Uint8Array; point: Uint8Array }[] = [];
  for (const w of requested) {
    const id = capture(w.keyId, 32, 32), role = w.role;
    if (role !== 2 && role !== 3) fail("inbound reader role");
    const identity = `${role}:${Array.from(id).join(",")}`;
    if (seen.has(identity)) fail("inbound duplicate reader");
    seen.add(identity);
    const key = value.keys.find(k => k.role === role && same(k.keyId, id));
    if (!key || !active(key) || !(key.scope & 8)) fail("inbound reader authority");
    if (role === 2) archives++;
    if (key.fromMs > validFromMs) validFromMs = key.fromMs;
    if (key.untilMs < expiresMs) expiresMs = key.untilMs;
    recipients.push({ role, keyId: copy(id), point: copy(key.point) });
  }
  if (archives !== 1) fail("inbound reader set");
  return { signerPoint: copy(signer.point), validFromMs, expiresMs, recipients };
}
