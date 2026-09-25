/** Experimental profile-02 trust candidate. Not connected to a production route. */

const enc = new TextEncoder();
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const maxSigned = (1n << 63n) - 1n;
const dayMs = 86_400_000n;
const skewMs = 300_000n;
const zero32 = new Uint8Array(32);
const zero16 = new Uint8Array(16);

export const DRAFT02_MAX_MANIFEST_AGE_MS = dayMs;
export const DRAFT02_CLOCK_SKEW_MS = skewMs;

export type ManifestKey02 = Readonly<{
  role: number; keyId: Uint8Array; point: Uint8Array; deviceId: Uint8Array;
  lineId: Uint8Array; scope: number; fromMs: bigint; untilMs: bigint; state: number;
}>;
export type Manifest02 = Readonly<{
  bytes: Uint8Array; digest: Uint8Array; accountId: Uint8Array; generation: bigint;
  version: bigint; issuedMs: bigint; expiresMs: bigint; previousDigest: Uint8Array;
  rootPoint: Uint8Array; keys: readonly ManifestKey02[];
}>;
/** This state must originate in an authenticated owner-root comparison, never a directory response. */
export type ManifestTrust02 = Readonly<{
  accountId: Uint8Array; generation: bigint; rootPoint: Uint8Array;
  version: bigint; digest: Uint8Array; anchorDigest: Uint8Array;
}>;

type VerifiedSnapshot = Readonly<{ before: ManifestTrust02; after: ManifestTrust02; authority: Manifest02 }>;
const verifiedSnapshots = new WeakMap<Manifest02, VerifiedSnapshot>();
function copyTrust(pin: ManifestTrust02): ManifestTrust02 {
  return { accountId: Uint8Array.from(pin.accountId), generation: pin.generation,
    rootPoint: Uint8Array.from(pin.rootPoint), version: pin.version,
    digest: Uint8Array.from(pin.digest), anchorDigest: Uint8Array.from(pin.anchorDigest) };
}
function copyManifest(value: Manifest02): Manifest02 {
  return { ...value, bytes: Uint8Array.from(value.bytes), digest: Uint8Array.from(value.digest),
    accountId: Uint8Array.from(value.accountId), previousDigest: Uint8Array.from(value.previousDigest),
    rootPoint: Uint8Array.from(value.rootPoint), keys: value.keys.map((key) => ({ ...key,
      keyId: Uint8Array.from(key.keyId), point: Uint8Array.from(key.point),
      deviceId: Uint8Array.from(key.deviceId), lineId: Uint8Array.from(key.lineId) })) };
}

function fail(why: string): never { throw new Error(`ZTSE draft-02 manifest: ${why}`); }
function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}
function u32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}
function u64(view: DataView, at: number): bigint {
  const n = view.getBigUint64(at, false);
  if (n > maxSigned) fail("u64 exceeds signed storage range");
  return n;
}
function scalar(bytes: Uint8Array): bigint {
  return bytes.reduce((n, b) => (n << 8n) | BigInt(b), 0n);
}
function fixed32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(n & 255n); n >>= 8n; }
  return out;
}
export function canonicalSignature02(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) fail("signature width");
  const r = scalar(raw.subarray(0, 32));
  const s = scalar(raw.subarray(32));
  if (r === 0n || r >= order || s === 0n || s >= order) fail("signature scalar range");
  return concat(fixed32(r), fixed32(s > (order >> 1n) ? order - s : s));
}
function requireLowS(raw: Uint8Array): void {
  if (!same(raw, canonicalSignature02(raw))) fail("high-s signature");
}
function transcript(label: string, unsigned: Uint8Array): Uint8Array {
  return concat(enc.encode(`${label}\0`), u32(unsigned.length), unsigned);
}
function ab(bytes: Uint8Array): ArrayBuffer { return Uint8Array.from(bytes).buffer; }
async function digest(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", ab(bytes)));
}
async function pointKey(point: Uint8Array): Promise<CryptoKey> {
  if (point.length !== 65 || point[0] !== 4) fail("point shape");
  try { return await crypto.subtle.importKey("raw", ab(point), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]); }
  catch { return fail("point curve"); }
}
async function verify(point: Uint8Array, signature: Uint8Array, label: string, unsigned: Uint8Array): Promise<void> {
  requireLowS(signature);
  const key = await pointKey(point);
  const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, ab(signature), ab(transcript(label, unsigned)));
  if (!ok) fail("signature verification");
}
async function keyId(role: number, point: Uint8Array): Promise<Uint8Array> {
  const algorithm = role <= 3 ? Uint8Array.of(0, 0x10) : Uint8Array.of(1, 1);
  return digest(concat(enc.encode("ZTSE/key/v1\0"), algorithm, point));
}

/** The fingerprint must have arrived by an independently authenticated owner channel. */
export async function enrollRootPin02(input: Uint8Array, comparedFingerprint: Uint8Array): Promise<ManifestTrust02> {
  if (input.length !== 94 || comparedFingerprint.length !== 32) fail("root pin size");
  const bytes = Uint8Array.from(input);
  if (!same(bytes.subarray(0, 5), Uint8Array.of(0x5a, 0x54, 0x52, 0x50, 2))) fail("root pin magic/profile");
  const accountId = bytes.subarray(5, 21);
  const generation = u64(new DataView(bytes.buffer), 21);
  const rootPoint = bytes.subarray(29, 94);
  if (same(accountId, zero16) || generation !== 1n) fail("root pin identity/generation");
  await pointKey(rootPoint);
  const fingerprint = await digest(concat(enc.encode("ZTSE/root-pin/v2\0"), bytes));
  if (!same(fingerprint, comparedFingerprint)) fail("root pin comparison");
  return { accountId: Uint8Array.from(accountId), generation, rootPoint: Uint8Array.from(rootPoint),
    version: 0n, digest: Uint8Array.from(zero32), anchorDigest: Uint8Array.from(zero32) };
}
function roleScope(role: number, scope: number, device: Uint8Array, line: Uint8Array): void {
  if (role < 1 || role > 6) fail("unknown role");
  const valid = [0, 4, 12, 4, 2, 1, 0][role];
  if (role === 3 ? ![4, 8, 12].includes(scope) : scope !== valid) fail("role/scope");
  const deviceBound = role === 1 || role === 4;
  const lineBound = deviceBound || role === 5;
  if (deviceBound ? same(device, zero16) : !same(device, zero16)) fail("role/subject");
  if (lineBound ? same(line, zero16) : !same(line, zero16)) fail("role/subject");
}
function timeWindow(issued: bigint, expires: bigint, now: bigint): void {
  if (issued <= 0n || expires <= issued || expires - issued > dayMs) fail("signed validity window");
  if (issued > now + skewMs || now >= expires) fail("stale or future signed object");
}

/** Syntax, point, key-ID, owner signature, pin, chain, and freshness validation. */
export async function verifyManifest02(input: Uint8Array, pin: ManifestTrust02, nowMs: bigint): Promise<Manifest02> {
  const trustedPin = copyTrust(pin);
  if (input.length < 364 || input.length > 9751) fail("size");
  const bytes = Uint8Array.from(input);
  if (!same(bytes.subarray(0, 5), Uint8Array.of(0x5a, 0x54, 0x4d, 0x41, 2))) fail("magic/profile");
  const count = bytes[150];
  if (count < 1 || count > 64 || bytes.length !== 215 + 149 * count) fail("count or exact size");
  const view = new DataView(bytes.buffer);
  const accountId = bytes.subarray(5, 21);
  const generation = u64(view, 21);
  const version = u64(view, 29);
  const issuedMs = u64(view, 37);
  const expiresMs = u64(view, 45);
  const previousDigest = bytes.subarray(53, 85);
  const rootPoint = bytes.subarray(85, 150);
  if (generation === 0n || version === 0n || same(accountId, zero16)) fail("identity/version");
  if (!same(accountId, trustedPin.accountId) || generation !== trustedPin.generation || !same(rootPoint, trustedPin.rootPoint)) fail("pin mismatch");
  timeWindow(issuedMs, expiresMs, nowMs);
  await pointKey(rootPoint);
  const keys: ManifestKey02[] = [];
  const seenPoints = new Set<string>();
  let ownerCount = 0;
  let archiveCount = 0;
  for (let i = 0; i < count; i++) {
    const at = 151 + i * 149;
    const role = bytes[at];
    const id = bytes.subarray(at + 1, at + 33);
    const point = bytes.subarray(at + 33, at + 98);
    const deviceId = bytes.subarray(at + 98, at + 114);
    const lineId = bytes.subarray(at + 114, at + 130);
    const scope = view.getUint16(at + 130, false);
    const fromMs = u64(view, at + 132);
    const untilMs = u64(view, at + 140);
    const state = bytes[at + 148];
    roleScope(role, scope, deviceId, lineId);
    if (fromMs > untilMs || state !== 1 && state !== 2) fail("key validity/state");
    if (i && (role < keys[i - 1].role || role === keys[i - 1].role && compare(id, keys[i - 1].keyId) <= 0)) fail("record order");
    await pointKey(point);
    if (!same(id, await keyId(role, point))) fail("key id");
    const pointHex = Array.from(point, (b) => b.toString(16).padStart(2, "0")).join("");
    if (seenPoints.has(pointHex)) fail("point reused across roles");
    seenPoints.add(pointHex);
    if (role === 6) {
      ownerCount++;
      if (!same(point, rootPoint) || state !== 1 || fromMs > issuedMs || untilMs < expiresMs) fail("owner root record");
    }
    if (role === 2 && state === 1) archiveCount++;
    keys.push({ role, keyId: id, point, deviceId, lineId, scope, fromMs, untilMs, state });
  }
  if (ownerCount !== 1 || archiveCount !== 1) fail("owner/archive cardinality");
  const signature = bytes.subarray(bytes.length - 64);
  await verify(rootPoint, signature, "ZTSE/manifest/v2", bytes.subarray(0, bytes.length - 64));
  // Signature randomness and the valid (r, n-s) twin must not change keyset identity.
  const manifestDigest = await digest(bytes.subarray(0, bytes.length - 64));
  if (trustedPin.version === 0n) {
    if (version !== 1n || !same(previousDigest, trustedPin.anchorDigest)) fail("genesis/transition chain");
  } else if (version === trustedPin.version && same(manifestDigest, trustedPin.digest)) {
    // Distinct valid signatures over the same unsigned fields are the same keyset.
  } else if (version !== trustedPin.version + 1n || !same(previousDigest, trustedPin.digest)) {
    fail("rollback, fork, or chain gap");
  }
  const accepted: Manifest02 = { bytes, digest: manifestDigest, accountId, generation, version,
    issuedMs, expiresMs, previousDigest, rootPoint, keys };
  verifiedSnapshots.set(accepted, { before: trustedPin,
    after: { ...copyTrust(trustedPin), version, digest: Uint8Array.from(manifestDigest) },
    authority: copyManifest(accepted) });
  return accepted;
}

function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

/** Persist this new high-water atomically before accepting envelope effects. */
export function advanceManifestTrust02(pin: ManifestTrust02, accepted: Manifest02): ManifestTrust02 {
  const snapshot = verifiedSnapshots.get(accepted);
  if (!snapshot) fail("advance requires a just-verified manifest");
  const before = snapshot.before;
  if (!same(pin.accountId, before.accountId) || pin.generation !== before.generation ||
      !same(pin.rootPoint, before.rootPoint) || pin.version !== before.version ||
      !same(pin.digest, before.digest) || !same(pin.anchorDigest, before.anchorDigest)) fail("advance pin mismatch");
  return copyTrust(snapshot.after);
}

/** Both old and new roots sign the same exact 215-byte transition body. */
export async function verifyRootTransition02(input: Uint8Array, pin: ManifestTrust02, nowMs: bigint, expectedNewRoot: Uint8Array): Promise<ManifestTrust02> {
  const trustedPin = copyTrust(pin);
  const comparedNewRoot = Uint8Array.from(expectedNewRoot);
  if (input.length !== 343) fail("transition size");
  const bytes = Uint8Array.from(input);
  if (!same(bytes.subarray(0, 5), Uint8Array.of(0x5a, 0x54, 0x52, 0x54, 2))) fail("transition magic/profile");
  const view = new DataView(bytes.buffer);
  const account = bytes.subarray(5, 21);
  const oldGeneration = u64(view, 21);
  const newGeneration = u64(view, 29);
  const oldRoot = bytes.subarray(37, 102);
  const newRoot = bytes.subarray(102, 167);
  const lastDigest = bytes.subarray(167, 199);
  const issued = u64(view, 199);
  const expires = u64(view, 207);
  if (trustedPin.version === 0n || !same(account, trustedPin.accountId) || oldGeneration !== trustedPin.generation ||
      newGeneration !== oldGeneration + 1n || !same(oldRoot, trustedPin.rootPoint) ||
      !same(newRoot, comparedNewRoot) || same(newRoot, oldRoot) || !same(lastDigest, trustedPin.digest)) fail("transition pin/chain");
  timeWindow(issued, expires, nowMs);
  const unsigned = bytes.subarray(0, 215);
  await verify(oldRoot, bytes.subarray(215, 279), "ZTSE/root-transition/v2", unsigned);
  await verify(newRoot, bytes.subarray(279, 343), "ZTSE/root-transition/v2", unsigned);
  return { accountId: Uint8Array.from(account), generation: newGeneration, rootPoint: Uint8Array.from(newRoot),
    version: 0n, digest: Uint8Array.from(zero32), anchorDigest: await digest(unsigned) };
}

/** Call only after exact profile-02 envelope signature verification. */
export function authorizeOutbound02(manifest: Manifest02, claims: {
  accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array; manifestDigest: Uint8Array;
  keysetVersion: bigint; signerKeyId: Uint8Array; wraps: readonly { role: number; keyId: Uint8Array }[];
}, nowMs: bigint): void {
  const bound = verifiedSnapshots.get(manifest)?.authority;
  if (!bound) fail("authorization requires a just-verified manifest");
  timeWindow(bound.issuedMs, bound.expiresMs, nowMs);
  if (!same(claims.accountId, bound.accountId) || !same(claims.manifestDigest, bound.digest) ||
      claims.keysetVersion !== bound.version || nowMs >= bound.expiresMs) fail("envelope manifest binding");
  const active = (key: ManifestKey02): boolean => key.state === 1 && key.fromMs <= nowMs && nowMs < key.untilMs;
  const signer = bound.keys.find((key) => key.role === 5 && same(key.keyId, claims.signerKeyId));
  if (!signer || !active(signer) || signer.scope !== 1 ||
      !same(signer.lineId, claims.lineId)) fail("outbound signer authority");
  let deviceCount = 0;
  let archiveCount = 0;
  let integrationCount = 0;
  for (const wrap of claims.wraps) {
    const key = bound.keys.find((candidate) => candidate.role === wrap.role && same(candidate.keyId, wrap.keyId));
    if (!key || !active(key) || !(key.scope & 4)) fail("reader authority");
    if (wrap.role === 1) {
      if (!same(key.deviceId, claims.deviceId) || !same(key.lineId, claims.lineId)) fail("selected device/line");
      deviceCount++;
    } else if (wrap.role === 2) archiveCount++;
    else if (wrap.role === 3) integrationCount++;
    else fail("reader role");
  }
  if (deviceCount !== 1 || archiveCount !== 1 || integrationCount > 6 ||
      new Set(claims.wraps.map((w) => `${w.role}:${Array.from(w.keyId).join(",")}`)).size !== claims.wraps.length) fail("reader set");
}

/**
 * Test-only inbound role check after exact profile-02 envelope signature verification.
 * This does not verify a phone's SMS observation, durable sequence/replay state,
 * live line binding, or the accepted inbound age window.
 */
export function authorizeInbound02(manifest: Manifest02, claims: {
  kind: 2; accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array;
  messageId: Uint8Array; eventId: Uint8Array; localSequence: bigint;
  manifestDigest: Uint8Array; keysetVersion: bigint; signerKeyId: Uint8Array;
  wraps: readonly { role: number; keyId: Uint8Array }[];
}, nowMs: bigint): void {
  const bound = verifiedSnapshots.get(manifest)?.authority;
  if (!bound) fail("authorization requires a just-verified manifest");
  timeWindow(bound.issuedMs, bound.expiresMs, nowMs);
  if (!same(claims.accountId, bound.accountId) || !same(claims.manifestDigest, bound.digest) ||
      claims.keysetVersion !== bound.version) fail("envelope manifest binding");
  if (claims.kind !== 2 || claims.messageId.length !== 16 || claims.eventId.length !== 16 ||
      !same(claims.messageId, claims.eventId) ||
      claims.localSequence < 1n || claims.localSequence > maxSigned) fail("inbound identity/sequence");
  const active = (key: ManifestKey02): boolean => key.state === 1 && key.fromMs <= nowMs && nowMs < key.untilMs;
  const signer = bound.keys.find((key) => key.role === 4 && same(key.keyId, claims.signerKeyId));
  if (!signer || !active(signer) || signer.scope !== 2 ||
      !same(signer.deviceId, claims.deviceId) || !same(signer.lineId, claims.lineId)) {
    fail("inbound signer authority");
  }
  let archiveCount = 0;
  let integrationCount = 0;
  for (const wrap of claims.wraps) {
    const key = bound.keys.find((candidate) => candidate.role === wrap.role && same(candidate.keyId, wrap.keyId));
    if (!key || !active(key) || !(key.scope & 8)) fail("inbound reader authority");
    if (wrap.role === 2) archiveCount++;
    else if (wrap.role === 3) integrationCount++;
    else fail("inbound reader role");
  }
  if (archiveCount !== 1 || integrationCount > 6 ||
      new Set(claims.wraps.map((w) => `${w.role}:${Array.from(w.keyId).join(",")}`)).size !== claims.wraps.length) {
    fail("inbound reader set");
  }
}
