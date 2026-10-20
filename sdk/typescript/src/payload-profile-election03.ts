/** Cryptographic election proof relative to independently authenticated durable
 * adapter records. No live backend reader, commit, session/MFA or CAS is supplied.
 * Historical acceptance never renews present permission or replaces evidence. */
import { isCanonicalP256Signature, keyId } from "./draft01.js";
import { verifiedManifestIdentity02, type Manifest02 } from "./draft02-manifest.js";
import { verifyManifest03From02, verifiedManifestIdentity03, type VerifiedManifest03 } from "./draft03-manifest.js";

export type DurableAcceptedElection03 = Readonly<{
  accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array;
  rootFingerprint: Uint8Array; vaultGeneration: bigint;
  oldBindingId: Uint8Array; oldBindingGeneration: bigint; oldBindingProofDigest: Uint8Array;
  newBindingId: Uint8Array; newBindingGeneration: bigint; selectedReaderKeyId: Uint8Array;
  priorManifestVersion: bigint; priorManifestDigest: Uint8Array; priorSignedManifestSha256: Uint8Array;
  acceptedManifestVersion: bigint; acceptedManifestDigest: Uint8Array; acceptedSignedManifestSha256: Uint8Array;
  electionCoreSha256: Uint8Array; electionCommitment: Uint8Array; electionBundleSha256: Uint8Array;
  acceptedAtMs: bigint;
}>;
/** Trusted PRESENT read, not received proof fields echoed back. Its origin,
 * durable chain/binding selection and live permission are adapter obligations. */
export type CurrentElectionAuthority03 = Readonly<{
  profile: 3; manifestProfile: 3;
  accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array;
  bindingId: Uint8Array; bindingGeneration: bigint; selectedReaderKeyId: Uint8Array;
  rootFingerprint: Uint8Array; vaultGeneration: bigint; manifestVersion: bigint; manifestDigest: Uint8Array;
  electionCommitment: Uint8Array; electionBundleSha256: Uint8Array;
  comparedAtMs: bigint; permissionExpiresAtMs: bigint;
}>;
declare const proofBrand: unique symbol;
export type VerifiedAcceptedElection03 = Readonly<{ [proofBrand]: true }>;
type Proof = Readonly<{ accepted: DurableAcceptedElection03; rootPoint: Uint8Array }>;
const proofs = new WeakMap<VerifiedAcceptedElection03, Proof>();
const enc = new TextEncoder(), max = (1n << 63n) - 1n;
const u8 = Uint8Array.prototype, arrayBuffer = ArrayBuffer.prototype;
const getPrototype = Object.getPrototypeOf, typed = getPrototype(u8);
const kind = Object.getOwnPropertyDescriptor(typed, Symbol.toStringTag)!.get!;
const storage = Object.getOwnPropertyDescriptor(typed, "buffer")!.get!;
const length = Object.getOwnPropertyDescriptor(typed, "byteLength")!.get!;
const ordinaryLength = Object.getOwnPropertyDescriptor(arrayBuffer, "byteLength")!.get!;
const set = u8.set;
function fail(why: string): never { throw new Error(`ZTSE election03: ${why}`); }
/** Intrinsic brands plus exact local prototypes, not allocation-history proof.
 * Copies without caller iterators/getters; shared and disguised element kinds refuse. */
export function captureElectionBytes03(value: Uint8Array, min: number, upper = min): Uint8Array {
  try {
    if (getPrototype(value) !== u8 || Reflect.apply(kind, value, []) !== "Uint8Array") fail("byte kind");
    const backing = Reflect.apply(storage, value, []);
    if (getPrototype(backing) !== arrayBuffer) fail("byte storage");
    Reflect.apply(ordinaryLength, backing, []);
    const n = Reflect.apply(length, value, []) as number;
    if (n < min || n > upper) fail("byte bounds");
    const copy = new Uint8Array(n); Reflect.apply(set, copy, [value]); return copy;
  } catch { return fail("unsupported byte input"); }
}
export function electionTime03(value: bigint): void {
  if (typeof value !== "bigint" || value < 1n || value > max) fail("integer type/range");
}
function same(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((v, i) => v === b[i]); }
function nonzero(a: Uint8Array): boolean { return a.some(v => v !== 0); }
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; } return out;
}
function buffer(a: Uint8Array): ArrayBuffer { return Uint8Array.from(a).buffer; }
async function sha(a: Uint8Array): Promise<Uint8Array> { return new Uint8Array(await crypto.subtle.digest("SHA-256", buffer(a))); }
function framed(label: string, payload: Uint8Array): Uint8Array {
  const n = new Uint8Array(4); new DataView(n.buffer).setUint32(0, payload.length, false);
  return concat(enc.encode(label + "\0"), n, payload);
}
async function verify(point: Uint8Array, signature: Uint8Array, transcript: Uint8Array): Promise<void> {
  if (!isCanonicalP256Signature(signature) || point[0] !== 4) fail("signature/point shape");
  const key = await crypto.subtle.importKey("raw", buffer(point), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, buffer(signature), buffer(transcript))) fail("signature verification");
}
const acceptedUuids = ["accountId", "deviceId", "lineId", "oldBindingId", "newBindingId"] as const;
const acceptedTimes = ["vaultGeneration", "oldBindingGeneration", "newBindingGeneration", "priorManifestVersion", "acceptedManifestVersion", "acceptedAtMs"] as const;
const acceptedDigests = ["rootFingerprint", "oldBindingProofDigest", "selectedReaderKeyId", "priorManifestDigest", "priorSignedManifestSha256", "acceptedManifestDigest", "acceptedSignedManifestSha256", "electionCoreSha256", "electionCommitment", "electionBundleSha256"] as const;
const currentUuids = ["accountId", "deviceId", "lineId", "bindingId"] as const;
const currentTimes = ["bindingGeneration", "vaultGeneration", "manifestVersion", "comparedAtMs", "permissionExpiresAtMs"] as const;
const currentDigests = ["selectedReaderKeyId", "rootFingerprint", "manifestDigest", "electionCommitment", "electionBundleSha256"] as const;
function closedRecord(value: object, names: readonly string[]): Record<string, unknown> {
  if (value === null || getPrototype(value) !== Object.prototype) fail("record type");
  const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(descriptors);
  if (keys.length !== names.length || keys.some(k => typeof k !== "string" || !names.includes(k))) fail("closed record fields");
  const out: Record<string, unknown> = {};
  for (const n of names) {
    const d = descriptors[n]; if (!d || !("value" in d)) fail("record accessor"); out[n] = d.value;
  }
  return out;
}
function record(value: object, uuids: readonly string[], times: readonly string[], digests: readonly string[], extra: readonly string[] = []): Record<string, unknown> {
  const out = closedRecord(value, [...uuids, ...times, ...digests, ...extra]);
  for (const n of [...uuids, ...digests]) {
    out[n] = captureElectionBytes03(out[n] as Uint8Array, uuids.includes(n) ? 16 : 32);
    if (!nonzero(out[n] as Uint8Array)) fail("zero identity/digest");
  }
  for (const n of times) electionTime03(out[n] as bigint);
  return out;
}
function accepted(value: DurableAcceptedElection03): DurableAcceptedElection03 {
  return record(value, acceptedUuids, acceptedTimes, acceptedDigests) as DurableAcceptedElection03;
}
/** Capture a trusted adapter tuple before any asynchronous caller work. */
export function captureCurrentElectionAuthority03(value: CurrentElectionAuthority03): CurrentElectionAuthority03 {
  const out = record(value, currentUuids, currentTimes, currentDigests, ["profile", "manifestProfile"]);
  if (out.profile !== 3 || out.manifestProfile !== 3 || (out.permissionExpiresAtMs as bigint) <= (out.comparedAtMs as bigint)) fail("current profile/deadline");
  return out as CurrentElectionAuthority03;
}

/** Historical crypto only. acceptedAt and exact original evidence must originate
 * in an authenticated immutable committed record; this helper cannot prove that
 * provenance, old session/MFA, original02 clock or durable fork selection. */
export async function verifyAcceptedPayloadProfileElection03(input: Readonly<{
  bundle: Uint8Array; expectedCore: Uint8Array; acceptedRecord: DurableAcceptedElection03;
  predecessor02: Manifest02; priorSignedManifest02: Uint8Array; acceptedSignedManifest03: Uint8Array;
  deviceSigningPointAtAcceptance: Uint8Array; ownerApprovalPointAtAcceptance: Uint8Array;
}>): Promise<VerifiedAcceptedElection03> {
  const bundle = captureElectionBytes03(input.bundle, 628), expected = captureElectionBytes03(input.expectedCore, 500);
  const a = accepted(input.acceptedRecord), prior02 = input.predecessor02;
  const signed02 = captureElectionBytes03(input.priorSignedManifest02, 364, 9751);
  const signed03 = captureElectionBytes03(input.acceptedSignedManifest03, 366, 9753);
  const devicePoint = captureElectionBytes03(input.deviceSigningPointAtAcceptance, 65);
  const ownerPoint = captureElectionBytes03(input.ownerApprovalPointAtAcceptance, 65);
  // Capture genuine02 identity before the first await; public object projections
  // and caller-picked historical times cannot supply durable provenance.
  const prior = verifiedManifestIdentity02(prior02, a.acceptedAtMs);
  const core = bundle.subarray(0, 500), view = new DataView(core.buffer);
  if (!same(core, expected) || !same(core.subarray(0, 8), Uint8Array.of(90, 84, 80, 69, 3, 1, 2, 3))
      || nonzero(core.subarray(496)) || !nonzero(core.subarray(56, 72)) || !nonzero(core.subarray(352, 384))) fail("core framing/challenge");
  for (const [at, name] of [[8, "accountId"], [24, "deviceId"], [40, "lineId"], [72, "oldBindingId"],
    [104, "oldBindingProofDigest"], [136, "rootFingerprint"], [184, "priorManifestDigest"],
    [224, "acceptedManifestDigest"], [256, "selectedReaderKeyId"]] as const) {
    const bytes = a[name]; if (!same(core.subarray(at, at + bytes.length), bytes)) fail("accepted field mismatch");
  }
  for (const [at, name] of [[88, "oldBindingGeneration"], [96, "newBindingGeneration"], [168, "vaultGeneration"],
    [176, "priorManifestVersion"], [216, "acceptedManifestVersion"]] as const) {
    if (view.getBigUint64(at, false) !== a[name]) fail("accepted integer mismatch");
  }
  const issued = view.getBigUint64(384, false), expires = view.getBigUint64(392, false);
  electionTime03(issued); electionTime03(expires);
  if (expires <= issued || expires - issued > 300_000n || a.acceptedAtMs < issued || a.acceptedAtMs >= expires
      || a.newBindingGeneration <= a.oldBindingGeneration || a.vaultGeneration !== 1n
      || a.priorManifestVersion === max || a.acceptedManifestVersion !== a.priorManifestVersion + 1n
      || !nonzero(core.subarray(400, 432)) || !nonzero(core.subarray(432, 464)) || !nonzero(core.subarray(464, 496))) fail("acceptance range/context");
  if (!same(await sha(signed02), a.priorSignedManifestSha256) || !same(await sha(signed03), a.acceptedSignedManifestSha256)
      || !same(await sha(core), a.electionCoreSha256) || !same(await sha(bundle), a.electionBundleSha256)
      || !same(await sha(framed("ZTSE/line/payload-profile/commitment/v1", core)), a.electionCommitment)) fail("original evidence digest");
  const verified = await verifyManifest03From02(signed03, prior02, signed02, a.acceptedAtMs);
  const identity = verifiedManifestIdentity03(verified, a.acceptedAtMs);
  if (!same(identity.accountId, a.accountId) || identity.generation !== a.vaultGeneration || identity.version !== a.acceptedManifestVersion
      || !same(identity.digest, a.acceptedManifestDigest) || prior.version !== a.priorManifestVersion || !same(prior.digest, a.priorManifestDigest)) fail("manifest acceptance binding");
  const generation = new Uint8Array(8); new DataView(generation.buffer).setBigUint64(0, identity.generation, false);
  const pin = concat(Uint8Array.of(90, 84, 82, 80, 2), identity.accountId, generation, identity.rootPoint);
  if (!same(await sha(concat(enc.encode("ZTSE/root-pin/v2\0"), pin)), a.rootFingerprint)) fail("root fingerprint");
  if (!same(await keyId(0x0101, devicePoint), core.subarray(288, 320))
      || !same(await keyId(0x0101, ownerPoint), core.subarray(320, 352))) fail("registry signing key id");
  const deviceSig = bundle.subarray(500, 564);
  await verify(devicePoint, deviceSig, framed("ZTSE/line/payload-profile/device/v1", core));
  await verify(ownerPoint, bundle.subarray(564), framed("ZTSE/line/payload-profile/owner/v1", concat(core, await sha(deviceSig))));
  const handle = Object.freeze({}) as VerifiedAcceptedElection03;
  proofs.set(handle, { accepted: accepted(a), rootPoint: Uint8Array.from(identity.rootPoint) }); return handle;
}

/** Owned historical metadata from a genuine proof handle. This accessor proves
 * no server acceptance provenance, current selection, permission or custody. */
export function verifiedAcceptedElectionIdentity03(handle: VerifiedAcceptedElection03): DurableAcceptedElection03 {
  const p = proofs.get(handle); if (!p) fail("requires exact election proof handle");
  return accepted(p.accepted);
}

/** Present comparison relative to independently authenticated durable tuples.
 * No historical signature creates present permission, global high-water or CAS.
 * A later03 token is selected by the trusted adapter, not by version arithmetic. */
export function requireCurrentElection03(handle: VerifiedAcceptedElection03, manifest: VerifiedManifest03,
  currentInput: CurrentElectionAuthority03, nowMs: bigint): CurrentElectionAuthority03 {
  electionTime03(nowMs);
  const p = proofs.get(handle); if (!p) fail("requires exact election proof handle");
  const c = captureCurrentElectionAuthority03(currentInput), a = p.accepted;
  if (nowMs < a.acceptedAtMs || nowMs < c.comparedAtMs || nowMs >= c.permissionExpiresAtMs) fail("current time/permission");
  for (const [left, right] of [["accountId", "accountId"], ["deviceId", "deviceId"], ["lineId", "lineId"],
    ["bindingId", "newBindingId"], ["selectedReaderKeyId", "selectedReaderKeyId"], ["rootFingerprint", "rootFingerprint"],
    ["electionCommitment", "electionCommitment"], ["electionBundleSha256", "electionBundleSha256"]] as const) {
    if (!same(c[left], a[right])) fail("current binding/election mismatch");
  }
  if (c.bindingGeneration !== a.newBindingGeneration || c.vaultGeneration !== a.vaultGeneration
      || c.manifestVersion < a.acceptedManifestVersion) fail("current generation/version");
  const identity = verifiedManifestIdentity03(manifest, nowMs);
  if (!same(identity.accountId, c.accountId) || !same(identity.rootPoint, p.rootPoint) || identity.generation !== c.vaultGeneration
      || identity.version !== c.manifestVersion || !same(identity.digest, c.manifestDigest)
      || c.manifestVersion === a.acceptedManifestVersion && !same(c.manifestDigest, a.acceptedManifestDigest)) fail("current manifest binding");
  return c;
}
