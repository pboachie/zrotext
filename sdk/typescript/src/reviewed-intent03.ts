// SPDX-License-Identifier: AGPL-3.0-only
/** Candidate reviewed-send03 dependency. Trusted adapter inputs remain external
 * obligations: no HTTP authentication, current DB read, lease, commit or radio
 * authority is conferred by a local context handle or by matching digests. */
import { authorizeOutbound03, type VerifiedManifest03 } from "./draft03-manifest.js";
import { isCanonicalP256Signature } from "./draft01.js";
import {
  captureCurrentElectionAuthority03, captureElectionBytes03, electionTime03,
  requireCurrentElection03, type CurrentElectionAuthority03, type VerifiedAcceptedElection03,
} from "./payload-profile-election03.js";

type Recipient03 = Readonly<{ role: 1 | 2 | 3; keyId: Uint8Array }>;
export type TrustedReviewContextInput03 = Readonly<{
  currentAuthority: CurrentElectionAuthority03; manifest: VerifiedManifest03;
  acceptedElection: VerifiedAcceptedElection03; accountSelectionEpoch: bigint;
  ownerUserId: Uint8Array; ownerSessionId: Uint8Array; canonicalOrigin: string;
  intervalId: Uint8Array; intervalFromMs: bigint; intervalUntilMs: bigint;
  peer: Uint8Array; signerKeyId: Uint8Array; recipients: readonly Recipient03[]; nowMs: bigint;
}>;
declare const contextBrand: unique symbol;
/** Private snapshot identity only; not proof that the caller is an adapter. */
export type ReviewContext03 = Readonly<{ [contextBrand]: true }>;
type Context = Omit<TrustedReviewContextInput03, "canonicalOrigin" | "currentAuthority"> & Readonly<{
  currentAuthority: CurrentElectionAuthority03; ownerSessionDigest: Uint8Array; originDigest: Uint8Array;
}>;
const contexts = new WeakMap<ReviewContext03, Context>();
const enc = new TextEncoder();
function fail(why: string): never { throw new Error(`ZTSE reviewed-intent03: ${why}`); }
function same(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((v, i) => v === b[i]); }
function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; } return out;
}
function ab(a: Uint8Array): ArrayBuffer { return Uint8Array.from(a).buffer; }
async function sha(a: Uint8Array): Promise<Uint8Array> { return new Uint8Array(await crypto.subtle.digest("SHA-256", ab(a))); }
function framed(label: string, bytes: Uint8Array): Uint8Array {
  const n = new Uint8Array(4); new DataView(n.buffer).setUint32(0, bytes.length, false);
  return concat(enc.encode(label + "\0"), n, bytes);
}
function closed(value: object, names: readonly string[]): Record<string, unknown> {
  if (value === null || Object.getPrototypeOf(value) !== Object.prototype) fail("record type");
  const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(descriptors);
  if (keys.length !== names.length || keys.some(k => typeof k !== "string" || !names.includes(k))) fail("closed record fields");
  const out: Record<string, unknown> = {};
  for (const name of names) {
    const d = descriptors[name]; if (!d || !("value" in d)) fail("record accessor"); out[name] = d.value;
  }
  return out;
}
function nonzero(value: Uint8Array, n: number): Uint8Array {
  const copy = captureElectionBytes03(value, n); if (!copy.some(v => v !== 0)) fail("zero identity/digest"); return copy;
}
function peerBytes(value: Uint8Array): Uint8Array {
  const p = captureElectionBytes03(value, 3, 16);
  if (p[0] !== 43 || p[1] < 49 || p[1] > 57 || !p.subarray(2).every(v => v >= 48 && v <= 57)) fail("peer");
  return p;
}
function recipients(value: readonly Recipient03[]): readonly Recipient03[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) fail("recipient array");
  const descriptors = Object.getOwnPropertyDescriptors(value) as Record<string, PropertyDescriptor>, count = descriptors.length.value as number;
  if (count < 2 || count > 8 || Reflect.ownKeys(descriptors).length !== count + 1) fail("recipient count/fields");
  const out: Recipient03[] = []; let devices = 0, archives = 0;
  for (let i = 0; i < count; i++) {
    const d = descriptors[String(i)]; if (!d || !("value" in d)) fail("recipient accessor/hole");
    const r = closed(d.value, ["role", "keyId"]), role = r.role;
    if (role !== 1 && role !== 2 && role !== 3) fail("recipient role");
    const id = nonzero(r.keyId as Uint8Array, 32), prior = out.at(-1);
    if (prior && (role < prior.role || role === prior.role && compare(prior.keyId, id) >= 0)) fail("recipient order/duplicate");
    devices += Number(role === 1); archives += Number(role === 2); out.push({ role, keyId: id });
  }
  if (devices !== 1 || archives !== 1) fail("recipient policy"); return out;
}
function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0;
}
function authorized(c: Omit<TrustedReviewContextInput03, "canonicalOrigin">, now: bigint) {
  electionTime03(now);
  if (now < c.nowMs) fail("captured context clock regressed");
  const a = requireCurrentElection03(c.acceptedElection, c.manifest, c.currentAuthority, now);
  if (now < c.intervalFromMs || now >= c.intervalUntilMs) fail("inactive approved interval");
  const selected = authorizeOutbound03(c.manifest, {
    accountId: a.accountId, deviceId: a.deviceId, lineId: a.lineId, generation: a.vaultGeneration,
    version: a.manifestVersion, digest: a.manifestDigest, signerKeyId: c.signerKeyId, wraps: c.recipients,
  }, now);
  if (!c.recipients.some(r => r.role === 1 && same(r.keyId, a.selectedReaderKeyId))) fail("selected physical reader");
  return selected;
}
/** The adapter must supply actual authenticated owner IDs, configured origin,
 * approved interval and durable current permission. This function only validates
 * shape, reconstructs canonical commitments and snapshots before the first await.
 * Arbitrary digests cannot be supplied in place of those explicit inputs. */
export async function captureTrustedReviewContext03(input: TrustedReviewContextInput03): Promise<ReviewContext03> {
  const p = closed(input, ["currentAuthority", "manifest", "acceptedElection", "accountSelectionEpoch", "ownerUserId",
    "ownerSessionId", "canonicalOrigin", "intervalId", "intervalFromMs", "intervalUntilMs", "peer", "signerKeyId", "recipients", "nowMs"]);
  const a = captureCurrentElectionAuthority03(p.currentAuthority as CurrentElectionAuthority03);
  for (const name of ["accountSelectionEpoch", "intervalFromMs", "intervalUntilMs", "nowMs"]) electionTime03(p[name] as bigint);
  if ((p.intervalUntilMs as bigint) <= (p.intervalFromMs as bigint)) fail("interval bounds");
  const origin = p.canonicalOrigin;
  if (typeof origin !== "string" || enc.encode(origin).length > 512) fail("origin type/length");
  const url = new URL(origin);
  if (url.protocol !== "https:" || url.origin !== origin || url.username || url.password) fail("canonical HTTPS origin");
  const captured = { currentAuthority: a, manifest: p.manifest as VerifiedManifest03, acceptedElection: p.acceptedElection as VerifiedAcceptedElection03,
    accountSelectionEpoch: p.accountSelectionEpoch as bigint, ownerUserId: nonzero(p.ownerUserId as Uint8Array, 16),
    ownerSessionId: nonzero(p.ownerSessionId as Uint8Array, 16), intervalId: nonzero(p.intervalId as Uint8Array, 16),
    intervalFromMs: p.intervalFromMs as bigint, intervalUntilMs: p.intervalUntilMs as bigint, peer: peerBytes(p.peer as Uint8Array),
    signerKeyId: nonzero(p.signerKeyId as Uint8Array, 32), recipients: recipients(p.recipients as Recipient03[]), nowMs: p.nowMs as bigint };
  authorized(captured, captured.nowMs);
  const sessionBytes = framed("ZTSE/line/payload-profile/owner-session/v1", concat(a.accountId, captured.ownerUserId, captured.ownerSessionId));
  const ownerSessionDigest = await sha(sessionBytes), originDigest = await sha(enc.encode(origin));
  const handle = Object.freeze({}) as ReviewContext03;
  contexts.set(handle, { ...captured, ownerSessionDigest, originDigest }); return handle;
}

/** Candidate-only ZTRI01. Immutable selection and review identity; no transport
 * lease/connection epochs, unsigned ceiling, plaintext or cached permission. */
export type ReviewedIntentFields03 = Readonly<{
  accountId: Uint8Array; deviceId: Uint8Array; lineId: Uint8Array; bindingId: Uint8Array;
  ownerUserId: Uint8Array; ownerSessionId: Uint8Array; intervalId: Uint8Array; messageId: Uint8Array;
  bindingGeneration: bigint; vaultGeneration: bigint; manifestVersion: bigint; accountSelectionEpoch: bigint;
  observedMs: bigint; messageExpiresMs: bigint; reviewIssuedMs: bigint; reviewExpiresMs: bigint;
  selectedReaderKeyId: Uint8Array; rootFingerprint: Uint8Array; manifestDigest: Uint8Array;
  electionCommitment: Uint8Array; electionBundleSha256: Uint8Array; ownerSessionDigest: Uint8Array;
  originDigest: Uint8Array; signerKeyId: Uint8Array; envelopeDigest: Uint8Array; unsignedDigest: Uint8Array;
  bodyDigest: Uint8Array; peer: Uint8Array; recipients: readonly Recipient03[]; smsCeiling: number;
}>;
const uuidFields = ["accountId", "deviceId", "lineId", "bindingId", "ownerUserId", "ownerSessionId", "intervalId", "messageId"] as const;
const numberFields = ["bindingGeneration", "vaultGeneration", "manifestVersion", "accountSelectionEpoch", "observedMs", "messageExpiresMs", "reviewIssuedMs", "reviewExpiresMs"] as const;
const digestFields = ["selectedReaderKeyId", "rootFingerprint", "manifestDigest", "electionCommitment", "electionBundleSha256", "ownerSessionDigest", "originDigest", "signerKeyId", "envelopeDigest", "unsignedDigest", "bodyDigest"] as const;
const header = Uint8Array.of(90, 84, 82, 73, 1, 3, 3, 0);
function fields(input: ReviewedIntentFields03): ReviewedIntentFields03 {
  const p = closed(input, [...uuidFields, ...numberFields, ...digestFields, "peer", "recipients", "smsCeiling"]);
  for (const name of uuidFields) p[name] = nonzero(p[name] as Uint8Array, 16);
  for (const name of digestFields) p[name] = nonzero(p[name] as Uint8Array, 32);
  for (const name of numberFields) electionTime03(p[name] as bigint);
  const ceiling = p.smsCeiling;
  if (typeof ceiling !== "number" || !Number.isInteger(ceiling) || ceiling < 1 || ceiling > 6) fail("canonical SMS ceiling1..6");
  p.peer = peerBytes(p.peer as Uint8Array); p.recipients = recipients(p.recipients as Recipient03[]);
  const f = p as ReviewedIntentFields03;
  if (!(f.observedMs <= f.reviewIssuedMs && f.reviewIssuedMs < f.reviewExpiresMs && f.reviewExpiresMs <= f.messageExpiresMs)
      || f.reviewExpiresMs - f.reviewIssuedMs > 30_000n || f.messageExpiresMs - f.observedMs > 900_000n) fail("review/message lifetime");
  if (!f.recipients.some(r => r.role === 1 && same(r.keyId, f.selectedReaderKeyId))) fail("selected reader commitment");
  return f;
}
function u64(n: bigint): Uint8Array { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n, false); return b; }
function encode(f: ReviewedIntentFields03): Uint8Array {
  return concat(header, ...uuidFields.map(n => f[n]), ...numberFields.map(n => u64(f[n])), ...digestFields.map(n => f[n]),
    Uint8Array.of(f.peer.length), f.peer, Uint8Array.of(f.recipients.length),
    ...f.recipients.map(r => concat(Uint8Array.of(r.role), r.keyId)), Uint8Array.of(f.smsCeiling));
}
/** Structural codec only. Caller-supplied fields do not become authentication. */
export function encodeReviewedIntent03(input: ReviewedIntentFields03): Uint8Array { return encode(fields(input)); }
/** Closed exact binary grammar; returns independent owned arrays. This is NOT
 * signature, original plaintext, adapter provenance or current permission proof. */
export function decodeReviewedIntent03(input: Uint8Array): ReviewedIntentFields03 {
  const bytes = captureElectionBytes03(input, 624, 835), view = new DataView(bytes.buffer);
  if (!same(bytes.subarray(0, 8), header)) fail("intent framing/profile/reserved");
  const p: Record<string, unknown> = {}; let at = 8;
  for (const name of uuidFields) { p[name] = bytes.slice(at, at + 16); at += 16; }
  for (const name of numberFields) { p[name] = view.getBigUint64(at, false); at += 8; }
  for (const name of digestFields) { p[name] = bytes.slice(at, at + 32); at += 32; }
  const peerLength = bytes[at++]; p.peer = bytes.slice(at, at + peerLength); at += peerLength;
  const count = bytes[at++];
  if (count < 2 || count > 8 || at + count * 33 + 1 !== bytes.length) fail("intent recipient/trailing framing");
  const rs: Recipient03[] = [];
  for (let i = 0; i < count; i++) { rs.push({ role: bytes[at++] as 1 | 2 | 3, keyId: bytes.slice(at, at + 32) }); at += 32; }
  p.recipients = rs; p.smsCeiling = bytes[at];
  const f = fields(p as ReviewedIntentFields03);
  if (!same(encode(f), bytes)) fail("noncanonical intent"); return f;
}
/** The new signature domain is independent of envelope03 and ZTCS01. */
export function reviewedIntentTranscript03(input: Uint8Array): Uint8Array {
  return framed("zrotext/conversation/reviewed-send03/v1", encode(decodeReviewedIntent03(input)));
}
function context(handle: ReviewContext03): Context {
  const c = contexts.get(handle); if (!c) fail("requires captured trusted context handle"); return c;
}
function timing(f: ReviewedIntentFields03, c: Context, now: bigint) {
  const a = authorized(c, now);
  if (f.reviewIssuedMs > now || now >= f.reviewExpiresMs || f.observedMs < a.validFromMs || f.observedMs < c.intervalFromMs
      || f.messageExpiresMs > a.expiresMs || f.messageExpiresMs > c.currentAuthority.permissionExpiresAtMs
      || f.messageExpiresMs > c.intervalUntilMs) fail("current review/whole-message permission");
  return a;
}
function bind(f: ReviewedIntentFields03, c: Context): void {
  const a = c.currentAuthority;
  for (const name of ["accountId", "deviceId", "lineId", "bindingId", "selectedReaderKeyId", "rootFingerprint", "manifestDigest", "electionCommitment", "electionBundleSha256"] as const)
    if (!same(f[name], a[name])) fail("immutable selection mismatch");
  for (const name of ["bindingGeneration", "vaultGeneration", "manifestVersion"] as const)
    if (f[name] !== a[name]) fail("selection counter mismatch");
  if (f.accountSelectionEpoch !== c.accountSelectionEpoch) fail("account selection epoch mismatch");
  for (const name of ["ownerUserId", "ownerSessionId", "intervalId", "ownerSessionDigest", "originDigest", "signerKeyId", "peer"] as const)
    if (!same(f[name], c[name])) fail("owner/session/origin/interval selection mismatch");
  if (f.recipients.length !== c.recipients.length || f.recipients.some((r, i) => r.role !== c.recipients[i].role || !same(r.keyId, c.recipients[i].keyId))) fail("review recipient set mismatch");
}
async function verifySignature(point: Uint8Array, signature: Uint8Array, transcript: Uint8Array): Promise<void> {
  if (!isCanonicalP256Signature(signature)) fail("canonical low-S raw64 signature");
  const key = await crypto.subtle.importKey("raw", ab(point), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, ab(signature), ab(transcript))) fail("signature verification");
}
/** Public structural and signature checks; no HPKE opening/plaintext claim. */
async function envelopeMatches(bytes: Uint8Array, f: ReviewedIntentFields03, signerPoint: Uint8Array): Promise<void> {
  if (!same(bytes.subarray(0, 8), Uint8Array.of(90, 84, 83, 69, 3, 1, 0, 0))) fail("outbound envelope03 header");
  const v = new DataView(bytes.buffer), length = v.getUint16(8, false), end = 10 + length;
  if (length !== 154 + f.peer.length || bytes.length < end + 16 + 17 + 1 + 292 + 64) fail("envelope protected/body bounds");
  const p = bytes.subarray(10, end);
  for (const [offset, wanted] of [[0, f.accountId], [16, f.messageId], [32, f.deviceId], [48, f.lineId],
    [72, f.manifestDigest], [104, f.signerKeyId], [154, f.peer]] as const)
    if (!same(p.subarray(offset, offset + wanted.length), wanted)) fail("envelope identity mismatch");
  if (v.getBigUint64(74, false) !== f.manifestVersion || v.getBigUint64(146, false) !== f.observedMs
      || v.getBigUint64(154, false) !== f.messageExpiresMs || p[152] !== 1 || p[153] !== f.peer.length) fail("envelope counter/time/peer framing");
  const bodyLength = v.getUint32(end + 12, false), bodyEnd = end + 16 + bodyLength;
  if (bodyLength < 17 || bodyLength > 32_784 || bodyEnd >= bytes.length) fail("envelope body length");
  const count = bytes[bodyEnd];
  if (count !== f.recipients.length || bodyEnd + 1 + 146 * count + 64 !== bytes.length) fail("envelope wrap count/trailing bytes");
  const points: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    const at = bodyEnd + 1 + 146 * i, r = f.recipients[i];
    if (bytes[at] !== r.role || !same(bytes.subarray(at + 1, at + 33), r.keyId)) fail("envelope exact wrap selection/order");
    const point = bytes.slice(at + 33, at + 98); if (point[0] !== 4) fail("envelope ephemeral point"); points.push(point);
  }
  // P-256 point membership is checked by WebCrypto, independently of the outer
  // signature. All envelope/intent arrays were captured before this first await.
  for (const point of points) await crypto.subtle.importKey("raw", ab(point), { name: "ECDH", namedCurve: "P-256" }, false, []);
  const unsigned = bytes.subarray(0, -64);
  if (!same(await sha(bytes), f.envelopeDigest) || !same(await sha(unsigned), f.unsignedDigest)) fail("exact envelope commitments");
  await verifySignature(signerPoint, bytes.subarray(-64), framed("ZTSE/sign/v3", unsigned));
}
function bodyBytes(text: string): Uint8Array {
  if (typeof text !== "string") fail("body type");
  const b = enc.encode(text), dec = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
  if (b.length < 1 || b.length > 32_768 || dec.decode(b) !== text || b.includes(0)
      || b.length >= 3 && b[0] === 239 && b[1] === 187 && b[2] === 191) fail("strict UTF-8 body");
  return b;
}
/** Local browser/SDK preparation only. bodyDigest commits the supplied strict
 * UTF-8 plaintext; the encrypted body is not opened here. Its relation to what
 * the owner reviewed remains the composer/UI's explicit custody obligation. */
export async function prepareReviewedIntent03(input: Readonly<{
  context: ReviewContext03; envelope: Uint8Array; body: string;
  reviewIssuedMs: bigint; reviewExpiresMs: bigint; smsCeiling: number; nowMs: bigint;
}>): Promise<Uint8Array> {
  const p = closed(input, ["context", "envelope", "body", "reviewIssuedMs", "reviewExpiresMs", "smsCeiling", "nowMs"]);
  const c = context(p.context as ReviewContext03), a = c.currentAuthority;
  const envelope = captureElectionBytes03(p.envelope as Uint8Array, 557, 34_213), body = bodyBytes(p.body as string);
  try {
    const now = p.nowMs as bigint, issued = p.reviewIssuedMs as bigint, expiry = p.reviewExpiresMs as bigint;
    electionTime03(now); electionTime03(issued); electionTime03(expiry);
    const messageId = envelope.slice(26, 42), v = new DataView(envelope.buffer);
    // Constructed from private owned context snapshots, never public projections.
    const envelopeDigest = await sha(envelope), unsignedDigest = await sha(envelope.subarray(0, -64)), bodyDigest = await sha(body);
    const f = fields({ accountId: a.accountId, deviceId: a.deviceId, lineId: a.lineId, bindingId: a.bindingId,
      ownerUserId: c.ownerUserId, ownerSessionId: c.ownerSessionId, intervalId: c.intervalId, messageId,
      bindingGeneration: a.bindingGeneration, vaultGeneration: a.vaultGeneration, manifestVersion: a.manifestVersion,
      accountSelectionEpoch: c.accountSelectionEpoch, observedMs: v.getBigUint64(146, false), messageExpiresMs: v.getBigUint64(154, false),
      reviewIssuedMs: issued, reviewExpiresMs: expiry, selectedReaderKeyId: a.selectedReaderKeyId, rootFingerprint: a.rootFingerprint,
      manifestDigest: a.manifestDigest, electionCommitment: a.electionCommitment, electionBundleSha256: a.electionBundleSha256,
      ownerSessionDigest: c.ownerSessionDigest, originDigest: c.originDigest, signerKeyId: c.signerKeyId,
      envelopeDigest, unsignedDigest, bodyDigest,
      peer: c.peer, recipients: c.recipients, smsCeiling: p.smsCeiling as number });
    const selected = timing(f, c, now);
    await envelopeMatches(envelope, f, selected.signerPoint); return encode(f);
  } finally { body.fill(0); }
}
declare const proofBrand: unique symbol;
export type VerifiedReviewedIntent03 = Readonly<{ [proofBrand]: true }>;
type Verified = Readonly<{ fields: ReviewedIntentFields03; intent: Uint8Array; signature: Uint8Array; envelope: Uint8Array }>;
const proofs = new WeakMap<VerifiedReviewedIntent03, Verified>();
/** Component crypto proof relative to an explicitly trusted current adapter
 * context/time. nowMs is the ORIGINAL review/signing or admission comparison
 * instant, not a later delivery clock. Later fetch needs a separate receipt-
 * bound verifier, message deadline and current lease checks; it must not renew
 * this signed review window. Does not consume a nonce, prove a DB read, reserve
 * quota, authenticate plaintext, issue a grant or authorize any radio effect. */
export async function verifyReviewedIntent03(input: Readonly<{
  context: ReviewContext03; intent: Uint8Array; signature: Uint8Array; envelope: Uint8Array; nowMs: bigint;
}>): Promise<VerifiedReviewedIntent03> {
  const p = closed(input, ["context", "intent", "signature", "envelope", "nowMs"]), c = context(p.context as ReviewContext03);
  const intent = captureElectionBytes03(p.intent as Uint8Array, 624, 835), signature = captureElectionBytes03(p.signature as Uint8Array, 64);
  const envelope = captureElectionBytes03(p.envelope as Uint8Array, 557, 34_213), now = p.nowMs as bigint;
  const f = decodeReviewedIntent03(intent); bind(f, c); const selected = timing(f, c, now);
  await envelopeMatches(envelope, f, selected.signerPoint);
  await verifySignature(selected.signerPoint, signature, reviewedIntentTranscript03(intent));
  const handle = Object.freeze({}) as VerifiedReviewedIntent03; proofs.set(handle, { fields: f, intent, signature, envelope }); return handle;
}
/** Owned copies only; the proof handle remains private and cannot be forged by
 * mutating this projection. Receiver/storage/transport integration is unmounted. */
export function verifiedReviewedIntentSnapshot03(handle: VerifiedReviewedIntent03): Readonly<{
  fields: ReviewedIntentFields03; intent: Uint8Array; signature: Uint8Array; envelope: Uint8Array;
}> {
  const p = proofs.get(handle); if (!p) fail("requires verified reviewed intent handle");
  return { fields: fields(p.fields), intent: Uint8Array.from(p.intent), signature: Uint8Array.from(p.signature), envelope: Uint8Array.from(p.envelope) };
}
