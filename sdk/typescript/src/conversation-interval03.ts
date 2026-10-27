// SPDX-License-Identifier: AGPL-3.0-only
/** Exact public ZTCA03 consent crypto. Actual authenticated current records,
 * full physical lease, connector grants, local key custody and durable install
 * ACK are adapter obligations. No returned object grants permission to send. */
import { authorizeInbound03, authorizeOutbound03, type VerifiedManifest03 } from './draft03-manifest.js';
import { isCanonicalP256Signature } from './draft01.js';
import { prepareSealedOutboundEnvelope03, type PreparedOutboundEnvelope03 } from './sealed-envelope03.js';
import { captureTrustedReviewContext03, type ReviewContext03 } from './reviewed-intent03.js';
import { captureCurrentElectionAuthority03, captureElectionBytes03, electionTime03, requireCurrentElection03,
  type CurrentElectionAuthority03, type VerifiedAcceptedElection03 } from './payload-profile-election03.js';

export const conversationDisclosureVersion03 = 'conversation-content03-v1';
export const conversationDisclosure03 = 'With your approval, ZROtext sends and receives SMS for this selected phone line and conversation, and transfers encrypted message content to your paired browser and the explicitly listed customer-controlled readers. Stop closes new sending, capture and transfer; retained encrypted content is deleted separately.';
const ids = ['accountId', 'deviceId', 'lineId', 'bindingId', 'intervalId', 'receiptId', 'ownerUserId', 'ownerSessionId', 'openingId'] as const;
const numbers = ['bindingGeneration', 'vaultGeneration', 'manifestVersion', 'selectionEpoch', 'issuedMs', 'setupExpiresMs', 'intervalFromMs', 'intervalUntilMs'] as const;
const digests = ['selectedReaderKeyId', 'archiveReaderKeyId', 'phoneSignerKeyId', 'browserSignerKeyId', 'rootFingerprint', 'manifestDigest',
  'electionCommitment', 'electionBundleSha256', 'ownerSessionDigest', 'originDigest', 'deviceSessionDigest', 'physicalSelectionDigest', 'nonce'] as const;
const header = Uint8Array.of(90, 84, 67, 65, 3, 3, 3, 0), enc = new TextEncoder();
export type ConversationIntegration03 = Readonly<{ connectorId: Uint8Array; readGrantId: Uint8Array; keyId: Uint8Array }>;
export type ConversationStatement03 = Readonly<Record<typeof ids[number] | typeof digests[number], Uint8Array>
  & Record<typeof numbers[number], bigint> & { peer: Uint8Array; integrationReaders: readonly ConversationIntegration03[] }>;
function fail(why: string): never { throw Error('Conversation consent03: ' + why); }
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
function join(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; } return out;
}
async function sha(b: Uint8Array): Promise<Uint8Array> { return new Uint8Array(await crypto.subtle.digest('SHA-256', Uint8Array.from(b).buffer)); }
function frame(label: string, b: Uint8Array): Uint8Array {
  const n = new Uint8Array(4); new DataView(n.buffer).setUint32(0, b.length); return join(enc.encode(label + '\0'), n, b);
}
function record(input: unknown, names: readonly string[]): Record<string, unknown> {
  if (!input || typeof input !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) fail('closed record');
  const ds = Object.getOwnPropertyDescriptors(input), keys = Reflect.ownKeys(ds);
  if (keys.length !== names.length || keys.some(k => typeof k !== 'string' || !names.includes(k))) fail('closed fields');
  const out: Record<string, unknown> = {};
  for (const n of names) { const d = ds[n]; if (!d || !('value' in d) || !d.enumerable) fail('record accessor'); out[n] = d.value; } return out;
}
function nonzero(value: unknown, width: number): Uint8Array {
  const b = captureElectionBytes03(value as Uint8Array, width); if (!b.some(v => v !== 0)) fail('zero identity/digest'); return b;
}
function mappings(input: unknown): readonly ConversationIntegration03[] {
  if (!Array.isArray(input) || Object.getPrototypeOf(input) !== Array.prototype) fail('mapping array');
  const ds = Object.getOwnPropertyDescriptors(input) as Record<string, PropertyDescriptor>, count = ds.length.value as number;
  if (count > 6 || Reflect.ownKeys(ds).length !== count + 1) fail('mapping count/fields');
  const out: ConversationIntegration03[] = [];
  for (let i = 0; i < count; i++) {
    const d = ds[i]; if (!d || !('value' in d)) fail('mapping accessor/hole');
    const r = record(d.value, ['connectorId', 'readGrantId', 'keyId']);
    const item = { connectorId: nonzero(r.connectorId, 16), readGrantId: nonzero(r.readGrantId, 16), keyId: nonzero(r.keyId, 32) };
    const prior = out.at(-1);
    if (prior && compare(prior.keyId, item.keyId) >= 0 || out.some(p => same(p.connectorId, item.connectorId) || same(p.readGrantId, item.readGrantId))) fail('mapping order/identity');
    out.push(item);
  }
  return out;
}
function compare(a: Uint8Array, b: Uint8Array): number { for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; }
function peer(value: unknown): Uint8Array {
  const b = captureElectionBytes03(value as Uint8Array, 3, 16);
  if (b[0] !== 43 || b[1] < 49 || b[1] > 57 || !b.subarray(2).every(v => v >= 48 && v <= 57)) fail('peer'); return b;
}
function statement(input: unknown): ConversationStatement03 {
  const s = record(input, [...ids, ...numbers, ...digests, 'peer', 'integrationReaders']);
  for (const n of ids) s[n] = nonzero(s[n], 16);
  for (const n of digests) s[n] = nonzero(s[n], 32);
  for (const n of numbers) electionTime03(s[n] as bigint);
  s.peer = peer(s.peer); s.integrationReaders = mappings(s.integrationReaders);
  const v = s as ConversationStatement03;
  if (v.intervalFromMs !== v.issuedMs || v.setupExpiresMs <= v.issuedMs || v.setupExpiresMs - v.issuedMs > 300000n
      || v.intervalUntilMs <= v.intervalFromMs || v.intervalUntilMs - v.intervalFromMs > 86400000n) fail('original time bounds');
  const handles = [v.bindingId, v.intervalId, v.receiptId, v.openingId];
  if (handles.some((a, i) => handles.slice(0, i).some(b => same(a, b)))) fail('handle alias'); return v;
}
/** Structural codec. Neither caller fields nor correctly framed bytes are authority. */
export async function encodeConversationStatement03(input: ConversationStatement03): Promise<Uint8Array> {
  const s = statement(input), ns = numbers.map(n => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, s[n]); return b; });
  const version = enc.encode(conversationDisclosureVersion03), disclosure = await sha(enc.encode(conversationDisclosure03));
  return join(header, ...ids.map(n => s[n]), ...ns, ...digests.map(n => s[n]), Uint8Array.of(version.length), version, disclosure,
    Uint8Array.of(s.peer.length), s.peer, Uint8Array.of(s.integrationReaders.length), ...s.integrationReaders.map(r => join(r.connectorId, r.readGrantId, r.keyId)));
}
export async function decodeConversationStatement03(input: Uint8Array): Promise<ConversationStatement03> {
  const b = captureElectionBytes03(input, 695, 1092), view = new DataView(b.buffer), s: Record<string, unknown> = {}; let at = 8;
  if (!same(b.subarray(0, 8), header)) fail('profile/header');
  for (const n of ids) { s[n] = b.slice(at, at + 16); at += 16; }
  for (const n of numbers) { s[n] = view.getBigUint64(at); at += 8; }
  for (const n of digests) { s[n] = b.slice(at, at + 32); at += 32; }
  const versionLength = b[at++], version = enc.encode(conversationDisclosureVersion03);
  if (!same(b.subarray(at, at + versionLength), version)) fail('disclosure version'); at += versionLength;
  const expected = await sha(enc.encode(conversationDisclosure03));
  if (!same(b.subarray(at, at + 32), expected)) fail('disclosure'); at += 32;
  const peerLength = b[at++]; s.peer = b.slice(at, at + peerLength); at += peerLength;
  const count = b[at++]; if (count > 6 || at + 64 * count !== b.length) fail('mapping/trailing framing');
  const rs = [];
  for (let i = 0; i < count; i++) { rs.push({ connectorId: b.slice(at, at + 16), readGrantId: b.slice(at + 16, at + 32), keyId: b.slice(at + 32, at + 64) }); at += 64; }
  s.integrationReaders = rs; return statement(s);
}
export type ConversationContextInput03 = Readonly<{
  currentAuthority: CurrentElectionAuthority03; acceptedElection: VerifiedAcceptedElection03; manifest: VerifiedManifest03;
  selectionEpoch: bigint; ownerUserId: Uint8Array; ownerSessionId: Uint8Array; canonicalOrigin: string;
  deviceSessionDigest: Uint8Array; physicalSelectionDigest: Uint8Array; archiveReaderKeyId: Uint8Array;
  phoneSignerKeyId: Uint8Array; browserSignerKeyId: Uint8Array; ownerDeadlineMs: bigint;
  peer: Uint8Array; integrationReaders: readonly ConversationIntegration03[]; nowMs: bigint;
}>;
declare const contextBrand: unique symbol;
export type ConversationContext03 = Readonly<{ [contextBrand]: true }>;
type Context = ConversationContextInput03 & Readonly<{ ownerSessionDigest: Uint8Array; originDigest: Uint8Array }>;
const contexts = new WeakMap<ConversationContext03, Context>();
function keys(c: Context | ConversationContextInput03, nowMs: bigint) {
  electionTime03(nowMs); if (nowMs < c.nowMs) fail('context clock regression');
  const a = requireCurrentElection03(c.acceptedElection, c.manifest, c.currentAuthority, nowMs);
  if (nowMs >= c.ownerDeadlineMs) fail('owner deadline');
  const claim = { accountId: a.accountId, deviceId: a.deviceId, lineId: a.lineId, generation: a.vaultGeneration, version: a.manifestVersion, digest: a.manifestDigest };
  const readers = [{ role: 2, keyId: c.archiveReaderKeyId }, ...c.integrationReaders.map(r => ({ role: 3, keyId: r.keyId }))];
  const inbound = authorizeInbound03(c.manifest, { ...claim, signerKeyId: c.phoneSignerKeyId, wraps: readers }, nowMs);
  const outbound = authorizeOutbound03(c.manifest, { ...claim, signerKeyId: c.browserSignerKeyId, wraps: [{ role: 1, keyId: a.selectedReaderKeyId }, ...readers] }, nowMs);
  return { a, inbound, outbound };
}
/** Trusted adapter supplies the real current records and its checked time.
 * This snapshots those inputs and checks their cryptographic consistency; it
 * cannot establish their server provenance, grant revocation or local custody. */
export async function captureConversationContext03(input: ConversationContextInput03): Promise<ConversationContext03> {
  const p = record(input, ['currentAuthority', 'acceptedElection', 'manifest', 'selectionEpoch', 'ownerUserId', 'ownerSessionId', 'canonicalOrigin',
    'deviceSessionDigest', 'physicalSelectionDigest', 'archiveReaderKeyId', 'phoneSignerKeyId', 'browserSignerKeyId', 'ownerDeadlineMs', 'peer', 'integrationReaders', 'nowMs']);
  p.currentAuthority = captureCurrentElectionAuthority03(p.currentAuthority as CurrentElectionAuthority03);
  for (const n of ['selectionEpoch', 'ownerDeadlineMs', 'nowMs']) electionTime03(p[n] as bigint);
  for (const n of ['ownerUserId', 'ownerSessionId']) p[n] = nonzero(p[n], 16);
  for (const n of ['deviceSessionDigest', 'physicalSelectionDigest', 'archiveReaderKeyId', 'phoneSignerKeyId', 'browserSignerKeyId']) p[n] = nonzero(p[n], 32);
  p.peer = peer(p.peer); p.integrationReaders = mappings(p.integrationReaders);
  if (typeof p.canonicalOrigin !== 'string' || enc.encode(p.canonicalOrigin).length > 512) fail('canonical origin');
  const url = new URL(p.canonicalOrigin);
  if (url.protocol !== 'https:' || url.origin !== p.canonicalOrigin || url.username || url.password) fail('canonical HTTPS origin');
  const c = p as ConversationContextInput03; keys(c, c.nowMs);
  const ownerSessionDigest = await sha(frame('ZTSE/line/payload-profile/owner-session/v1', join(c.currentAuthority.accountId, c.ownerUserId, c.ownerSessionId)));
  const originDigest = await sha(enc.encode(c.canonicalOrigin)), token = Object.freeze({}) as ConversationContext03;
  contexts.set(token, { ...c, ownerSessionDigest, originDigest }); return token;
}
function context(token: ConversationContext03): Context { const c = contexts.get(token); if (!c) fail('genuine context handle required'); return c; }
function binding(s: ConversationStatement03, c: Context, nowMs: bigint, pending: boolean) {
  const k = keys(c, nowMs), a = k.a;
  const expected = [a.accountId, a.deviceId, a.lineId, a.bindingId, c.ownerUserId, c.ownerSessionId];
  if ([s.accountId, s.deviceId, s.lineId, s.bindingId, s.ownerUserId, s.ownerSessionId].some((v, i) => !same(v, expected[i]))
      || [s.bindingGeneration, s.vaultGeneration, s.manifestVersion, s.selectionEpoch].some((v, i) => v !== [a.bindingGeneration, a.vaultGeneration, a.manifestVersion, c.selectionEpoch][i])) fail('current selection');
  const ds = [a.selectedReaderKeyId, c.archiveReaderKeyId, c.phoneSignerKeyId, c.browserSignerKeyId, a.rootFingerprint, a.manifestDigest,
    a.electionCommitment, a.electionBundleSha256, c.ownerSessionDigest, c.originDigest, c.deviceSessionDigest, c.physicalSelectionDigest];
  if (digests.slice(0, 12).some((n, i) => !same(s[n], ds[i])) || !same(s.peer, c.peer)
      || s.integrationReaders.length !== c.integrationReaders.length || s.integrationReaders.some((r, i) =>
        (['connectorId', 'readGrantId', 'keyId'] as const).some(n => !same(r[n], c.integrationReaders[i][n])))) fail('current commitments/peer/readers');
  if (nowMs < s.issuedMs || nowMs >= s.intervalUntilMs || s.issuedMs < k.inbound.validFromMs || s.issuedMs < k.outbound.validFromMs
      || s.intervalUntilMs > k.inbound.expiresMs || s.intervalUntilMs > k.outbound.expiresMs || s.intervalUntilMs > c.ownerDeadlineMs
      || pending && (nowMs >= s.setupExpiresMs || s.setupExpiresMs > a.permissionExpiresAtMs)) fail('current interval/setup time');
  return k;
}
/** Validates an unsigned candidate before the browser signs its exact request.
 * This does not check an opening/receipt against a durable local journal. */
export async function checkConversationStatement03(input: Uint8Array, token: ConversationContext03, nowMs: bigint): Promise<ConversationStatement03> {
  const c = context(token), s = await decodeConversationStatement03(input); binding(s, c, nowMs, true); return s;
}
export function conversationRequestTranscript03(statementBytes: Uint8Array): Uint8Array {
  return frame('zrotext/conversation/request03/v1', captureElectionBytes03(statementBytes, 695, 1092));
}
export type ConversationReceiptSignature03 = Readonly<{ signature: Uint8Array; timeMs: bigint }>;
function receipt(input: ConversationReceiptSignature03 | null): ConversationReceiptSignature03 | null {
  if (input === null) return null;
  const p = record(input, ['signature', 'timeMs']), b = captureElectionBytes03(p.signature as Uint8Array, 64);
  electionTime03(p.timeMs as bigint); if (!isCanonicalP256Signature(b)) fail('strict low-S signature');
  return { signature: b, timeMs: p.timeMs as bigint };
}
export type ConversationReceiptsInput03 = Readonly<{ context: ConversationContext03; statement: Uint8Array;
  request: ConversationReceiptSignature03 | null; approval: ConversationReceiptSignature03 | null;
  installed: ConversationReceiptSignature03 | null; nowMs: bigint; pending: boolean }>;
/** Rechecks original three independent signatures and original acceptance times
 * while checking present permission separately. A complete result is public
 * crypto, never the phone's durable install ACK, restored custody or Ready. */
export async function verifyConversationReceipts03(input: ConversationReceiptsInput03): Promise<ConversationStatement03> {
  const p = record(input, ['context', 'statement', 'request', 'approval', 'installed', 'nowMs', 'pending']);
  if (typeof p.pending !== 'boolean') fail('pending flag');
  const c = context(p.context as ConversationContext03), raw = captureElectionBytes03(p.statement as Uint8Array, 695, 1092);
  const request = receipt(p.request as ConversationReceiptSignature03 | null), approval = receipt(p.approval as ConversationReceiptSignature03 | null);
  const installed = receipt(p.installed as ConversationReceiptSignature03 | null), nowMs = p.nowMs as bigint;
  const s = await decodeConversationStatement03(raw), k = binding(s, c, nowMs, p.pending);
  if (approval && !request || installed && (!request || !approval)) fail('receipt phase gap');
  let prior = s.issuedMs;
  async function verify(value: ConversationReceiptSignature03, point: Uint8Array, label: string, payload: Uint8Array) {
    if (value.timeMs < prior || value.timeMs >= s.setupExpiresMs || value.timeMs > nowMs) fail('original receipt time');
    const key = await crypto.subtle.importKey('raw', Uint8Array.from(point).buffer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, Uint8Array.from(value.signature).buffer,
      Uint8Array.from(frame(label, payload)).buffer)) fail('receipt signature'); prior = value.timeMs;
  }
  if (request) await verify(request, k.outbound.signerPoint, 'zrotext/conversation/request03/v1', raw);
  if (approval) await verify(approval, k.inbound.signerPoint, 'zrotext/conversation/approve03/v1', join(raw, await sha(request!.signature)));
  if (installed) await verify(installed, k.inbound.signerPoint, 'zrotext/conversation/install03/v1', join(raw, await sha(request!.signature), await sha(approval!.signature)));
  binding(s, c, nowMs, p.pending); return s;
}

export type InstalledConversationMessageInput03 = Readonly<{
  context: ConversationContext03; statement: Uint8Array;
  request: ConversationReceiptSignature03; approval: ConversationReceiptSignature03;
  installed: ConversationReceiptSignature03; messageId: Uint8Array;
  observedMs: bigint; expiresMs: bigint; content: string;
  nowMs: () => bigint; signal: AbortSignal;
}>;
/** Bridge the SAME private checked context and all three original receipts to
 * unsigned ciphertext and a V2 review context. The actual adapter must obtain
 * fresh held service facts and authentic original receipt times, retain custody
 * and journal both signing burns. No signature, HTTP, installed ACK or effect
 * permission is created here; a displayed active flag cannot enter this API. */
export async function prepareInstalledConversationMessage03(input: InstalledConversationMessageInput03): Promise<Readonly<{
  prepared: PreparedOutboundEnvelope03; reviewContext: ReviewContext03; statement: ConversationStatement03;
}>> {
  const p = record(input, ['context', 'statement', 'request', 'approval', 'installed', 'messageId',
    'observedMs', 'expiresMs', 'content', 'nowMs', 'signal']);
  const c = context(p.context as ConversationContext03), raw = captureElectionBytes03(p.statement as Uint8Array, 695, 1092);
  const request = receipt(p.request as ConversationReceiptSignature03), approval = receipt(p.approval as ConversationReceiptSignature03);
  const installed = receipt(p.installed as ConversationReceiptSignature03), messageId = nonzero(p.messageId, 16);
  if (!request || !approval || !installed || typeof p.content !== 'string' || typeof p.nowMs !== 'function'
      || !(p.signal instanceof AbortSignal)) fail('original installed proofs and live preparation required');
  const observed = p.observedMs as bigint, expires = p.expiresMs as bigint, signal = p.signal as AbortSignal;
  electionTime03(observed); electionTime03(expires);
  let floor = c.nowMs;
  const now = () => {
    if (signal.aborted) fail('preparation withdrawn'); const n = (p.nowMs as () => bigint)(); electionTime03(n);
    if (signal.aborted || n < floor) fail('preparation clock/withdrawal'); floor = n; return n;
  };
  const s = await verifyConversationReceipts03({ context: p.context as ConversationContext03, statement: raw,
    request, approval, installed, nowMs: now(), pending: false });
  const from = installed.timeMs > s.intervalFromMs ? installed.timeMs : s.intervalFromMs;
  const check = () => { const n = now(); binding(s, c, n, false); return n; };
  check();
  if (observed < from || expires > s.intervalUntilMs || expires > c.ownerDeadlineMs) fail('installed message bounds');
  const recipients = [{ role: 1 as const, keyId: c.currentAuthority.selectedReaderKeyId },
    { role: 2 as const, keyId: c.archiveReaderKeyId }, ...c.integrationReaders.map(r => ({ role: 3 as const, keyId: r.keyId }))];
  const reviewContext = await captureTrustedReviewContext03({ currentAuthority: c.currentAuthority,
    manifest: c.manifest, acceptedElection: c.acceptedElection, accountSelectionEpoch: c.selectionEpoch,
    ownerUserId: c.ownerUserId, ownerSessionId: c.ownerSessionId, canonicalOrigin: c.canonicalOrigin,
    intervalId: s.intervalId, intervalFromMs: from, intervalUntilMs: s.intervalUntilMs,
    peer: c.peer, signerKeyId: c.browserSignerKeyId, recipients, nowMs: check() });
  const k = binding(s, c, check(), false);
  const prepared = await prepareSealedOutboundEnvelope03({ manifest: c.manifest, acceptedElection: c.acceptedElection,
    currentAuthority: c.currentAuthority, nowMs: check(), messageId, observedMs: observed, expiresMs: expires,
    peer: c.peer, content: p.content, signerPublicPoint: k.outbound.signerPoint, recipients });
  check(); return Object.freeze({ prepared, reviewContext, statement: s });
}
