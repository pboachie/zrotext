// SPDX-License-Identifier: AGPL-3.0-only
/** Independent historical crypto and exact snapshot progress, never current
 * owner/device permission, original acceptance provenance or durable highwater.
 * The trusted adapter must supply immutable original evidence and a real first
 * election proof; caller projections cannot substitute for either proof token. */
import {
  captureElectionBytes03, electionTime03, verifiedAcceptedElectionIdentity03,
  requireCurrentElection03, type VerifiedAcceptedElection03, type DurableAcceptedElection03,
  captureCurrentElectionAuthority03, type CurrentElectionAuthority03,
} from './payload-profile-election03.js';
import {
  verifyManifest03Current, verifiedManifestIdentity03, type VerifiedManifest03,
} from './draft03-manifest.js';
import { verifyManifestInstallPossession03 } from './manifest-install03.js';
import { verifyProfile03ManifestOutput } from './profile03-manifest-proposal.js';

export const manifestEvidenceFields03 = ['root_pin', 'prior_manifest02', 'prior_accepted_ms',
  'accepted_manifest03', 'accepted_ms', 'bundle', 'device_signing_point', 'owner_approval_point',
  'registration_evidence', 'activation_evidence'] as const;
export type OriginalManifestEvidence03 = Readonly<Record<typeof manifestEvidenceFields03[number], string>>;
export type ManifestPosition03 = Readonly<{ version: bigint; digest: Uint8Array; ancestry: Uint8Array }>;
declare const historyBrand: unique symbol;
export type VerifiedManifestHistory03 = Readonly<{ [historyBrand]: true }>;
type State = Readonly<{
  proof: VerifiedAcceptedElection03; accepted: DurableAcceptedElection03; origin: string;
  challenge: Uint8Array; evidence: OriginalManifestEvidence03; manifest: VerifiedManifest03;
  signed: Uint8Array; acceptedMs: bigint; position: ManifestPosition03;
  tip: (ManifestPosition03 & Readonly<{ acceptedMs: bigint }>) | null;
  comparedMs: bigint; complete: boolean;
}>;
const histories = new WeakMap<VerifiedManifestHistory03, State>(), enc = new TextEncoder();
const max = (1n << 63n) - 1n;
function fail(): never { throw Error('Accepted manifest history03 refused'); }
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
function join(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; } return out;
}
function n64(n: bigint): Uint8Array<ArrayBuffer> {
  electionTime03(n); const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, n); return out;
}
async function sha(v: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', Uint8Array.from(v).buffer));
}
async function commitment(label: string, ...parts: Uint8Array[]): Promise<Uint8Array<ArrayBuffer>> {
  const value = join(...parts), size = new Uint8Array(4); new DataView(size.buffer).setUint32(0, value.length);
  return sha(join(enc.encode(label + '\0'), size, value));
}
function record(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value), keys = Reflect.ownKeys(descriptors);
  if (keys.length !== names.length || keys.some(k => typeof k !== 'string' || !names.includes(k))) fail();
  return Object.fromEntries(names.map(k => {
    const d = descriptors[k]; if (!d || !('value' in d) || !d.enumerable) fail(); return [k, d.value];
  }));
}
function array(value: unknown): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) fail();
  const d = Object.getOwnPropertyDescriptors(value) as Record<string, PropertyDescriptor>, n = d.length.value as number;
  if (!Number.isInteger(n) || n < 0 || n > 8 || Reflect.ownKeys(d).length !== n + 1) fail();
  return Array.from({ length: n }, (_, i) => { const v = d[i]; if (!v || !('value' in v)) fail(); return v.value; });
}
export function manifestHistoryDecimal03(value: unknown): bigint {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value)) fail();
  const n = BigInt(value); if (n > max) fail(); return n;
}
function uuid(value: unknown): Uint8Array {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)) fail();
  const b = Uint8Array.from(value.replaceAll('-', '').match(/../g)!, x => parseInt(x, 16));
  if (!b.some(v => v !== 0)) fail(); return b;
}
export function manifestHistoryBase64url03(value: Uint8Array): string {
  let raw = ''; for (const b of value) raw += String.fromCharCode(b);
  return btoa(raw).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
export function manifestHistoryBinary03(value: unknown, low: number, high = low): Uint8Array {
  if (typeof value !== 'string' || value.length > Math.ceil(high * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) fail();
  let raw: string; try { raw = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4)); } catch { return fail(); }
  const b = Uint8Array.from(raw, c => c.charCodeAt(0));
  if (b.length < low || b.length > high || manifestHistoryBase64url03(b) !== value) fail(); return b;
}
function evidence(value: unknown): OriginalManifestEvidence03 {
  const out = record(value, manifestEvidenceFields03);
  for (const k of manifestEvidenceFields03) {
    if (k === 'prior_accepted_ms' || k === 'accepted_ms') manifestHistoryDecimal03(out[k]);
    else manifestHistoryBinary03(out[k], k === 'root_pin' ? 94 : k.endsWith('_point') ? 65 : k === 'bundle' ? 628 : 1,
      k === 'root_pin' ? 94 : k.endsWith('_point') ? 65 : k === 'bundle' ? 628 : k.includes('evidence') ? 98304 : 9753);
  }
  return Object.freeze(out) as OriginalManifestEvidence03;
}
function state(handle: VerifiedManifestHistory03): State { const s = histories.get(handle); if (!s) fail(); return s; }
function save(s: State): VerifiedManifestHistory03 {
  const handle = Object.freeze({}) as VerifiedManifestHistory03; histories.set(handle, s); return handle;
}
function position(r: Record<string, unknown>, prefix: string): ManifestPosition03 {
  return { version: manifestHistoryDecimal03(r[prefix + '_version']), digest: manifestHistoryBinary03(r[prefix + '_digest'], 32),
    ancestry: manifestHistoryBinary03(r[prefix + '_ancestry_sha256'], 32) };
}
function equalPosition(a: ManifestPosition03, b: ManifestPosition03): boolean {
  return a.version === b.version && same(a.digest, b.digest) && same(a.ancestry, b.ancestry);
}
/** Start only at the exact original first03 checkpoint. Durable imported later
 * state is not accepted here; it must be reconstructed from retained originals. */
export async function startAcceptedManifestHistory03(input: Readonly<{
  acceptedElection: VerifiedAcceptedElection03; firstManifest: VerifiedManifest03;
  originalEvidence: OriginalManifestEvidence03; origin: string;
}>): Promise<VerifiedManifestHistory03> {
  const r = record(input, ['acceptedElection', 'firstManifest', 'originalEvidence', 'origin']);
  const proof = r.acceptedElection as VerifiedAcceptedElection03, a = verifiedAcceptedElectionIdentity03(proof);
  const first = r.firstManifest as VerifiedManifest03, e = evidence(r.originalEvidence), origin = r.origin;
  if (typeof origin !== 'string' || enc.encode(origin).length > 512) fail();
  const url = new URL(origin); if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password) fail();
  const signed = manifestHistoryBinary03(e.accepted_manifest03, 366, 9753), bundle = manifestHistoryBinary03(e.bundle, 628);
  const acceptedMs = manifestHistoryDecimal03(e.accepted_ms), id = verifiedManifestIdentity03(first, acceptedMs);
  if (acceptedMs !== a.acceptedAtMs || id.comparisonMs !== acceptedMs || id.version !== a.acceptedManifestVersion
      || id.generation !== 1n || !same(id.accountId, a.accountId) || !same(id.digest, a.acceptedManifestDigest)
      || !same(await sha(signed), a.acceptedSignedManifestSha256) || !same(await sha(bundle), a.electionBundleSha256)
      || !same(await sha(manifestHistoryBinary03(e.prior_manifest02, 364, 9751)), a.priorSignedManifestSha256)
      || !same(await sha(join(enc.encode('ZTSE/root-pin/v2\0'), manifestHistoryBinary03(e.root_pin, 94))), a.rootFingerprint)) fail();
  const manifest = await verifyManifest03Current(signed, first, acceptedMs), challenge = bundle.slice(56, 72);
  if (!challenge.some(v => v !== 0)) fail();
  const ancestry = await commitment('ZTSE/line/payload-profile/manifest-ancestry-base03/v1', a.accountId,
    challenge, a.newBindingId, await sha(signed), n64(acceptedMs), a.electionBundleSha256);
  return save({ proof, accepted: a, origin, challenge, evidence: e, manifest, signed, acceptedMs,
    position: { version: id.version, digest: id.digest, ancestry }, tip: null, comparedMs: acceptedMs, complete: false });
}
/** Owned request cursor only, not a signed checkpoint or permission. */
export function acceptedManifestHistoryCursor03(handle: VerifiedManifestHistory03): Readonly<{
  after: ManifestPosition03; tip: ManifestPosition03 | null; complete: boolean;
}> {
  const s = state(handle), copy = (p: ManifestPosition03) => ({ version: p.version, digest: Uint8Array.from(p.digest), ancestry: Uint8Array.from(p.ancestry) });
  return Object.freeze({ after: copy(s.position), tip: s.tip ? copy(s.tip) : null, complete: s.complete });
}
const pageNames = ['v', 'kind', 'account_id', 'device_id', 'line_id', 'binding_id', 'binding_generation', 'selection_epoch',
  'election_digest', 'election_bundle_sha256', 'root_fingerprint', 'after_version', 'after_digest', 'after_ancestry_sha256',
  'tip_version', 'tip_digest', 'tip_ancestry_sha256', 'tip_accepted_ms', 'compared_ms', 'entries', 'next_version', 'next_digest',
  'next_ancestry_sha256', 'complete', 'evidence'];
/** Verify one exact snapshot page. A new immutable handle prevents asynchronous
 * mutation/racing page application from changing an existing verified cursor. */
export async function continueAcceptedManifestHistory03(handle: VerifiedManifestHistory03, candidate: unknown): Promise<VerifiedManifestHistory03> {
  const s = state(handle), r = record(candidate, pageNames), a = s.accepted, e = evidence(r.evidence);
  const after = position(r, 'after'), tip = { ...position(r, 'tip'), acceptedMs: manifestHistoryDecimal03(r.tip_accepted_ms) };
  const next = position(r, 'next'), comparedMs = manifestHistoryDecimal03(r.compared_ms);
  const entries = array(r.entries).map(value => {
    const v = record(value, ['opening_id', 'statement', 'signature', 'successor_manifest03', 'accepted_ms']);
    return { opening: uuid(v.opening_id), statement: manifestHistoryBinary03(v.statement, 513), signature: manifestHistoryBinary03(v.signature, 64),
      signed: manifestHistoryBinary03(v.successor_manifest03, 366, 9753), acceptedMs: manifestHistoryDecimal03(v.accepted_ms) };
  });
  if (r.v !== 1 || r.kind !== 'manifest_ancestry03' || typeof r.complete !== 'boolean'
      || manifestEvidenceFields03.some(k => e[k] !== s.evidence[k])
      || !same(uuid(r.account_id), a.accountId) || !same(uuid(r.device_id), a.deviceId) || !same(uuid(r.line_id), a.lineId)
      || !same(uuid(r.binding_id), a.newBindingId) || manifestHistoryDecimal03(r.binding_generation) !== a.newBindingGeneration
      || r.selection_epoch !== '1' || !same(manifestHistoryBinary03(r.root_fingerprint, 32), a.rootFingerprint)
      || !same(manifestHistoryBinary03(r.election_digest, 32), a.electionCommitment)
      || !same(manifestHistoryBinary03(r.election_bundle_sha256, 32), a.electionBundleSha256)
      || !equalPosition(after, s.position) || s.tip && (!equalPosition(tip, s.tip) || tip.acceptedMs !== s.tip.acceptedMs)
      || tip.version < s.position.version || tip.acceptedMs < s.acceptedMs || comparedMs < s.comparedMs
      || comparedMs < tip.acceptedMs || entries.reduce((n, v) => n + 16 + v.statement.length + v.signature.length + v.signed.length + 8, 0) > 65536) fail();
  let manifest = s.manifest, signed = s.signed, acceptedMs = s.acceptedMs, p = s.position;
  const originDigest = await sha(enc.encode(s.origin));
  for (const row of entries) {
    const f = await verifyManifestInstallPossession03(row.statement, row.signature);
    if (!same(row.opening, f.openingId) || !same(f.accountId, a.accountId) || !same(f.deviceId, a.deviceId)
        || !same(f.lineId, a.lineId) || !same(f.bindingId, a.newBindingId) || !same(f.electionChallengeId, s.challenge)
        || f.bindingGeneration !== a.newBindingGeneration || f.predecessorVersion !== p.version || f.successorVersion > tip.version
        || !same(f.predecessorDigest, p.digest) || !same(f.rootFingerprint, a.rootFingerprint)
        || !same(f.electionCommitment, a.electionCommitment) || !same(f.electionBundleSha256, a.electionBundleSha256)
        || !same(f.originDigest, originDigest) || row.acceptedMs < acceptedMs || row.acceptedMs < f.issuedMs
        || row.acceptedMs >= f.expiresMs || row.acceptedMs > comparedMs || !same(f.signedSuccessorSha256, await sha(row.signed))
        || !same(f.ownerSessionDigest, await commitment('ZTSE/line/payload-profile/owner-session/v1', a.accountId, f.ownerUserId, f.ownerSessionId))) fail();
    const active = Array.from({ length: signed[152] }, (_, i) => signed.slice(153 + i * 149, 153 + (i + 1) * 149))
      .filter(k => k[0] === 5 && k[148] === 1 && same(k.subarray(114, 130), a.lineId));
    const operation = active.length === 0 ? 'enroll' : same(active[0].subarray(1, 33), f.signerKeyId) ? 'renew' : 'replace';
    const view = new DataView(row.signed.buffer);
    if (f.signerPoint.length !== 65 || same(f.signerPoint, manifestHistoryBinary03(s.evidence.device_signing_point, 65))
        || same(f.signerPoint, manifestHistoryBinary03(s.evidence.owner_approval_point, 65))
        || same(f.signerPoint, manifestHistoryBinary03(s.evidence.root_pin, 94).subarray(29))) fail();
    manifest = await verifyProfile03ManifestOutput({ predecessor: manifest, originalSigned03: signed, nowMs: row.acceptedMs, signed03: row.signed,
      scope: { operation, accountId: a.accountId, deviceId: a.deviceId, lineId: a.lineId, origin: s.origin,
        rootFingerprint: a.rootFingerprint, predecessorVersion: p.version, predecessorDigest: p.digest, predecessorAcceptedMs: acceptedMs,
        phoneReaderKeyId: a.selectedReaderKeyId, browserPoint: f.signerPoint, browserKeyId: f.signerKeyId,
        issuedMs: view.getBigUint64(39), expiresMs: view.getBigUint64(47) } });
    const id = verifiedManifestIdentity03(manifest, row.acceptedMs);
    if (id.version !== f.successorVersion) fail();
    p = { version: id.version, digest: id.digest, ancestry: await commitment('ZTSE/line/payload-profile/manifest-ancestry-step03/v1',
      p.ancestry, row.opening, await sha(row.statement), await sha(row.signature), await sha(row.signed), n64(row.acceptedMs)) };
    signed = row.signed; acceptedMs = row.acceptedMs;
  }
  if (!equalPosition(p, next) || r.complete !== equalPosition(p, tip) || r.complete && acceptedMs !== tip.acceptedMs
      || !r.complete && entries.length === 0) fail();
  return save({ ...s, manifest, signed, acceptedMs, position: p, tip, comparedMs, complete: r.complete });
}
/** Final genuine crypto token checked against a SEPARATE trusted present read.
 * No raw DTO is converted to authority here; original source/auth/physical
 * selection and durable monotonic persistence remain adapter obligations. */
export async function requireAcceptedManifestHistoryCurrent03(handle: VerifiedManifestHistory03,
  current: CurrentElectionAuthority03, exactSigned: Uint8Array, ancestry: Uint8Array, nowMs: bigint): Promise<VerifiedManifest03> {
  const s = state(handle), signed = captureElectionBytes03(exactSigned, 366, 9753), prefix = captureElectionBytes03(ancestry, 32);
  const authority = captureCurrentElectionAuthority03(current);
  if (!s.complete || !s.tip || nowMs < s.comparedMs || !same(s.signed, signed) || !same(s.position.ancestry, prefix)
      || authority.comparedAtMs < s.comparedMs || authority.manifestVersion !== s.position.version
      || !same(authority.manifestDigest, s.position.digest)) fail();
  requireCurrentElection03(s.proof, s.manifest, authority, nowMs);
  return verifyManifest03Current(signed, s.manifest, nowMs);
}

/** Separate bounded parser for the additive history/current DTOs. Existing
 * first-only profile parsers are unchanged. Detect decoded duplicate keys before
 * object construction; prototype names, deep nesting and oversized lists refuse. */
function parse(raw: string): unknown {
  let at = 0;
  const space = () => { while (at < raw.length && /[ \t\r\n]/.test(raw[at])) at++; };
  const string = () => {
    const start = at++;
    while (at < raw.length) {
      const c = raw[at++]; if (c === '"') { try { return JSON.parse(raw.slice(start, at)) as string; } catch { return fail(); } }
      if (c === '\\') at++;
    } return fail();
  };
  function value(depth: number): unknown {
    space(); if (depth > 4) fail();
    if (raw[at] === '"') return string();
    if (raw[at] === '{') {
      at++; const out: Record<string, unknown> = Object.create(null), seen = new Set<string>(); space();
      if (raw[at] === '}') { at++; return out; }
      while (at < raw.length) {
        space(); if (raw[at] !== '"') fail(); const k = string();
        if (seen.has(k) || seen.size >= 64 || k.length > 128 || k === '__proto__') fail(); seen.add(k);
        space(); if (raw[at++] !== ':') fail(); out[k] = value(depth + 1); space();
        const end = raw[at++]; if (end === '}') return out; if (end !== ',') fail();
      } return fail();
    }
    if (raw[at] === '[') {
      at++; const out: unknown[] = []; space(); if (raw[at] === ']') { at++; return out; }
      while (at < raw.length) {
        if (out.length >= 8) fail(); out.push(value(depth + 1)); space();
        const end = raw[at++]; if (end === ']') return out; if (end !== ',') fail();
      } return fail();
    }
    for (const [word, result] of [['true', true], ['false', false], ['null', null]] as const) {
      if (raw.startsWith(word, at)) { at += word.length; return result; }
    }
    if (raw[at] === '1' || raw[at] === '3') return Number(raw[at++]); return fail();
  }
  const out = value(0); space(); if (at !== raw.length) fail(); return out;
}
const currentNames = ['v', 'kind', 'envelope_profile', 'manifest_profile', 'account_id', 'user_id', 'owner_session_id',
  'device_id', 'line_id', 'selection_epoch', 'origin_digest', 'owner_session_digest', 'device_session_digest', 'site_id', 'instance_id',
  'connection_epoch', 'deployment_epoch', 'old_binding_id', 'old_binding_generation', 'old_binding_proof_digest', 'binding_id',
  'binding_generation', 'reader_key_id', 'device_signing_key_id', 'approval_key_id', 'root_fingerprint', 'trust_generation',
  'manifest_version', 'manifest_digest', 'election_digest', 'election_bundle_sha256', 'compared_ms', 'permission_expires_ms',
  'physical_selection', 'current_manifest03', 'manifest_ancestry_sha256', 'evidence'];
export type OwnerManifestHistoryOptions03 = Readonly<{
  origin: string; accountId: string; userId: string; ownerSessionId: string;
  currentCsrf: () => string; signal: AbortSignal; timeoutMs?: number; fetchImpl?: typeof fetch;
}>;
export type OriginalManifestBootstrapCandidate03 = Readonly<{
  v: 1; kind: 'manifest_original03'; line_id: string; binding_id: string; evidence: OriginalManifestEvidence03;
}>;
/** Actual fixed same-origin owner transport. Reads one bounded history page per
 * explicit call; no automatic mutation, new key, renewal, retry or factor use.
 * These reads still depend on the configured service's real cookie auth and
 * selected records. They do not attest browser/phone private-key custody. */
export class OwnerManifestHistoryClient03 {
  readonly #options: OwnerManifestHistoryOptions03; readonly #csrf: string;
  #busy = false; #lastCompared = 0n; #lastLocalMs = 0n;
  constructor(options: OwnerManifestHistoryOptions03) {
    const r = record(options, ['origin', 'accountId', 'userId', 'ownerSessionId', 'currentCsrf', 'signal',
      ...['timeoutMs', 'fetchImpl'].filter(k => Object.hasOwn(options, k))]);
    if (typeof r.origin !== 'string' || enc.encode(r.origin).length > 512) fail();
    const u = new URL(r.origin); if (u.protocol !== 'https:' || u.origin !== r.origin || u.username || u.password) fail();
    for (const name of ['accountId', 'userId', 'ownerSessionId']) uuid(r[name]);
    if (typeof r.currentCsrf !== 'function' || !(r.signal instanceof AbortSignal) || r.fetchImpl !== undefined && typeof r.fetchImpl !== 'function') fail();
    const timeout = r.timeoutMs ?? 15000;
    if (typeof timeout !== 'number' || !Number.isSafeInteger(timeout) || timeout < 1 || timeout > 60000) fail();
    this.#options = Object.freeze({ ...r, timeoutMs: timeout }) as OwnerManifestHistoryOptions03;
    this.#csrf = this.#readCsrf(); this.#check();
  }
  #readCsrf(): string {
    const c = this.#options.currentCsrf(); if (typeof c !== 'string' || !c.startsWith('ztc_') || c.length !== 47) fail();
    manifestHistoryBinary03(c.slice(4), 32); return c;
  }
  #check(): void { if (this.#options.signal.aborted || this.#readCsrf() !== this.#csrf) fail(); }
  async #run<T>(handle: VerifiedManifestHistory03, op: (s: State, signal: AbortSignal) => Promise<T>): Promise<T> {
    this.#check(); const s = state(handle);
    if (s.origin !== this.#options.origin || !same(s.accepted.accountId, uuid(this.#options.accountId))) fail();
    return this.#operation(signal => op(s, signal));
  }
  async #operation<T>(op: (signal: AbortSignal) => Promise<T>): Promise<T> {
    this.#check(); if (this.#busy) fail();
    this.#busy = true; const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const close = () => abort.abort(); this.#options.signal.addEventListener('abort', close, { once: true });
    try {
      return await Promise.race([op(abort.signal).then(v => { this.#check(); if (abort.signal.aborted) fail(); return v; }),
        new Promise<never>((_, reject) => {
          const refuse = () => reject(Error('Owner manifest read unavailable'));
          abort.signal.addEventListener('abort', refuse, { once: true });
          timer = setTimeout(() => abort.abort(), this.#options.timeoutMs);
          if (abort.signal.aborted) refuse();
        })]);
    } catch { throw Error('Owner manifest read unavailable'); }
    finally { clearTimeout(timer); this.#options.signal.removeEventListener('abort', close); abort.abort(); this.#busy = false; }
  }
  async #request(path: 'original' | 'history' | 'current', body: object, signal: AbortSignal): Promise<unknown> {
    this.#check(); if (signal.aborted) fail();
    const response = await (this.#options.fetchImpl ?? fetch)(this.#options.origin + '/v1/account/sealed/payload-profile/manifests/' + path, {
      method: 'POST', mode: 'same-origin', credentials: 'same-origin', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer', signal,
      headers: { 'content-type': 'application/json', accept: 'application/json', 'x-zrotext-csrf': this.#csrf }, body: JSON.stringify(body),
    });
    this.#check(); if (signal.aborted || response.status !== 200 || response.redirected
        || response.url && response.url !== this.#options.origin + '/v1/account/sealed/payload-profile/manifests/' + path
        || response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json' || !response.body) fail();
    const reader = response.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
    const cancel = () => { void reader.cancel().catch(() => {}); }; signal.addEventListener('abort', cancel, { once: true });
    try {
      while (true) {
        const chunk = await reader.read(); this.#check(); if (signal.aborted) fail(); if (chunk.done) break;
        size += chunk.value.byteLength; if (size > 192 * 1024) fail(); chunks.push(Uint8Array.from(chunk.value));
      }
      return parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(join(...chunks)));
    } finally { signal.removeEventListener('abort', cancel); cancel(); reader.releaseLock(); }
  }
  /** Cold bootstrap candidates only, BEFORE a history handle exists. The caller
   * must independently verify compared root, original proofs and historical
   * acceptance before startAcceptedManifestHistory03. No current tuple/physical
   * handle is created from this historical public response. */
  async original(lineId: string): Promise<OriginalManifestBootstrapCandidate03> {
    uuid(lineId);
    return this.#operation(async signal => {
      const r = record(await this.#request('original', { v: 1, line_id: lineId }, signal), ['v', 'kind', 'line_id', 'binding_id', 'evidence']);
      const e = evidence(r.evidence), pin = manifestHistoryBinary03(e.root_pin, 94), bundle = manifestHistoryBinary03(e.bundle, 628);
      if (r.v !== 1 || r.kind !== 'manifest_original03' || r.line_id !== lineId
          || !same(pin.subarray(0, 5), Uint8Array.of(90, 84, 82, 80, 2))
          || !same(pin.subarray(5, 21), uuid(this.#options.accountId))
          || !same(bundle.subarray(8, 24), uuid(this.#options.accountId)) || !same(bundle.subarray(40, 56), uuid(lineId))) fail();
      uuid(r.binding_id);
      return Object.freeze({ v: 1, kind: 'manifest_original03', line_id: lineId, binding_id: r.binding_id as string, evidence: e });
    });
  }
  async next(handle: VerifiedManifestHistory03): Promise<VerifiedManifestHistory03> {
    return this.#run(handle, async (s, signal) => {
      const p = s.position, t = s.tip, b = manifestHistoryBase64url03;
      const value = await this.#request('history', { v: 1, line_id: uuidText(s.accepted.lineId), after_version: String(p.version), after_digest: b(p.digest),
        after_ancestry_sha256: b(p.ancestry), tip_version: t ? String(t.version) : null, tip_digest: t ? b(t.digest) : null,
        tip_ancestry_sha256: t ? b(t.ancestry) : null }, signal);
      const verified = await continueAcceptedManifestHistory03(handle, value), compared = state(verified).comparedMs;
      if (compared < this.#lastCompared) fail(); this.#lastCompared = compared; return verified;
    });
  }
  async current(handle: VerifiedManifestHistory03, nowMs: () => bigint): Promise<Readonly<{
    manifest: VerifiedManifest03; acceptedElection: VerifiedAcceptedElection03; currentAuthority: CurrentElectionAuthority03;
  }>> {
    return this.#run(handle, async (s, signal) => {
      if (!s.complete || typeof nowMs !== 'function') fail(); const started = nowMs(); electionTime03(started);
      if (started < this.#lastLocalMs) fail();
      const r = record(await this.#request('current', { v: 1, line_id: uuidText(s.accepted.lineId) }, signal), currentNames), a = s.accepted;
      const currentMs = nowMs(); electionTime03(currentMs); if (currentMs < started) fail();
      const original = evidence(r.evidence);
      if (r.v !== 1 || r.kind !== 'owner_manifest_selection03' || r.envelope_profile !== 3 || r.manifest_profile !== 3
          || r.selection_epoch !== '1' || r.trust_generation !== '1' || r.account_id !== this.#options.accountId
          || r.user_id !== this.#options.userId || r.owner_session_id !== this.#options.ownerSessionId
          || !same(uuid(r.device_id), a.deviceId) || !same(uuid(r.line_id), a.lineId) || !same(uuid(r.old_binding_id), a.oldBindingId)
          || manifestHistoryDecimal03(r.old_binding_generation) !== a.oldBindingGeneration
          || !same(manifestHistoryBinary03(r.old_binding_proof_digest, 32), a.oldBindingProofDigest)
          || !same(manifestHistoryBinary03(r.origin_digest, 32), await sha(enc.encode(s.origin)))
          || !same(manifestHistoryBinary03(r.owner_session_digest, 32), await commitment('ZTSE/line/payload-profile/owner-session/v1',
            a.accountId, uuid(r.user_id), uuid(r.owner_session_id)))
          || manifestEvidenceFields03.some(k => original[k] !== s.evidence[k])) fail();
      for (const name of ['site_id', 'instance_id']) if (typeof r[name] !== 'string' || !(r[name] as string).length || (r[name] as string).length > 256) fail();
      for (const name of ['connection_epoch', 'deployment_epoch']) manifestHistoryDecimal03(r[name]);
      for (const name of ['device_session_digest', 'device_signing_key_id', 'approval_key_id']) {
        if (!manifestHistoryBinary03(r[name], 32).some(v => v !== 0)) fail();
      }
      for (const [name, point] of [['device_signing_key_id', 'device_signing_point'], ['approval_key_id', 'owner_approval_point']] as const) {
        if (!same(manifestHistoryBinary03(r[name], 32), await sha(join(enc.encode('ZTSE/key/v1\0'), Uint8Array.of(1, 1), manifestHistoryBinary03(s.evidence[point], 65))))) fail();
      }
      const physical = record(r.physical_selection, ['kind', ...(r.physical_selection && typeof r.physical_selection === 'object'
        && Object.getOwnPropertyDescriptor(r.physical_selection, 'kind')?.value === 'owner_refresh03' ? ['refresh_id', 'bundle', 'accepted_ms', 'installed_ms'] : [])]);
      if (physical.kind === 'owner_refresh03') {
        uuid(physical.refresh_id); manifestHistoryBinary03(physical.bundle, 745);
        const accepted = manifestHistoryDecimal03(physical.accepted_ms), installed = manifestHistoryDecimal03(physical.installed_ms);
        if (accepted < a.acceptedAtMs || installed < accepted || installed > currentMs) fail();
      } else if (physical.kind !== 'original_v2') fail();
      const authority: CurrentElectionAuthority03 = { profile: 3, manifestProfile: 3, accountId: uuid(r.account_id), deviceId: uuid(r.device_id), lineId: uuid(r.line_id),
        bindingId: uuid(r.binding_id), bindingGeneration: manifestHistoryDecimal03(r.binding_generation), selectedReaderKeyId: manifestHistoryBinary03(r.reader_key_id, 32),
        rootFingerprint: manifestHistoryBinary03(r.root_fingerprint, 32), vaultGeneration: 1n, manifestVersion: manifestHistoryDecimal03(r.manifest_version),
        manifestDigest: manifestHistoryBinary03(r.manifest_digest, 32), electionCommitment: manifestHistoryBinary03(r.election_digest, 32),
        electionBundleSha256: manifestHistoryBinary03(r.election_bundle_sha256, 32), comparedAtMs: manifestHistoryDecimal03(r.compared_ms),
        permissionExpiresAtMs: manifestHistoryDecimal03(r.permission_expires_ms) };
      if (authority.comparedAtMs < this.#lastCompared) fail();
      const manifest = await requireAcceptedManifestHistoryCurrent03(handle, authority, manifestHistoryBinary03(r.current_manifest03, 366, 9753),
        manifestHistoryBinary03(r.manifest_ancestry_sha256, 32), currentMs);
      const finishedMs = nowMs(); electionTime03(finishedMs); if (finishedMs < currentMs) fail();
      requireCurrentElection03(s.proof, manifest, authority, finishedMs);
      const fresh = await verifyManifest03Current(s.signed, manifest, finishedMs);
      // A verifier wait can cross expiry or a clock boundary. Make the last
      // permission check synchronous AFTER that wait, immediately before release.
      const releasedMs = nowMs(); electionTime03(releasedMs); if (releasedMs < finishedMs) fail();
      requireCurrentElection03(s.proof, fresh, authority, releasedMs);
      this.#lastLocalMs = releasedMs;
      this.#lastCompared = authority.comparedAtMs;
      return Object.freeze({ manifest: fresh, acceptedElection: s.proof, currentAuthority: captureCurrentElectionAuthority03(authority) });
    });
  }
}
function uuidText(bytes: Uint8Array): string {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
}
