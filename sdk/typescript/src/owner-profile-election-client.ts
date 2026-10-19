// SPDX-License-Identifier: AGPL-3.0-only
/** Owner election transport. Returned candidates are not signature verification,
 * current device permission, an installed reader, or authority to send. */
import { captureElectionBytes03 } from './payload-profile-election03.js';
import { isCanonicalP256Signature } from './draft01.js';

export type ElectionRecovery03 = Readonly<{
  v: 1; origin: string; account_id: string; user_id: string; owner_session_id: string;
  device_id: string; root_fingerprint: string; opening_id: string; line_id: string;
  successor_manifest03: string;
}>;
export type ElectionCredentials03 = Readonly<{ password: string; factor: string }>;
export type ClosedUnacceptedCandidate03 = Readonly<{
  openingId: string; challengeId: string; newBindingId: string; core: Uint8Array;
  closedUnacceptedMs: bigint; supersededByChallengeId: string;
}>;
export type ElectionReservationCandidate03 = Readonly<{
  openingId: string; challengeId: string; newBindingId: string; core: Uint8Array;
  successorManifest03: Uint8Array; issuedMs: bigint; expiresMs: bigint; status: 'reserved' | 'accepted';
  closedUnaccepted: readonly ClosedUnacceptedCandidate03[];
}>;
export type ElectionReceiptCandidate03 = Readonly<{
  openingId: string; challengeId: string; bindingId: string; bindingGeneration: bigint;
  electionDigest: Uint8Array; bundleSha256: Uint8Array; acceptedMs: bigint; selectionEpoch: bigint;
}>;
const ids = ['account_id', 'user_id', 'owner_session_id', 'device_id', 'line_id', 'old_binding_id', 'binding_id'] as const;
const counters = ['selection_epoch', 'connection_epoch', 'deployment_epoch', 'old_binding_generation',
  'binding_generation', 'trust_generation', 'manifest_version', 'compared_ms', 'permission_expires_ms'] as const;
const digests = ['origin_digest', 'owner_session_digest', 'device_session_digest', 'old_binding_proof_digest',
  'reader_key_id', 'device_signing_key_id', 'approval_key_id', 'root_fingerprint', 'manifest_digest',
  'election_digest', 'election_bundle_sha256'] as const;
const evidenceNames = ['root_pin', 'prior_manifest02', 'prior_accepted_ms', 'accepted_manifest03', 'accepted_ms',
  'bundle', 'device_signing_point', 'owner_approval_point', 'registration_evidence', 'activation_evidence'] as const;
export type CurrentProfileCandidate03 = Readonly<{
  v: 1; envelope_profile: 3; manifest_profile: 3; site_id: string; instance_id: string;
  evidence: Readonly<Record<typeof evidenceNames[number], string>>;
} & Record<typeof ids[number] | typeof counters[number] | typeof digests[number], string>>;
const originalIds = ['account_id', 'user_id', 'owner_session_id', 'device_id', 'line_id', 'old_binding_id'] as const;
const originalCounters = ['selection_epoch', 'connection_epoch', 'deployment_epoch', 'old_binding_generation',
  'trust_generation', 'manifest_version', 'compared_ms', 'permission_expires_ms'] as const;
const originalDigests = ['origin_digest', 'owner_session_digest', 'device_session_digest', 'old_binding_proof_digest',
  'reader_key_id', 'device_signing_key_id', 'approval_key_id', 'root_fingerprint', 'manifest_digest'] as const;
const originalEvidence = ['root_pin', 'prior_manifest02', 'prior_accepted_ms', 'device_signing_point',
  'owner_approval_point', 'registration_evidence', 'activation_evidence'] as const;
export type OriginalProfileCandidate02 = Readonly<{
  v: 1; envelope_profile: 2; manifest_profile: 2; site_id: string; instance_id: string;
  evidence: Readonly<Record<typeof originalEvidence[number], string>>;
} & Record<typeof originalIds[number] | typeof originalCounters[number] | typeof originalDigests[number], string>>;
export type OwnerProfileElectionOptions03 = Readonly<{
  origin: string; accountId: string; userId: string; ownerSessionId: string; deviceId: string;
  /** Previously independently compared root, never copied from this HTTP response. */
  rootFingerprint: Uint8Array; currentCsrf: () => string;
  /** Persist the PUBLIC recovery record before network admission. Never receives factors. */
  saveRecovery: (record: ElectionRecovery03) => Promise<void>;
  signal: AbortSignal; timeoutMs?: number; fetchImpl?: typeof fetch;
}>;
export class OwnerProfileElectionError03 extends Error {
  constructor(readonly code: string, readonly outcome: 'refused' | 'unknown' = 'refused') {
    super('Owner profile operation unavailable'); this.name = 'OwnerProfileElectionError03';
  }
}
const MAX = (1n << 63n) - 1n, RESPONSE_MAX = 192 * 1024, REQUEST_MAX = 96 * 1024;
const basePath = '/v1/account/sealed/payload-profile', enc = new TextEncoder();
const recoveryNames = ['v', 'origin', 'account_id', 'user_id', 'owner_session_id', 'device_id',
  'root_fingerprint', 'opening_id', 'line_id', 'successor_manifest03'];
function fail(code = 'invalid'): never { throw new OwnerProfileElectionError03(code); }
function record(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value), actual = Reflect.ownKeys(descriptors);
  if (actual.length !== keys.length || actual.some(k => typeof k !== 'string' || !keys.includes(k))) fail();
  const out: Record<string, unknown> = Object.create(null);
  for (const k of keys) { const d = descriptors[k]; if (!d || !('value' in d) || !d.enumerable) fail(); out[k] = d.value; }
  return out;
}
function uuid(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
    || value === '00000000-0000-0000-0000-000000000000') fail(); return value;
}
function uuidBytes(value: string): Uint8Array { return Uint8Array.from(value.replaceAll('-', '').match(/../g)!, b => parseInt(b, 16)); }
function uuidText(value: Uint8Array): string {
  const h = [...value].map(b => b.toString(16).padStart(2, '0')).join('');
  return uuid(h.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5'));
}
function decimal(value: unknown): bigint {
  if (typeof value !== 'string' || !/^[1-9][0-9]{0,18}$/.test(value)) fail();
  const n = BigInt(value); if (n > MAX) fail(); return n;
}
function b64(bytes: Uint8Array): string {
  let raw = ''; for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
function binary(value: unknown, min: number, max = min, nonzero = false): Uint8Array {
  if (typeof value !== 'string' || value.length > Math.ceil(max * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(value)) fail();
  let raw: string; try { raw = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4)); }
  catch { return fail(); }
  const bytes = Uint8Array.from(raw, c => c.charCodeAt(0));
  if (bytes.length < min || bytes.length > max || b64(bytes) !== value || nonzero && !bytes.some(b => b !== 0)) fail();
  return bytes;
}
function same(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((v, i) => v === b[i]); }
function frame(label: string, value: Uint8Array): Uint8Array {
  const prefix = enc.encode(label + '\0'), out = new Uint8Array(prefix.length + 4 + value.length);
  out.set(prefix); new DataView(out.buffer).setUint32(prefix.length, value.length, false); out.set(value, prefix.length + 4); return out;
}
async function sha(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', Uint8Array.from(value).buffer));
}
function origin(value: unknown): string {
  if (typeof value !== 'string' || enc.encode(value).length > 512) fail();
  let u: URL; try { u = new URL(value); } catch { return fail(); }
  if (u.protocol !== 'https:' || u.origin !== value || u.username || u.password) fail(); return value;
}
function csrf(value: unknown): string {
  if (typeof value !== 'string' || !value.startsWith('ztc_') || value.length !== 47) fail('session_changed');
  binary(value.slice(4), 32); return value;
}
function credentials(value: ElectionCredentials03): ElectionCredentials03 {
  const r = record(value, ['password', 'factor']);
  if (typeof r.password !== 'string' || enc.encode(r.password).length < 1 || enc.encode(r.password).length > 1024
    || typeof r.factor !== 'string') fail();
  if (!/^[0-9]{6}$/.test(r.factor)) {
    if (!r.factor.startsWith('zrc_') || r.factor.length !== 26) fail(); binary(r.factor.slice(4), 16);
  }
  return { password: r.password, factor: r.factor };
}
/** Closed bounded JSON, detecting decoded duplicate keys before DTO validation. */
function json(raw: string): unknown {
  let at = 0;
  const whitespace = () => { while (at < raw.length && /[ \r\n\t]/.test(raw[at])) at++; };
  function string(): string {
    const start = at++;
    while (at < raw.length) { const c = raw[at++]; if (c === '"') {
      try { return JSON.parse(raw.slice(start, at)); } catch { return fail('response'); }
    } if (c === '\\') at++; } return fail('response');
  }
  function value(depth: number): unknown {
    whitespace(); if (depth > 3) fail('response');
    if (raw[at] === '"') return string();
    if (raw[at] === '{') {
      at++; const out: Record<string, unknown> = Object.create(null), seen = new Set<string>(); whitespace();
      if (raw[at] === '}') { at++; return out; }
      while (at < raw.length) {
        whitespace(); if (raw[at] !== '"') fail('response'); const key = string();
        if (seen.has(key) || seen.size >= 64 || key.length > 128 || key === '__proto__') fail('response');
        seen.add(key); whitespace(); if (raw[at++] !== ':') fail('response'); out[key] = value(depth + 1); whitespace();
        const end = raw[at++]; if (end === '}') return out; if (end !== ',') fail('response');
      } return fail('response');
    }
    if (raw[at] === '[') {
      at++; const out: unknown[] = []; whitespace();
      if (raw[at] === ']') { at++; return out; }
      while (at < raw.length) {
        if (out.length >= 16) fail('response'); out.push(value(depth + 1)); whitespace();
        const end = raw[at++]; if (end === ']') return out; if (end !== ',') fail('response');
      } return fail('response');
    }
    // Only version/profile constants are JSON numbers. Counters are decimal strings.
    if (raw[at] === '1' || raw[at] === '2' || raw[at] === '3') return Number(raw[at++]);
    return fail('response');
  }
  const parsed = value(0); whitespace(); if (at !== raw.length) fail('response'); return parsed;
}
function wait<T>(promise: Promise<T>, signal: AbortSignal, deadline: number, localParser = false): Promise<T> {
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (fn: () => void) => { if (done) return; done = true; clearTimeout(timer); signal.removeEventListener('abort', abort); fn(); };
    const abort = () => finish(() => reject(new OwnerProfileElectionError03('closed')));
    const timer = setTimeout(() => finish(() => reject(new OwnerProfileElectionError03('timeout'))), Math.max(0, deadline - performance.now()));
    signal.addEventListener('abort', abort, { once: true }); if (signal.aborted) abort();
    promise.then(v => finish(() => resolve(v)), error => finish(() => reject(
      localParser && error instanceof OwnerProfileElectionError03 ? error : new OwnerProfileElectionError03('unavailable'))));
  });
}
const errors: Record<number, readonly string[]> = {
  400: ['invalid_request'], 401: ['authentication_required'], 403: ['origin_or_csrf_refused'], 404: ['not_found'],
  409: ['conflict'], 410: ['expired'], 422: ['unsupported_state'], 429: ['rate_limited'], 503: ['temporarily_unavailable'],
};

export class OwnerProfileElectionClient03 {
  readonly #origin: string; readonly #account: string; readonly #user: string; readonly #session: string;
  readonly #device: string; readonly #root: string; readonly #csrfValue: string; readonly #options: OwnerProfileElectionOptions03;
  readonly #abort = new AbortController(); readonly #parentAbort: () => void;
  #busy = false; #closed = false; #lastCompared = 0n; #opening: ElectionRecovery03 | null = null;
  constructor(options: OwnerProfileElectionOptions03) {
    const o = record(options, ['origin', 'accountId', 'userId', 'ownerSessionId', 'deviceId', 'rootFingerprint',
      'currentCsrf', 'saveRecovery', 'signal', ...['timeoutMs', 'fetchImpl'].filter(k => Object.hasOwn(options, k))]);
    this.#origin = origin(o.origin); this.#account = uuid(o.accountId); this.#user = uuid(o.userId);
    this.#session = uuid(o.ownerSessionId); this.#device = uuid(o.deviceId);
    this.#root = b64(captureElectionBytes03(o.rootFingerprint as Uint8Array, 32)); binary(this.#root, 32, 32, true);
    if (typeof o.currentCsrf !== 'function' || typeof o.saveRecovery !== 'function' || !(o.signal instanceof AbortSignal)
      || o.fetchImpl !== undefined && typeof o.fetchImpl !== 'function') fail();
    const timeout = o.timeoutMs ?? 15_000; if (!Number.isSafeInteger(timeout) || (timeout as number) < 1 || (timeout as number) > 60_000) fail();
    this.#options = Object.freeze({ ...o, timeoutMs: timeout }) as OwnerProfileElectionOptions03;
    this.#csrfValue = csrf(this.#options.currentCsrf()); this.#parentAbort = () => this.close();
    this.#options.signal.addEventListener('abort', this.#parentAbort, { once: true });
    if (this.#options.signal.aborted) this.close();
  }
  close(): void {
    this.#closed = true; this.#abort.abort(); this.#options.signal.removeEventListener('abort', this.#parentAbort);
  }
  #live(): void {
    if (this.#closed || this.#options.signal.aborted) fail('closed');
    let current: string; try { current = csrf(this.#options.currentCsrf()); } catch { this.close(); return fail('session_changed'); }
    if (current !== this.#csrfValue) { this.close(); fail('session_changed'); }
  }
  #recovery(value: ElectionRecovery03): ElectionRecovery03 {
    const r = record(value, recoveryNames);
    if (r.v !== 1 || r.origin !== this.#origin || r.account_id !== this.#account || r.user_id !== this.#user
      || r.owner_session_id !== this.#session || r.device_id !== this.#device || r.root_fingerprint !== this.#root) fail('scope');
    uuid(r.opening_id); uuid(r.line_id); binary(r.successor_manifest03, 366, 9753);
    if (this.#opening && ['opening_id', 'line_id', 'successor_manifest03'].some(k => r[k] !== this.#opening![k as keyof ElectionRecovery03])) fail('opening_conflict');
    const captured = Object.freeze({ ...r }) as ElectionRecovery03; this.#opening = captured; return captured;
  }
  createOpening(lineId: string, successor: Uint8Array): ElectionRecovery03 {
    this.#live(); if (this.#opening) fail('opening_in_progress'); uuid(lineId); const bytes = captureElectionBytes03(successor, 366, 9753);
    if (!same(bytes.subarray(0, 7), Uint8Array.of(90, 84, 77, 65, 3, 3, 2))) fail();
    return this.#recovery({ v: 1, origin: this.#origin, account_id: this.#account, user_id: this.#user,
      owner_session_id: this.#session, device_id: this.#device, root_fingerprint: this.#root,
      opening_id: crypto.randomUUID(), line_id: lineId, successor_manifest03: b64(bytes) });
  }
  restoreOpening(value: ElectionRecovery03): ElectionRecovery03 { this.#live(); return this.#recovery(value); }
  async #digests(): Promise<{ origin: Uint8Array; session: Uint8Array }> {
    const label = enc.encode('ZTSE/line/payload-profile/owner-session/v1\0'), n = new Uint8Array(4);
    new DataView(n.buffer).setUint32(0, 48, false);
    const bytes = new Uint8Array(label.length + 4 + 48); bytes.set(label); bytes.set(n, label.length);
    [this.#account, this.#user, this.#session].forEach((id, i) => bytes.set(uuidBytes(id), label.length + 4 + 16 * i));
    return { origin: new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(this.#origin))),
      session: new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) };
  }
  async #core(core: Uint8Array, opening: Pick<ElectionRecovery03, 'line_id'>, challenge: string, historical = false): Promise<void> {
    if (!same(core.subarray(0, 8), Uint8Array.of(90, 84, 80, 69, 3, 1, 2, 3)) || core.subarray(496).some(b => b !== 0)
      || uuidText(core.subarray(8, 24)) !== this.#account || uuidText(core.subarray(24, 40)) !== this.#device
      || uuidText(core.subarray(40, 56)) !== opening.line_id || uuidText(core.subarray(56, 72)) !== challenge
      || b64(core.subarray(136, 168)) !== this.#root) fail('scope');
    const view = new DataView(core.buffer, core.byteOffset, core.byteLength);
    for (const at of [88, 96, 168, 176, 216, 384, 392]) { const n = view.getBigUint64(at, false); if (n < 1n || n > MAX) fail('response'); }
    if (view.getBigUint64(96, false) <= view.getBigUint64(88, false) || view.getBigUint64(168, false) !== 1n
      || view.getBigUint64(216, false) !== view.getBigUint64(176, false) + 1n) fail('response');
    uuidText(core.subarray(72, 88));
    for (const at of [104, 184, 224, 256, 288, 320, 352, 400, 432, 464]) if (!core.subarray(at, at + 32).some(b => b !== 0)) fail('response');
    if (!historical) {
      const expected = await this.#digests(); this.#live();
      if (!same(core.subarray(400, 432), expected.origin) || !same(core.subarray(432, 464), expected.session)) fail('scope');
    }
  }
  async #read(response: Response, deadline: number): Promise<unknown> {
    if (response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json' || !response.body) fail('response');
    const size = response.headers.get('content-length');
    if (size !== null && (!/^(0|[1-9][0-9]{0,8})$/.test(size) || Number(size) > RESPONSE_MAX)) fail('response');
    const reader = response.body.getReader(), chunks: Uint8Array[] = []; let total = 0, complete = false;
    try {
      while (true) {
        const chunk = await wait(reader.read(), this.#abort.signal, deadline); this.#live();
        if (chunk.done) { complete = true; break; }
        total += chunk.value.byteLength; if (total > RESPONSE_MAX) fail('response'); chunks.push(Uint8Array.from(chunk.value));
      }
      const bytes = new Uint8Array(total); let at = 0; for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.byteLength; }
      return json(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes));
    } finally {
      if (!complete) void reader.cancel().catch(() => {});
      try { reader.releaseLock(); } catch { /* A cancelled pending read still owns its lock. */ }
    }
  }
  async #request<T>(path: string, body: object, mutation: boolean, statuses: readonly number[],
    parse: (value: unknown) => Promise<T> | T, recovery?: ElectionRecovery03): Promise<T> {
    this.#live(); if (this.#busy) fail('busy'); this.#busy = true;
    const deadline = performance.now() + this.#options.timeoutMs!; let sent = false, knownRefusal = false, response: Response | undefined;
    try {
      const encoded = JSON.stringify(body); if (enc.encode(encoded).length > REQUEST_MAX) fail();
      if (recovery) { await wait(Promise.resolve().then(() => this.#options.saveRecovery(recovery)), this.#abort.signal, deadline); this.#live(); }
      const request = this.#options.fetchImpl ?? globalThis.fetch; this.#live(); sent = true;
      const url = this.#origin + basePath + path;
      response = await wait(Promise.resolve().then(() => { this.#live(); return request(url, {
        method: 'POST', credentials: 'same-origin', mode: 'same-origin', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer',
        headers: { 'content-type': 'application/json', accept: 'application/json', 'x-zrotext-csrf': this.#csrfValue },
        body: encoded, signal: this.#abort.signal,
      }); }), this.#abort.signal, deadline); this.#live();
      if (!response) fail('response');
      if (response.redirected || response.type === 'opaque' || response.type === 'opaqueredirect' || response.url && response.url !== url) fail('response');
      const parsed = await this.#read(response, deadline); this.#live();
      if (!statuses.includes(response.status)) {
        const e = record(parsed, ['error']); if (typeof e.error !== 'string' || !errors[response.status]?.includes(e.error)) fail('response');
        knownRefusal = true; throw new OwnerProfileElectionError03(e.error);
      }
      const result = await wait(Promise.resolve().then(() => parse(parsed)), this.#abort.signal, deadline, true); this.#live(); return result;
    } catch (error) {
      const code = error instanceof OwnerProfileElectionError03 ? error.code : 'unavailable';
      if (sent && !knownRefusal) this.close();
      throw new OwnerProfileElectionError03(code, mutation && sent && !knownRefusal ? 'unknown' : 'refused');
    } finally { if (response?.body && !response.body.locked) void response.body.cancel().catch(() => {}); this.#busy = false; }
  }
  async #reservation(value: unknown, opening: ElectionRecovery03): Promise<ElectionReservationCandidate03> {
    const r = record(value, ['v', 'opening_id', 'challenge_id', 'new_binding_id', 'core', 'successor_manifest03', 'issued_ms', 'expires_ms', 'status', 'closed_unaccepted']);
    const challenge = uuid(r.challenge_id), binding = uuid(r.new_binding_id), core = binary(r.core, 500);
    if (r.v !== 1 || r.opening_id !== opening.opening_id || r.successor_manifest03 !== opening.successor_manifest03
      || new Set([opening.opening_id, challenge, binding]).size !== 3 || !['reserved', 'accepted'].includes(r.status as string)) fail('scope');
    const issued = decimal(r.issued_ms), expires = decimal(r.expires_ms), view = new DataView(core.buffer);
    if (expires <= issued || expires - issued > 300_000n || view.getBigUint64(384, false) !== issued || view.getBigUint64(392, false) !== expires) fail('response');
    await this.#core(core, opening, challenge);
    const successor = binary(r.successor_manifest03, 366, 9753);
    if (!same(await sha(successor.subarray(0, -64)), core.subarray(224, 256))) fail('scope');
    const closedUnaccepted = await this.#closures(r.closed_unaccepted, opening, challenge, binding, core);
    this.#live();
    return Object.freeze({ openingId: opening.opening_id, challengeId: challenge, newBindingId: binding, core,
      successorManifest03: binary(r.successor_manifest03, 366, 9753), issuedMs: issued, expiresMs: expires, status: r.status as 'reserved' | 'accepted', closedUnaccepted });
  }
  async #closures(value: unknown, opening: ElectionRecovery03, challenge: string, binding: string,
    current: Uint8Array): Promise<readonly ClosedUnacceptedCandidate03[]> {
    if (!Array.isArray(value) || value.length > 16) fail('response');
    const occupied = new Set([opening.opening_id, challenge, binding, uuidText(current.subarray(72, 88))]);
    if (occupied.size !== 4) fail('scope');
    const rows: ClosedUnacceptedCandidate03[] = [];
    for (const item of value) {
      const r = record(item, ['opening_id', 'challenge_id', 'new_binding_id', 'core', 'closed_unaccepted_ms', 'superseded_by_challenge_id']);
      const openingId = uuid(r.opening_id), challengeId = uuid(r.challenge_id), newBindingId = uuid(r.new_binding_id);
      for (const id of [openingId, challengeId, newBindingId]) { if (occupied.has(id)) fail('scope'); occupied.add(id); }
      const core = binary(r.core, 500), closedUnacceptedMs = decimal(r.closed_unaccepted_ms);
      await this.#core(core, opening, challengeId, true);
      // Original02 binding, root, predecessor, selected keys and origin stay exact.
      // Historical owner/device sessions, nonce and proposed successor digest may differ.
      for (const [start, end] of [[72, 96], [104, 224], [256, 352], [400, 432]]) {
        if (!same(core.subarray(start, end), current.subarray(start, end))) fail('scope');
      }
      const view = new DataView(core.buffer, core.byteOffset, core.byteLength);
      const issued = view.getBigUint64(384), expires = view.getBigUint64(392);
      if (expires <= issued || expires - issued > 300_000n || closedUnacceptedMs < expires) fail('response');
      rows.push(Object.freeze({ openingId, challengeId, newBindingId, core, closedUnacceptedMs,
        supersededByChallengeId: uuid(r.superseded_by_challenge_id) }));
    }
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i], next = rows[i + 1], target = next?.core ?? current;
      const view = new DataView(row.core.buffer, row.core.byteOffset, row.core.byteLength);
      const targetView = new DataView(target.buffer, target.byteOffset, target.byteLength);
      if (row.supersededByChallengeId !== (next?.challengeId ?? challenge)
        || view.getBigUint64(96) >= targetView.getBigUint64(96)
        || row.closedUnacceptedMs !== targetView.getBigUint64(384)) fail('scope');
    }
    return Object.freeze(rows);
  }
  async reserve(opening: ElectionRecovery03, factor: ElectionCredentials03): Promise<ElectionReservationCandidate03> {
    const o = this.#recovery(opening), c = credentials(factor);
    return this.#request('/challenges', { v: 1, opening_id: o.opening_id, line_id: o.line_id,
      successor_manifest03: o.successor_manifest03, ...c }, true, [200, 201], v => this.#reservation(v, o), o);
  }
  async status(opening: ElectionRecovery03): Promise<ElectionReservationCandidate03> {
    const o = this.#recovery(opening);
    return this.#request('/challenges/status', { v: 1, opening_id: o.opening_id, line_id: o.line_id }, false, [200], v => this.#reservation(v, o));
  }
  async deviceProof(opening: ElectionRecovery03, challengeId: string): Promise<Readonly<{ challengeId: string; signature: Uint8Array }>> {
    const o = this.#recovery(opening), challenge = uuid(challengeId);
    return this.#request('/challenges/proof', { v: 1, opening_id: o.opening_id, challenge_id: challenge }, false, [200], value => {
      const r = record(value, ['v', 'opening_id', 'challenge_id', 'device_signature']), signature = binary(r.device_signature, 64);
      if (r.v !== 1 || r.opening_id !== o.opening_id || r.challenge_id !== challenge || !isCanonicalP256Signature(signature)) fail('scope');
      return Object.freeze({ challengeId: challenge, signature });
    });
  }
  async commit(opening: ElectionRecovery03, challengeId: string, bundle: Uint8Array, factor: ElectionCredentials03): Promise<ElectionReceiptCandidate03> {
    const o = this.#recovery(opening), challenge = uuid(challengeId), exact = captureElectionBytes03(bundle, 628), c = credentials(factor);
    if (!isCanonicalP256Signature(exact.subarray(500, 564)) || !isCanonicalP256Signature(exact.subarray(564))) fail();
    await this.#core(exact.subarray(0, 500), o, challenge); this.#live();
    return this.#request('/elections', { v: 1, opening_id: o.opening_id, challenge_id: challenge,
      successor_manifest03: o.successor_manifest03, bundle: b64(exact), ...c }, true, [200, 201], async value => {
      const r = record(value, ['v', 'opening_id', 'challenge_id', 'binding_id', 'binding_generation', 'election_digest', 'bundle_sha256', 'accepted_ms', 'selection_epoch']);
      if (r.v !== 1 || r.opening_id !== o.opening_id || r.challenge_id !== challenge
        || decimal(r.binding_generation) !== new DataView(exact.buffer).getBigUint64(96, false)) fail('scope');
      const digest = await sha(exact), commitment = await sha(frame('ZTSE/line/payload-profile/commitment/v1', exact.subarray(0, 500)));
      const accepted = decimal(r.accepted_ms), view = new DataView(exact.buffer);
      this.#live(); if (r.bundle_sha256 !== b64(digest) || r.election_digest !== b64(commitment)
        || accepted < view.getBigUint64(384, false) || accepted >= view.getBigUint64(392, false)) fail('scope');
      return Object.freeze({ openingId: o.opening_id, challengeId: challenge, bindingId: uuid(r.binding_id), bindingGeneration: decimal(r.binding_generation),
        electionDigest: binary(r.election_digest, 32, 32, true), bundleSha256: binary(r.bundle_sha256, 32, 32, true),
        acceptedMs: decimal(r.accepted_ms), selectionEpoch: decimal(r.selection_epoch) });
    }, o);
  }
  /** Original02 candidate only: no allocation, historical acceptance or key comparison ceremony. */
  async bootstrap(lineId: string): Promise<OriginalProfileCandidate02> {
    const line = uuid(lineId);
    return this.#request('/bootstrap', { v: 1, line_id: line }, false, [200], async value => {
      const r = record(value, ['v', 'envelope_profile', 'manifest_profile', ...originalIds, ...originalCounters,
        ...originalDigests, 'site_id', 'instance_id', 'evidence']);
      if (r.v !== 1 || r.envelope_profile !== 2 || r.manifest_profile !== 2 || r.account_id !== this.#account
        || r.user_id !== this.#user || r.owner_session_id !== this.#session || r.device_id !== this.#device
        || r.line_id !== line || r.root_fingerprint !== this.#root || r.trust_generation !== '1') fail('scope');
      for (const k of originalIds) uuid(r[k]);
      // A never-elected account has an actual initial zero epoch. No other counter admits zero.
      for (const k of originalCounters) if (k !== 'selection_epoch' || r[k] !== '0') decimal(r[k]);
      for (const k of originalDigests) binary(r[k], 32, 32, true);
      for (const k of ['site_id', 'instance_id']) if (typeof r[k] !== 'string' || enc.encode(r[k] as string).length < 1
        || enc.encode(r[k] as string).length > 256 || /[\p{Cc}\p{Cs}]/u.test(r[k] as string)) fail('response');
      const compared = decimal(r.compared_ms);
      if (compared < this.#lastCompared || decimal(r.permission_expires_ms) <= compared) fail('response');
      const e = record(r.evidence, originalEvidence), pin = binary(e.root_pin, 94), prior = binary(e.prior_manifest02, 364, 9751);
      for (const k of ['device_signing_point', 'owner_approval_point']) binary(e[k], 65);
      for (const k of ['registration_evidence', 'activation_evidence']) binary(e[k], 1, REQUEST_MAX);
      if (decimal(e.prior_accepted_ms) > compared || !same(pin.subarray(0, 5), Uint8Array.of(90, 84, 82, 80, 2))
        || uuidText(pin.subarray(5, 21)) !== this.#account || new DataView(pin.buffer).getBigUint64(21) !== 1n
        || !same(prior.subarray(0, 5), Uint8Array.of(90, 84, 77, 65, 2)) || uuidText(prior.subarray(5, 21)) !== this.#account
        || new DataView(prior.buffer).getBigUint64(21) !== 1n
        || new DataView(prior.buffer).getBigUint64(29) !== decimal(r.manifest_version)) fail('scope');
      const expected = await this.#digests(), rootLabel = enc.encode('ZTSE/root-pin/v2\0');
      const rootInput = new Uint8Array(rootLabel.length + pin.length); rootInput.set(rootLabel); rootInput.set(pin, rootLabel.length);
      if (r.origin_digest !== b64(expected.origin) || r.owner_session_digest !== b64(expected.session)
        || r.root_fingerprint !== b64(await sha(rootInput)) || r.manifest_digest !== b64(await sha(prior.subarray(0, -64)))) fail('scope');
      this.#live(); this.#lastCompared = compared;
      return Object.freeze({ ...r, evidence: Object.freeze({ ...e }) }) as OriginalProfileCandidate02;
    });
  }
  async current(lineId: string): Promise<CurrentProfileCandidate03> {
    const line = uuid(lineId);
    return this.#request('/current', { v: 1, line_id: line }, false, [200], async value => {
      const r = record(value, ['v', 'envelope_profile', 'manifest_profile', ...ids, ...counters, ...digests, 'site_id', 'instance_id', 'evidence']);
      if (r.v !== 1 || r.envelope_profile !== 3 || r.manifest_profile !== 3 || r.account_id !== this.#account || r.user_id !== this.#user
        || r.owner_session_id !== this.#session || r.device_id !== this.#device || r.line_id !== line || r.root_fingerprint !== this.#root) fail('scope');
      for (const k of ids) uuid(r[k]); for (const k of counters) decimal(r[k]); for (const k of digests) binary(r[k], 32, 32, true);
      for (const k of ['site_id', 'instance_id']) if (typeof r[k] !== 'string' || enc.encode(r[k] as string).length < 1
        || enc.encode(r[k] as string).length > 256 || /[\p{Cc}\p{Cs}]/u.test(r[k] as string)) fail('response');
      const compared = decimal(r.compared_ms);
      if (compared < this.#lastCompared || decimal(r.permission_expires_ms) <= compared || decimal(r.binding_generation) <= decimal(r.old_binding_generation)) fail('response');
      const expected = await this.#digests(); this.#live();
      if (r.origin_digest !== b64(expected.origin) || r.owner_session_digest !== b64(expected.session)) fail('scope');
      const e = record(r.evidence, evidenceNames);
      for (const k of ['prior_accepted_ms', 'accepted_ms']) decimal(e[k]);
      for (const [k, min, max] of [['root_pin', 94, 94], ['prior_manifest02', 364, 9751], ['accepted_manifest03', 366, 9753],
        ['bundle', 628, 628], ['device_signing_point', 65, 65], ['owner_approval_point', 65, 65],
        ['registration_evidence', 1, REQUEST_MAX], ['activation_evidence', 1, REQUEST_MAX]] as const) binary(e[k], min, max);
      const pin = binary(e.root_pin, 94);
      if (!same(pin.subarray(0, 5), Uint8Array.of(90, 84, 82, 80, 2)) || uuidText(pin.subarray(5, 21)) !== this.#account) fail('scope');
      const rootLabel = enc.encode('ZTSE/root-pin/v2\0'), rootInput = new Uint8Array(rootLabel.length + pin.length);
      rootInput.set(rootLabel); rootInput.set(pin, rootLabel.length);
      if (b64(await sha(rootInput)) !== this.#root) fail('scope'); this.#live();
      const proof = binary(e.bundle, 628);
      // Original acceptance sessions/lease digests remain historical. A fresh
      // authorized owner session must not rewrite that evidence to read it.
      await this.#core(proof.subarray(0, 500), { line_id: line }, uuidText(proof.subarray(56, 72)), true);
      const view = new DataView(proof.buffer);
      if (r.old_binding_id !== uuidText(proof.subarray(72, 88)) || decimal(r.old_binding_generation) !== view.getBigUint64(88, false)
        || decimal(r.binding_generation) !== view.getBigUint64(96, false) || decimal(r.trust_generation) !== view.getBigUint64(168, false)
        || decimal(r.manifest_version) !== view.getBigUint64(216, false)) fail('scope');
      for (const [k, at] of [['old_binding_proof_digest', 104], ['manifest_digest', 224], ['reader_key_id', 256],
        ['device_signing_key_id', 288], ['approval_key_id', 320]] as const) if (r[k] !== b64(proof.subarray(at, at + 32))) fail('scope');
      const accepted = decimal(e.accepted_ms);
      if (accepted < view.getBigUint64(384, false) || accepted >= view.getBigUint64(392, false) || accepted > compared
        || decimal(e.prior_accepted_ms) > accepted || r.election_bundle_sha256 !== b64(await sha(proof))
        || r.election_digest !== b64(await sha(frame('ZTSE/line/payload-profile/commitment/v1', proof.subarray(0, 500))))
        || r.manifest_digest !== b64(await sha(binary(e.accepted_manifest03, 366, 9753).subarray(0, -64)))
        || !same(proof.subarray(184, 216), await sha(binary(e.prior_manifest02, 364, 9751).subarray(0, -64)))) fail('scope');
      this.#live();
      this.#lastCompared = compared;
      return Object.freeze({ ...r, evidence: Object.freeze({ ...e }) }) as CurrentProfileCandidate03;
    });
  }
}
