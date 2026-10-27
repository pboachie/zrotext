// SPDX-License-Identifier: AGPL-3.0-only
/** Exact ordinary-owner V2 transport. Component proofs and passive receipts do
 * not establish installed consent, held current records, custody or effects.
 * No signatures, composition, factors, new IDs or automatic retries occur here. */
import { manifestHistoryBase64url03 as b64, manifestHistoryBinary03 as binary,
  manifestHistoryDecimal03 as decimal } from './accepted-manifest-history03.js';
import { decodeReviewedIntent03V2, verifiedReviewedIntentSnapshot03V2,
  type ReviewedIntentFields03V2, type VerifiedReviewedIntent03V2 } from './reviewed-intent03.js';
import { captureElectionBytes03, electionTime03 } from './payload-profile-election03.js';
import { isCanonicalP256Signature } from './draft01.js';

type Packet03 = Readonly<{ v: 1; envelope: string; reviewed_intent: string; reviewed_signature: string }>;
export type ReviewedSendRecovery03 = Readonly<{ v: 1; origin: string; account_id: string; user_id: string;
  owner_session_id: string; device_id: string; line_id: string; root_fingerprint: string; packet: Packet03 }>;
export type ReviewedSendReceipt03 = Readonly<{ v: 1; message_id: string; interval_id: string; accepted_ms: string;
  expires_ms: string; selection_epoch: string; envelope_sha256: string; reviewed_intent_sha256: string;
  reviewed_signature_sha256: string; sms_ceiling: number }>;
export type OwnerReviewedSendOptions03 = Readonly<{ origin: string; accountId: string; userId: string;
  ownerSessionId: string; deviceId: string; lineId: string; rootFingerprint: Uint8Array; signal: AbortSignal;
  currentCsrf: () => string; nowMs: () => bigint; saveBeforeSubmit: (record: ReviewedSendRecovery03) => Promise<void>;
  timeoutMs?: number; fetchImpl?: typeof fetch }>;
export class ReviewedSendTransportError03 extends Error {
  constructor(readonly code: string) { super('Message request needs reconciliation'); }
}
type Parsed = Readonly<{ record: ReviewedSendRecovery03; fields: ReviewedIntentFields03V2;
  envelopeHash: string; intentHash: string; signatureHash: string }>;
const enc = new TextEncoder();
const errors: Readonly<Record<number, string>> = { 400: 'invalid_request', 401: 'authentication_required',
  403: 'origin_or_csrf_refused', 404: 'not_found', 409: 'conflict', 410: 'expired',
  422: 'unsupported_state', 429: 'rate_limited' };
function fail(code = 'invalid'): never { throw new ReviewedSendTransportError03(code); }
function closed(input: unknown, names: readonly string[]): Record<string, unknown> {
  if (!input || typeof input !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) fail();
  const ds = Object.getOwnPropertyDescriptors(input), keys = Reflect.ownKeys(ds), out: Record<string, unknown> = {};
  if (keys.length !== names.length || keys.some(k => typeof k !== 'string' || !names.includes(k))) fail();
  for (const k of names) { const d = ds[k]; if (!d || !('value' in d)) fail(); out[k] = d.value; } return out;
}
// These replies are flat records containing strings and integer constants 1..6.
// Keep this grammar separate from history/current DTO numeric constants. Detect
// decoded duplicate keys, including escaped spellings, before construction.
function reply(bytes: Uint8Array): unknown {
  const raw = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  let at = 0;
  const space = () => { while (at < raw.length && /[ \t\r\n]/.test(raw[at])) at++; };
  const string = (): string => {
    if (raw[at] !== '"') fail('response'); const start = at++;
    while (at < raw.length) {
      const c = raw[at++];
      if (c === '"') { const value: unknown = JSON.parse(raw.slice(start, at));
        if (typeof value !== 'string' || value.length > 128) fail('response'); return value; }
      if (c === '\\') at++;
    } return fail('response');
  };
  const out: Record<string, unknown> = Object.create(null), seen = new Set<string>();
  space(); if (raw[at++] !== '{') fail('response'); space();
  if (raw[at] !== '}') for (;;) {
    space(); const key = string(); if (seen.has(key) || seen.size >= 10 || key === '__proto__') fail('response'); seen.add(key);
    space(); if (raw[at++] !== ':') fail('response'); space();
    if (raw[at] === '"') out[key] = string();
    else if (/^[1-6]$/.test(raw[at] ?? '')) out[key] = Number(raw[at++]);
    else fail('response');
    space(); if (raw[at] === '}') break; if (raw[at++] !== ',') fail('response');
  }
  at++; space(); if (at !== raw.length) fail('response'); return out;
}
function id(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
      || value === '00000000-0000-0000-0000-000000000000') fail(); return value;
}
function uuid(bytes: Uint8Array): string {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
}
function origin(value: unknown): string {
  if (typeof value !== 'string' || enc.encode(value).length > 512) fail();
  const u = new URL(value); if (u.protocol !== 'https:' || u.origin !== value || u.username || u.password) fail(); return value;
}
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
async function sha(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', Uint8Array.from(bytes).buffer));
}
async function parseRecovery(input: ReviewedSendRecovery03): Promise<Parsed> {
  const r = closed(input, ['v', 'origin', 'account_id', 'user_id', 'owner_session_id', 'device_id', 'line_id', 'root_fingerprint', 'packet']);
  if (r.v !== 1) fail(); origin(r.origin);
  for (const name of ['account_id', 'user_id', 'owner_session_id', 'device_id', 'line_id']) id(r[name]);
  const root = binary(r.root_fingerprint, 32), p = closed(r.packet, ['v', 'envelope', 'reviewed_intent', 'reviewed_signature']);
  if (p.v !== 1) fail();
  const envelope = binary(p.envelope, 557, 34_213), intent = binary(p.reviewed_intent, 592, 803), signature = binary(p.reviewed_signature, 64);
  if (!isCanonicalP256Signature(signature)) fail();
  const f = decodeReviewedIntent03V2(intent);
  for (const [key, field] of [['account_id', 'accountId'], ['user_id', 'ownerUserId'], ['owner_session_id', 'ownerSessionId'],
    ['device_id', 'deviceId'], ['line_id', 'lineId']] as const) if (r[key] !== uuid(f[field])) fail();
  if (!same(root, f.rootFingerprint)) fail();
  // Capture every descriptor/byte before the first await. This parser provides
  // exact public recovery linkage, never a current or signature proof handle.
  const packet = Object.freeze(p) as Packet03, record = Object.freeze({ ...r, packet }) as ReviewedSendRecovery03;
  const envelopeHash = await sha(envelope), unsignedHash = await sha(envelope.subarray(0, -64));
  if (!same(envelopeHash, f.envelopeDigest) || !same(unsignedHash, f.unsignedDigest)
      || !same(await sha(enc.encode(record.origin)), f.originDigest)) fail();
  return { record, fields: f, envelopeHash: b64(envelopeHash), intentHash: b64(await sha(intent)), signatureHash: b64(await sha(signature)) };
}
/** Structural/hash linkage only; this cannot restore a private proof or signing
 * authorization. Its ciphertext-only output is suitable for protected storage. */
export async function captureReviewedSendRecovery03(input: ReviewedSendRecovery03): Promise<ReviewedSendRecovery03> {
  return (await parseRecovery(input)).record;
}

export class OwnerReviewedSendClient03 {
  readonly #o: OwnerReviewedSendOptions03; readonly #root: Uint8Array; readonly #csrf: string;
  #busy = false; #closed = false; #lastTime = 0n; #active?: AbortController;
  constructor(input: OwnerReviewedSendOptions03) {
    const r = closed(input, ['origin', 'accountId', 'userId', 'ownerSessionId', 'deviceId', 'lineId', 'rootFingerprint',
      'signal', 'currentCsrf', 'nowMs', 'saveBeforeSubmit', ...['timeoutMs', 'fetchImpl'].filter(k => Object.hasOwn(input, k))]);
    origin(r.origin); for (const n of ['accountId', 'userId', 'ownerSessionId', 'deviceId', 'lineId']) id(r[n]);
    if (!(r.signal instanceof AbortSignal) || typeof r.currentCsrf !== 'function' || typeof r.nowMs !== 'function'
        || typeof r.saveBeforeSubmit !== 'function' || r.fetchImpl !== undefined && typeof r.fetchImpl !== 'function') fail();
    const timeout = r.timeoutMs ?? 15000;
    if (typeof timeout !== 'number' || !Number.isSafeInteger(timeout) || timeout < 1 || timeout > 60000) fail();
    this.#root = captureElectionBytes03(r.rootFingerprint as Uint8Array, 32); if (!this.#root.some(v => v !== 0)) fail();
    this.#o = Object.freeze({ ...r, timeoutMs: timeout }) as OwnerReviewedSendOptions03;
    this.#csrf = this.#readCsrf(); this.#live();
  }
  #readCsrf(): string {
    const c = this.#o.currentCsrf(); if (typeof c !== 'string' || c.length !== 47 || !c.startsWith('ztc_')) fail(); binary(c.slice(4), 32); return c;
  }
  #live(signal?: AbortSignal): void {
    if (this.#closed || this.#o.signal.aborted || signal?.aborted || this.#readCsrf() !== this.#csrf) fail('withdrawn');
  }
  #now(signal: AbortSignal): bigint {
    this.#live(signal); const n = this.#o.nowMs(); electionTime03(n);
    if (n < this.#lastTime) fail('clock_regressed'); this.#lastTime = n; return n;
  }
  #window(f: ReviewedIntentFields03V2, signal: AbortSignal): void {
    const n = this.#now(signal); if (n < f.reviewIssuedMs || n >= f.reviewExpiresMs || n >= f.messageExpiresMs) fail('review_expired');
  }
  #scope(p: Parsed, sameSession: boolean): void {
    const r = p.record;
    if (r.origin !== this.#o.origin || r.account_id !== this.#o.accountId || r.user_id !== this.#o.userId
        || r.device_id !== this.#o.deviceId || r.line_id !== this.#o.lineId || !same(p.fields.rootFingerprint, this.#root)
        || sameSession && r.owner_session_id !== this.#o.ownerSessionId) fail('scope');
  }
  async #run<T>(op: (signal: AbortSignal) => Promise<T>): Promise<T> {
    this.#live(); if (this.#busy) fail('pending'); this.#busy = true;
    const control = new AbortController(), close = () => { this.#closed = true; control.abort(); };
    this.#active = control; this.#o.signal.addEventListener('abort', close, { once: true });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([op(control.signal).then(v => { this.#live(control.signal); return v; }),
        new Promise<never>((_, reject) => { control.signal.addEventListener('abort', () => reject(new ReviewedSendTransportError03('interrupted')), { once: true });
          timer = setTimeout(close, this.#o.timeoutMs); if (control.signal.aborted) reject(new ReviewedSendTransportError03('interrupted')); })]);
    } catch (e) { this.#closed = true; if (e instanceof ReviewedSendTransportError03) throw e; throw new ReviewedSendTransportError03('interrupted'); }
    finally { clearTimeout(timer); this.#o.signal.removeEventListener('abort', close); control.abort(); this.#active = undefined; this.#busy = false; }
  }
  async #http(status: boolean, packet: object, signal: AbortSignal): Promise<unknown> {
    this.#live(signal); const body = JSON.stringify(packet); if (enc.encode(body).length > 96 * 1024) fail();
    const url = this.#o.origin + '/v1/owner/conversation/send03' + (status ? '/status' : '');
    const r = await (this.#o.fetchImpl ?? fetch)(url, { method: 'POST', mode: 'same-origin', credentials: 'same-origin', redirect: 'error', cache: 'no-store',
      referrerPolicy: 'no-referrer', signal, headers: { 'content-type': 'application/json', accept: 'application/json', 'x-zrotext-csrf': this.#csrf }, body });
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    const cancel = () => { if (reader) void reader.cancel().catch(() => {}); else if (r.body) void r.body.cancel().catch(() => {}); };
    signal.addEventListener('abort', cancel, { once: true });
    try {
      this.#live(signal); if (r.redirected || r.url && r.url !== url) fail('response');
      if (r.status === 503) fail('http_503');
      const refused = Object.hasOwn(errors, r.status);
      if (!(refused || (status ? r.status === 200 : r.status === 200 || r.status === 201)) || !r.body
          || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(r.headers.get('content-type') ?? '')) fail('response');
      reader = r.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
      for (;;) {
        const part = await reader.read(); this.#live(signal); if (part.done) break;
        size += part.value.length; if (size > 192 * 1024) fail('response'); chunks.push(Uint8Array.from(part.value));
      }
      const bytes = new Uint8Array(size); let at = 0; for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.length; }
      const value = reply(bytes);
      if (refused) { const e = closed(value, ['error']); if (e.error !== errors[r.status]) fail('response'); fail('http_' + r.status); }
      return value;
    } finally { signal.removeEventListener('abort', cancel); cancel(); reader?.releaseLock(); }
  }
  #receipt(input: unknown, p: Parsed): ReviewedSendReceipt03 {
    const r = closed(input, ['v', 'message_id', 'interval_id', 'accepted_ms', 'expires_ms', 'selection_epoch',
      'envelope_sha256', 'reviewed_intent_sha256', 'reviewed_signature_sha256', 'sms_ceiling']), f = p.fields;
    if (r.v !== 1 || id(r.message_id) !== uuid(f.messageId) || id(r.interval_id) !== uuid(f.intervalId)
        || decimal(r.expires_ms) !== f.messageExpiresMs || decimal(r.selection_epoch) !== f.accountSelectionEpoch
        || r.sms_ceiling !== f.smsCeiling || r.envelope_sha256 !== p.envelopeHash || r.reviewed_intent_sha256 !== p.intentHash
        || r.reviewed_signature_sha256 !== p.signatureHash) fail('response');
    const accepted = decimal(r.accepted_ms);
    if (accepted < f.reviewIssuedMs || accepted >= f.reviewExpiresMs) fail('response');
    return Object.freeze(r) as ReviewedSendReceipt03;
  }
  async send(proof: VerifiedReviewedIntent03V2): Promise<ReviewedSendReceipt03> {
    const s = verifiedReviewedIntentSnapshot03V2(proof), f = s.fields;
    const record: ReviewedSendRecovery03 = Object.freeze({ v: 1, origin: this.#o.origin, account_id: uuid(f.accountId), user_id: uuid(f.ownerUserId),
      owner_session_id: uuid(f.ownerSessionId), device_id: uuid(f.deviceId), line_id: uuid(f.lineId), root_fingerprint: b64(f.rootFingerprint),
      packet: Object.freeze({ v: 1, envelope: b64(s.envelope), reviewed_intent: b64(s.intent), reviewed_signature: b64(s.signature) }) });
    return this.#run(async signal => {
      this.#window(f, signal); const p = await parseRecovery(record); this.#live(signal); this.#scope(p, true); this.#window(f, signal);
      await this.#o.saveBeforeSubmit(p.record); this.#live(signal); this.#window(f, signal);
      const receipt = this.#receipt(await this.#http(false, p.record.packet, signal), p); this.#live(signal);
      if (decimal(receipt.accepted_ms) > this.#now(signal)) fail('response'); return receipt;
    });
  }
  /** Exact original-user reconciliation only, even after expiry/Stop/sign-in.
   * No live-device clock, current permission or signing operation is required. */
  async status(original: ReviewedSendRecovery03): Promise<ReviewedSendReceipt03> {
    return this.#run(async signal => {
      const p = await parseRecovery(original); this.#live(signal); this.#scope(p, false);
      return this.#receipt(await this.#http(true, { v: 1, message_id: uuid(p.fields.messageId), interval_id: uuid(p.fields.intervalId),
        envelope_sha256: p.envelopeHash, reviewed_intent_sha256: p.intentHash, reviewed_signature_sha256: p.signatureHash }, signal), p);
    });
  }
  close(): void { this.#closed = true; this.#active?.abort(); }
}
