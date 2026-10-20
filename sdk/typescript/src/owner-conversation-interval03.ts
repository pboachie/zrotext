// SPDX-License-Identifier: AGPL-3.0-only
/** Fixed ordinary-owner interval transport. Public candidates and exact replay
 * records do not provide current permission, crypto validation or install ACK.
 * No automatic retry, key creation, factor persistence or content disclosure. */
import { decodeOwnerProfileJson03, manifestHistoryBase64url03 as b64, manifestHistoryBinary03 as binary,
  manifestHistoryDecimal03 as decimal } from './accepted-manifest-history03.js';
import { decodeConversationStatement03, type ConversationStatement03 } from './conversation-interval03.js';
import { captureElectionBytes03 } from './payload-profile-election03.js';
import { isCanonicalP256Signature } from './draft01.js';

type Mapping = Readonly<{ connector_id: string; read_grant_id: string; key_id: string }>;
export type IntervalReserveCommand03 = Readonly<{ v: 1; opening_id: string; line_id: string; peer: string;
  archive_reader_key_id: string; phone_signer_key_id: string; browser_signer_key_id: string;
  interval_expires_ms: string; integration_readers: readonly Mapping[] }>;
export type IntervalRequestOriginal03 = Readonly<{ v: 1; opening_id: string; interval_id: string; statement: string; owner_signature: string }>;
export type IntervalReceiptCandidate03 = Readonly<{ v: 1; opening_id: string; interval_id: string; receipt_id: string; statement: string;
  owner_signature: string | null; phone_signature: string | null; installed_signature: string | null;
  requested_ms: string | null; approved_ms: string | null; installed_ms: string | null;
  phase: 'reserved' | 'requested' | 'install_pending' | 'active' | 'stopped' | 'expired' }>;
export type IntervalTransportRecovery03 = Readonly<{ v: 1; kind: 'reservation' | 'request' | 'stop'; origin: string;
  account_id: string; user_id: string; owner_session_id: string; device_id: string; line_id: string;
  packet: IntervalReserveCommand03 | IntervalRequestOriginal03 | Readonly<{ v: 1; interval_id: string }> }>;
export type IntervalTransportOptions03 = Readonly<{ origin: string; accountId: string; userId: string; ownerSessionId: string;
  deviceId: string; lineId: string; rootFingerprint: Uint8Array; currentCsrf: () => string; signal: AbortSignal;
  saveRecovery: (publicRecord: IntervalTransportRecovery03) => Promise<void>; timeoutMs?: number; fetchImpl?: typeof fetch }>;
export class IntervalTransportError03 extends Error {
  constructor(readonly code: string, readonly outcome: 'refused' | 'unknown' = 'unknown') { super('Conversation setup unavailable'); }
}
const enc = new TextEncoder(), names = ['v', 'opening_id', 'interval_id', 'receipt_id', 'statement', 'owner_signature', 'phone_signature',
  'installed_signature', 'requested_ms', 'approved_ms', 'installed_ms', 'phase'];
const errors: Readonly<Record<number, string>> = { 400: 'invalid_request', 401: 'authentication_required', 403: 'origin_or_csrf_refused',
  404: 'not_found', 409: 'conflict', 410: 'expired', 422: 'unsupported_state', 429: 'rate_limited' };
function fail(code = 'invalid', outcome: 'refused' | 'unknown' = 'refused'): never { throw new IntervalTransportError03(code, outcome); }
function record(input: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!input || typeof input !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) fail();
  const ds = Object.getOwnPropertyDescriptors(input), keys = Reflect.ownKeys(ds), out: Record<string, unknown> = {};
  if (keys.length !== fields.length || keys.some(k => typeof k !== 'string' || !fields.includes(k))) fail();
  for (const k of fields) { const d = ds[k]; if (!d || !('value' in d) || !d.enumerable) fail(); out[k] = d.value; } return out;
}
function id(value: unknown): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
      || value === '00000000-0000-0000-0000-000000000000') fail(); return value;
}
function uuidText(value: Uint8Array): string { return Array.from(value, b => b.toString(16).padStart(2, '0')).join('').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5'); }
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);
function signature(value: unknown): Uint8Array { const b = binary(value, 64); if (!isCanonicalP256Signature(b)) fail(); return b; }
function array(input: unknown): unknown[] {
  if (!Array.isArray(input) || Object.getPrototypeOf(input) !== Array.prototype) fail();
  const ds = Object.getOwnPropertyDescriptors(input) as Record<string, PropertyDescriptor>, n = ds.length.value as number;
  if (n > 6 || Reflect.ownKeys(ds).length !== n + 1) fail();
  return Array.from({ length: n }, (_, i) => { const d = ds[i]; if (!d || !('value' in d)) fail(); return d.value; });
}
function reserve(input: IntervalReserveCommand03): IntervalReserveCommand03 {
  const r = record(input, ['v', 'opening_id', 'line_id', 'peer', 'archive_reader_key_id', 'phone_signer_key_id', 'browser_signer_key_id', 'interval_expires_ms', 'integration_readers']);
  if (r.v !== 1 || typeof r.peer !== 'string' || !/^\+[1-9][0-9]{1,14}$/.test(r.peer)) fail();
  id(r.opening_id); id(r.line_id); decimal(r.interval_expires_ms);
  for (const n of ['archive_reader_key_id', 'phone_signer_key_id', 'browser_signer_key_id']) if (!binary(r[n], 32).some(v => v !== 0)) fail();
  let prior = ''; const connectors = new Set(), grants = new Set();
  r.integration_readers = Object.freeze(array(r.integration_readers).map(value => {
    const m = record(value, ['connector_id', 'read_grant_id', 'key_id']); id(m.connector_id); id(m.read_grant_id);
    const key = Array.from(binary(m.key_id, 32), b => b.toString(16).padStart(2, '0')).join('');
    if (/^0+$/.test(key) || prior && key <= prior || connectors.has(m.connector_id) || grants.has(m.read_grant_id)) fail();
    prior = key; connectors.add(m.connector_id); grants.add(m.read_grant_id); return Object.freeze(m) as Mapping;
  }));
  return Object.freeze(r) as IntervalReserveCommand03;
}
function original(input: IntervalRequestOriginal03): IntervalRequestOriginal03 {
  const r = record(input, ['v', 'opening_id', 'interval_id', 'statement', 'owner_signature']);
  if (r.v !== 1) fail(); id(r.opening_id); id(r.interval_id); binary(r.statement, 695, 1092); signature(r.owner_signature);
  return Object.freeze(r) as IntervalRequestOriginal03;
}
export class OwnerConversationIntervalClient03 {
  readonly #o: IntervalTransportOptions03; readonly #csrf: string; readonly #root: Uint8Array;
  #busy = false;
  constructor(input: IntervalTransportOptions03) {
    const r = record(input, ['origin', 'accountId', 'userId', 'ownerSessionId', 'deviceId', 'lineId', 'rootFingerprint', 'currentCsrf', 'signal', 'saveRecovery',
      ...['timeoutMs', 'fetchImpl'].filter(k => Object.hasOwn(input, k))]);
    if (typeof r.origin !== 'string' || enc.encode(r.origin).length > 512) fail();
    const u = new URL(r.origin); if (u.protocol !== 'https:' || u.origin !== r.origin || u.username || u.password) fail();
    for (const k of ['accountId', 'userId', 'ownerSessionId', 'deviceId', 'lineId']) id(r[k]);
    if (!(r.signal instanceof AbortSignal) || typeof r.currentCsrf !== 'function' || typeof r.saveRecovery !== 'function'
        || r.fetchImpl !== undefined && typeof r.fetchImpl !== 'function') fail();
    const timeout = r.timeoutMs ?? 15000;
    if (typeof timeout !== 'number' || !Number.isSafeInteger(timeout) || timeout < 1 || timeout > 60000) fail();
    this.#root = captureElectionBytes03(r.rootFingerprint as Uint8Array, 32); if (!this.#root.some(v => v !== 0)) fail();
    this.#o = Object.freeze({ ...r, timeoutMs: timeout }) as IntervalTransportOptions03;
    this.#csrf = this.#readCsrf(); this.#guard();
  }
  #readCsrf(): string { const c = this.#o.currentCsrf(); if (typeof c !== 'string' || c.length !== 47 || !c.startsWith('ztc_')) fail(); binary(c.slice(4), 32); return c; }
  #guard(): void { if (this.#o.signal.aborted || this.#readCsrf() !== this.#csrf) fail('withdrawn', 'unknown'); }
  async #run<T>(op: (signal: AbortSignal) => Promise<T>): Promise<T> {
    this.#guard(); if (this.#busy) fail('pending'); this.#busy = true;
    const abort = new AbortController(), close = () => abort.abort(); let timer: ReturnType<typeof setTimeout> | undefined;
    this.#o.signal.addEventListener('abort', close, { once: true });
    try {
      return await Promise.race([op(abort.signal).then(v => { this.#guard(); if (abort.signal.aborted) fail('withdrawn', 'unknown'); return v; }),
        new Promise<never>((_, reject) => { const refuse = () => reject(new IntervalTransportError03('interrupted'));
          abort.signal.addEventListener('abort', refuse, { once: true }); timer = setTimeout(close, this.#o.timeoutMs); if (abort.signal.aborted) refuse(); })]);
    } catch (e) { if (e instanceof IntervalTransportError03) throw e; throw new IntervalTransportError03('interrupted'); }
    finally { clearTimeout(timer); this.#o.signal.removeEventListener('abort', close); abort.abort(); this.#busy = false; }
  }
  async #save(kind: IntervalTransportRecovery03['kind'], packet: IntervalTransportRecovery03['packet'], signal: AbortSignal) {
    this.#guard(); if (signal.aborted) fail('withdrawn', 'unknown');
    await this.#o.saveRecovery(Object.freeze({ v: 1, kind, origin: this.#o.origin, account_id: this.#o.accountId, user_id: this.#o.userId,
      owner_session_id: this.#o.ownerSessionId, device_id: this.#o.deviceId, line_id: this.#o.lineId, packet }));
    this.#guard(); if (signal.aborted) fail('withdrawn', 'unknown');
  }
  async #http(path: 'challenges' | 'requests' | 'status' | 'openings/status' | 'stop', body: object, signal: AbortSignal): Promise<unknown> {
    this.#guard(); if (signal.aborted) fail('withdrawn', 'unknown'); const serialized = JSON.stringify(body);
    if (enc.encode(serialized).length > 96 * 1024) fail();
    const url = this.#o.origin + '/v1/owner/conversation/interval03/' + path;
    const r = await (this.#o.fetchImpl ?? fetch)(url, { method: 'POST', mode: 'same-origin', credentials: 'same-origin', redirect: 'error',
      cache: 'no-store', referrerPolicy: 'no-referrer', signal, headers: { 'content-type': 'application/json', accept: 'application/json', 'x-zrotext-csrf': this.#csrf }, body: serialized });
    this.#guard(); if (signal.aborted || r.redirected || r.url && r.url !== url) fail('response', 'unknown');
    // A database commit may be uncertain when the service returns503. Retain
    // the exact original for passive reconciliation; never infer nonacceptance.
    if (r.status === 503) fail('http_503', 'unknown');
    if (path === 'stop' && r.status === 204) { if (r.body !== null) fail('response', 'unknown'); return null; }
    const refused = Object.hasOwn(errors, r.status);
    if (!(refused || (path === 'challenges' || path === 'requests' ? [200, 201].includes(r.status) : path !== 'stop' && r.status === 200))
        || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(r.headers.get('content-type') ?? '') || !r.body) fail('response', 'unknown');
    const reader = r.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
    const cancel = () => { void reader.cancel().catch(() => {}); }; signal.addEventListener('abort', cancel, { once: true });
    try {
      for (;;) { const chunk = await reader.read(); this.#guard(); if (signal.aborted) fail('withdrawn', 'unknown'); if (chunk.done) break;
        size += chunk.value.length; if (size > 192 * 1024) fail('response', 'unknown'); chunks.push(Uint8Array.from(chunk.value)); }
      const all = new Uint8Array(size); let at = 0; for (const chunk of chunks) { all.set(chunk, at); at += chunk.length; }
      const value = decodeOwnerProfileJson03(all);
      if (refused) {
        let error: Record<string, unknown>;
        try { error = record(value, ['error']); } catch { fail('response', 'unknown'); }
        if (error.error !== errors[r.status]) fail('response', 'unknown');
        fail('http_' + r.status, 'refused');
      }
      return value;
    } finally { signal.removeEventListener('abort', cancel); cancel(); reader.releaseLock(); }
  }
  #selection(s: ConversationStatement03, opening: string, session: boolean): void {
    if (uuidText(s.accountId) !== this.#o.accountId || uuidText(s.deviceId) !== this.#o.deviceId || uuidText(s.lineId) !== this.#o.lineId
        || uuidText(s.ownerUserId) !== this.#o.userId || session && uuidText(s.ownerSessionId) !== this.#o.ownerSessionId
        || uuidText(s.openingId) !== opening || !same(s.rootFingerprint, this.#root)) fail();
  }
  async #receipt(value: unknown, opening: string, interval?: string): Promise<IntervalReceiptCandidate03> {
    try {
      const r = record(value, names); if (r.v !== 1 || r.opening_id !== opening || interval !== undefined && r.interval_id !== interval) fail();
      const s = await decodeConversationStatement03(binary(r.statement, 695, 1092)); this.#selection(s, opening, false);
      if (id(r.interval_id) !== uuidText(s.intervalId) || id(r.receipt_id) !== uuidText(s.receiptId)
          || !['reserved', 'requested', 'install_pending', 'active', 'stopped', 'expired'].includes(r.phase as string)) fail();
      let count = 0, prior = s.issuedMs;
      for (const [proof, time] of [['owner_signature', 'requested_ms'], ['phone_signature', 'approved_ms'], ['installed_signature', 'installed_ms']]) {
        if (r[proof] === null && r[time] === null) continue;
        signature(r[proof]); const at = decimal(r[time]); if (count !== ['owner_signature','phone_signature','installed_signature'].indexOf(proof)
            || at < prior || at >= s.setupExpiresMs) fail(); prior = at; count++;
      }
      if (['reserved','requested','install_pending','active'].includes(r.phase as string)
          && count !== ['reserved','requested','install_pending','active'].indexOf(r.phase as string)) fail();
      return Object.freeze(r) as IntervalReceiptCandidate03;
    } catch { throw new IntervalTransportError03('response'); }
  }
  async reserve(input: IntervalReserveCommand03): Promise<IntervalReceiptCandidate03> {
    const command = reserve(input); if (command.line_id !== this.#o.lineId) fail();
    return this.#run(async signal => {
      await this.#save('reservation', command, signal); const reply = await this.#receipt(await this.#http('challenges', command, signal), command.opening_id);
      try {
        const s = await decodeConversationStatement03(binary(reply.statement, 695, 1092)); this.#selection(s, command.opening_id, true);
        if (new TextDecoder().decode(s.peer) !== command.peer || s.intervalUntilMs !== decimal(command.interval_expires_ms)
          || b64(s.archiveReaderKeyId) !== command.archive_reader_key_id || b64(s.phoneSignerKeyId) !== command.phone_signer_key_id
          || b64(s.browserSignerKeyId) !== command.browser_signer_key_id || s.integrationReaders.length !== command.integration_readers.length
          || s.integrationReaders.some((r, i) => uuidText(r.connectorId) !== command.integration_readers[i].connector_id
            || uuidText(r.readGrantId) !== command.integration_readers[i].read_grant_id || b64(r.keyId) !== command.integration_readers[i].key_id)) fail('response', 'unknown');
      } catch { throw new IntervalTransportError03('response'); }
      return reply;
    });
  }
  async request(input: IntervalRequestOriginal03, credentials: Readonly<{ password: string; factor: string }>): Promise<IntervalReceiptCandidate03> {
    const packet = original(input), factors = record(credentials, ['password', 'factor']);
    for (const n of ['password', 'factor']) if (typeof factors[n] !== 'string' || !(factors[n] as string).length || (factors[n] as string).length > 1024) fail();
    return this.#run(async signal => {
      const s = await decodeConversationStatement03(binary(packet.statement, 695, 1092)); this.#selection(s, packet.opening_id, true);
      if (uuidText(s.intervalId) !== packet.interval_id) fail(); await this.#save('request', packet, signal);
      const reply = await this.#receipt(await this.#http('requests', { ...packet, ...factors }, signal), packet.opening_id, packet.interval_id);
      if (reply.statement !== packet.statement || reply.owner_signature !== packet.owner_signature) fail('response', 'unknown'); return reply;
    });
  }
  async openingStatus(openingId: string): Promise<IntervalReceiptCandidate03> {
    const opening = id(openingId); return this.#run(async signal => this.#receipt(await this.#http('openings/status', { v: 1, opening_id: opening }, signal), opening));
  }
  async status(openingId: string, intervalId: string): Promise<IntervalReceiptCandidate03> {
    const opening = id(openingId), interval = id(intervalId);
    return this.#run(async signal => this.#receipt(await this.#http('status', { v: 1, opening_id: opening, interval_id: interval }, signal), opening, interval));
  }
  async stop(intervalId: string): Promise<void> {
    const packet = Object.freeze({ v: 1 as const, interval_id: id(intervalId) });
    return this.#run(async signal => { await this.#save('stop', packet, signal); await this.#http('stop', packet, signal); });
  }
}
