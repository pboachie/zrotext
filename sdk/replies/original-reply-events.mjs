// SPDX-License-Identifier: AGPL-3.0-only
/** Customer-owned original-event checkpoints. No plaintext, key or approval ledger. */
import { DatabaseSync } from 'node:sqlite';
import { createHash, randomUUID } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { OriginalReplyClient } from '../typescript/dist/original-reply-client.js';
import { canonicalWorkflowAction } from '../typescript/dist/workflow-decisions.js';
import { SealedEventReceiver } from './sealed-events.mjs';
const day = 86400000;
const validId = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) && !/^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(value);
const idText = bytes => Buffer.from(bytes).toString('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
const idBytes = text => Uint8Array.from(Buffer.from(text.replaceAll('-', ''), 'hex'));
const hash = value => createHash('sha256').update(value).digest('hex');
export class OriginalReplyEventError extends Error {
  constructor(code) { super(code); this.name = 'OriginalReplyEventError'; this.code = code; }
}
const fail = code => { throw new OriginalReplyEventError(code); };
const closed = (value, names) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join('\0') !== [...names].sort().join('\0')) fail('invalid_request');
};
/** Open only from trusted local application configuration. Both SQLite paths must be in
 * an operator-owned private directory; this library does not establish filesystem ACLs.
 * Separate secrets and the selected reader client never enter model parameters.
 */
export async function createOriginalReplyReceiver(options) {
  if (!(options.client instanceof OriginalReplyClient)) fail('invalid_request');
  const proof = await options.client.current();
  return new OriginalReplyReceiver(options, proof);
}
class OriginalReplyReceiver {
  #client; #receiver; #db; #clock; #scope; #current; #capacity; #retention; #maximumTurns; #callbackTimeout;
  #busy = false; #denied = false; #closed = false;
  constructor({ client, journalPath, receiverPath, webhookSecret, cursorSecret, clock = Date.now,
    capacity = 1024, retentionMs = 8 * day, maximumAutomaticTurns = 1, callbackTimeoutMs = 5000 }, proof) {
    if (![journalPath, receiverPath].every(p => typeof p === 'string' && isAbsolute(p)) || journalPath === receiverPath ||
        !Number.isSafeInteger(capacity) || capacity < 1 || capacity > 4096 || !Number.isSafeInteger(retentionMs) || retentionMs < 8 * day || retentionMs > 30 * day ||
        !Number.isInteger(maximumAutomaticTurns) || maximumAutomaticTurns < 1 || maximumAutomaticTurns > 8 ||
        !Number.isInteger(callbackTimeoutMs) || callbackTimeoutMs < 1 || callbackTimeoutMs > 10000 || typeof clock !== 'function') fail('invalid_request');
    this.#client = client; this.#clock = clock; this.#current = proof; this.#capacity = capacity;
    this.#retention = retentionMs; this.#maximumTurns = maximumAutomaticTurns; this.#callbackTimeout = callbackTimeoutMs;
    this.#scope = JSON.stringify({ account: idText(proof.account), device: idText(proof.device), line: idText(proof.line), interval: idText(proof.interval),
      connector: idText(proof.connector), readGrant: idText(proof.readGrant), reader: Buffer.from(proof.reader).toString('hex') });
    try {
      this.#db = new DatabaseSync(journalPath);
      this.#db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;
        CREATE TABLE IF NOT EXISTS original_reply_scope(id INTEGER PRIMARY KEY CHECK(id=1),scope TEXT NOT NULL,last_clock INTEGER NOT NULL,denied INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS original_reply_checkpoints(seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL UNIQUE,request_id TEXT NOT NULL UNIQUE,
          active_request_id TEXT,semantic_digest TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN('unknown','consumed','retired')),outcome TEXT,created_ms INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS original_reply_turns(seq INTEGER PRIMARY KEY AUTOINCREMENT,active_request_id TEXT NOT NULL UNIQUE,attempted INTEGER NOT NULL);`);
      const existing = this.#db.prepare('SELECT * FROM original_reply_scope WHERE id=1').get();
      if (existing && existing.scope !== this.#scope) fail('foreign_scope');
      if (!existing) this.#db.prepare('INSERT INTO original_reply_scope(id,scope,last_clock) VALUES(1,?,?)').run(this.#scope, this.#now());
      this.#denied = Boolean(existing?.denied);
      this.#receiver = new SealedEventReceiver({ path: receiverPath, accountId: idText(proof.account), deviceId: idText(proof.device), lineId: idText(proof.line),
        webhookSecret, cursorSecret, clock, capacity, retentionMs, authority: () => {
          const p = this.#current;
          return { active: !this.#denied && !this.#closed && BigInt(this.#now()) < p.expiresMs,
            accountId: idText(p.account), deviceId: idText(p.device), lineId: idText(p.line), expiresAtMs: Number(p.expiresMs), revision: p.revision };
        } });
    } catch { this.#receiver?.close(); this.#db?.close(); fail('unavailable'); }
  }
  #now() { const value = this.#clock(); if (!Number.isSafeInteger(value) || value <= 0) fail('unavailable'); return value; }
  #local() {
    if (this.#closed || this.#denied) fail('unavailable');
    const row = this.#db.prepare('SELECT last_clock,denied FROM original_reply_scope WHERE id=1').get(), now = this.#now();
    if (!row || row.denied || now < row.last_clock) fail('unavailable');
    this.#db.prepare('UPDATE original_reply_scope SET last_clock=? WHERE id=1').run(now); return now;
  }
  async #refresh() {
    this.#local(); const proof = await this.#client.current();
    const selected = JSON.stringify({ account: idText(proof.account), device: idText(proof.device), line: idText(proof.line), interval: idText(proof.interval),
      connector: idText(proof.connector), readGrant: idText(proof.readGrant), reader: Buffer.from(proof.reader).toString('hex') });
    if (selected !== this.#scope || this.#local() >= Number(proof.expiresMs)) fail('unavailable');
    this.#current = proof;
  }
  #transaction(fn) {
    this.#db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); this.#db.exec('COMMIT'); return result; }
    catch (error) { this.#db.exec('ROLLBACK'); throw error; }
  }
  #reserve(eventId, activeRequestId, semanticDigest, automatic) {
    return this.#transaction(() => {
      const now = this.#local(), existing = this.#db.prepare('SELECT * FROM original_reply_checkpoints WHERE event_id=?').get(eventId);
      if (existing) {
        if (existing.active_request_id !== activeRequestId || existing.semantic_digest !== semanticDigest) fail('conflict');
        return { row: existing, fresh: false };
      }
      const count = this.#db.prepare("SELECT count(*) AS n,sum(CASE WHEN state!='retired' THEN 1 ELSE 0 END) AS active FROM original_reply_checkpoints").get();
      if (count.n >= 8192 || count.active >= this.#capacity) fail('capacity');
      if (automatic && activeRequestId !== null) {
        const turns = this.#db.prepare('SELECT attempted FROM original_reply_turns WHERE active_request_id=?').get(activeRequestId);
        if ((turns?.attempted ?? 0) >= this.#maximumTurns) fail('loop_limit');
        if (!turns && this.#db.prepare('SELECT count(*) AS n FROM original_reply_turns').get().n >= 128) fail('capacity');
        this.#db.prepare('INSERT INTO original_reply_turns(active_request_id,attempted) VALUES(?,1) ON CONFLICT(active_request_id) DO UPDATE SET attempted=attempted+1').run(activeRequestId);
      }
      const requestId = randomUUID();
      this.#db.prepare("INSERT INTO original_reply_checkpoints(event_id,request_id,active_request_id,semantic_digest,state,created_ms) VALUES(?,?,?,?,'unknown',?)")
        .run(eventId, requestId, activeRequestId, semanticDigest, now);
      return { row: { event_id: eventId, request_id: requestId }, fresh: true };
    });
  }
  #complete(row, outcome) {
    if (outcome.event_id !== row.event_id || outcome.consumption_id !== row.request_id) fail('unavailable');
    this.#transaction(() => {
      this.#local(); const result = this.#db.prepare("UPDATE original_reply_checkpoints SET state='consumed',outcome=? WHERE event_id=? AND request_id=? AND state='unknown'")
        .run(JSON.stringify(outcome), row.event_id, row.request_id);
      if (result.changes !== 1) fail('unavailable');
    });
  }
  async #reconcile(row) {
    if (row.state === 'retired') fail('retired');
    const outcome = await this.#client.status(row.request_id);
    if (row.state === 'unknown') this.#complete(row, outcome);
    else if (outcome.event_id !== row.event_id || JSON.stringify(outcome) !== row.outcome) fail('conflict');
    return { replay: true, outcome };
  }
  async #operation(fn) {
    if (this.#busy) fail('unavailable'); this.#busy = true;
    try { return await fn(); }
    catch (error) { if (error instanceof OriginalReplyEventError) throw error; fail('unavailable'); }
    finally { this.#busy = false; }
  }
  /** Metadata ingest remains raw-byte HMAC/digest authenticated and opaque. No body classification. */
  ingest(bytes, headers) { return this.#operation(async () => { await this.#refresh(); const result = this.#receiver.ingest(bytes, headers); await this.#refresh(); return result; }); }
  page(cursor = null, limit = 20) { return this.#operation(async () => { await this.#refresh(); return this.#client.page(cursor, limit); }); }
  /** Explicit descriptor submission uses only the independent Propose credential held by the client. */
  consume(input) {
    return this.#operation(async () => {
      closed(input, ['event_id', 'active_request_id', 'descriptor']);
      if (!validId(input.event_id) || input.active_request_id !== null && !validId(input.active_request_id)) fail('invalid_request');
      const descriptor = input.descriptor === null ? null : JSON.parse(new TextDecoder().decode(canonicalWorkflowAction(input.descriptor)));
      const owned = { event_id: input.event_id, active_request_id: input.active_request_id, descriptor };
      const digest = hash(JSON.stringify(owned)); await this.#refresh();
      const reservation = this.#reserve(owned.event_id, owned.active_request_id, digest, descriptor !== null);
      if (!reservation.fresh) return this.#reconcile(reservation.row);
      const outcome = await this.#client.consume({ request_id: reservation.row.request_id, ...owned });
      this.#complete(reservation.row, outcome); await this.#refresh(); return { replay: false, outcome };
    });
  }
  /** One bounded transient original-text callback. A crash or timeout becomes status-only recovery.
   * No callback is run for unassociated events. Its output is a proposal, never approval or Send.
   */
  process(eventId, activeRequestId, propose, automaticAuthority = null) {
    return this.#operation(async () => {
      if (!validId(eventId) || activeRequestId !== null && !validId(activeRequestId) || activeRequestId !== null && typeof propose !== 'function') fail('invalid_request');
      const digest = hash(JSON.stringify({ event_id: eventId, active_request_id: activeRequestId, method: 'process' }));
      await this.#refresh(); const reservation = this.#reserve(eventId, activeRequestId, digest, activeRequestId !== null);
      if (!reservation.fresh) return this.#reconcile(reservation.row);
      if (automaticAuthority !== null) { if (typeof automaticAuthority !== 'function') fail('invalid_request'); automaticAuthority(); }
      let descriptor = null;
      if (activeRequestId !== null) {
        const text = await this.#client.read(idBytes(eventId));
        if (automaticAuthority !== null) automaticAuthority();
        const controller = new AbortController(); let timer;
        try { descriptor = await Promise.race([Promise.resolve().then(() => propose(text, { eventId, activeRequestId, signal: controller.signal })),
          new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new OriginalReplyEventError('unavailable')); }, this.#callbackTimeout); })]); }
        finally { clearTimeout(timer); controller.abort(); }
        if (descriptor !== null) descriptor = JSON.parse(new TextDecoder().decode(canonicalWorkflowAction(descriptor)));
      }
      // The callback is an arbitrary await. Local erasure or live withdrawal
      // during that await must stop a new proposal, not merely its return value.
      await this.#refresh();
      if (automaticAuthority !== null) automaticAuthority();
      const outcome = await this.#client.consume({ request_id: reservation.row.request_id, event_id: eventId, active_request_id: activeRequestId, descriptor });
      this.#complete(reservation.row, outcome); await this.#refresh(); return { replay: false, outcome };
    });
  }
  /** Trusted-local metadata takeout; does not grant a remote reader or require a live service. */
  exportMetadata({ kind = 'checkpoints', after = 0, limit = 20 } = {}) {
    if (this.#closed || !['checkpoints', 'turns'].includes(kind) || !Number.isSafeInteger(after) || after < 0 || !Number.isInteger(limit) || limit < 1 || limit > 32) fail('invalid_request');
    const rows = kind === 'checkpoints' ? this.#db.prepare('SELECT seq,event_id,request_id,active_request_id,semantic_digest,state,outcome,created_ms FROM original_reply_checkpoints WHERE seq>? ORDER BY seq LIMIT ?').all(after, limit)
      : this.#db.prepare('SELECT seq,active_request_id,attempted FROM original_reply_turns WHERE seq>? ORDER BY seq LIMIT ?').all(after, limit);
    return { kind, rows, next: rows.length === limit ? rows[rows.length - 1].seq : null, opaque: true };
  }
  /** Existing opaque capture metadata only; bounded by the configured receiver
   * capacity and fenced by the independently current original-reader grant. */
  exportOpaqueMetadata() { return this.#operation(async () => {
    await this.#refresh(); const result = this.#receiver.exportMetadata(); await this.#refresh(); return result;
  }); }
  /** Retire completed payload metadata but preserve bounded event/request tombstones and unknowns. */
  retain() {
    return this.#transaction(() => { const now = this.#local(); return this.#db.prepare("UPDATE original_reply_checkpoints SET state='retired',outcome=NULL WHERE state='consumed' AND created_ms<?").run(now - this.#retention).changes; });
  }
  /** Logical customer-local erasure. WAL copies/backups and already shared plaintext are not retracted. */
  erase() {
    if (this.#closed) fail('unavailable'); this.#denied = true;
    this.#transaction(() => { this.#db.exec('UPDATE original_reply_scope SET denied=1 WHERE id=1; DELETE FROM original_reply_checkpoints; DELETE FROM original_reply_turns;'); });
    this.#receiver.erase();
  }
  close() { if (this.#closed) return; this.#closed = true; this.#receiver?.close(); this.#db?.close(); }
}
