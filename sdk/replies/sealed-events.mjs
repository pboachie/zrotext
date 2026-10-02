// SPDX-License-Identifier: AGPL-3.0-only
/** Customer-local opaque receiver. Webhook authentication is not content-reader authority. */
import { DatabaseSync } from 'node:sqlite';
import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { createReplyEventServer, ReplyEventError } from './reply-events.mjs';
import { parseConversationInbound02 } from '../typescript/dist/conversation-reader.js';

const fields = ['v', 'type', 'event_id', 'delivery_id', 'account_id', 'device_id',
  'observed_at_ms', 'envelope_b64', 'unsigned_digest_b64'];
const day = 86_400_000;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const same = (left, right) => left.length === right.length && timingSafeEqual(left, right);
const validId = value => typeof value === 'string' && uuid.test(value) && !/^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(value);
const bytesId = bytes => {
  const text = Buffer.from(bytes).toString('hex');
  return `${text.slice(0, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}-${text.slice(16, 20)}-${text.slice(20)}`;
};
export class SealedEventError extends Error {
  constructor(code) { super(code); this.name = 'SealedEventError'; this.code = code; }
}
const fail = code => { throw new SealedEventError(code); };
function decode(value, minimum, maximum) {
  if (typeof value !== 'string' || value.length > Math.ceil(maximum / 3) * 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail('invalid_event');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length < minimum || bytes.length > maximum || bytes.toString('base64') !== value) fail('invalid_event');
  return bytes;
}

/** One durable ledger per independently selected account/device/line. No envelope,
 * peer, plaintext, private key, reply classification or action reservation is stored. */
export class SealedEventReceiver {
  constructor({ path, accountId, deviceId, lineId, webhookSecret, cursorSecret, authority,
    clock = Date.now, capacity = 4096, retentionMs = 8 * day }) {
    if (typeof path !== 'string' || !path || path === ':memory:' ||
        ![accountId, deviceId, lineId].every(validId) || typeof authority !== 'function' ||
        typeof clock !== 'function' || !Number.isInteger(capacity) || capacity < 1 || capacity > 4096 ||
        !Number.isSafeInteger(retentionMs) || retentionMs < 8 * day || retentionMs > 30 * day ||
        !(webhookSecret instanceof Uint8Array) || webhookSecret.length !== 32 ||
        !(cursorSecret instanceof Uint8Array) || cursorSecret.length !== 32) fail('invalid_request');
    Object.assign(this, { accountId, deviceId, lineId, authority, clock, capacity, retentionMs });
    this.webhookSecret = Buffer.from(webhookSecret); this.cursorSecret = Buffer.from(cursorSecret);
    this.db = new DatabaseSync(path);
    try {
      this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;
        CREATE TABLE IF NOT EXISTS sealed_scope(id INTEGER PRIMARY KEY CHECK(id=1),account TEXT NOT NULL,
          device TEXT NOT NULL,line TEXT NOT NULL,instance TEXT NOT NULL,last_clock INTEGER NOT NULL,
          floor INTEGER NOT NULL DEFAULT 0,denied INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS sealed_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,event TEXT NOT NULL UNIQUE,
          digest TEXT NOT NULL,envelope_digest TEXT NOT NULL,observed INTEGER NOT NULL,received INTEGER NOT NULL,
          revision TEXT NOT NULL);`);
      const existing = this.db.prepare('SELECT * FROM sealed_scope WHERE id=1').get();
      if (existing && (existing.account !== accountId || existing.device !== deviceId || existing.line !== lineId)) fail('foreign_scope');
      if (!existing) this.db.prepare('INSERT INTO sealed_scope(id,account,device,line,instance,last_clock) VALUES(1,?,?,?,?,?)')
        .run(accountId, deviceId, lineId, randomUUID(), this.now());
    } catch (error) { this.db.close(); this.webhookSecret.fill(0); this.cursorSecret.fill(0); throw error; }
  }
  now() {
    const value = this.clock();
    if (!Number.isSafeInteger(value) || value < 0) fail('unavailable');
    return value;
  }
  transaction(operation) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = operation(); this.db.exec('COMMIT'); return result; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  current(now) {
    const scope = this.db.prepare('SELECT * FROM sealed_scope WHERE id=1').get();
    if (scope.denied || now < scope.last_clock) fail('revoked');
    let live; try { live = this.authority(); } catch { fail('revoked'); }
    if (!live || live.active !== true || live.accountId !== this.accountId || live.deviceId !== this.deviceId ||
        live.lineId !== this.lineId || !Number.isSafeInteger(live.expiresAtMs) || live.expiresAtMs <= now ||
        typeof live.revision !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(live.revision)) fail('revoked');
    this.db.prepare('UPDATE sealed_scope SET last_clock=? WHERE id=1').run(now);
    return { ...scope, revision: live.revision };
  }
  prune(now) {
    const row = this.db.prepare('SELECT max(seq) AS seq FROM sealed_events WHERE received<=?').get(now - this.retentionMs);
    if (row.seq !== null) {
      this.db.prepare('UPDATE sealed_scope SET floor=max(floor,?) WHERE id=1').run(row.seq);
      this.db.prepare('DELETE FROM sealed_events WHERE received<=?').run(now - this.retentionMs);
    }
  }
  ingest(raw, headers) {
    if (!(raw instanceof Uint8Array) || raw.length < 1 || raw.length > 65_536) fail('invalid_event');
    raw = Buffer.from(raw);
    const now = this.now(), timestamp = headers?.['x-zrotext-timestamp'], signature = headers?.['x-zrotext-signature'];
    if (typeof timestamp !== 'string' || !/^[1-9][0-9]{0,12}$/.test(timestamp) ||
        !Number.isSafeInteger(Number(timestamp)) || Math.abs(now - Number(timestamp) * 1000) > 300_000 ||
        typeof signature !== 'string' || !/^v1=[0-9a-f]{64}$/.test(signature) ||
        !same(createHmac('sha256', this.webhookSecret).update(timestamp).update('.').update(raw).digest(),
          Buffer.from(signature.slice(3), 'hex'))) fail('invalid_signature');
    let event;
    try { event = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)); } catch { fail('invalid_event'); }
    if (!event || Array.isArray(event) || Object.keys(event).length !== fields.length ||
        fields.some(field => !Object.hasOwn(event, field)) || event.v !== 1 || event.type !== 'sealed.inbound_event' ||
        !['event_id', 'delivery_id', 'account_id', 'device_id'].every(field => validId(event[field])) ||
        !Number.isSafeInteger(event.observed_at_ms) || event.observed_at_ms < now - 7 * day ||
        event.observed_at_ms > now) fail('invalid_event');
    if (event.account_id !== this.accountId || event.device_id !== this.deviceId) fail('foreign_scope');
    const bytes = decode(event.envelope_b64, 426, 34_082), unsignedDigest = decode(event.unsigned_digest_b64, 32, 32);
    let envelope;
    try { envelope = parseConversationInbound02(bytes); } catch { fail('invalid_event'); }
    if (bytesId(envelope.accountId) !== this.accountId || bytesId(envelope.deviceId) !== this.deviceId ||
        bytesId(envelope.lineId) !== this.lineId || bytesId(envelope.eventId) !== event.event_id ||
        envelope.observedMs !== BigInt(event.observed_at_ms) ||
        !same(createHash('sha256').update(envelope.unsigned).digest(), unsignedDigest)) fail('foreign_scope');
    // Syntax/digest consistency is not origin-signature or manifest verification.
    const digest = unsignedDigest.toString('hex'), envelopeDigest = hash(bytes);
    return this.transaction(() => {
      const live = this.current(this.now()); this.prune(this.now());
      const previous = this.db.prepare('SELECT * FROM sealed_events WHERE event=?').get(event.event_id);
      if (previous) {
        if (previous.digest !== digest || previous.envelope_digest !== envelopeDigest || previous.observed !== event.observed_at_ms)
          fail('identity_conflict');
        if (previous.revision !== live.revision) fail('revoked');
        this.current(this.now()); return { eventId: event.event_id, created: false };
      }
      if (this.db.prepare('SELECT count(*) AS total FROM sealed_events').get().total >= this.capacity) fail('retention_full');
      this.db.prepare('INSERT INTO sealed_events(event,digest,envelope_digest,observed,received,revision) VALUES(?,?,?,?,?,?)')
        .run(event.event_id, digest, envelopeDigest, event.observed_at_ms, this.now(), live.revision);
      if (this.current(this.now()).revision !== live.revision) fail('revoked');
      return { eventId: event.event_id, created: true };
    });
  }
  page({ consumerId, cursor = null, limit = 20 }) {
    if (!validId(consumerId) || !Number.isInteger(limit) || limit < 1 || limit > 20) fail('invalid_request');
    return this.transaction(() => {
      const now = this.now(), live = this.current(now); this.prune(now);
      let after = this.db.prepare('SELECT floor FROM sealed_scope WHERE id=1').get().floor;
      if (cursor !== null) {
        if (typeof cursor !== 'string' || cursor.length > 1024 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(cursor)) fail('invalid_cursor');
        const [payload, mac] = cursor.split('.');
        if (!same(createHmac('sha256', this.cursorSecret).update(payload).digest(), Buffer.from(mac, 'base64url'))) fail('invalid_cursor');
        let value; try { value = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); } catch { fail('invalid_cursor'); }
        if (!Array.isArray(value) || value.length !== 5 || value[0] !== live.instance || value[1] !== consumerId ||
            value[2] !== live.revision || !Number.isSafeInteger(value[3]) || value[3] < after ||
            !Number.isSafeInteger(value[4]) || value[4] <= now || value[4] > now + 300_000) fail('invalid_cursor');
        after = value[3];
      }
      const rows = this.db.prepare('SELECT * FROM sealed_events WHERE seq>? ORDER BY seq LIMIT ?').all(after, limit);
      if (rows.some(row => row.revision !== live.revision)) fail('revoked');
      const events = rows.map(row => ({ sequence: row.seq, eventId: row.event, accountId: this.accountId,
        deviceId: this.deviceId, lineId: this.lineId, observedAtMs: row.observed, unsignedDigest: row.digest,
        content: { kind: 'unavailable' }, approval: false }));
      const payload = Buffer.from(JSON.stringify([live.instance, consumerId, live.revision,
        rows.at(-1)?.seq ?? after, now + 300_000])).toString('base64url');
      if (this.current(this.now()).revision !== live.revision) fail('revoked');
      return { events, cursor: `${payload}.${createHmac('sha256', this.cursorSecret).update(payload).digest('base64url')}` };
    });
  }
  consume() { fail('unavailable'); }
  exportMetadata() {
    return this.transaction(() => {
      const live = this.current(this.now()); this.prune(this.now());
      const rows = this.db.prepare('SELECT event,digest,observed,received,revision FROM sealed_events ORDER BY seq').all();
      if (rows.some(row => row.revision !== live.revision)) fail('revoked');
      if (this.current(this.now()).revision !== live.revision) fail('revoked');
      return { accountId: this.accountId, deviceId: this.deviceId, lineId: this.lineId, events: rows };
    });
  }
  expire() { this.transaction(() => { this.current(this.now()); this.prune(this.now()); }); }
  deny() { this.db.prepare('UPDATE sealed_scope SET denied=1 WHERE id=1').run(); }
  erase() { this.transaction(() => { this.db.exec('UPDATE sealed_scope SET denied=1 WHERE id=1; DELETE FROM sealed_events;'); }); }
  close() { this.db.close(); this.webhookSecret.fill(0); this.cursorSecret.fill(0); }
}

/** Reuse the bounded customer transport, adapting redacted errors only. There is
 * no consumption/action API: /consume always refuses. TLS ingress is operator-owned. */
export function createSealedEventServer(receiver, authenticate) {
  // The shared server recognizes ReplyEventError; preserve its closed status mapping.
  const adapter = Object.create(receiver);
  for (const method of ['ingest', 'page', 'consume', 'expire']) adapter[method] = (...args) => {
    try { return receiver[method](...args); }
    catch (error) {
      if (error instanceof SealedEventError) {
        // Importing the class statically avoids granting any legacy reply semantics.
        throw new ReplyEventError(error.code);
      }
      throw error;
    }
  };
  return createReplyEventServer(adapter, authenticate);
}
