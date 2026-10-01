// SPDX-License-Identifier: AGPL-3.0-only
/** Customer-local candidate adapter. No send, approval or server grant authority. */
import { DatabaseSync } from 'node:sqlite';
import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const digest = value => createHash('sha256').update(value).digest('hex');
const fail = code => { throw new ReplyEventError(code); };
const id = value => { if (typeof value !== 'string' || !uuid.test(value)) fail('invalid_request'); return value; };
const integer = value => Number.isSafeInteger(value) && value >= 0;
const equal = (a, b) => a.length === b.length && timingSafeEqual(a, b);
const stopClasses = new Set(['opt_out', 'opt_out_review']);
const classes = new Set(['captured_local', 'sim_unverified', 'send_unverified', 'encryption_unverified',
  'opt_out', 'opt_out_review', 'opt_in']);
const fields = ['v', 'type', 'event_id', 'delivery_id', 'account_id', 'device_id', 'message_id',
  'attempt_id', 'classification', 'observed_at_ms', 'part_count', 'content_kind',
  'content_ciphertext_b64', 'event_digest_b64', 'device_signature_der_b64'];

export class ReplyEventError extends Error {
  constructor(code) { super(code); this.name = 'ReplyEventError'; this.code = code; }
}

function base64(value, min, max) {
  if (typeof value !== 'string' || value.length > Math.ceil(max / 3) * 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) fail('invalid_event');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length < min || bytes.length > max || bytes.toString('base64') !== value) fail('invalid_event');
  return bytes;
}

function parseEvent(raw) {
  let event;
  try { event = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)); } catch { fail('invalid_event'); }
  if (!event || Array.isArray(event) || Object.keys(event).length !== fields.length ||
      fields.some(field => !Object.hasOwn(event, field)) || event.v !== 1 || event.type !== 'inbound.message' ||
      !classes.has(event.classification) || !integer(event.observed_at_ms) ||
      !Number.isInteger(event.part_count) || event.part_count < 1 || event.part_count > 6 ||
      !['metadata_only', 'opaque_pilot'].includes(event.content_kind)) fail('invalid_event');
  for (const field of ['event_id', 'delivery_id', 'account_id', 'device_id', 'message_id', 'attempt_id']) id(event[field]);
  base64(event.event_digest_b64, 32, 32);
  base64(event.device_signature_der_b64, 8, 80);
  if (event.content_kind === 'metadata_only') {
    if (event.content_ciphertext_b64 !== null) fail('invalid_event');
  } else base64(event.content_ciphertext_b64, 32, 8192);
  if (stopClasses.has(event.classification) && event.content_kind !== 'metadata_only') fail('invalid_event');
  return event;
}

/** Each database is bound to one account/line. Secrets remain only in local memory.
 * authority is an independently authenticated synchronous current-scope lookup,
 * not data supplied by the agent or webhook. Absence always denies access.
 * reader may fetch existing selected content by event identity; ciphertext and
 * plaintext never enter this metadata ledger. Current opaque_pilot is not read. */
export class ReplyEventAdapter {
  constructor({ path, accountId, lineId, webhookSecret, cursorSecret, authority,
    reader, readerId = null, clock = Date.now, retentionMs = 86_400_000, maxEvents = 1024 }) {
    this.accountId = id(accountId); this.lineId = id(lineId);
    if (typeof path !== 'string' || !path || path === ':memory:' ||
        !(webhookSecret instanceof Uint8Array) || webhookSecret.length !== 32 ||
        !(cursorSecret instanceof Uint8Array) || cursorSecret.length !== 32 ||
        typeof clock !== 'function' || !integer(retentionMs) || retentionMs < 60_000 || retentionMs > 604_800_000 ||
        !Number.isInteger(maxEvents) || maxEvents < 1 || maxEvents > 4096) fail('invalid_request');
    this.webhookSecret = Buffer.from(webhookSecret); this.cursorSecret = Buffer.from(cursorSecret);
    this.authority = authority; this.reader = reader; this.clock = clock;
    this.readerId = readerId === null ? null : id(readerId);
    this.retentionMs = retentionMs; this.maxEvents = maxEvents;
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=1000; PRAGMA secure_delete=ON;
      CREATE TABLE IF NOT EXISTS scope(id INTEGER PRIMARY KEY CHECK(id=1), account TEXT NOT NULL,
        line TEXT NOT NULL, instance TEXT NOT NULL, format INTEGER NOT NULL DEFAULT 1, floor INTEGER NOT NULL DEFAULT 0,
        last_clock INTEGER NOT NULL DEFAULT 0, stopped INTEGER NOT NULL DEFAULT 0,
        revoked INTEGER NOT NULL DEFAULT 0, takeover INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, event TEXT UNIQUE NOT NULL,
        fingerprint TEXT NOT NULL, device TEXT NOT NULL, message TEXT NOT NULL, attempt TEXT NOT NULL,
        classification TEXT NOT NULL, observed INTEGER NOT NULL, received INTEGER NOT NULL,
        revision TEXT NOT NULL, content_kind TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS consumers(id TEXT PRIMARY KEY, checkpoint INTEGER NOT NULL DEFAULT 0,
        gap_count INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, message TEXT NOT NULL, attempt TEXT NOT NULL,
        device TEXT NOT NULL, starts INTEGER NOT NULL, expires INTEGER NOT NULL, max_turns INTEGER NOT NULL,
        turns INTEGER NOT NULL DEFAULT 0, last_observed INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY, event TEXT UNIQUE NOT NULL,
        consumer TEXT NOT NULL, disposition TEXT NOT NULL, state TEXT NOT NULL, created INTEGER NOT NULL);`);
    const scope = this.db.prepare('SELECT * FROM scope WHERE id=1').get();
    if (!scope) this.db.prepare('INSERT INTO scope(id,account,line,instance) VALUES(1,?,?,?)')
      .run(this.accountId, this.lineId, randomUUID());
    else if (scope.account !== this.accountId || scope.line !== this.lineId || scope.format !== 1) { this.db.close(); fail('foreign_scope'); }
    this.instance = this.db.prepare('SELECT instance FROM scope WHERE id=1').get().instance;
  }

  close() { this.db.close(); this.webhookSecret.fill(0); this.cursorSecret.fill(0); }
  transaction(operation) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = operation(); this.db.exec('COMMIT'); return result; }
    catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }
  now() {
    const now = this.clock();
    if (!integer(now)) fail('unavailable');
    return now;
  }
  current(event, now) {
    const scope = this.db.prepare('SELECT * FROM scope WHERE id=1').get();
    if (scope.revoked || scope.takeover || now < scope.last_clock) fail('revoked');
    let current;
    try { current = this.authority?.(event ? Object.freeze({ ...event }) : null, now); } catch { fail('unavailable'); }
    if (!current || current.active !== true || current.accountId !== this.accountId || current.lineId !== this.lineId ||
        typeof current.revision !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(current.revision) ||
        !integer(current.expiresAtMs) || current.expiresAtMs <= now ||
        (event && current.deviceId !== event.device_id)) fail('revoked');
    return current;
  }
  prune(now) {
    const floor = this.db.prepare('SELECT max(seq) AS seq FROM events WHERE received<=?').get(now - this.retentionMs).seq;
    if (floor !== null) {
      this.db.prepare('UPDATE scope SET floor=max(floor,?) WHERE id=1').run(floor);
      this.db.prepare('DELETE FROM actions WHERE event IN (SELECT event FROM events WHERE received<=?)').run(now - this.retentionMs);
      this.db.prepare('DELETE FROM events WHERE received<=?').run(now - this.retentionMs);
    }
    this.db.prepare('DELETE FROM requests WHERE expires<=?').run(now - this.retentionMs);
    this.db.prepare('UPDATE scope SET last_clock=? WHERE id=1').run(now);
  }
  /** Call periodically when idle; expiry also runs on resume, consumption and export.
   * Erasure does not require a still-active content-reader grant. */
  expire() {
    const now = this.now();
    this.transaction(() => {
      if (now < this.db.prepare('SELECT last_clock FROM scope WHERE id=1').get().last_clock) fail('unavailable');
      this.prune(now);
    });
  }

  /** Verify HMAC of exact transport bytes before parsing or exposing identities. */
  ingest(raw, headers) {
    const now = this.now();
    if (!(raw instanceof Uint8Array) || raw.length < 1 || raw.length > 65_536) fail('invalid_event');
    raw = Buffer.from(raw);
    const timestamp = headers?.['x-zrotext-timestamp']; const signature = headers?.['x-zrotext-signature'];
    if (typeof timestamp !== 'string' || !/^[1-9][0-9]{0,12}$/.test(timestamp) ||
        !Number.isSafeInteger(Number(timestamp)) || Math.abs(now - Number(timestamp) * 1000) > 300_000 ||
        typeof signature !== 'string' || !/^v1=[0-9a-f]{64}$/.test(signature)) fail('invalid_signature');
    const expected = createHmac('sha256', this.webhookSecret).update(timestamp).update('.').update(raw).digest();
    if (!equal(expected, Buffer.from(signature.slice(3), 'hex'))) fail('invalid_signature');
    const event = parseEvent(raw);
    if (event.account_id !== this.accountId) fail('foreign_scope');
    if (event.observed_at_ms > now + 300_000 || event.observed_at_ms <= now - this.retentionMs) fail('expired');
    const result = this.transaction(() => {
      const current = this.current(event, now); this.prune(now);
      // Delivery identity may change on replay; the original inbound identity may not.
      const core = { ...event }; delete core.delivery_id;
      const fingerprint = digest(JSON.stringify(fields.filter(field => field !== 'delivery_id').map(field => core[field])));
      const old = this.db.prepare('SELECT fingerprint,seq FROM events WHERE event=?').get(event.event_id);
      if (old) { if (old.fingerprint !== fingerprint) fail('identity_conflict'); return { created: false, sequence: old.seq }; }
      // Even a full retention ledger must durably stop pending automatic work.
      if (stopClasses.has(event.classification)) this.db.prepare('UPDATE scope SET stopped=1 WHERE id=1').run();
      if (this.db.prepare('SELECT count(*) AS count FROM events').get().count >= this.maxEvents) return { full: true };
      const inserted = this.db.prepare(`INSERT INTO events(event,fingerprint,device,message,attempt,
        classification,observed,received,revision,content_kind) VALUES(?,?,?,?,?,?,?,?,?,?)`)
        .run(event.event_id, fingerprint, event.device_id, event.message_id, event.attempt_id,
          event.classification, event.observed_at_ms, now, current.revision, event.content_kind);
      return { created: true, sequence: Number(inserted.lastInsertRowid) };
    });
    if (result.full) fail('retention_full');
    return result;
  }

  /** This local request records correlation only. It cannot approve or queue SMS. */
  registerRequest(request) {
    const now = this.now();
    if (!request || !integer(request.startsAtMs) || !integer(request.expiresAtMs) ||
        request.startsAtMs > now || request.expiresAtMs <= now || request.expiresAtMs > now + this.retentionMs ||
        !Number.isInteger(request.maxTurns) || request.maxTurns < 1 || request.maxTurns > 8) fail('invalid_request');
    const snapshot = { id: id(request.id), message: id(request.messageId), attempt: id(request.attemptId),
      device: id(request.deviceId), starts: request.startsAtMs, expires: request.expiresAtMs, max: request.maxTurns };
    return this.transaction(() => {
      this.current({ device_id: snapshot.device, message_id: snapshot.message, attempt_id: snapshot.attempt,
        account_id: this.accountId, line_id: this.lineId }, now); this.prune(now);
      if (this.db.prepare('SELECT count(*) AS count FROM requests').get().count >= 128) fail('retention_full');
      const old = this.db.prepare('SELECT * FROM requests WHERE id=?').get(snapshot.id);
      if (old) {
        if (old.message !== snapshot.message || old.attempt !== snapshot.attempt || old.device !== snapshot.device ||
            old.starts !== snapshot.starts || old.expires !== snapshot.expires || old.max_turns !== snapshot.max) fail('identity_conflict');
        return;
      }
      this.db.prepare('INSERT INTO requests(id,message,attempt,device,starts,expires,max_turns) VALUES(?,?,?,?,?,?,?)')
        .run(snapshot.id, snapshot.message, snapshot.attempt, snapshot.device, snapshot.starts, snapshot.expires, snapshot.max);
    });
  }

  consumer(consumerId) {
    id(consumerId);
    const row = this.db.prepare('SELECT checkpoint FROM consumers WHERE id=?').get(consumerId);
    if (row) return row.checkpoint;
    if (this.db.prepare('SELECT count(*) AS count FROM consumers').get().count >= 16) fail('retention_full');
    this.db.prepare('INSERT INTO consumers(id) VALUES(?)').run(consumerId);
    return 0;
  }
  /** Trusted local owner reconciliation after explicit expired-gap review.
   * Never exposed to an agent HTTP client, and never performs skipped effects. */
  resynchronize(consumerId) {
    this.expire();
    return this.transaction(() => {
      this.current(null, this.now()); const checkpoint = this.consumer(consumerId);
      const floor = this.db.prepare('SELECT floor FROM scope WHERE id=1').get().floor;
      if (checkpoint < floor) this.db.prepare('UPDATE consumers SET checkpoint=?,gap_count=gap_count+1 WHERE id=?').run(floor, consumerId);
      return { skippedThrough: floor, reviewRequired: true };
    });
  }
  cursor(consumerId, sequence, revision, now) {
    const payload = Buffer.from(JSON.stringify([1, this.instance, this.accountId, this.lineId, consumerId,
      sequence, revision, now + this.retentionMs])).toString('base64url');
    return payload + '.' + createHmac('sha256', this.cursorSecret).update(payload).digest('base64url');
  }
  readCursor(token, consumerId, revision, now) {
    if (typeof token !== 'string' || token.length > 1024 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(token)) fail('invalid_cursor');
    const [payload, signature] = token.split('.');
    if (!equal(createHmac('sha256', this.cursorSecret).update(payload).digest(), Buffer.from(signature, 'base64url'))) fail('invalid_cursor');
    let values;
    try { values = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); } catch { fail('invalid_cursor'); }
    if (!Array.isArray(values) || values.length !== 8 || values[0] !== 1 || values[1] !== this.instance ||
        values[2] !== this.accountId || values[3] !== this.lineId || values[4] !== consumerId ||
        !integer(values[5]) || values[6] !== revision || !integer(values[7]) || values[7] <= now) fail('invalid_cursor');
    const scope = this.db.prepare('SELECT floor FROM scope WHERE id=1').get();
    if (values[5] < scope.floor) fail('cursor_expired');
    return values[5];
  }
  event(row) {
    return { account_id: this.accountId, line_id: this.lineId, device_id: row.device,
      event_id: row.event, message_id: row.message, attempt_id: row.attempt,
      classification: row.classification, observed_at_ms: row.observed };
  }
  async content(row, now) {
    if (stopClasses.has(row.classification)) return { kind: 'metadata_stop' };
    // opaque_pilot is explicitly not a reviewed customer content format.
    const grant = this.current(this.event(row), now);
    if (row.content_kind === 'opaque_pilot' || row.observed <= now - this.retentionMs ||
        this.readerId === null || grant.canReadContent !== true || grant.readerId !== this.readerId ||
        this.db.prepare('SELECT stopped FROM scope WHERE id=1').get().stopped || typeof this.reader !== 'function') {
      return { kind: 'unavailable' };
    }
    let result; const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
      result = await Promise.race([
        this.reader(Object.freeze(this.event(row)), controller.signal),
        new Promise((_, reject) => controller.signal.addEventListener('abort', () => reject(new Error()), { once: true })),
      ]);
    } catch { return { kind: 'unavailable' }; }
    finally { clearTimeout(timeout); }
    const current = this.current(this.event(row), this.now());
    if (row.observed <= this.now() - this.retentionMs || current.canReadContent !== true ||
        current.readerId !== this.readerId ||
        this.db.prepare('SELECT stopped FROM scope WHERE id=1').get().stopped) return { kind: 'unavailable' };
    if (!result || result.kind !== 'decrypted' || typeof result.text !== 'string' ||
        Buffer.byteLength(result.text, 'utf8') < 1 || Buffer.byteLength(result.text, 'utf8') > 32_768 ||
        Buffer.from(result.text, 'utf8').toString('utf8') !== result.text ||
        result.text.includes('\0') || result.text.startsWith('\ufeff')) return { kind: 'unavailable' };
    return { kind: 'decrypted', text: result.text, readerId: this.readerId };
  }

  async page({ consumerId, cursor = null, limit = 20 }) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 20) fail('invalid_request');
    this.expire();
    const now = this.now();
    const selection = this.transaction(() => {
      const current = this.current(null, now); this.prune(now);
      const checkpoint = this.consumer(consumerId);
      const after = cursor === null ? checkpoint : this.readCursor(cursor, consumerId, current.revision, now);
      const floor = this.db.prepare('SELECT floor FROM scope WHERE id=1').get().floor;
      if (after < floor) fail('cursor_expired');
      const rows = this.db.prepare('SELECT * FROM events WHERE seq>? ORDER BY seq LIMIT ?').all(Math.max(after, checkpoint), limit);
      return { rows, revision: current.revision, after };
    });
    const events = [];
    for (const row of selection.rows) {
      const current = this.current(this.event(row), this.now());
      if (row.revision !== current.revision || current.revision !== selection.revision) fail('revoked');
      const content = await this.content(row, this.now());
      if (this.current(this.event(row), this.now()).revision !== row.revision) fail('revoked');
      events.push({ sequence: row.seq, ...this.event(row), content, consumed: row.consumed === 1, approval: false });
    }
    const sequence = events.at(-1)?.sequence ?? selection.after;
    return { events, cursor: this.cursor(consumerId, sequence, selection.revision, this.now()) };
  }

  /** Atomic consumption plus a durable action identity, committed before any effect.
   * Replays return the original reservation; they never grant another execution.
   * A reserved action recovered after restart is uncertain and must not be retried. */
  async consume({ consumerId, eventId, actionId }) {
    id(consumerId); id(eventId); id(actionId);
    this.expire();
    const row = this.db.prepare('SELECT * FROM events WHERE event=?').get(eventId);
    if (!row) fail('expired');
    const now = this.now(); const current = this.current(this.event(row), now);
    if (current.revision !== row.revision) fail('revoked');
    const content = await this.content(row, now);
    return this.transaction(() => {
      const time = this.now();
      const live = this.current(this.event(row), time);
      if (live.revision !== row.revision) fail('revoked');
      this.prune(time);
      const stored = this.db.prepare('SELECT * FROM events WHERE event=?').get(eventId);
      if (!stored) fail('expired');
      const previous = this.db.prepare('SELECT * FROM actions WHERE event=? OR id=?').get(eventId, actionId);
      if (previous) {
        if (previous.event !== eventId || previous.id !== actionId || previous.consumer !== consumerId) fail('identity_conflict');
        return { actionId, disposition: previous.disposition, execute: false,
          state: previous.state === 'reserved' ? 'unknown' : previous.state, approval: false };
      }
      const checkpoint = this.consumer(consumerId);
      const next = this.db.prepare('SELECT seq FROM events WHERE seq>? ORDER BY seq LIMIT 1').get(checkpoint);
      if (!next || next.seq !== stored.seq || stored.consumed) fail('out_of_order');
      const scope = this.db.prepare('SELECT stopped FROM scope WHERE id=1').get();
      const candidates = this.db.prepare(`SELECT * FROM requests WHERE message=? AND attempt=? AND device=?
        AND starts<=? AND expires>? AND expires>?`).all(stored.message, stored.attempt, stored.device, stored.observed, time, stored.observed);
      let disposition = stopClasses.has(stored.classification) ? 'stop' : 'owner_review';
      let request;
      if (!scope.stopped && content.kind === 'decrypted' && live.canReadContent === true &&
          live.readerId === this.readerId && stored.classification === 'captured_local' &&
          stored.observed > time - this.retentionMs && stored.observed <= time && candidates.length === 1) {
        request = candidates[0];
        if (stored.observed >= request.last_observed && request.turns < request.max_turns) disposition = 'reply_notice';
      }
      if (disposition === 'reply_notice') this.db.prepare('UPDATE requests SET turns=turns+1,last_observed=? WHERE id=?')
        .run(stored.observed, request.id);
      this.db.prepare('INSERT INTO actions(id,event,consumer,disposition,state,created) VALUES(?,?,?,?,?,?)')
        .run(actionId, eventId, consumerId, disposition, 'reserved', time);
      this.db.prepare('UPDATE events SET consumed=1 WHERE event=?').run(eventId);
      this.db.prepare('UPDATE consumers SET checkpoint=? WHERE id=?').run(stored.seq, consumerId);
      return { actionId, disposition, execute: true, state: 'reserved', approval: false };
    });
  }

  /** Local recipient reply notification/review only; callback must enforce its own
   * idempotency using actionId. There is deliberately no SMS/approval callback. */
  async runAction(request, effect) {
    if (typeof effect !== 'function') fail('invalid_request');
    const reservation = await this.consume(request);
    if (!reservation.execute) return reservation;
    const row = this.db.prepare('SELECT * FROM events WHERE event=?').get(request.eventId);
    try {
      if (!row) fail('revoked');
      const current = this.current(this.event(row), this.now());
      if (current.revision !== row.revision || (reservation.disposition === 'reply_notice' &&
          (current.canReadContent !== true || current.readerId !== this.readerId))) fail('revoked');
      if (reservation.disposition === 'reply_notice' && this.db.prepare('SELECT stopped FROM scope WHERE id=1').get().stopped) fail('revoked');
      await effect(Object.freeze({ ...reservation }));
      this.db.prepare("UPDATE actions SET state='completed' WHERE id=? AND state='reserved'").run(reservation.actionId);
      return { ...reservation, state: 'completed' };
    } catch {
      this.db.prepare("UPDATE actions SET state='unknown' WHERE id=? AND state='reserved'").run(reservation.actionId);
      return { ...reservation, state: 'unknown', execute: false };
    }
  }

  /** Trusted local owner control, never available through event text. No undo API. */
  deny(reason) {
    if (!['revocation', 'takeover', 'deletion'].includes(reason)) fail('invalid_request');
    this.transaction(() => {
      this.db.prepare(`UPDATE scope SET ${reason === 'takeover' ? 'takeover' : 'revoked'}=1 WHERE id=1`).run();
      if (reason === 'deletion') this.db.exec('DELETE FROM actions; DELETE FROM events; DELETE FROM requests; DELETE FROM consumers;');
    });
  }
  exportMetadata() {
    this.expire();
    this.current(null, this.now());
    return { accountId: this.accountId, lineId: this.lineId,
      events: this.db.prepare('SELECT event,device,message,attempt,classification,observed,consumed FROM events ORDER BY seq').all(),
      actions: this.db.prepare('SELECT id,event,consumer,disposition,state FROM actions ORDER BY created,id').all(),
      checkpoints: this.db.prepare('SELECT id,checkpoint,gap_count FROM consumers ORDER BY id').all() };
  }
}

/** Unstarted customer HTTP server. The deployment must supply TLS/egress ingress
 * controls; the test/local listener can bind localhost. Agent authentication is
 * a separate trusted callback and can never register requests or change scope. */
export function createReplyEventServer(adapter, authenticate) {
  let inFlight = 0; let expiry;
  const server = createServer({ maxHeaderSize: 8192 }, async (request, response) => {
    response.setHeader('content-type', 'application/json');
    response.setHeader('cache-control', 'no-store');
    response.setHeader('x-content-type-options', 'nosniff');
    if (inFlight >= 4) { response.writeHead(503); response.end('{"code":"unavailable"}'); return; }
    inFlight++;
    const send = (status, body) => {
      if (response.destroyed || response.writableEnded) return;
      response.writeHead(status); response.end(JSON.stringify(body));
    };
    try {
      const url = new URL(request.url, 'http://adapter.invalid');
      if (url.pathname === '/webhook' && request.method === 'POST' && !url.search) {
        const raw = await body(request, 65_536);
        send(202, adapter.ingest(raw, request.headers));
        return;
      }
      let access;
      try { access = await authenticate?.(request.headers.authorization); } catch { fail('unauthorized'); }
      if (!access || !uuid.test(access.consumerId)) fail('unauthorized');
      if (url.pathname === '/events' && request.method === 'GET') {
        if ([...url.searchParams.keys()].some(key => !['cursor', 'limit'].includes(key)) ||
            ['cursor', 'limit'].some(key => url.searchParams.getAll(key).length > 1)) fail('invalid_request');
        send(200, await adapter.page({ consumerId: access.consumerId, cursor: url.searchParams.get('cursor'),
          limit: url.searchParams.has('limit') ? Number(url.searchParams.get('limit')) : 20 }));
      } else if (url.pathname === '/consume' && request.method === 'POST' && !url.search) {
        let input; try { input = JSON.parse((await body(request, 1024)).toString('utf8')); } catch { fail('invalid_request'); }
        if (!input || Array.isArray(input) || Object.keys(input).length !== 2 ||
            !Object.hasOwn(input, 'eventId') || !Object.hasOwn(input, 'actionId')) fail('invalid_request');
        send(200, await adapter.consume({ ...input, consumerId: access.consumerId }));
      } else send(404, { code: 'unavailable' });
    } catch (error) {
      const code = error instanceof ReplyEventError ? error.code : 'unavailable';
      const status = code === 'unauthorized' ? 401 : ['revoked', 'foreign_scope'].includes(code) ? 403
        : ['expired', 'cursor_expired'].includes(code) ? 410 : ['identity_conflict', 'out_of_order'].includes(code) ? 409
        : ['unavailable', 'retention_full'].includes(code) ? 503 : 400;
      send(status, { code });
    } finally { inFlight--; }
  });
  server.on('listening', () => {
    clearInterval(expiry);
    expiry = setInterval(() => {
      try { adapter.expire(); } catch { /* Access paths still enforce expiry and fail closed on storage failure. */ }
    }, 60_000);
    expiry.unref();
  });
  server.on('close', () => clearInterval(expiry));
  return server;
}

async function body(request, maximum) {
  if (request.headers['content-length'] !== undefined &&
      (!/^[0-9]{1,6}$/.test(request.headers['content-length']) || Number(request.headers['content-length']) > maximum)) fail('invalid_request');
  const chunks = []; let count = 0;
  const timeout = setTimeout(() => request.destroy(), 5000);
  try {
    for await (const chunk of request) { count += chunk.length; if (count > maximum) fail('invalid_request'); chunks.push(chunk); }
    return Buffer.concat(chunks);
  } finally { clearTimeout(timeout); }
}
