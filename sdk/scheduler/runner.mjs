// SPDX-License-Identifier: AGPL-3.0-only
// Customer-owned credentials stay outside the durable metadata journal.
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { existsSync, openSync, closeSync, lstatSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { WorkflowToolClient, WorkflowToolError } from '../typescript/dist/workflow-tool-client.js';
import { validateWorkflowRequest } from '../typescript/dist/workflow-tools.js';

export class SchedulerError extends Error {
  constructor(code) { super(code); this.code = code; }
}
const fail = code => { throw new SchedulerError(code); };
const snapshot = value => JSON.parse(JSON.stringify(value));
const ordered = value => Array.isArray(value) ? value.map(ordered) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, ordered(value[key])])) : value;
const encode = value => JSON.stringify(ordered(value));
const terminal = new Set(['prepared', 'cancelled', 'expired', 'blocked']);

/** Explicitly installed customer timer; never a relay actor or renderer. */
export class ScheduledRunner {
  #client; #db; #active = false; #running = false; #epoch = 0;
  constructor({ client, filename, enabled = false }) {
    if (!(client instanceof WorkflowToolClient) || typeof filename !== 'string' || !isAbsolute(filename)) fail('invalid_configuration');
    // The enclosing directory is trusted customer startup configuration. Never
    // put this journal in a directory writable by an untrusted local actor.
    if (!existsSync(filename)) closeSync(openSync(filename, 'wx', 0o600));
    const file = lstatSync(filename);
    if (!file.isFile() || file.isSymbolicLink() || file.nlink !== 1 || (process.platform !== 'win32' && (file.mode & 0o077))) fail('invalid_configuration');
    this.#client = client;
    this.#db = new DatabaseSync(filename);
    this.#db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=3000;
      CREATE TABLE IF NOT EXISTS scheduled_actions (
        action_id TEXT PRIMARY KEY, identity TEXT NOT NULL, state TEXT NOT NULL,
        next_ms INTEGER NOT NULL, request_id TEXT, result TEXT, lease_id TEXT,
        lease_until INTEGER NOT NULL DEFAULT 0
      );`);
    this.#active = enabled === true;
  }
  #operation() { if (!this.#active) fail('disabled'); return this.#epoch; }
  #check(epoch) { if (!this.#active || this.#epoch !== epoch) fail('disabled'); }
  async #ready(context) {
    const ready = await this.#client.readiness();
    for (const method of ['workflow.action.status', 'workflow.action.schedule', 'workflow.action.send']) {
      if (!ready.methods.some(entry => entry.method === method && entry.permission_granted)) fail('unavailable_permission');
    }
    if (context && ready.scope.context_id !== context) fail('scope_changed');
    return ready.scope.context_id;
  }
  /** Reserve the real server occurrence; never invent a local approved action. */
  async enqueue(params) {
    const epoch = this.#operation();
    validateWorkflowRequest('workflow.action.schedule', params);
    params = snapshot(params);
    const context = await this.#ready();
    this.#check(epoch);
    const pending = { context_id: context, key: params.key, occurrence: null, schedule_request: params.request_id, params };
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#db.prepare('SELECT identity FROM scheduled_actions WHERE action_id=?').get(params.key.action_id);
      if (row) {
        const stored = JSON.parse(row.identity);
        if (stored.context_id !== context || encode(stored.params) !== encode(params)) fail('changed_schedule');
      } else {
        if (this.#db.prepare('SELECT count(*) AS n FROM scheduled_actions').get().n >= 1000) fail('journal_full');
        // Reserve bounded metadata before the scheduling mutation. A crash or
        // response loss can be resumed only with this exact schedule request.
        this.#db.prepare("INSERT INTO scheduled_actions(action_id,identity,state,next_ms) VALUES(?,?,'schedule_unknown',0)")
          .run(params.key.action_id, encode(pending));
      }
      this.#db.exec('COMMIT');
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
    this.#check(epoch);
    const result = await this.#client.call('workflow.action.schedule', params);
    const occurrence = result.result;
    const identity = encode({ context_id: context, key: params.key, occurrence,
      schedule_request: params.request_id, params });
    const row = this.#db.prepare('SELECT identity FROM scheduled_actions WHERE action_id=?').get(params.key.action_id);
    if (row && JSON.parse(row.identity).occurrence !== null) {
      // The server replay has already rechecked actual authority. Do not adopt
      // changed output/window identities as a fresh scheduler job.
      if (row.identity !== identity) fail('changed_schedule');
      return this.inspect(params.key.action_id);
    }
    const state = occurrence.phase === 'owner_review' ? 'owner_review' : 'waiting';
    this.#db.prepare("UPDATE scheduled_actions SET identity=?,state=?,next_ms=? WHERE action_id=? AND state='schedule_unknown'")
      .run(identity, state, occurrence.opens_at_ms ?? occurrence.expires_at_ms, params.key.action_id);
    return this.inspect(params.key.action_id);
  }
  inspect(action) {
    const row = this.#db.prepare('SELECT state,request_id,result FROM scheduled_actions WHERE action_id=?').get(action);
    if (!row) fail('not_found');
    return { state: row.state, request_id: row.request_id, result: row.result ? JSON.parse(row.result) : null };
  }
  #claim(action) {
    const lease = randomUUID(), now = Date.now();
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.#db.prepare('SELECT * FROM scheduled_actions WHERE action_id=?').get(action);
      if (!row) fail('not_found');
      if (terminal.has(row.state) || row.state === 'owner_review' || row.state === 'schedule_unknown' || row.next_ms > now || row.lease_until > now) {
        this.#db.exec('COMMIT'); return null;
      }
      this.#db.prepare('UPDATE scheduled_actions SET lease_id=?,lease_until=? WHERE action_id=?').run(lease, now + 60000, action);
      this.#db.exec('COMMIT'); return { ...row, lease, identity: JSON.parse(row.identity) };
    } catch (error) { this.#db.exec('ROLLBACK'); throw error; }
  }
  #finish(row, state, result, request = row.request_id) {
    const changed = this.#db.prepare('UPDATE scheduled_actions SET state=?,result=?,request_id=?,next_ms=?,lease_id=NULL,lease_until=0 WHERE action_id=? AND lease_id=?')
      .run(state, result ? encode(result) : null, request, Date.now() + 5000, row.action_id, row.lease).changes;
    if (changed !== 1) fail('lease_lost');
  }
  async advance(action) {
    const epoch = this.#operation();
    const row = this.#claim(action);
    if (!row) return this.inspect(action);
    try {
      const { key, context_id: context, occurrence } = row.identity;
      await this.#ready(context);
      this.#check(epoch);
      const status = (await this.#client.call('workflow.action.status', { request_id: randomUUID(), context_id: context, action_id: key.action_id })).result;
      this.#check(epoch);
      if (['account_id','action_id','revision','binding_digest'].some(field => status.key[field] !== key[field])) fail('action_changed');
      if (status.phase === 'dispatching' && status.delivery.availability === 'available') {
        // The public occurrence DTO intentionally contains no dispatch ID.
        // Discover it only through the server's exact-action delivery projection.
        this.#finish(row, 'prepared', { state: 'prepared', message_id: status.delivery.message_id, dispatch_id: status.delivery.dispatch_id });
      } else if (['dispatching', 'unknown'].includes(status.phase) && status.delivery.availability !== 'available') {
        // Unavailable projection metadata cannot prove rollback or completion.
        // Retain the original send identity and continue status-only recovery.
        this.#finish(row, 'unknown', null);
      } else if (status.phase !== 'approved') {
        this.#finish(row, 'blocked', null);
      } else if (row.state === 'unknown') {
        // A lost response cannot prove rollback. Reconcile only; no automatic
        // exact replay or fresh send identity after uncertainty, even on restart.
        this.#finish(row, 'unknown', null);
      } else if (Date.now() >= occurrence.expires_at_ms) {
        // Local wall time is only a conservative stop/wakeup hint. Server time
        // and current authority remain the effect predicates on every call.
        this.#finish(row, 'expired', null);
      } else {
        this.#check(epoch);
        const request = randomUUID();
        const changed = this.#db.prepare("UPDATE scheduled_actions SET state='unknown',request_id=?,result=NULL WHERE action_id=? AND lease_id=? AND lease_until>?")
          .run(request, action, row.lease, Date.now()).changes;
        if (changed !== 1) fail('lease_lost');
        row.request_id = request;
        row.state = 'unknown';
        const sent = (await this.#client.call('workflow.action.send', { request_id: request, key, occurrence_id: occurrence.occurrence_id })).result;
        this.#finish(row, sent.state === 'prepared' ? 'prepared' : 'waiting', sent, request);
      }
    } catch (error) {
      if (error instanceof SchedulerError && error.code === 'disabled') {
        // Stop pending work without changing its durable waiting/unknown truth.
        this.#db.prepare('UPDATE scheduled_actions SET lease_id=NULL,lease_until=0 WHERE action_id=? AND lease_id=?').run(action, row.lease);
      } else if (row.state === 'unknown' || (error instanceof WorkflowToolError && error.state === 'unknown')) this.#finish(row, 'unknown', null);
      else this.#finish(row, 'blocked', null);
      throw error;
    }
    return this.inspect(action);
  }
  /** Explicit own-prepared withdrawal; server owns identity/grant/refund CAS. */
  async cancel(action, request = randomUUID()) {
    const epoch = this.#operation();
    const row = this.#db.prepare('SELECT identity FROM scheduled_actions WHERE action_id=?').get(action);
    if (!row) fail('not_found');
    const { key, context_id: context } = JSON.parse(row.identity);
    await this.#ready(context);
    this.#check(epoch);
    const response = (await this.#client.call('workflow.action.cancel', { request_id: request, key })).result;
    this.#db.prepare("UPDATE scheduled_actions SET state='cancelled',result=?,lease_id=NULL,lease_until=0 WHERE action_id=?")
      .run(encode(response), action);
    return this.inspect(action);
  }
  /** Bounded unattended customer loop; credentials are rechecked per cycle. */
  async run({ signal } = {}) {
    if (!this.#active || this.#running) fail('disabled');
    this.#running = true;
    try {
      while (!signal?.aborted && this.#active) {
        const due = this.#db.prepare("SELECT action_id FROM scheduled_actions WHERE state IN ('waiting','unknown') AND next_ms<=? ORDER BY next_ms,action_id LIMIT 20").all(Date.now());
        for (const row of due) {
          if (signal?.aborted || !this.#active) break;
          await this.advance(row.action_id).catch(() => {}); // redacted durable state remains inspectable
        }
        await new Promise(resolve => {
          const finish = () => { clearTimeout(timer); signal?.removeEventListener('abort', finish); resolve(); };
          const timer = setTimeout(finish, 5000);
          signal?.addEventListener('abort', finish, { once: true });
          if (signal?.aborted) finish();
        });
      }
    } finally { this.#running = false; }
  }
  disable() { this.#active = false; this.#epoch += 1; }
  close() { if (this.#running) fail('runner_active'); this.#active = false; this.#epoch += 1; this.#db.close(); }
}
