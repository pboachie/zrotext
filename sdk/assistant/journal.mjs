// SPDX-License-Identifier: AGPL-3.0-only
// Customer-owned provider-call metadata only; not a decision/send/schedule ledger.
import { DatabaseSync } from 'node:sqlite';
import { closeSync, lstatSync, openSync } from 'node:fs';
import { isAbsolute } from 'node:path';

export class RoutineError extends Error {
  constructor(code) { super(code); this.name = 'RoutineError'; this.code = code; }
}
const fail = code => { throw new RoutineError(code); };
const maxRows = 1000;

export class RoutineJournal {
  #db;
  constructor(path) {
    if (typeof path !== 'string' || !isAbsolute(path)) fail('storage_unavailable');
    try {
      try { closeSync(openSync(path, 'wx', 0o600)); }
      catch (error) { if (error?.code !== 'EEXIST') throw error; }
      const stat = lstatSync(path);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error();
      this.#db = new DatabaseSync(path);
      this.#db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        PRAGMA busy_timeout=1000; PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY CHECK(version=1)) STRICT;
        INSERT OR IGNORE INTO schema_version VALUES(1);
        CREATE TABLE IF NOT EXISTS policies(scope TEXT PRIMARY KEY, digest TEXT NOT NULL,
          expires_ms INTEGER NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS controls(scope TEXT PRIMARY KEY REFERENCES policies(scope),
          reason TEXT NOT NULL CHECK(reason IN ('stop','takeover'))) STRICT;
        CREATE TABLE IF NOT EXISTS clock(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
          high_water INTEGER NOT NULL, erased INTEGER NOT NULL CHECK(erased IN (0,1))) STRICT;
        INSERT OR IGNORE INTO clock VALUES(1,0,0);
        CREATE TABLE IF NOT EXISTS calls(id TEXT PRIMARY KEY, scope TEXT NOT NULL REFERENCES policies(scope),
          conversation TEXT NOT NULL, request_digest TEXT NOT NULL, day INTEGER NOT NULL, units INTEGER NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('reserved','unknown','proposed','refused')),
          expires_ms INTEGER NOT NULL, result TEXT) STRICT;`);
      if (this.#db.prepare('SELECT count(*) AS n FROM schema_version WHERE version=1').get().n !== 1) throw new Error();
      if (this.#db.prepare('PRAGMA quick_check').get().quick_check !== 'ok') throw new Error();
    } catch { this.#db?.close(); fail('storage_unavailable'); }
  }
  #transaction(fn) {
    try {
      this.#db.exec('BEGIN IMMEDIATE');
      const result = fn();
      this.#db.exec('COMMIT');
      return result;
    } catch (error) {
      try { this.#db.exec('ROLLBACK'); } catch { /* preserve closed failure */ }
      if (error instanceof RoutineError) throw error;
      fail('storage_unavailable');
    }
  }
  bind(scope, digest, expiresMs) {
    this.#transaction(() => {
      if (this.#db.prepare('SELECT erased FROM clock WHERE singleton=1').get().erased) fail('erased');
      const existing = this.#db.prepare('SELECT digest FROM policies WHERE scope=?').get(scope);
      if (existing && existing.digest !== digest) fail('policy_conflict');
      if (!existing && this.#db.prepare('SELECT count(*) AS n FROM policies').get().n >= maxRows) fail('capacity');
      this.#db.prepare('INSERT OR IGNORE INTO policies VALUES(?,?,?)').run(scope, digest, expiresMs);
    });
  }
  check(scope, now) {
    return this.#transaction(() => {
      const policy = this.#db.prepare('SELECT expires_ms FROM policies WHERE scope=?').get(scope);
      if (!policy || policy.expires_ms <= now) fail('expired');
      const clock = this.#db.prepare('SELECT high_water,erased FROM clock WHERE singleton=1').get();
      if (clock.erased) fail('erased');
      const high = clock.high_water;
      if (now < high) fail('clock_unavailable');
      this.#db.prepare('UPDATE clock SET high_water=? WHERE singleton=1').run(now);
      if (this.#db.prepare('SELECT reason FROM controls WHERE scope=?').get(scope)) fail('withdrawn');
    });
  }
  withdraw(scope, reason) {
    if (!['stop', 'takeover'].includes(reason)) fail('invalid_request');
    this.#transaction(() => this.#db.prepare('INSERT OR IGNORE INTO controls VALUES(?,?)').run(scope, reason));
  }
  reserve({id, scope, conversation, digest, now, expiresMs, units, callLimit, unitLimit, turnLimit}) {
    return this.#transaction(() => {
      // This check is in the same write transaction as all budget counters.
      const policy = this.#db.prepare('SELECT expires_ms FROM policies WHERE scope=?').get(scope);
      if (!policy || policy.expires_ms <= now || this.#db.prepare('SELECT 1 FROM controls WHERE scope=?').get(scope)) fail('withdrawn');
      const clock = this.#db.prepare('SELECT high_water,erased FROM clock WHERE singleton=1').get();
      if (clock.erased) fail('erased');
      const high = clock.high_water;
      if (now < high) fail('clock_unavailable');
      this.#db.prepare('UPDATE clock SET high_water=? WHERE singleton=1').run(now);
      const previous = this.#db.prepare('SELECT request_digest,state,result FROM calls WHERE id=?').get(id);
      if (previous) {
        if (previous.request_digest !== digest) fail('replay_conflict');
        return { state: previous.state === 'reserved' ? 'unknown' : previous.state,
          ...(previous.result ? JSON.parse(previous.result) : {}) };
      }
      const day = Math.floor(now / 86400000);
      // Global daily limits span all scopes/generations in this customer journal.
      const daily = this.#db.prepare('SELECT count(*) AS n,coalesce(sum(units),0) AS units FROM calls WHERE day=?').get(day);
      const turns = this.#db.prepare('SELECT count(*) AS n FROM calls WHERE conversation=?').get(conversation).n;
      if (daily.n >= callLimit || daily.units + units > unitLimit || turns >= turnLimit) fail('budget_exhausted');
      if (this.#db.prepare('SELECT count(*) AS n FROM calls').get().n >= maxRows) fail('capacity');
      this.#db.prepare('INSERT INTO calls VALUES(?,?,?,?,?,?,?,?,NULL)').run(id,scope,conversation,digest,day,units,'reserved',expiresMs);
      return null;
    });
  }
  mark(id, scope, state, result = null) {
    if (!['unknown','refused','proposed'].includes(state)) fail('invalid_request');
    this.#transaction(() => {
      const changed = this.#db.prepare("UPDATE calls SET state=?,result=? WHERE id=? AND scope=? AND state IN ('reserved','unknown')")
        .run(state, result ? JSON.stringify(result) : null, id, scope).changes;
      if (changed !== 1) fail('replay_conflict');
    });
  }
  exportMetadata(before = null) {
    if (before !== null && (typeof before !== 'string' || !/^[0-9a-f]{64}$/.test(before))) fail('invalid_request');
    try {
      if (before && !this.#db.prepare('SELECT 1 FROM calls WHERE id=?').get(before)) fail('not_found');
      const rows = this.#db.prepare('SELECT id,scope,day,units,state,expires_ms,result FROM calls WHERE (? IS NULL OR id<?) ORDER BY id DESC LIMIT 101').all(before,before);
      const truncated = rows.length > 100; rows.length = Math.min(rows.length,100);
      return { calls: rows.map(row => ({ ...row, result: row.result ? JSON.parse(row.result) : null })),
        truncated, nextCursor: truncated ? rows.at(-1).id : null };
    } catch (error) { if (error instanceof RoutineError) throw error; fail('storage_unavailable'); }
  }
  prune(now) {
    return this.#transaction(() => {
      const high = this.#db.prepare('SELECT high_water FROM clock WHERE singleton=1').get().high_water;
      if (now < high) fail('clock_unavailable');
      // Retain charged calls until their UTC budget day AND policy have expired.
      // An early event expiry must not replenish today's provider/turn budget.
      this.#db.prepare('DELETE FROM calls WHERE expires_ms<=? AND day<? AND scope IN (SELECT scope FROM policies WHERE expires_ms<=?)')
        .run(now, Math.floor(now / 86400000), now);
      this.#db.prepare('DELETE FROM controls WHERE scope IN (SELECT scope FROM policies WHERE expires_ms<=? AND NOT EXISTS (SELECT 1 FROM calls WHERE calls.scope=policies.scope))').run(now);
      this.#db.prepare('DELETE FROM policies WHERE expires_ms<=? AND NOT EXISTS (SELECT 1 FROM calls WHERE calls.scope=policies.scope)').run(now);
      this.#db.prepare('UPDATE clock SET high_water=? WHERE singleton=1').run(now);
    });
  }
  eraseMetadata() {
    this.#transaction(() => this.#db.exec('DELETE FROM calls; DELETE FROM controls; DELETE FROM policies; UPDATE clock SET erased=1 WHERE singleton=1;'));
  }
  close() { this.#db.close(); }
}
