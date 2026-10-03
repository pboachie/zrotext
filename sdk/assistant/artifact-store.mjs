// SPDX-License-Identifier: AGPL-3.0-only
// Durable encrypted artifacts only; no credentials, model text or approvals.
import { DatabaseSync } from 'node:sqlite';
import { isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { closed, fail, id, digest } from './routine-service.mjs';
import { privateStore } from './private-store.mjs';
export const ciphertextDigest = bytes => createHash('sha256').update(bytes).digest('hex');
export class CipherArtifactStore {
  #db; #guard;
  constructor(path) {
    if(typeof path!=='string'||!isAbsolute(path)) fail('storage_unavailable');
    try {
      this.#guard=privateStore(path);
      this.#db=new DatabaseSync(path);
      this.#db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=1000;
        CREATE TABLE IF NOT EXISTS encrypted_artifacts(call_id TEXT PRIMARY KEY, input_context TEXT NOT NULL,
        input_revision INTEGER NOT NULL CHECK(input_revision BETWEEN 1 AND 128), input_digest TEXT NOT NULL,
        archive_digest TEXT NOT NULL, expires_ms INTEGER NOT NULL, envelope BLOB NOT NULL) STRICT;
        CREATE TABLE IF NOT EXISTS observed_clock(singleton INTEGER PRIMARY KEY CHECK(singleton=1),high_water INTEGER NOT NULL CHECK(high_water BETWEEN 0 AND 9007199254740991)) STRICT;
        INSERT OR IGNORE INTO observed_clock VALUES(1,0);
        CREATE TRIGGER IF NOT EXISTS observed_clock_before_update BEFORE UPDATE ON observed_clock
          WHEN NEW.singleton<>OLD.singleton OR NEW.high_water<OLD.high_water
          BEGIN SELECT RAISE(ABORT,'clock cannot roll back'); END;`);
      this.#guard.verify();
      if(this.#db.prepare('PRAGMA quick_check').get().quick_check!=='ok') throw Error();
    } catch { this.#db?.close(); fail('storage_unavailable'); }
  }
  observeTime(nowMs){
    if(!Number.isSafeInteger(nowMs)||nowMs<1)fail('clock_unavailable');this.#guard.verify();
    try{this.#db.exec('BEGIN IMMEDIATE');const prior=this.#db.prepare('SELECT high_water FROM observed_clock WHERE singleton=1').get();
      if(!prior||nowMs<prior.high_water)fail('clock_unavailable');
      this.#db.prepare('UPDATE observed_clock SET high_water=? WHERE singleton=1').run(nowMs);this.#db.exec('COMMIT');
    }catch(error){try{this.#db.exec('ROLLBACK');}catch{}if(error?.code==='clock_unavailable')throw error;fail('storage_unavailable');}
    this.#guard.verify();return nowMs;
  }
  put(value) {
    this.#guard.verify();
    const v=closed(value,['call_id','input_context','input_revision','input_digest','expires_ms','envelope']);
    if(!id(v.call_id)||!id(v.input_context)||!Number.isSafeInteger(v.input_revision)||v.input_revision<1||v.input_revision>128||
      !digest(v.input_digest)||!Number.isSafeInteger(v.expires_ms)||v.expires_ms<1||!(v.envelope instanceof Uint8Array)||v.envelope.length<308||v.envelope.length>33075) fail('invalid_artifact');
    const bytes=Uint8Array.from(v.envelope), hash=ciphertextDigest(bytes);
    // Only the assigned initial ZTWC output context may enter this journal.
    const header=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
    if(Buffer.from(bytes.subarray(0,5)).toString('hex')!=='5a54574301'||![1,2,3].includes(bytes[5])||
      Buffer.from(bytes.subarray(70,86)).toString('hex')!==v.call_id.replaceAll('-','')||
      header.getBigUint64(94)!==1n||header.getBigUint64(102)!==BigInt(v.expires_ms)||header.getUint32(287)!==bytes.length-291) {bytes.fill(0);fail('invalid_artifact');}
    try {
      this.#db.exec('BEGIN IMMEDIATE');
      const old=this.#db.prepare('SELECT * FROM encrypted_artifacts WHERE call_id=?').get(v.call_id);
      if(old && (old.input_context!==v.input_context||old.input_revision!==v.input_revision||old.input_digest!==v.input_digest||old.archive_digest!==hash||old.expires_ms!==v.expires_ms||!Buffer.from(old.envelope).equals(Buffer.from(bytes)))) fail('artifact_conflict');
      if(!old) {
        const totals=this.#db.prepare('SELECT count(*) AS n, COALESCE(sum(length(envelope)),0) AS bytes FROM encrypted_artifacts').get();
        if(totals.n>=1000||totals.bytes+bytes.length>4*1024*1024) fail('capacity');
        this.#db.prepare('INSERT INTO encrypted_artifacts VALUES(?,?,?,?,?,?,?)').run(v.call_id,v.input_context,v.input_revision,v.input_digest,hash,v.expires_ms,bytes);
      }
      this.#db.exec('COMMIT'); this.#guard.verify(); return hash;
    } catch(e) { try{this.#db.exec('ROLLBACK');}catch{} if(e?.code) throw e; fail('storage_unavailable'); }
    finally { bytes.fill(0); }
  }
  read(callId,nowMs) {
    this.#guard.verify();
    if(!id(callId)||!Number.isSafeInteger(nowMs)||nowMs<1) fail('invalid_request');
    // Observation commits before expiry refusal. Erase/prune never reset it.
    this.observeTime(nowMs);
    const v=this.#db.prepare('SELECT * FROM encrypted_artifacts WHERE call_id=?').get(callId);
    if(!v||v.expires_ms<=nowMs) fail('artifact_unavailable');
    this.#guard.verify();
    const envelope=Uint8Array.from(v.envelope);
    if(ciphertextDigest(envelope)!==v.archive_digest) fail('storage_unavailable');
    return Object.freeze({...v,envelope});
  }
  erase(callId) { this.#guard.verify(); if(!id(callId)) fail('invalid_request'); this.#db.prepare('DELETE FROM encrypted_artifacts WHERE call_id=?').run(callId); }
  prune(nowMs) { this.#guard.verify(); if(!Number.isSafeInteger(nowMs)||nowMs<1) fail('invalid_request'); this.observeTime(nowMs);this.#db.prepare('DELETE FROM encrypted_artifacts WHERE expires_ms<=?').run(nowMs);this.#guard.verify(); }
  close() { this.#db.close(); }
}
