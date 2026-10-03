// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, createHmac } from 'node:crypto';
import { parseConversationInbound02 } from '../dist/conversation-reader.js';
import { DatabaseSync } from 'node:sqlite';
import { OriginalReplyClient } from '../dist/original-reply-client.js';
import { createOriginalReplyReceiver } from '../../replies/original-reply-events.mjs';
import { originalReplyFixture } from './original-reply-fixture.mjs';
const hex = b => Buffer.from(b).toString('hex');
const uuid = b => hex(b).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
async function fixture() {
  const f = await originalReplyFixture(), dir = await mkdtemp(join(tmpdir(), 'original-reply-'));
  const proof = { account_id: uuid(f.scope.account), interval_id: uuid(f.scope.interval), device_id: uuid(f.scope.device), line_id: uuid(f.scope.line),
    connector_id: uuid(f.scope.connector), read_grant_id: uuid(f.scope.readGrant), reader_id: hex(f.scope.reader), root_generation: 1, authority_revision: 1,
    expires_at_ms: 90000, observed_at_ms: 2000, current_manifest_version: 7, current_manifest_digest: hex(f.manifest.digest),
    manifest_chain: [{ version: 7, accepted_at_ms: 2000, manifest_b64: Buffer.from(f.manifest.bytes).toString('base64') }] };
  const effects = new Map(), calls = []; let lose = false, revoked = false;
  const client = new OriginalReplyClient({ origin: 'https://customer.invalid', credential: 'ztr_' + Buffer.alloc(32, 7).toString('base64url'),
    scope: f.scope, privateKey: f.privateKey, acceptedHistory: [f.manifest], clock: () => 2000n,
    fetch: async (_url, init) => {
      const r = JSON.parse(init.body); calls.push(r.method);
      if (revoked) return new Response('', { status: 403 });
      let result;
      if (r.method === 'current') result = proof;
      else if (r.method === 'consume') {
        assert.equal(init.headers['x-zrotext-output-authorization'], undefined);
        result = { event_id: r.params.event_id, consumption_id: r.params.request_id, disposition: 'owner_review', active_request_id: r.params.active_request_id, action: null };
        effects.set(r.params.request_id, result);
        if (lose) { lose = false; throw new Error('synthetic lost receipt'); }
      } else if (r.method === 'status') {
        result = effects.get(r.consumption_id); if (!result) return new Response('', { status: 403 });
      } else if (r.method === 'read') result = { event_id: uuid(f.event), accepted_at_ms: 2000, envelope_b64: Buffer.from(f.envelope).toString('base64'),
        historical_manifest_version: 7, statement_b64: Buffer.from(f.statement).toString('base64'), approval_signature_b64: Buffer.from(f.approval).toString('base64'),
        installation_signature_b64: Buffer.from(f.installation).toString('base64'), activation_manifest_version: 7, proof };
      else throw new Error('unexpected method');
      return new Response(JSON.stringify({ kind: r.method, result }), { headers: { 'content-type': 'application/json' } });
    } });
  const options = { client, journalPath: join(dir, 'journal.sqlite'), receiverPath: join(dir, 'receiver.sqlite'),
    webhookSecret: Buffer.alloc(32, 9), cursorSecret: Buffer.alloc(32, 10), clock: () => 2000 };
  return { f, options, calls, dir, lose: () => { lose = true; }, revoke: () => { revoked = true; } };
}
test('original receiver reconciles a lost receipt after restart without another effect', async () => {
  const h = await fixture(), input = { event_id: uuid(h.f.event), active_request_id: null, descriptor: null };
  let r = await createOriginalReplyReceiver(h.options); h.lose();
  await assert.rejects(r.consume(input), /unavailable/);
  assert.equal(r.exportMetadata().rows[0].state, 'unknown'); assert.equal(r.retain(), 0); r.close();
  r = await createOriginalReplyReceiver(h.options);
  assert.equal((await r.consume(input)).replay, true);
  assert.equal(h.calls.filter(v => v === 'consume').length, 1);
  assert.equal(h.calls.filter(v => v === 'status').length, 1); r.close();
});
test('original receiver decrypts once for a bounded callback and never retries unknown callback work', async () => {
  const h = await fixture(); let count = 0;
  const active = '15151515-1515-1515-1515-151515151515';
  let r = await createOriginalReplyReceiver({ ...h.options, callbackTimeoutMs: 5 });
  await assert.rejects(r.process(uuid(h.f.event), active, async (text, context) => {
    count++; assert.equal(text, 'synthetic original reply'); assert.equal(context.activeRequestId, active);
    return new Promise(() => {});
  }), /unavailable/);
  r.close(); r = await createOriginalReplyReceiver(h.options);
  await assert.rejects(r.process(uuid(h.f.event), active, () => { count++; return null; }), /unavailable/);
  assert.equal(count, 1); assert.equal(h.calls.filter(v => v === 'read').length, 1);
  assert.equal(h.calls.filter(v => v === 'consume').length, 0);
  assert.equal(r.exportMetadata().rows[0].state, 'unknown'); r.close();
  const bytes = await readFile(h.options.journalPath);
  assert.equal(bytes.includes(Buffer.from('synthetic original reply')), false);
});
test('original receiver erasure is durable and revoked authority cannot replay metadata effects', async () => {
  const h = await fixture(), input = { event_id: uuid(h.f.event), active_request_id: null, descriptor: null };
  let r = await createOriginalReplyReceiver(h.options); await r.consume(input); h.revoke();
  await assert.rejects(r.consume(input), /unavailable/); assert.equal(h.calls.filter(v => v === 'consume').length, 1);
  r.erase(); assert.equal(r.exportMetadata().rows.length, 0); r.close();
  await assert.rejects(createOriginalReplyReceiver(h.options), /Original reply unavailable/);
});
test('original receiver authenticates exact opaque sender bytes without persisting ciphertext or plaintext', async () => {
  const h = await fixture(), envelope = parseConversationInbound02(h.f.envelope);
  const raw = Buffer.from(JSON.stringify({ v: 1, type: 'sealed.inbound_event', event_id: uuid(h.f.event),
    delivery_id: '19191919-1919-1919-1919-191919191919', account_id: uuid(h.f.scope.account), device_id: uuid(h.f.scope.device),
    observed_at_ms: 2000, envelope_b64: Buffer.from(h.f.envelope).toString('base64'),
    unsigned_digest_b64: createHash('sha256').update(envelope.unsigned).digest('base64') }));
  const headers = { 'x-zrotext-timestamp': '2', 'x-zrotext-signature': 'v1=' + createHmac('sha256', h.options.webhookSecret).update('2.').update(raw).digest('hex') };
  const r = await createOriginalReplyReceiver(h.options);
  assert.equal((await r.ingest(raw, headers)).created, true);
  assert.equal((await r.ingest(raw, headers)).created, false);
  await assert.rejects(r.ingest(Buffer.concat([raw, Buffer.from(' ')]), headers), /unavailable/);
  assert.equal((await r.exportOpaqueMetadata()).events.length, 1); r.close();
  const bytes = await readFile(h.options.receiverPath);
  assert.equal(bytes.includes(Buffer.from(h.f.envelope)), false);
  assert.equal(bytes.includes(Buffer.from('synthetic original reply')), false);
});
test('original receiver local erasure during a callback prevents a new consumption', async () => {
  const h = await fixture(), r = await createOriginalReplyReceiver(h.options);
  await assert.rejects(r.process(uuid(h.f.event), '20202020-2020-2020-2020-202020202020', async () => { r.erase(); return null; }), /unavailable/);
  assert.equal(h.calls.filter(v => v === 'consume').length, 0);
  assert.equal(r.exportMetadata().rows.length, 0); r.close();
  const reopened = await createOriginalReplyReceiver(h.options);
  await assert.rejects(reopened.process(uuid(h.f.event), null), /unavailable/); reopened.close();
});
test('original receiver retention preserves unknown recovery and denies retired event reuse', async () => {
  const h = await fixture(), input = { event_id: uuid(h.f.event), active_request_id: null, descriptor: null };
  let r = await createOriginalReplyReceiver(h.options); await r.consume(input); r.close();
  const db = new DatabaseSync(h.options.journalPath);
  db.exec('UPDATE original_reply_checkpoints SET created_ms=-691200000'); db.close();
  r = await createOriginalReplyReceiver(h.options);
  assert.equal(r.retain(), 1); assert.equal(r.exportMetadata().rows[0].state, 'retired');
  await assert.rejects(r.consume(input), /retired/);
  assert.equal(h.calls.filter(v => v === 'consume').length, 1); r.close();
});
