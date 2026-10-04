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
  const effects = new Map(), calls = []; let lose = false, revoked = false, beforeRead = null;
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
      } else if (r.method === 'read') { beforeRead?.(); result = { event_id: uuid(f.event), accepted_at_ms: 2000, envelope_b64: Buffer.from(f.envelope).toString('base64'),
        historical_manifest_version: 7, statement_b64: Buffer.from(f.statement).toString('base64'), approval_signature_b64: Buffer.from(f.approval).toString('base64'),
        installation_signature_b64: Buffer.from(f.installation).toString('base64'), activation_manifest_version: 7, proof }; }
      else throw new Error('unexpected method');
      return new Response(JSON.stringify({ kind: r.method, result }), { headers: { 'content-type': 'application/json' } });
    } });
  const options = { client, journalPath: join(dir, 'journal.sqlite'), receiverPath: join(dir, 'receiver.sqlite'),
    webhookSecret: Buffer.alloc(32, 9), cursorSecret: Buffer.alloc(32, 10), clock: () => 2000 };
  return { f, options, calls, dir, lose: () => { lose = true; }, beforeRead: fn => { beforeRead = fn; }, revoke: () => { revoked = true; } };
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


async function compositionFixture(h) {
  const { ReplyEventAdapter } = await import('../../replies/reply-events.mjs');
  const { createCustomerReplies } = await import('../../replies/customer-replies.mjs');
  const account = uuid(h.f.scope.account), line = uuid(h.f.scope.line), device = uuid(h.f.scope.device);
  const secret = '<synthetic-signing-key-material>', options = { path: join(h.dir, 'stop.sqlite'), accountId: account, lineId: line,
    webhookSecret: Buffer.from(secret), cursorSecret: Buffer.alloc(32, 22), clock: () => 2000,
    authority: () => ({ active: true, revision: 'scope1', accountId: account, lineId: line, deviceId: device, expiresAtMs: 90000 }) };
  const event = { v: 1, type: 'inbound.message', event_id: '45454545-4545-4545-4545-454545454545',
    delivery_id: '46464646-4646-4646-4646-464646464646', account_id: account, device_id: device,
    message_id: '47474747-4747-4747-4747-474747474747', attempt_id: '48484848-4848-4848-4848-484848484848',
    classification: 'opt_out', observed_at_ms: 2000, part_count: 1, content_kind: 'metadata_only', content_ciphertext_b64: null,
    event_digest_b64: Buffer.alloc(32, 23).toString('base64'), device_signature_der_b64: Buffer.alloc(8, 24).toString('base64') };
  const raw = Buffer.from(JSON.stringify(event)), timestamp = '2', headers = { 'x-zrotext-timestamp': timestamp,
    'x-zrotext-signature': 'v1=' + createHmac('sha256', secret).update(timestamp).update('.').update(raw).digest('hex') };
  let metadata = new ReplyEventAdapter(options), customer = await createCustomerReplies({ metadata, original: h.options });
  return { get metadata() { return metadata; }, get customer() { return customer; }, raw, headers, options,
    async restart() { customer.close(); metadata.close(); metadata = new ReplyEventAdapter(options); customer = await createCustomerReplies({ metadata, original: h.options }); },
    close() { customer.close(); metadata.close(); } };
}

test('customer composition binds independently authenticated metadata and original scopes', async () => {
  const h = await fixture(), { ReplyEventAdapter } = await import('../../replies/reply-events.mjs');
  const { createCustomerReplies } = await import('../../replies/customer-replies.mjs');
  for (const foreign of ['accountId', 'lineId']) {
    const accountId = foreign === 'accountId' ? '51515151-5151-5151-5151-515151515151' : uuid(h.f.scope.account);
    const lineId = foreign === 'lineId' ? '52525252-5252-5252-5252-525252525252' : uuid(h.f.scope.line);
    const metadata = new ReplyEventAdapter({ path: join(h.dir, foreign + '.sqlite'), accountId, lineId,
      webhookSecret: Buffer.alloc(32, 21), cursorSecret: Buffer.alloc(32, 22), clock: () => 2000,
      authority: () => ({ active: true, revision: 'scope1', accountId, lineId, expiresAtMs: 90000 }) });
    try { await assert.rejects(createCustomerReplies({ metadata, original: h.options }), /foreign_scope/); }
    finally { metadata.close(); }
  }
  assert.equal(h.calls.filter(x => x === 'consume').length, 0);
});

test('customer composition authenticates metadata STOP and preserves its distinct durable stop on restart', async () => {
  const h = await fixture(), c = await compositionFixture(h);
  try {
    assert.throws(() => c.customer.ingestMetadataStop(c.raw, { ...c.headers, 'x-zrotext-signature': 'v1=' + '00'.repeat(32) }));
    c.metadata.assertAutomaticCurrent();
    assert.throws(() => c.customer.ingestMetadataStop(Buffer.from(JSON.stringify({ type: 'sealed.inbound_event', classification: 'opt_out' })), c.headers), /invalid_event/);
    assert.equal(c.customer.ingestMetadataStop(c.raw, c.headers).created, true);
    assert.equal(c.customer.ingestMetadataStop(c.raw, c.headers).created, false);
    await c.restart(); assert.throws(() => c.metadata.assertAutomaticCurrent(), /stopped/); let callbacks = 0;
    await assert.rejects(c.customer.processOriginal(uuid(h.f.event), '49494949-4949-4949-4949-494949494949', () => { callbacks++; return null; }), /unavailable/);
    assert.equal(callbacks, 0); assert.equal(h.calls.filter(x => x === 'read' || x === 'consume').length, 0);
    assert.equal(c.customer.exportOriginal().rows[0].state, 'unknown'); assert.equal(c.customer.retainOriginal(), 0);
    assert.equal(c.metadata.exportMetadata().events[0].event, '45454545-4545-4545-4545-454545454545');
    assert.equal(c.customer.exportOriginal().rows[0].event_id, uuid(h.f.event));
  } finally { c.close(); }
});

test('metadata STOP during original callback forbids consumption and restart never repeats the callback', async () => {
  const h = await fixture(), c = await compositionFixture(h); let callbacks = 0;
  const active = '49494949-4949-4949-4949-494949494949';
  try {
    await assert.rejects(c.customer.processOriginal(uuid(h.f.event), active, async text => {
      callbacks++; assert.equal(text, 'synthetic original reply'); c.customer.ingestMetadataStop(c.raw, c.headers); return null;
    }), /unavailable/);
    assert.throws(() => c.metadata.assertAutomaticCurrent(), /stopped/);
    assert.equal(h.calls.filter(x => x === 'read').length, 1); assert.equal(h.calls.filter(x => x === 'consume').length, 0);
    await c.restart();
    await assert.rejects(c.customer.processOriginal(uuid(h.f.event), active, () => { callbacks++; return null; }), /unavailable/);
    assert.equal(callbacks, 1); assert.equal(h.calls.filter(x => x === 'status').length, 1);
    assert.equal(h.calls.filter(x => x === 'read').length, 1); assert.equal(c.customer.exportOriginal().rows[0].state, 'unknown');
  } finally { c.close(); }
});

test('customer composition uses original routes without treating unavailable content as metadata STOP', async () => {
  const h = await fixture(), c = await compositionFixture(h);
  try {
    const result = await c.customer.consumeOwnerReview(uuid(h.f.event)); assert.equal(result.outcome.disposition, 'owner_review');
    await c.restart(); assert.equal((await c.customer.consumeOwnerReview(uuid(h.f.event))).replay, true);
    assert.equal(h.calls.filter(x => x === 'consume').length, 1); assert.equal(h.calls.filter(x => x === 'status').length, 1);
    assert.equal(h.calls.filter(x => x === 'read').length, 0); c.metadata.assertAutomaticCurrent();
    assert.equal(c.metadata.exportMetadata().events.length, 0);
  } finally { c.close(); }
});


test('metadata STOP during original decryption prevents the first callback or consumption', async () => {
  const h = await fixture(), c = await compositionFixture(h); let callbacks = 0;
  try {
    h.beforeRead(() => c.customer.ingestMetadataStop(c.raw, c.headers));
    await assert.rejects(c.customer.processOriginal(uuid(h.f.event), '49494949-4949-4949-4949-494949494949', () => { callbacks++; return null; }), /unavailable/);
    assert.equal(callbacks, 0); assert.equal(h.calls.filter(x => x === 'read').length, 1);
    assert.equal(h.calls.filter(x => x === 'consume').length, 0); assert.throws(() => c.metadata.assertAutomaticCurrent(), /stopped/);
  } finally { c.close(); }
});

test('original authority refusal never creates a metadata STOP or fabricated legacy identity', async () => {
  const h = await fixture(), c = await compositionFixture(h); let callbacks = 0;
  try {
    h.revoke();
    await assert.rejects(c.customer.processOriginal(uuid(h.f.event), '49494949-4949-4949-4949-494949494949', () => { callbacks++; return null; }), /unavailable/);
    assert.equal(callbacks, 0); c.metadata.assertAutomaticCurrent(); assert.equal(c.metadata.exportMetadata().events.length, 0);
    assert.equal(h.calls.filter(x => x === 'consume').length, 0);
  } finally { c.close(); }
});
