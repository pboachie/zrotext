// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHmac, webcrypto } from 'node:crypto';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ReplyEventAdapter, createReplyEventServer } from '../../replies/reply-events.mjs';
import { createSelectedDraftReader } from '../../replies/selected-draft-reader.mjs';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { keyId } from '../dist/draft01.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

globalThis.crypto ??= webcrypto;
const uid = number => `10000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const account = uid(1), line = uid(2), device = uid(3), message = uid(4), attempt = uid(5), consumer = uid(6);
const syntheticWebhookBytes = Buffer.alloc(32, 1), cursorSecret = Buffer.alloc(32, 2);
const initial = 1_700_000_000_000;
const rejects = (operation, code) => assert.throws(operation, error => error.code === code);
const rejectsAsync = (operation, code) => assert.rejects(operation, error => error.code === code);

async function fixture(run, extra = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'zrotext-replies-'));
  let time = initial; let active = true; let revision = 'grant_1'; let reads = 0; let canReadContent = true;
  const options = { path: join(directory, 'metadata.sqlite'), accountId: account, lineId: line,
    webhookSecret: syntheticWebhookBytes, cursorSecret, clock: () => time, retentionMs: 60_000,
    authority: event => ({ active, revision, accountId: account, lineId: line, deviceId: device,
      expiresAtMs: time + 120_000, readerId: uid(7), canReadContent }), readerId: uid(7),
    reader: async () => { reads++; return { kind: 'decrypted', text: 'Synthetic reply' }; }, ...extra };
  let adapter = new ReplyEventAdapter(options);
  const event = (number = 10, patch = {}) => ({ v: 1, type: 'inbound.message', event_id: uid(number),
    delivery_id: uid(number + 1000), account_id: account, device_id: device, message_id: message,
    attempt_id: attempt, classification: 'captured_local', observed_at_ms: time, part_count: 1,
    content_kind: 'metadata_only', content_ciphertext_b64: null,
    event_digest_b64: Buffer.alloc(32, number % 255).toString('base64'),
    device_signature_der_b64: Buffer.alloc(8, 3).toString('base64'), ...patch });
  const signed = value => {
    const raw = Buffer.from(JSON.stringify(value)); const timestamp = String(Math.floor(time / 1000));
    return [raw, { 'x-zrotext-timestamp': timestamp, 'x-zrotext-signature': 'v1=' +
      createHmac('sha256', syntheticWebhookBytes).update(timestamp).update('.').update(raw).digest('hex') }];
  };
  const request = (number = 20, patch = {}) => ({ id: uid(number), messageId: message, attemptId: attempt,
    deviceId: device, startsAtMs: initial - 1000, expiresAtMs: time + 50_000, maxTurns: 2, ...patch });
  const context = { get adapter() { return adapter; }, options, event, signed, request,
    advance: milliseconds => { time += milliseconds; }, revoke: () => { active = false; },
    revise: () => { revision = 'grant_2'; }, revokeReader: () => { canReadContent = false; }, reads: () => reads,
    restart: () => { adapter.close(); adapter = new ReplyEventAdapter(options); } };
  try { await run(context); } finally { adapter.close(); await rm(directory, { recursive: true, force: true }); }
}

test('webhook verification rejects changed bytes, stale timestamps, foreign scope and unknown fields before exposing identities', () => fixture(async f => {
  const [raw, headers] = f.signed(f.event());
  rejects(() => f.adapter.ingest(Buffer.concat([raw, Buffer.from(' ')]), headers), 'invalid_signature');
  rejects(() => f.adapter.ingest(raw, { ...headers, 'x-zrotext-timestamp': String(initial / 1000 - 301) }), 'invalid_signature');
  rejects(() => f.adapter.ingest(...f.signed(f.event(10, { account_id: uid(90) }))), 'foreign_scope');
  rejects(() => f.adapter.ingest(...f.signed(f.event(10, { device_id: uid(90) }))), 'revoked');
  rejects(() => f.adapter.ingest(...f.signed({ ...f.event(), plaintext: 'Synthetic extra' })), 'invalid_event');
  assert.equal(f.reads(), 0); assert.equal(f.adapter.exportMetadata().events.length, 0);
}));

test('delivery replay retains the original inbound identity and changed signed content is refused', () => fixture(async f => {
  assert.equal(f.adapter.ingest(...f.signed(f.event())).created, true);
  assert.equal(f.adapter.ingest(...f.signed(f.event(10, { delivery_id: uid(999) }))).created, false);
  rejects(() => f.adapter.ingest(...f.signed(f.event(10, { part_count: 2 }))), 'identity_conflict');
  assert.equal(f.adapter.exportMetadata().events.length, 1);
}));

test('durable consumption commits the action identity before effects and consumer restart cannot repeat it', () => fixture(async f => {
  f.adapter.registerRequest(f.request()); f.adapter.ingest(...f.signed(f.event()));
  const input = { consumerId: consumer, eventId: uid(10), actionId: uid(30) }; let effects = 0;
  const outcome = await f.adapter.runAction(input, async result => {
    effects++; assert.equal(result.approval, false); assert.equal(result.disposition, 'reply_notice');
    const reopened = new ReplyEventAdapter(f.options);
    try { assert.equal((await reopened.consume(input)).execute, false); } finally { reopened.close(); }
  });
  assert.equal(outcome.state, 'completed'); f.restart();
  assert.equal((await f.adapter.runAction(input, () => { effects++; })).execute, false);
  assert.equal(effects, 1); assert.equal((await f.adapter.page({ consumerId: consumer })).events.length, 0);
  await rejectsAsync(() => f.adapter.consume({ ...input, actionId: uid(31) }), 'identity_conflict');
}));

test('failure after reservation stays unknown and interrupted reservations never execute after restart', () => fixture(async f => {
  f.adapter.registerRequest(f.request()); f.adapter.ingest(...f.signed(f.event()));
  const first = { consumerId: consumer, eventId: uid(10), actionId: uid(30) }; let effects = 0;
  assert.equal((await f.adapter.runAction(first, () => { effects++; throw Error('private details'); })).state, 'unknown');
  f.adapter.ingest(...f.signed(f.event(11))); const second = { ...first, eventId: uid(11), actionId: uid(31) };
  assert.equal((await f.adapter.consume(second)).execute, true); f.restart();
  assert.equal((await f.adapter.runAction(second, () => { effects++; })).execute, false);
  assert.equal((await f.adapter.runAction(first, () => { effects++; })).state, 'unknown');
  assert.equal(effects, 1);
}));

test('reordered replies, unrelated windows and ambiguous requests enter owner review without approval', () => fixture(async f => {
  f.adapter.registerRequest(f.request()); f.adapter.ingest(...f.signed(f.event()));
  const consume = async number => f.adapter.consume({ consumerId: consumer, eventId: uid(number), actionId: uid(number + 100) });
  assert.equal((await consume(10)).disposition, 'reply_notice');
  f.adapter.ingest(...f.signed(f.event(11, { observed_at_ms: initial - 1 })));
  assert.equal((await consume(11)).disposition, 'owner_review');
  f.adapter.ingest(...f.signed(f.event(12, { message_id: uid(99) })));
  assert.equal((await consume(12)).disposition, 'owner_review');
  f.adapter.registerRequest(f.request(21)); f.adapter.ingest(...f.signed(f.event(13)));
  const ambiguous = await consume(13); assert.equal(ambiguous.disposition, 'owner_review'); assert.equal(ambiguous.approval, false);
}));

test('automatic turn cap survives restart and STOP is metadata-only even when the cap is exhausted', () => fixture(async f => {
  f.adapter.registerRequest(f.request(20, { maxTurns: 1 }));
  const consume = async number => f.adapter.consume({ consumerId: consumer, eventId: uid(number), actionId: uid(number + 100) });
  f.adapter.ingest(...f.signed(f.event())); assert.equal((await consume(10)).disposition, 'reply_notice'); f.restart();
  f.adapter.ingest(...f.signed(f.event(11))); assert.equal((await consume(11)).disposition, 'owner_review');
  const reads = f.reads(); f.adapter.ingest(...f.signed(f.event(12, { classification: 'opt_out' })));
  assert.equal((await consume(12)).disposition, 'stop'); assert.equal(f.reads(), reads);
  f.adapter.ingest(...f.signed(f.event(13, { classification: 'opt_in' }))); await consume(13);
  f.adapter.ingest(...f.signed(f.event(14))); assert.equal((await consume(14)).disposition, 'owner_review');
}));

test('STOP durably denies pending automatic actions even if the bounded event ledger is full', () => fixture(async f => {
  f.adapter.registerRequest(f.request()); f.adapter.ingest(...f.signed(f.event()));
  rejects(() => f.adapter.ingest(...f.signed(f.event(11, { classification: 'opt_out_review' }))), 'retention_full');
  f.restart();
  const result = await f.adapter.consume({ consumerId: consumer, eventId: uid(10), actionId: uid(30) });
  assert.equal(result.disposition, 'owner_review');
}, { maxEvents: 1 }));

test('opaque pilot content is unavailable and never sent to the selected reader', () => fixture(async f => {
  f.adapter.registerRequest(f.request()); f.adapter.ingest(...f.signed(f.event(10,
    { content_kind: 'opaque_pilot', content_ciphertext_b64: Buffer.alloc(32).toString('base64') })));
  const page = await f.adapter.page({ consumerId: consumer });
  assert.deepEqual(page.events[0].content, { kind: 'unavailable' }); assert.equal(f.reads(), 0);
  assert.equal((await f.adapter.consume({ consumerId: consumer, eventId: uid(10), actionId: uid(30) })).disposition, 'owner_review');
}));

test('offline cursors bind database account line consumer and current scope generation', () => fixture(async f => {
  f.adapter.ingest(...f.signed(f.event()));
  const page = await f.adapter.page({ consumerId: consumer }); f.restart();
  assert.equal((await f.adapter.page({ consumerId: consumer, cursor: page.cursor })).events.length, 0);
  await rejectsAsync(() => f.adapter.page({ consumerId: uid(99), cursor: page.cursor }), 'invalid_cursor');
  await rejectsAsync(() => f.adapter.page({ consumerId: consumer, cursor: page.cursor + 'x' }), 'invalid_cursor');
  f.revise(); await rejectsAsync(() => f.adapter.page({ consumerId: consumer, cursor: page.cursor }), 'invalid_cursor');
  rejects(() => new ReplyEventAdapter({ ...f.options, accountId: uid(88) }), 'foreign_scope');
}));

test('expired resume reports a gap and old authenticated events cannot reopen actions', () => fixture(async f => {
  f.adapter.ingest(...f.signed(f.event())); const cursor = (await f.adapter.page({ consumerId: consumer })).cursor;
  f.advance(60_001);
  await rejectsAsync(() => f.adapter.page({ consumerId: consumer, cursor }), 'invalid_cursor');
  rejects(() => f.adapter.ingest(...f.signed(f.event(10, { observed_at_ms: initial }))), 'expired');
  assert.equal(f.adapter.exportMetadata().events.length, 0);
}));

test('revocation and owner takeover deny pending reads and actions across reopen without exposing plaintext', () => fixture(async f => {
  f.adapter.registerRequest(f.request()); f.adapter.ingest(...f.signed(f.event()));
  f.adapter.deny('takeover'); f.restart();
  await rejectsAsync(() => f.adapter.page({ consumerId: consumer }), 'revoked');
  await rejectsAsync(() => f.adapter.runAction({ consumerId: consumer, eventId: uid(10), actionId: uid(30) }, () => assert.fail()), 'revoked');
  assert.equal(f.reads(), 0);
}));

test('authority is checked again after reader awaits and before notification effects', () => fixture(async f => {
  f.adapter.ingest(...f.signed(f.event()));
  f.adapter.reader = async () => { f.revoke(); return { kind: 'decrypted', text: 'Synthetic secret' }; };
  await rejectsAsync(() => f.adapter.page({ consumerId: consumer }), 'revoked');
}));

test('atomic consumer checkpoints forbid out of order actions and concurrent consumption has one effect', () => fixture(async f => {
  f.adapter.registerRequest(f.request()); f.adapter.ingest(...f.signed(f.event())); f.adapter.ingest(...f.signed(f.event(11)));
  await rejectsAsync(() => f.adapter.consume({ consumerId: consumer, eventId: uid(11), actionId: uid(31) }), 'out_of_order');
  let effects = 0; const input = { consumerId: consumer, eventId: uid(10), actionId: uid(30) };
  await Promise.all([f.adapter.runAction(input, () => { effects++; }), f.adapter.runAction(input, () => { effects++; })]);
  assert.equal(effects, 1);
}));

test('export contains only bounded metadata and deletion purges pending events with a durable denial', () => fixture(async f => {
  f.adapter.ingest(...f.signed(f.event())); await f.adapter.page({ consumerId: consumer });
  const exported = JSON.stringify(f.adapter.exportMetadata());
  assert.ok(!exported.includes('Synthetic reply')); assert.ok(!exported.includes('ciphertext')); assert.ok(!exported.includes('secret'));
  f.adapter.deny('deletion'); f.restart(); await rejectsAsync(() => f.adapter.page({ consumerId: consumer }), 'revoked');
  assert.equal(f.adapter.db.prepare('SELECT count(*) AS n FROM events').get().n, 0);
  assert.equal(f.adapter.db.prepare('SELECT count(*) AS n FROM consumers').get().n, 0);
}));

test('customer HTTP adapter verifies a real raw webhook and resumable authenticated local client requests', () => fixture(async f => {
  const server = createReplyEventServer(f.adapter, authorization => authorization === 'Bearer synthetic' ? { consumerId: consumer } : null);
  await new Promise(resolve => server.listen(0, 'localhost', resolve));
  const origin = `http://localhost:${server.address().port}`;
  try {
    const [raw, headers] = f.signed(f.event());
    assert.equal((await fetch(origin + '/webhook', { method: 'POST', headers, body: raw })).status, 202);
    assert.equal((await fetch(origin + '/events')).status, 401);
    const response = await fetch(origin + '/events', { headers: { authorization: 'Bearer synthetic' } });
    assert.equal(response.status, 200); assert.equal(response.headers.get('cache-control'), 'no-store');
    const page = await response.json(); assert.equal(page.events[0].event_id, uid(10));
    assert.equal(page.events[0].approval, false);
    const commit = await fetch(origin + '/consume', { method: 'POST', headers: { authorization: 'Bearer synthetic' },
      body: JSON.stringify({ eventId: uid(10), actionId: uid(30) }) });
    assert.equal(commit.status, 200); assert.equal((await commit.json()).disposition, 'owner_review');
    assert.equal((await fetch(origin + '/consume', { method: 'POST', headers: { authorization: 'Bearer synthetic' },
      body: JSON.stringify({ eventId: uid(10), actionId: uid(30), scope: 'owner' }) })).status, 400);
  } finally { await new Promise(resolve => server.close(resolve)); }
}));

test('selected content delegates signature and decryption to the existing SDK and binds the exact inbound event', async () => {
  const fixture = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/ztse-draft-01.json', import.meta.url)));
  const bytes = value => Uint8Array.from(Buffer.from(value, 'hex'));
  const uuid = value => { const hex = Buffer.from(value).toString('hex'); return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`; };
  const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
  const pair = await suite.kem.deriveKeyPair(bytes(fixture.archiveIkmHex));
  const point = new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  const context = { accountId: bytes(fixture.accountIdHex), deviceId: bytes(fixture.deviceIdHex), lineId: bytes(fixture.lineIdHex),
    peer: fixture.peer, manifestDigest: bytes(fixture.manifestDigestHex), signerPublicPoint: bytes(fixture.signerPublicPointHex),
    recipientRole: 2, recipientKeyId: await keyId(0x0010, point), recipientPrivateKey: pair.privateKey };
  const envelope = bytes(fixture.inbound.envelopeHex);
  const event = { account_id: uuid(context.accountId), device_id: uuid(context.deviceId), line_id: uuid(context.lineId),
    event_id: uuid(envelope.subarray(26, 42)), observed_at_ms: Number(new DataView(envelope.buffer,
      envelope.byteOffset, envelope.byteLength).getBigUint64(146, false)) };
  let active = true;
  const reader = createSelectedDraftReader({ load: async () => ({ envelope, context }), authorize: () => active });
  assert.deepEqual(await reader(event), { kind: 'decrypted', text: fixture.inbound.plaintext });
  assert.deepEqual(await reader({ ...event, event_id: uid(99) }), { kind: 'unavailable' });
  envelope[envelope.length - 1] ^= 1; await assert.rejects(reader(event)); envelope[envelope.length - 1] ^= 1;
  active = false; assert.deepEqual(await reader(event), { kind: 'unavailable' });
});

test('independent process commits survive abrupt exit and cannot repeat a reserved effect', () => fixture(async f => {
  f.adapter.registerRequest(f.request()); f.adapter.ingest(...f.signed(f.event()));
  const module = new URL('../../replies/reply-events.mjs', import.meta.url).href;
  const code = `import { ReplyEventAdapter } from ${JSON.stringify(module)};
    const adapter = new ReplyEventAdapter({path: process.argv[1], accountId: ${JSON.stringify(account)},
      lineId: ${JSON.stringify(line)}, webhookSecret: Buffer.alloc(32,1), cursorSecret: Buffer.alloc(32,2),
      clock:()=>${initial}, retentionMs:60000, authority:()=>({active:true,revision:'grant_1',
        accountId:${JSON.stringify(account)},lineId:${JSON.stringify(line)},deviceId:${JSON.stringify(device)},
        expiresAtMs:${initial + 120000},readerId:${JSON.stringify(uid(7))},canReadContent:true}),
        readerId:${JSON.stringify(uid(7))},reader:async()=>({kind:'decrypted',text:'Synthetic reply'})});
    await adapter.consume({consumerId:${JSON.stringify(consumer)},eventId:${JSON.stringify(uid(10))},actionId:${JSON.stringify(uid(30))}});
    process.exit(0);`;
  await promisify(execFile)(process.execPath, ['--input-type=module', '-e', code, f.options.path], { timeout: 10_000 });
  f.restart(); let effects = 0;
  const result = await f.adapter.runAction({ consumerId: consumer, eventId: uid(10), actionId: uid(30) }, () => { effects++; });
  assert.equal(effects, 0); assert.equal(result.state, 'unknown'); assert.equal(result.execute, false);
}));

test('expiry and STOP during selected-reader work suppress plaintext across pending events', () => fixture(async f => {
  f.adapter.ingest(...f.signed(f.event()));
  f.adapter.reader = async () => { f.adapter.ingest(...f.signed(f.event(11, { classification: 'opt_out' })));
    return { kind: 'decrypted', text: 'Synthetic reply' }; };
  const page = await f.adapter.page({ consumerId: consumer });
  assert.deepEqual(page.events[0].content, { kind: 'unavailable' });
}));

test('expiry during reader work becomes unavailable and cannot consume an automatic turn', () => fixture(async f => {
  f.adapter.registerRequest(f.request()); f.adapter.ingest(...f.signed(f.event()));
  f.adapter.reader = async () => { f.advance(60_001); return { kind: 'decrypted', text: 'Synthetic reply' }; };
  assert.deepEqual((await f.adapter.page({ consumerId: consumer })).events[0].content, { kind: 'unavailable' });
  await rejectsAsync(() => f.adapter.consume({ consumerId: consumer, eventId: uid(10), actionId: uid(30) }), 'expired');
}));

test('missing scope authority and wrong trusted line fail closed without reading content', () => fixture(async f => {
  f.adapter.authority = undefined;
  rejects(() => f.adapter.ingest(...f.signed(f.event())), 'revoked');
  f.adapter.authority = () => ({ active: true, revision: 'grant_1', accountId: account, lineId: uid(99),
    deviceId: device, expiresAtMs: initial + 120_000 });
  rejects(() => f.adapter.ingest(...f.signed(f.event())), 'revoked'); assert.equal(f.reads(), 0);
}));

test('expired checkpoints require explicit owner gap review and never run skipped effects', () => fixture(async f => {
  f.adapter.ingest(...f.signed(f.event())); await f.adapter.page({ consumerId: consumer });
  f.advance(60_001); await rejectsAsync(() => f.adapter.page({ consumerId: consumer }), 'cursor_expired');
  f.adapter.ingest(...f.signed(f.event(11)));
  const gap = f.adapter.resynchronize(consumer); assert.equal(gap.reviewRequired, true); assert.equal(gap.skippedThrough, 1);
  f.restart(); const resumed = await f.adapter.page({ consumerId: consumer });
  assert.equal(resumed.events.length, 1); assert.equal(resumed.events[0].event_id, uid(11));
  assert.equal(f.adapter.exportMetadata().checkpoints[0].gap_count, 1);
  assert.equal(f.adapter.exportMetadata().actions.length, 0);
}));

test('reader-only revocation during decryption removes content while metadata scope stays active', () => fixture(async f => {
  f.adapter.ingest(...f.signed(f.event()));
  f.adapter.reader = async () => { f.revokeReader(); return { kind: 'decrypted', text: 'Synthetic reply' }; };
  const page = await f.adapter.page({ consumerId: consumer });
  assert.deepEqual(page.events[0].content, { kind: 'unavailable' });
  const result = await f.adapter.consume({ consumerId: consumer, eventId: uid(10), actionId: uid(30) });
  assert.equal(result.disposition, 'owner_review');
}));

test('page completion removes earlier plaintext when a later read revokes, stops or expires content', async () => {
  for (const change of ['reader', 'stop', 'expiry']) await fixture(async f => {
    f.adapter.ingest(...f.signed(f.event())); f.adapter.ingest(...f.signed(f.event(11)));
    let reads = 0;
    f.adapter.reader = async () => {
      if (++reads === 2) {
        if (change === 'reader') f.revokeReader();
        else if (change === 'stop') f.adapter.ingest(...f.signed(f.event(12, { classification: 'opt_out' })));
        else f.advance(60_001);
      }
      return { kind: 'decrypted', text: 'Synthetic reply' };
    };
    const page = await f.adapter.page({ consumerId: consumer });
    assert.equal(reads, 2);
    assert.deepEqual(page.events.map(event => event.content), [{ kind: 'unavailable' }, { kind: 'unavailable' }], change);
  });
});

test('selected reader refuses a load completed after authorization loss or cancellation before parsing', async () => {
  for (const change of ['authorization', 'cancellation']) {
    let active = true; const controller = new AbortController();
    const reader = createSelectedDraftReader({ authorize: () => active, load: async () => {
      if (change === 'authorization') active = false;
      else controller.abort();
      return { envelope: Uint8Array.of(1), context: {} };
    } });
    assert.deepEqual(await reader({}, controller.signal), { kind: 'unavailable' }, change);
  }
});

test('selected reader cancellation during asynchronous authorization prevents loading or opening', async () => {
  for (const stage of [1, 2]) {
    const controller = new AbortController(); let checks = 0; let loads = 0;
    const reader = createSelectedDraftReader({ authorize: async () => {
      if (++checks === stage) controller.abort();
      return true;
    }, load: async () => { loads++; return { envelope: Uint8Array.of(1), context: {} }; } });
    assert.deepEqual(await reader({}, controller.signal), { kind: 'unavailable' });
    assert.equal(loads, stage - 1);
  }
});

test('consumption cannot advance past an expired checkpoint without owner gap review', () => fixture(async f => {
  f.adapter.ingest(...f.signed(f.event())); await f.adapter.page({ consumerId: consumer });
  f.advance(60_001); f.adapter.ingest(...f.signed(f.event(11)));
  f.adapter.registerRequest(f.request(20, { startsAtMs: initial + 60_000 }));
  const input = { consumerId: consumer, eventId: uid(11), actionId: uid(30) }; let effects = 0;
  await rejectsAsync(() => f.adapter.runAction(input, () => { effects++; }), 'cursor_expired');
  assert.equal(effects, 0); assert.equal(f.adapter.exportMetadata().actions.length, 0);
  assert.equal(f.adapter.exportMetadata().checkpoints[0].checkpoint, 0);
  assert.equal(f.adapter.db.prepare('SELECT turns FROM requests').get().turns, 0);
  assert.equal(f.adapter.db.prepare('SELECT consumed FROM events').get().consumed, 0);
  f.adapter.resynchronize(consumer); f.restart();
  const result = await f.adapter.runAction(input, () => { effects++; });
  assert.equal(result.disposition, 'reply_notice'); assert.equal(result.state, 'completed');
  assert.equal(effects, 1);
}));

test('a hung selected reader is aborted within the bounded receive window and reports unavailable', () => fixture(async f => {
  f.adapter.ingest(...f.signed(f.event())); let aborted = false;
  f.adapter.reader = (_, signal) => new Promise(() => { signal.addEventListener('abort', () => { aborted = true; }); });
  const page = await f.adapter.page({ consumerId: consumer });
  assert.equal(aborted, true); assert.deepEqual(page.events[0].content, { kind: 'unavailable' });
}));

test('clock rollback does not reopen expired grant or retention decisions', () => fixture(async f => {
  f.adapter.ingest(...f.signed(f.event())); f.advance(-1);
  await rejectsAsync(() => f.adapter.page({ consumerId: consumer }), 'unavailable');
  rejects(() => f.adapter.ingest(...f.signed(f.event(11))), 'revoked');
}));

test('a valid HMAC cursor from another database account and line remains foreign', () => fixture(async f => {
  f.adapter.ingest(...f.signed(f.event())); const page = await f.adapter.page({ consumerId: consumer });
  const foreign = new ReplyEventAdapter({ ...f.options, path: f.options.path + '.foreign', accountId: uid(80), lineId: uid(81),
    authority: () => ({ active: true, revision: 'grant_1', accountId: uid(80), lineId: uid(81),
      deviceId: device, expiresAtMs: initial + 120_000 }) });
  try { await rejectsAsync(() => foreign.page({ consumerId: consumer, cursor: page.cursor }), 'invalid_cursor'); }
  finally { foreign.close(); }
}));

test('shared exact webhook vector exposes metadata STOP and reserves the original action only once', () => fixture(async f => {
  const vector = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/agent-reply-events-01.json', import.meta.url)));
  const accepted = f.adapter.ingest(Buffer.from(vector.rawBody, 'utf8'), {
    'x-zrotext-timestamp': vector.timestamp, 'x-zrotext-signature': vector.signature });
  assert.deepEqual(accepted, vector.responses[3]);
  const page = await f.adapter.page({ consumerId: consumer });
  assert.deepEqual(page.events, vector.responses[0].events);
  const input = { consumerId: consumer, eventId: page.events[0].event_id, actionId: vector.responses[1].actionId };
  assert.deepEqual(await f.adapter.consume(input), vector.responses[1]);
  assert.deepEqual(await f.adapter.consume(input), vector.responses[2]);
  assert.equal(f.reads(), 0);
}));

test('malformed reader text never becomes decrypted or consumes a reply turn', () => fixture(async f => {
  f.adapter.registerRequest(f.request()); f.adapter.ingest(...f.signed(f.event()));
  for (const text of ['', '\ufeffSynthetic', 'Synthetic\0reply', '\ud800', 'Ā'.repeat(20_000)]) {
    f.adapter.reader = async () => ({ kind: 'decrypted', text });
    assert.deepEqual((await f.adapter.page({ consumerId: consumer })).events[0].content, { kind: 'unavailable' });
  }
  const result = await f.adapter.consume({ consumerId: consumer, eventId: uid(10), actionId: uid(30) });
  assert.equal(result.disposition, 'owner_review'); assert.equal(f.adapter.db.prepare('SELECT turns FROM requests').get().turns, 0);
}));
