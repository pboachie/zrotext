// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, createHmac } from 'node:crypto';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { SealedEventReceiver, createSealedEventServer } from '../../replies/sealed-events.mjs';

const id = number => `10000000-0000-4000-8000-${String(number).padStart(12, '0')}`;
const account = id(1), device = id(2), line = id(3), consumer = id(4);
const initial = 1_700_000_000_000, day = 86_400_000;
const syntheticWebhookBytes = Buffer.alloc(32, 7), cursorSecret = Buffer.alloc(32, 8);
const reject = (operation, code) => assert.throws(operation, error => error.code === code);
const uuidBytes = value => Buffer.from(value.replaceAll('-', ''), 'hex');

// Valid profile-02 grammar with canonical synthetic r=s=1 signature. No claim
// of AEAD/signature validity or production profile approval is made by this fixture.
function event(number, observed = initial, overrides = {}) {
  const protectedBytes = Buffer.alloc(172);
  uuidBytes(account).copy(protectedBytes, 0); uuidBytes(id(number)).copy(protectedBytes, 16);
  uuidBytes(device).copy(protectedBytes, 32); uuidBytes(line).copy(protectedBytes, 48);
  protectedBytes.writeBigUInt64BE(1n, 64); protectedBytes.writeBigUInt64BE(BigInt(observed), 136);
  uuidBytes(id(number)).copy(protectedBytes, 144); protectedBytes.writeBigUInt64BE(BigInt(number), 160);
  protectedBytes[168] = 3; protectedBytes.set([43, 49, 50], 169);
  const prefix = Buffer.from([90, 84, 83, 69, 2, 2, 0, 0, 0, 172]);
  const length = Buffer.alloc(4); length.writeUInt32BE(17);
  const wrap = Buffer.alloc(146); wrap[0] = 2; wrap[33] = 4;
  const unsigned = Buffer.concat([prefix, protectedBytes, Buffer.alloc(12), length, Buffer.alloc(17), Buffer.from([1]), wrap]);
  const signature = Buffer.alloc(64); signature[31] = 1; signature[63] = 1;
  return { v: 1, type: 'sealed.inbound_event', event_id: id(number), delivery_id: id(number + 1000),
    account_id: account, device_id: device, observed_at_ms: observed,
    envelope_b64: Buffer.concat([unsigned, signature]).toString('base64'),
    unsigned_digest_b64: createHash('sha256').update(unsigned).digest('base64'), ...overrides };
}
function signed(value, now = initial) {
  const raw = Buffer.from(JSON.stringify(value)), timestamp = String(Math.floor(now / 1000));
  return { raw, headers: { 'x-zrotext-timestamp': timestamp,
    'x-zrotext-signature': `v1=${createHmac('sha256', syntheticWebhookBytes).update(timestamp).update('.').update(raw).digest('hex')}` } };
}
async function fixture(run, extra = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'zrotext-sealed-receiver-'));
  let time = initial, active = true, revision = 'selected_1';
  const options = { path: join(directory, 'events.sqlite'), accountId: account, deviceId: device, lineId: line,
    webhookSecret: syntheticWebhookBytes, cursorSecret, clock: () => time,
    authority: () => ({ active, revision, accountId: account, deviceId: device, lineId: line, expiresAtMs: time + 10_000 }), ...extra };
  let receiver = new SealedEventReceiver(options);
  try { await run({ get receiver() { return receiver; }, directory, options,
    reopen: () => { receiver.close(); receiver = new SealedEventReceiver(options); },
    time: value => { time = value; }, active: value => { active = value; }, revision: value => { revision = value; },
    ingest: value => { const { raw, headers } = signed(value, time); return receiver.ingest(raw, headers); } }); }
  finally { receiver.close(); await rm(directory, { recursive: true, force: true }); }
}

test('receiver shape matches the sender schema and does not promote its wire-only vector into an envelope', async () => {
  const schema = JSON.parse(await readFile(new URL('../../../protocol/v1/openapi/sealed-v1.json', import.meta.url), 'utf8'))
    .components.schemas.SealedWebhookEventBody;
  assert.deepEqual(Object.keys(event(10)).sort(), [...schema.required].sort());
  assert.equal(schema.additionalProperties, false);
  const vector = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/sealed-event-delivery-01.json', import.meta.url), 'utf8'));
  assert.deepEqual(Object.keys(JSON.parse(vector.raw_body)).sort(), [...schema.required].sort());
  const vectorSecret = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
  assert.equal(`v1=${createHmac('sha256', vectorSecret).update(String(vector.timestamp_seconds)).update('.')
    .update(vector.raw_body).digest('hex')}`, vector.signature);
  await fixture(async f => {
    reject(() => f.receiver.ingest(Buffer.from(vector.raw_body), {
      'x-zrotext-timestamp': String(vector.timestamp_seconds), 'x-zrotext-signature': vector.signature,
    }), 'invalid_event');
  }, { accountId: vector.body.account_id, deviceId: vector.body.device_id, webhookSecret: vectorSecret, clock: () => 1000 });
});

test('opaque receiver durably deduplicates retries and delivery generations without persisting envelope', async () => {
  await fixture(async f => {
    const value = event(10);
    assert.deepEqual(f.ingest(value), { eventId: id(10), created: true });
    f.reopen();
    assert.deepEqual(f.ingest({ ...value, delivery_id: id(999) }), { eventId: id(10), created: false });
    const page = f.receiver.page({ consumerId: consumer });
    assert.equal(page.events.length, 1); assert.deepEqual(page.events[0].content, { kind: 'unavailable' });
    assert.equal(page.events[0].approval, false);
    assert.equal(Object.hasOwn(page.events[0], 'classification'), false);
    assert.equal(Object.hasOwn(page.events[0], 'messageId'), false);
    assert.equal(JSON.stringify(page).includes(value.envelope_b64), false);
    assert.equal(f.receiver.exportMetadata().events.length, 1);
    f.receiver.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    assert.equal((await readFile(f.options.path)).includes(Buffer.from(value.envelope_b64)), false);
    reject(() => f.receiver.consume({ eventId: id(10) }), 'unavailable');
  });
});
test('opaque receiver authenticates exact raw bytes and refuses stale, malformed and substituted scope', async () => {
  await fixture(async f => {
    const { raw, headers } = signed(event(10));
    reject(() => f.receiver.ingest(Buffer.concat([raw, Buffer.from(' ')]), headers), 'invalid_signature');
    reject(() => f.receiver.ingest(raw, { ...headers, 'x-zrotext-timestamp': '1' }), 'invalid_signature');
    for (const patch of [{ account_id: id(90) }, { device_id: id(91) }]) reject(() => f.ingest(event(10, initial, patch)), 'foreign_scope');
    reject(() => f.ingest(event(10, initial, { classification: 'opt_out' })), 'invalid_event');
    reject(() => f.ingest(event(10, initial, { event_id: id(91) })), 'foreign_scope');
    reject(() => f.ingest(event(10, initial, { unsigned_digest_b64: Buffer.alloc(32).toString('base64') })), 'foreign_scope');
    reject(() => f.ingest(event(10, initial, { observed_at_ms: initial - 1 })), 'foreign_scope');
    reject(() => f.ingest(event(10, initial, { envelope_b64: 'AA==' })), 'invalid_event');
    assert.equal(f.receiver.page({ consumerId: consumer }).events.length, 0);
  });
});
test('same event changed ciphertext conflicts while reordered arrivals retain one stable cursor stream', async () => {
  await fixture(async f => {
    f.ingest(event(12, initial - 1000)); f.ingest(event(10));
    const changed = event(10), bytes = Buffer.from(changed.envelope_b64, 'base64'); bytes[198] ^= 1;
    changed.envelope_b64 = bytes.toString('base64');
    changed.unsigned_digest_b64 = createHash('sha256').update(bytes.subarray(0, -64)).digest('base64');
    reject(() => f.ingest(changed), 'identity_conflict');
    const first = f.receiver.page({ consumerId: consumer, limit: 1 });
    f.reopen();
    const second = f.receiver.page({ consumerId: consumer, cursor: first.cursor });
    assert.deepEqual([first.events[0].eventId, second.events[0].eventId], [id(12), id(10)]);
    reject(() => f.receiver.page({ consumerId: id(90), cursor: first.cursor }), 'invalid_cursor');
  });
});
test('current authority fences replay, cursors, scope reopening and final insertion rollback', async () => {
  await fixture(async f => {
    f.ingest(event(10)); const page = f.receiver.page({ consumerId: consumer });
    f.active(false); reject(() => f.ingest(event(10)), 'revoked'); reject(() => f.receiver.page({ consumerId: consumer }), 'revoked');
    reject(() => f.receiver.exportMetadata(), 'revoked');
    f.active(true); f.revision('selected_2'); reject(() => f.ingest(event(10)), 'revoked');
    reject(() => f.receiver.page({ consumerId: consumer, cursor: page.cursor }), 'invalid_cursor');
    reject(() => new SealedEventReceiver({ ...f.options, lineId: id(99) }), 'foreign_scope');
  });
  let checks = 0;
  await fixture(async f => {
    reject(() => f.ingest(event(10)), 'revoked');
    assert.equal(f.receiver.db.prepare('SELECT count(*) AS count FROM sealed_events').get().count, 0);
  }, { authority: () => ({ active: ++checks === 1, revision: 'selected_1', accountId: account,
    deviceId: device, lineId: line, expiresAtMs: initial + 10_000 }) });
});
test('clock rollback and independently expired selection refuse all retained metadata', async () => {
  await fixture(async f => {
    f.ingest(event(10)); f.time(initial - 1);
    reject(() => f.receiver.page({ consumerId: consumer }), 'revoked');
    f.time(initial); f.receiver.deny(); f.reopen();
    reject(() => f.receiver.exportMetadata(), 'revoked');
  });
  await fixture(async f => {
    reject(() => f.ingest(event(10)), 'revoked');
  }, { authority: () => ({ active: true, revision: 'selected_1', accountId: account,
    deviceId: device, lineId: line, expiresAtMs: initial }) });
});
test('capacity refuses rather than evicts live dedupe fences; eight-day expiry cannot reaccept old captures', async () => {
  await fixture(async f => {
    f.ingest(event(10)); reject(() => f.ingest(event(11)), 'retention_full');
    assert.equal(f.ingest(event(10)).created, false);
    const page = f.receiver.page({ consumerId: consumer });
    f.time(initial + 8 * day + 1); f.receiver.expire();
    reject(() => f.ingest(event(10)), 'invalid_event');
    reject(() => f.receiver.page({ consumerId: consumer, cursor: page.cursor }), 'invalid_cursor');
    assert.equal(f.receiver.page({ consumerId: consumer }).events.length, 0);
    f.ingest(event(11, initial + 8 * day + 1));
    f.receiver.erase(); f.reopen(); reject(() => f.receiver.page({ consumerId: consumer }), 'revoked');
  }, { capacity: 1 });
});
test('actual bounded HTTP transport acknowledges signed sender body once and refuses fabricated reply consumption', async () => {
  await fixture(async f => {
    const server = createSealedEventServer(f.receiver, authorization => authorization === 'Bearer synthetic' ? { consumerId: consumer } : null);
    server.listen(0, '127.0.0.1'); await once(server, 'listening');
    const origin = `http://127.0.0.1:${server.address().port}`;
    try {
      const { raw, headers } = signed(event(10));
      for (const created of [true, false]) {
        const result = await fetch(`${origin}/webhook`, { method: 'POST', headers, body: raw });
        assert.equal(result.status, 202); assert.deepEqual(await result.json(), { eventId: id(10), created });
      }
      assert.equal((await fetch(`${origin}/events`)).status, 401);
      const page = await fetch(`${origin}/events`, { headers: { authorization: 'Bearer synthetic' } });
      assert.equal(page.status, 200); assert.equal(page.headers.get('cache-control'), 'no-store');
      assert.deepEqual((await page.json()).events[0].content, { kind: 'unavailable' });
      const refused = await fetch(`${origin}/consume`, { method: 'POST', headers: { authorization: 'Bearer synthetic' },
        body: JSON.stringify({ eventId: id(10), actionId: id(80) }) });
      assert.equal(refused.status, 503); assert.deepEqual(await refused.json(), { code: 'unavailable' });
      f.active(false);
      const revoked = await fetch(`${origin}/webhook`, { method: 'POST', headers, body: raw });
      assert.equal(revoked.status, 403); assert.deepEqual(await revoked.json(), { code: 'revoked' });
    } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  });
});
