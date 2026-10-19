// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { OwnerProfileElectionClient03, OwnerProfileElectionError03 } from '../dist/owner-profile-election-client.js';
import { fixture, uuid, sha, frame } from './fixtures/profile03-outbound-fixture.mjs';

const origin = 'https://gateway.example.test', base = origin + '/v1/account/sealed/payload-profile';
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const id = bytes => {
  const h = Buffer.from(bytes).toString('hex'); return h.replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
};
const account = id(uuid(1)), device = id(uuid(20)), line = id(uuid(40)), user = id(uuid(140)), session = id(uuid(160));
const csrf = 'ztc_' + b64(new Uint8Array(32).fill(11));
const factor = { password: 'example', factor: '123456' };
const data = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const refusal = (status, error) => new Response(JSON.stringify({ error }), { status, headers: { 'content-type': 'application/json' } });
const signed = fixture();
async function setup(overrides = {}) {
  const f = await signed, calls = [], saved = [], parent = new AbortController(); let csrfValue = csrf, handler;
  const options = { origin, accountId: account, userId: user, ownerSessionId: session, deviceId: device,
    rootFingerprint: f.fingerprint.slice(), currentCsrf: () => csrfValue,
    saveRecovery: async record => { saved.push(record); }, signal: parent.signal,
    fetchImpl: async (url, init) => { calls.push({ url, init }); return handler(url, init); }, ...overrides };
  const client = new OwnerProfileElectionClient03(options), opening = client.createOpening(line, f.first.bytes);
  return { f, client, opening, options, calls, saved, parent, changeCsrf: value => csrfValue = value, handle: fn => handler = fn };
}
async function reservation(s, mutate = () => {}) {
  // These tests exercise transport binding, not signature acceptance. Changing
  // synthetic context digests deliberately invalidates the fixture signatures.
  const core = s.f.core.slice();
  core.set(await sha(new TextEncoder().encode(origin)), 400);
  core.set(await sha(frame('ZTSE/line/payload-profile/owner-session/v1',
    new Uint8Array([...uuid(1), ...uuid(140), ...uuid(160)]))), 432);
  const result = { v: 1, opening_id: s.opening.opening_id, challenge_id: id(core.subarray(56, 72)),
    new_binding_id: id(uuid(100)), core: b64(core), successor_manifest03: s.opening.successor_manifest03,
    issued_ms: '9000', expires_ms: '20000', status: 'reserved' };
  mutate(result); return result;
}
async function bundle(s) {
  const r = await reservation(s), bytes = s.f.bundle.slice(); bytes.set(Buffer.from(r.core, 'base64url')); return { r, bytes };
}
async function receipt(s, packet) {
  return { v: 1, opening_id: s.opening.opening_id, challenge_id: packet.r.challenge_id, binding_id: id(uuid(100)),
    binding_generation: '7', election_digest: b64(await sha(frame('ZTSE/line/payload-profile/commitment/v1', packet.bytes.subarray(0, 500)))),
    bundle_sha256: b64(await sha(packet.bytes)), accepted_ms: '10000', selection_epoch: '1' };
}
async function current(s) {
  const f = s.f, expected = await reservation(s), core = Buffer.from(expected.core, 'base64url');
  return { v: 1, envelope_profile: 3, manifest_profile: 3, account_id: account, user_id: user, owner_session_id: session,
    device_id: device, line_id: line, selection_epoch: '1', origin_digest: b64(core.subarray(400, 432)),
    owner_session_digest: b64(core.subarray(432, 464)), device_session_digest: b64(new Uint8Array(32).fill(8)),
    site_id: 'fixture-site', instance_id: 'fixture-instance', connection_epoch: '2', deployment_epoch: '1',
    old_binding_id: id(uuid(80)), old_binding_generation: '4', old_binding_proof_digest: b64(f.accepted.oldBindingProofDigest),
    binding_id: id(uuid(100)), binding_generation: '7', reader_key_id: b64(f.accepted.selectedReaderKeyId),
    device_signing_key_id: b64(core.subarray(288, 320)), approval_key_id: b64(core.subarray(320, 352)),
    root_fingerprint: b64(f.fingerprint), trust_generation: '1', manifest_version: '2', manifest_digest: b64(f.first.digest),
    election_digest: b64(f.accepted.electionCommitment), election_bundle_sha256: b64(await sha(f.bundle)),
    compared_ms: '30000', permission_expires_ms: '60000', evidence: { root_pin: b64(f.pinBytes), prior_manifest02: b64(f.old.bytes),
      prior_accepted_ms: '10000', accepted_manifest03: b64(f.first.bytes), accepted_ms: '10000', bundle: b64(f.bundle),
      device_signing_point: b64(f.enrollment.point), owner_approval_point: b64(f.approval.point),
      registration_evidence: b64(new Uint8Array([1])), activation_evidence: b64(new Uint8Array([2])) } };
}
async function original(s) {
  const r = await current(s);
  for (const k of ['binding_id', 'binding_generation', 'election_digest', 'election_bundle_sha256']) delete r[k];
  r.envelope_profile = 2; r.manifest_profile = 2; r.selection_epoch = '0';
  r.manifest_version = '1'; r.manifest_digest = b64(s.f.old.digest);
  for (const k of ['accepted_manifest03', 'accepted_ms', 'bundle']) delete r.evidence[k];
  return r;
}
function deferred() { let resolve; const promise = new Promise(r => resolve = r); return { promise, resolve }; }
const checkError = (code, outcome) => error => error instanceof OwnerProfileElectionError03 && error.code === code && (!outcome || error.outcome === outcome);

test('recovery stores only exact public input before same-origin reservation and returns no authority', async () => {
  const s = await setup(), r = await reservation(s), trace = [];
  s.options.saveRecovery = () => { throw Error('caller mutation must not change captured options'); };
  s.handle((url, init) => {
    trace.push('network'); assert.equal(s.saved.length, 1); assert.deepEqual(s.saved[0], s.opening);
    assert.equal(url, base + '/challenges'); assert.equal(init.credentials, 'same-origin'); assert.equal(init.mode, 'same-origin');
    assert.equal(init.redirect, 'error'); assert.equal(init.cache, 'no-store'); assert.equal(init.referrerPolicy, 'no-referrer');
    assert.equal(init.headers['x-zrotext-csrf'], csrf); assert.equal(init.headers.Authorization, undefined);
    const body = JSON.parse(init.body); assert.equal(body.opening_id, s.opening.opening_id); assert.equal(body.factor, factor.factor);
    assert.equal(body.successor_manifest03, s.opening.successor_manifest03);
    return data(r, 201);
  });
  const value = await s.client.reserve(s.opening, factor);
  assert.equal(value.challengeId, r.challenge_id); assert.equal(value.status, 'reserved'); assert.equal(value.expiresMs, 20000n);
  assert(!('password' in s.saved[0])); assert(!('factor' in s.saved[0])); assert(Object.isFrozen(s.saved[0]));
  assert(!('authorized' in value)); assert(!('current' in value)); assert.deepEqual(trace, ['network']); s.client.close();
});

test('failed durable save refuses before HTTP and never consumes a factor', async () => {
  const s = await setup({ saveRecovery: async () => { throw Error('storage unavailable'); } });
  await assert.rejects(s.client.reserve(s.opening, factor), checkError('unavailable', 'refused'));
  assert.equal(s.calls.length, 0); s.client.close();
});

test('changed retry content and another opening refuse without network', async () => {
  const s = await setup();
  assert.throws(() => s.client.createOpening(line, s.f.first.bytes), checkError('opening_in_progress'));
  for (const change of [r => r.opening_id = id(uuid(200)), r => r.line_id = id(uuid(210)),
    r => r.successor_manifest03 = b64(new Uint8Array(s.f.first.bytes.length).fill(9))]) {
    const record = structuredClone(s.opening); change(record);
    await assert.rejects(s.client.reserve(record, factor), checkError('opening_conflict', 'refused'));
  }
  assert.equal(s.calls.length, 0); s.client.close();
});

test('restoration checks original account/session/origin/root and refuses accessor or secret fields', async () => {
  const s = await setup(); assert.deepEqual(s.client.restoreOpening(structuredClone(s.opening)), s.opening);
  for (const change of [r => r.origin = 'https://other.example.test', r => r.owner_session_id = id(uuid(190)),
    r => r.account_id = id(uuid(180)), r => r.root_fingerprint = b64(new Uint8Array(32).fill(7)),
    r => r.password = 'example', r => Object.defineProperty(r, 'line_id', { get() { throw Error('getter invoked'); }, enumerable: true })]) {
    const value = structuredClone(s.opening); change(value); assert.throws(() => s.client.restoreOpening(value), OwnerProfileElectionError03);
  }
  assert.equal(s.calls.length, 0); s.client.close();
});

test('lost reservation response stays unknown and explicit restored status observes the same original expiry', async () => {
  const s = await setup(); s.handle(() => { throw Error('network may have committed'); });
  await assert.rejects(s.client.reserve(s.opening, factor), checkError('unavailable', 'unknown'));
  await assert.rejects(s.client.status(s.opening), checkError('closed'));
  const fresh = await setup(); fresh.client.close();
  const observed = new OwnerProfileElectionClient03({ ...fresh.options, fetchImpl: async (url, init) => {
    assert.equal(url, base + '/challenges/status'); assert.deepEqual(JSON.parse(init.body), { v: 1, opening_id: s.opening.opening_id, line_id: line });
    return data(await reservation(s));
  } });
  const record = observed.restoreOpening(s.opening), result = await observed.status(record);
  assert.equal(result.expiresMs, 20000n); assert.equal(result.openingId, s.opening.opening_id); assert.equal(s.calls.length, 1); observed.close();
});

test('duplicate decoded keys, unknown keys, wrong content type and malformed UTF8 refuse post outcome as unknown', async () => {
  for (const kind of ['duplicate', 'escaped_duplicate', 'extra', 'wrong_type', 'utf8', 'bom']) {
    const s = await setup(), r = await reservation(s); let response;
    const raw = JSON.stringify(r);
    // Deliberately prepend one duplicate member to this known serialized object;
    // this is malformed fixture construction, not an escaping operation.
    if (kind === 'duplicate') response = new Response('{"v":1,' + raw.slice(1), { headers: { 'content-type': 'application/json' } });
    if (kind === 'escaped_duplicate') response = new Response('{"\\u0076":1,' + raw.slice(1), { headers: { 'content-type': 'application/json' } });
    if (kind === 'extra') response = data({ ...r, verified: true });
    if (kind === 'wrong_type') response = new Response(raw, { headers: { 'content-type': 'text/plain' } });
    if (kind === 'utf8') response = new Response(new Uint8Array([255]), { headers: { 'content-type': 'application/json' } });
    if (kind === 'bom') response = new Response('\ufeff' + raw, { headers: { 'content-type': 'application/json' } });
    s.handle(() => response);
    await assert.rejects(s.client.reserve(s.opening, factor), error => error instanceof OwnerProfileElectionError03 && error.outcome === 'unknown');
    assert.equal(s.calls.length, 1); s.client.close();
  }
});

test('stream and declared size limits cancel the response and do not return late candidates', async () => {
  for (const declared of [false, true]) {
    let cancelled = false;
    const s = await setup();
    const body = new ReadableStream({ start(c) { if (!declared) c.enqueue(new Uint8Array(192 * 1024 + 1)); }, cancel() { cancelled = true; } });
    const response = new Response(body, { headers: { 'content-type': 'application/json', ...(declared ? { 'content-length': String(192 * 1024 + 1) } : {}) } });
    s.handle(() => response);
    await assert.rejects(s.client.reserve(s.opening, factor), checkError('response', 'unknown'));
    assert(cancelled); s.client.close();
  }
});

test('redirect responses never become an authorized alternate origin', async () => {
  const s = await setup(), response = data(await reservation(s));
  Object.defineProperty(response, 'redirected', { value: true }); s.handle(() => response);
  await assert.rejects(s.client.reserve(s.opening, factor), checkError('response', 'unknown')); assert.equal(s.calls.length, 1);
});

test('cross-scope core, substituted successor and noncanonical numbers cannot pass reservation parsing', async () => {
  for (const change of [r => r.opening_id = id(uuid(90)), r => r.challenge_id = id(uuid(91)),
    r => r.new_binding_id = r.challenge_id, r => r.issued_ms = '09000', r => r.expires_ms = '9999999999999999999',
    r => r.successor_manifest03 += '=', r => { const bytes = Buffer.from(r.core, 'base64url'); bytes[8] ^= 1; r.core = b64(bytes); },
    r => { const bytes = Buffer.from(r.core, 'base64url'); bytes[432] ^= 1; r.core = b64(bytes); },
    r => { const bytes = Buffer.from(r.core, 'base64url'); bytes[496] = 1; r.core = b64(bytes); }]) {
    const s = await setup(), r = await reservation(s, change); s.handle(() => data(r));
    await assert.rejects(s.client.reserve(s.opening, factor), e => e instanceof OwnerProfileElectionError03 && e.outcome === 'unknown'); s.client.close();
  }
});

test('known closed refusal is distinct from uncertain mutation and never retried automatically', async () => {
  for (const [status, code] of [[401, 'authentication_required'], [409, 'conflict'], [410, 'expired'], [429, 'rate_limited'], [503, 'temporarily_unavailable']]) {
    const s = await setup(); s.handle(() => refusal(status, code));
    await assert.rejects(s.client.reserve(s.opening, factor), checkError(code, 'refused')); assert.equal(s.calls.length, 1); s.client.close();
  }
  const s = await setup(); s.handle(() => refusal(401, 'conflict'));
  await assert.rejects(s.client.reserve(s.opening, factor), checkError('response', 'unknown'));
});

test('CSRF change before network refuses and after send prevents late response disclosure', async () => {
  const before = await setup(); before.changeCsrf('ztc_' + b64(new Uint8Array(32).fill(12)));
  await assert.rejects(before.client.reserve(before.opening, factor), checkError('session_changed', 'refused')); assert.equal(before.calls.length, 0);
  const after = await setup(), response = await reservation(after);
  after.handle(() => { after.changeCsrf('ztc_' + b64(new Uint8Array(32).fill(12))); return data(response); });
  await assert.rejects(after.client.reserve(after.opening, factor), checkError('session_changed', 'unknown'));
});

test('caller abort and unresponsive fetch are bounded, retire the client and preserve public recovery', async () => {
  const s = await setup(), started = deferred();
  s.handle(() => { started.resolve(); return new Promise(() => {}); });
  const pending = s.client.reserve(s.opening, factor); await started.promise; s.parent.abort();
  await assert.rejects(pending, checkError('closed', 'unknown')); assert.equal(s.saved.length, 1);
  const timed = await setup({ timeoutMs: 30 }); timed.handle(() => new Promise(() => {}));
  await assert.rejects(timed.client.reserve(timed.opening, factor), checkError('timeout', 'unknown')); assert.equal(timed.calls.length, 1);
  assert.throws(() => timed.client.createOpening(line, timed.f.first.bytes), checkError('closed'));
});

test('stalled response consumption times out and cancels without accepting a partial JSON object', async () => {
  let cancelled = false; const s = await setup({ timeoutMs: 30 });
  s.handle(() => new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('{')); }, cancel() { cancelled = true; } }),
    { headers: { 'content-type': 'application/json' } }));
  await assert.rejects(s.client.reserve(s.opening, factor), checkError('timeout', 'unknown')); assert(cancelled);
});

test('only one operation runs while save or network is pending', async () => {
  const gate = deferred(), started = deferred(), s = await setup({ saveRecovery: () => { started.resolve(); return gate.promise; } });
  s.handle(async () => data(await reservation(s)));
  const pending = s.client.reserve(s.opening, factor); await started.promise;
  await assert.rejects(s.client.status(s.opening), checkError('busy')); gate.resolve(); await pending; s.client.close();
});

test('exact commit receipt binds original bundle, challenge, generation and acceptance time', async () => {
  const s = await setup(), packet = await bundle(s), expected = await receipt(s, packet);
  s.handle((url, init) => { assert.equal(url, base + '/elections'); assert.equal(JSON.parse(init.body).bundle, b64(packet.bytes)); return data(expected); });
  const result = await s.client.commit(s.opening, packet.r.challenge_id, packet.bytes, factor);
  assert.equal(result.bindingGeneration, 7n); assert.equal(result.acceptedMs, 10000n); assert.equal(s.saved.length, 1); s.client.close();
  for (const change of [r => r.bundle_sha256 = b64(new Uint8Array(32).fill(3)), r => r.election_digest = b64(new Uint8Array(32).fill(3)),
    r => r.accepted_ms = '20000', r => r.binding_generation = '8', r => r.challenge_id = id(uuid(190))]) {
    const other = await setup(), p = await bundle(other), value = await receipt(other, p); change(value); other.handle(() => data(value));
    await assert.rejects(other.client.commit(other.opening, p.r.challenge_id, p.bytes, factor), e => e.outcome === 'unknown'); other.client.close();
  }
});

test('device proof is a single scoped observation and malformed or substituted signatures refuse', async () => {
  for (const kind of ['valid', 'pending', 'scope', 'signature']) {
    const s = await setup(), challenge = id(s.f.core.subarray(56, 72));
    s.handle((url, init) => {
      assert.equal(url, base + '/challenges/proof');
      assert.deepEqual(JSON.parse(init.body), { v: 1, opening_id: s.opening.opening_id, challenge_id: challenge });
      if (kind === 'pending') return refusal(404, 'not_found');
      return data({ v: 1, opening_id: s.opening.opening_id, challenge_id: kind === 'scope' ? id(uuid(190)) : challenge,
        device_signature: b64(kind === 'signature' ? new Uint8Array(64) : s.f.bundle.subarray(500, 564)) });
    });
    if (kind === 'valid') { const observed = await s.client.deviceProof(s.opening, challenge); assert.equal(observed.signature.length, 64); }
    else await assert.rejects(s.client.deviceProof(s.opening, challenge), OwnerProfileElectionError03);
    assert.equal(s.calls.length, 1); assert.equal(s.saved.length, 0); s.client.close();
  }
});

test('current read uses POST with present session while preserving genuine historical session bytes', async () => {
  const s = await setup(), value = await current(s);
  s.handle((url, init) => { assert.equal(url, base + '/current'); assert.deepEqual(JSON.parse(init.body), { v: 1, line_id: line }); return data(value); });
  const result = await s.client.current(line); assert.equal(result.owner_session_id, session);
  assert.equal(result.evidence.bundle, b64(s.f.bundle)); assert.notEqual(Buffer.from(result.evidence.bundle, 'base64url').subarray(432, 464).toString('base64url'), result.owner_session_digest);
  assert(Object.isFrozen(result)); assert(Object.isFrozen(result.evidence)); assert.equal(s.saved.length, 0); s.client.close();
});

test('current projection refuses wrong scope/root, stale deadline, clock regression and changed signed evidence framing', async () => {
  for (const change of [r => r.user_id = id(uuid(180)), r => r.owner_session_digest = b64(new Uint8Array(32).fill(3)),
    r => r.permission_expires_ms = r.compared_ms, r => r.site_id = 'hidden\u0000suffix', r => r.evidence.bundle += '=',
    r => r.binding_generation = '8', r => r.election_bundle_sha256 = b64(new Uint8Array(32).fill(3)),
    r => r.reader_key_id = b64(new Uint8Array(32).fill(3)), r => r.evidence.accepted_ms = '20000',
    r => r.evidence.extra = 'unsupported', r => { const pin = Buffer.from(r.evidence.root_pin, 'base64url'); pin[93] ^= 1; r.evidence.root_pin = b64(pin); }]) {
    const s = await setup(), value = await current(s); change(value); s.handle(() => data(value));
    await assert.rejects(s.client.current(line), OwnerProfileElectionError03); s.client.close();
  }
  const s = await setup(), value = await current(s); s.handle(() => data(value)); await s.client.current(line);
  value.compared_ms = '29999'; await assert.rejects(s.client.current(line), error => {
    assert.equal(error.code, 'response'); return error instanceof OwnerProfileElectionError03;
  }); s.client.close();
});

test('unsafe origin, mutable/shared bytes, malformed factor and extended recovery input refuse before HTTP', async () => {
  const s = await setup(); s.client.close();
  for (const value of ['http://gateway.example.test', origin + '/', origin + '/path', origin + '?query', 'https://user@gateway.example.test']) {
    assert.throws(() => new OwnerProfileElectionClient03({ ...s.options, origin: value }), OwnerProfileElectionError03);
  }
  const fresh = await setup();
  await assert.rejects(fresh.client.reserve(fresh.opening, { ...factor, factor: '12345' }), OwnerProfileElectionError03);
  const oversized = { ...factor }; oversized.password = new TextDecoder().decode(new Uint8Array(1025).fill(65));
  await assert.rejects(fresh.client.reserve(fresh.opening, oversized), OwnerProfileElectionError03);
  const shared = new Uint8Array(new SharedArrayBuffer(628));
  await assert.rejects(fresh.client.commit(fresh.opening, id(uuid(60)), shared, factor)); assert.equal(fresh.calls.length, 0); fresh.client.close();
});

test('bootstrap reads a scoped original02 candidate with actual zero epoch without allocating or saving a ceremony', async () => {
  const s = await setup(), r = await original(s);
  s.handle((url, init) => {
    assert.equal(url, base + '/bootstrap'); assert.equal(init.method, 'POST');
    assert.deepEqual(JSON.parse(init.body), { v: 1, line_id: line }); assert.equal(s.saved.length, 0);
    return data(r);
  });
  const value = await s.client.bootstrap(line);
  assert.equal(value.envelope_profile, 2); assert.equal(value.selection_epoch, '0');
  assert(!('accepted' in value)); assert(!('binding_generation' in value)); assert(Object.isFrozen(value.evidence)); s.client.close();
});

test('bootstrap refuses scope, profile, frame, digest, counter and late-session substitutions', async () => {
  const changes = [r => r.envelope_profile = 3, r => r.user_id = id(uuid(141)), r => r.old_binding_generation = '0',
    r => r.selection_epoch = '00', r => r.selection_epoch = '-1', r => r.trust_generation = '2',
    r => r.manifest_version = '2', r => r.manifest_digest = b64(new Uint8Array(32).fill(5)),
    r => r.permission_expires_ms = r.compared_ms, r => r.evidence.prior_accepted_ms = '60001',
    r => r.evidence.bundle = b64(new Uint8Array(628)), r => r.evidence.registration_evidence = '',
    r => r.evidence.root_pin = b64(new Uint8Array(94)), r => r.owner_session_digest = b64(new Uint8Array(32).fill(5))];
  for (const change of changes) {
    const s = await setup(), r = await original(s); change(r); s.handle(() => data(r));
    await assert.rejects(s.client.bootstrap(line), error => error instanceof OwnerProfileElectionError03 && error.outcome === 'refused'); s.client.close();
  }
  const s = await setup(), response = deferred(); s.handle(() => response.promise);
  const pending = s.client.bootstrap(line); await new Promise(resolve => setImmediate(resolve)); s.changeCsrf('ztc_' + b64(new Uint8Array(32).fill(12)));
  response.resolve(data(await original(s))); await assert.rejects(pending, checkError('session_changed')); s.client.close();
});
