// SPDX-License-Identifier: AGPL-3.0-only
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
if (!globalThis.crypto) globalThis.crypto = webcrypto;
const api = import('../review/root.mjs');
const id = (n) => '10000000-0000-4000-8000-' + n.toString(16).padStart(12, '0');
const b64 = (n) => Buffer.alloc(32, n).toString('base64');
const token = (n) => Buffer.alloc(32, n).toString('base64url');

async function fixture() {
  const { ReviewRootClient } = await api;
  let next = 0, rawCookies = '', ownerIssued = false, failAck = false, failCancel = false, retainCancelCookie = false, cancelled = false, failLogin = false, omitStaging = false, mutateContext = () => {}, beforeReply = async () => {};
  const requests = [];
  const preparation = id(201), stageName = '__Host-ztrw-c-' + preparation.replaceAll('-', '');
  const stage = stageName + '=' + token(1), broker = '__Host-ztrw-broker-csrf=' + token(2), owner = '__Host-ztrw-owner-csrf=' + token(3);
  const response = (body) => new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
  const op = (body, state) => ({ version: 1, request_id: body.request_id, preparation_id: preparation, generation: '1', state, create_deadline_ms: '1300000', delivery_deadline_ms: '1600000', server_now_ms: '1000000' });
  const client = new ReviewRootClient({ origin: 'https://example.test', newId: () => id(++next), cookies: () => rawCookies,
    fetch: async (url, options) => {
      const path = new URL(url).pathname.replace('/v1/review/', ''), body = JSON.parse(options.body);
      requests.push({ path, body, options }); await beforeReply(path, body);
      switch (path) {
        case 'browser/prepare': case 'browser/confirm':
          return response({ version: 1, request_id: body.request_id, browser_context_commitment_b64: b64(4), issued_ms: '900000', expires_ms: '1600000', server_now_ms: '1000000', outstanding: null, owner_session_issued: ownerIssued });
        case 'preparations':
          if (!omitStaging) rawCookies = stage;
          return response(op(body, 'prepared'));
        case 'preparations/confirm': return response(op(body, 'confirmed'));
        case 'login/bootstrap':
          if (failLogin) throw Error('Synthetic connection lost after dispatch');
          return response(op(body, 'committed_known'));
        case 'login/status': rawCookies = stage + '; ' + broker; return response(op(body, 'committed_known'));
        case 'workspace/status': ownerIssued = true; rawCookies = stage + '; ' + broker + '; ' + owner; return response(op(body, 'committed_known'));
        case 'session/context': {
          const value = { version: 1, request_id: body.request_id, realm: id(1), database_commitment_b64: b64(5), config_digest_b64: b64(6), config_revision: '1', origin: 'https://example.test',
            account: id(2), owner_user: id(3), review_owner_session: id(4), broker_principal: id(5), credential_id: id(6), credential_revision: '1', broker_session: id(7), auth_event: id(8),
            issued_ms: '900000', absolute_expiry_ms: '1600000', idle_deadline_ms: '1500000', server_now_ms: '1000000', capabilities: ['bootstrap_session', 'root_issue', 'root_complete', 'root_receipt', 'root_custody_export'], root_state: { kind: 'no_root_history' }, locator_retained: true };
          mutateContext(value); return response(value);
        }
        case 'session/confirm': rawCookies = broker + '; ' + owner; if (failAck) { failAck = false; throw Error('Synthetic ACK response lost after clearing cookies'); } return response(op(body, 'committed_known'));
        case 'preparations/cancel': if (retainCancelCookie) retainCancelCookie = false; else rawCookies = ''; cancelled = true; if (failCancel) { failCancel = false; throw Error('Synthetic cancellation response lost after cookie cleanup'); } return response(op(body, 'cancelled_no_effect'));
        case 'preparations/status': return response(op(body, cancelled ? 'cancelled_no_effect' : 'prepared'));
        default: throw Error('Unexpected route ' + path);
      }
    } });
  return { client, requests, setFailLogin: (v) => { failLogin = v; }, failAck: () => { failAck = true; }, failCancel: () => { failCancel = true; }, retainCancelCookie: () => { retainCancelCookie = true; }, existingOwner: (withCookies = true) => { ownerIssued = true; rawCookies = withCookies ? broker + '; ' + owner : ''; }, omitStaging: () => { omitStaging = true; }, mutateContext: (f) => { mutateContext = f; }, beforeReply: (f) => { beforeReply = f; }, op };
}

test('sign-in confirms original preparation then promotes broker and owner in separate requests', async () => {
  const f = await fixture(); await f.client.initialize();
  await f.client.login('pilot', () => 'synthetic-review-password');
  assert.deepEqual(f.requests.map((r) => r.path), ['browser/prepare', 'browser/confirm', 'preparations', 'preparations/confirm', 'login/bootstrap', 'login/status', 'workspace/status', 'session/context', 'session/confirm']);
  const staged = f.requests.filter((r) => ['preparations/confirm', 'login/bootstrap', 'login/status', 'workspace/status', 'session/confirm'].includes(r.path));
  assert.equal(new Set(staged.map((r) => r.body.request_id)).size, 1);
  assert.equal(new Set(staged.map((r) => r.body.preparation_id)).size, 1);
  assert.ok(staged.every((r) => r.options.headers['X-Ztrw-Prepared-Csrf'] === token(1)));
  assert.deepEqual(f.requests.filter((r) => Object.hasOwn(r.body, 'password')).map((r) => r.path), ['login/bootstrap']);
  assert.equal(f.client.snapshot().pending, null);
  assert.equal(f.client.snapshot().context.account, id(2));
  assert.ok(f.requests.every((r) => r.options.credentials === 'same-origin' && r.options.redirect === 'error' && r.options.cache === 'no-store'));
});

test('lost sign-in response retains original identity and explicit reconciliation never repeats login or prepare', async () => {
  const f = await fixture(); await f.client.initialize(); f.setFailLogin(true);
  await assert.rejects(f.client.login('pilot', () => 'synthetic-review-password'));
  const original = f.client.snapshot().pending;
  assert.equal(original.phase, 'login_unconfirmed');
  await assert.rejects(f.client.login('pilot', () => assert.fail('must not read another password')));
  await f.client.reconcile();
  assert.equal(f.client.snapshot().pending, null);
  assert.equal(f.requests.filter((r) => r.path === 'preparations').length, 1);
  assert.equal(f.requests.filter((r) => r.path === 'login/bootstrap').length, 1);
  assert.ok(f.requests.filter((r) => ['login/status', 'workspace/status', 'session/confirm'].includes(r.path)).every((r) => r.body.request_id === original.request_id));
});

test('missing staged cookie refuses before password access and never allocates a replacement', async () => {
  const f = await fixture(); await f.client.initialize(); f.omitStaging();
  await assert.rejects(f.client.login('pilot', () => assert.fail('must not request password without original cookies')));
  await assert.rejects(f.client.reconcile());
  await assert.rejects(f.client.login('pilot', () => assert.fail('must not allocate again')));
  assert.equal(f.requests.filter((r) => r.path === 'preparations').length, 1);
  assert.equal(f.requests.filter((r) => r.path === 'login/bootstrap').length, 0);
});

test('lost delivery acknowledgement reconciles exact original proof after staging cookies were cleared', async () => {
  const f = await fixture(); await f.client.initialize(); f.failAck();
  await assert.rejects(f.client.login('pilot', () => 'synthetic-review-password'));
  const original = f.client.snapshot().pending;
  assert.equal(original.phase, 'ack_unconfirmed');
  await f.client.reconcile();
  const acknowledgements = f.requests.filter((r) => r.path === 'session/confirm');
  assert.equal(acknowledgements.length, 2);
  assert.deepEqual(acknowledgements[0].body, acknowledgements[1].body);
  assert.equal(acknowledgements[1].options.headers['X-Ztrw-Prepared-Csrf'], token(1));
  assert.equal(f.requests.filter((r) => r.path === 'preparations').length, 1);
  assert.equal(f.requests.filter((r) => r.path === 'login/bootstrap').length, 1);
  assert.equal(f.client.snapshot().pending, null);
});

test('existing browser owner history requires actual current context instead of another workspace', async () => {
  const f = await fixture(); f.existingOwner(); await f.client.initialize();
  assert.equal(f.client.snapshot().context.account, id(2));
  assert.equal(f.client.snapshot().canSignIn, false);
  await assert.rejects(f.client.login('pilot', () => assert.fail('must not allocate replacement')));
  assert.equal(f.requests.filter((r) => r.path === 'preparations').length, 0);
  const lost = await fixture(); lost.existingOwner(false);
  await assert.rejects(lost.client.initialize());
  await assert.rejects(lost.client.login('pilot', () => assert.fail('missing cookies are not proof of no prior owner')));
  assert.equal(lost.requests.filter((r) => r.path === 'preparations').length, 0);
});

test('lost cancellation response reconciles only the original terminal result after cookie cleanup', async () => {
  const f = await fixture(); await f.client.initialize(); f.setFailLogin(true);
  await assert.rejects(f.client.login('pilot', () => 'synthetic-review-password'));
  const original = f.client.snapshot().pending;
  f.failCancel(); await assert.rejects(f.client.cancel());
  assert.equal(f.client.snapshot().pending.phase, 'cancel_unconfirmed');
  await assert.rejects(f.client.cancel());
  await f.client.reconcile();
  const reads = f.requests.filter((r) => r.path === 'preparations/status');
  assert.equal(reads.length, 1);
  assert.deepEqual(reads[0].body, { version: 1, request_id: original.request_id, preparation_id: original.preparation_id, generation: original.generation });
  assert.equal(reads[0].options.headers['X-Ztrw-Prepared-Csrf'], token(1));
  assert.equal(f.requests.filter((r) => r.path === 'preparations/cancel').length, 1);
  assert.equal(f.requests.filter((r) => r.path === 'preparations').length, 1);
  assert.equal(f.requests.filter((r) => r.path === 'login/bootstrap').length, 1);
  assert.equal(f.client.snapshot().pending, null);
  assert.equal(f.client.snapshot().canSignIn, true);
});

test('known terminal cleanup never routes back into login or root promotion', async () => {
  const f = await fixture(); await f.client.initialize(); f.setFailLogin(true);
  await assert.rejects(f.client.login('pilot', () => 'synthetic-review-password'));
  const original = f.client.snapshot().pending;
  f.retainCancelCookie(); await assert.rejects(f.client.cancel());
  assert.equal(f.client.snapshot().pending.phase, 'terminal_cleanup');
  const before = f.requests.length;
  await assert.rejects(f.client.reconcile());
  assert.equal(f.requests.length, before);
  await f.client.cancel();
  assert.equal(f.client.snapshot().pending, null);
  const cancels = f.requests.filter((r) => r.path === 'preparations/cancel');
  assert.equal(cancels.length, 2);
  assert.ok(cancels.every((r) => r.body.request_id === original.request_id && r.body.preparation_id === original.preparation_id));
  assert.equal(f.requests.filter((r) => r.path === 'login/status').length, 0);
});

test('changed context, unknown response fields and configuration ABA are refused', async () => {
  for (const change of [(v) => { v.config_revision = '3'; }, (v) => { v.account = id(999); }, (v) => { v.ordinary_session = id(999); }, (v) => { v.root_state = { kind: 'no_root_history', replacement: true }; }]) {
    const f = await fixture(); await f.client.initialize(); await f.client.login('pilot', () => 'synthetic-review-password');
    f.mutateContext(change); await assert.rejects(f.client.refresh());
    assert.equal(f.requests.filter((r) => r.path === 'preparations').length, 1);
  }
});

test('pause waits for the whole active sign-in sequence and refuses a new action', async () => {
  const f = await fixture(); await f.client.initialize();
  let release; f.beforeReply((path) => path === 'login/bootstrap' ? new Promise((resolve) => { release = resolve; }) : Promise.resolve());
  const running = f.client.login('pilot', () => 'synthetic-review-password');
  while (!release) await new Promise((resolve) => setImmediate(resolve));
  const pause = id(700);
  assert.equal(f.client.flight.requestPause(pause), true);
  assert.equal(f.client.flight.pauseStatus(pause).state, 'waiting');
  await assert.rejects(f.client.refresh());
  release(); await running;
  assert.equal(f.client.flight.pauseStatus(pause).state, 'paused');
  assert.equal(f.client.flight.resume(id(701)), false);
  assert.equal(f.client.flight.resume(pause), true);
});

test('CSRF cookie parser refuses duplicates, noncanonical encoding and zero values', async () => {
  const { cookie } = await api;
  assert.equal(cookie('x=unrelated; token=' + token(1), 'token'), token(1));
  for (const raw of ['token=' + token(1) + '; token=' + token(1), 'token=' + token(0), 'token=' + b64(1), 'token=bad', 'token=' + token(1) + '\r\n']) assert.throws(() => cookie(raw, 'token'));
});
