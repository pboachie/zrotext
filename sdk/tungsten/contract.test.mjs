import assert from 'node:assert/strict';
import test from 'node:test';
import { ZrotextClient } from './generated/typescript/dist/client.js';
import { operations, api } from './generated/typescript/dist/descriptors.js';

const messageId = '11111111-2222-4333-8444-555555555555';
function fixture(handler) {
  const seen = [];
  const client = new ZrotextClient({
    baseUrl: 'https://gateway.example.test',
    auth: { bearerAuth: 'synthetic-test-token' },
    validateResponses: 'strict',
    fetch: async (url, init) => {
      seen.push({ url: String(url), ...init });
      return handler(url, init);
    },
  });
  return { client, seen };
}

test('planned aliases have no callable descriptors and default retries are disabled', () => {
  for (const operation of operations) {
    assert.ok(!['/v1/messages', '/v1/devices', '/v1/usage'].includes(operation.path));
    assert.ok(!operation.path.startsWith('/v1/messages/'));
  }
  assert.equal(api.retries.readOnly.max, 0);
  assert.equal(api.retries.mutating.max, 0);
});

test('status uses scoped bearer transport without redirect following', async () => {
  const { client, seen } = fixture(() => new Response(JSON.stringify({
    message_id: messageId, device_id: messageId, state: 'unknown',
    state_version: 1, created_at_ms: 1, updated_at_ms: 1,
  }), { headers: { 'content-type': 'application/json' } }));
  const result = await client.public.alphaMessages.getStatus({ messageId });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, `https://gateway.example.test/v1/alpha/messages/${messageId}`);
  assert.equal(seen[0].method, 'GET');
  assert.equal(new Headers(seen[0].headers).get('authorization'), 'Bearer synthetic-test-token');
  assert.equal(seen[0].redirect, 'manual');
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.value.state, 'unknown');
});

test('read failures make one attempt', async () => {
  const { client, seen } = fixture(() => { throw new TypeError('synthetic connection loss'); });
  const result = await client.public.alphaMessages.getStatus({ messageId });
  assert.equal(result.ok, false);
  assert.equal(seen.length, 1);
});

test('uncertain cancellation never retries', async () => {
  const { client, seen } = fixture(() => { throw new TypeError('synthetic connection loss'); });
  const result = await client.public.alphaMessages.cancel({ messageId });
  assert.equal(result.ok, false);
  assert.equal(result.error.category, 'OUTCOME_UNKNOWN');
  assert.equal(seen.length, 1);
});

test('redirects are rejected without a second request', async () => {
  const { client, seen } = fixture(() => new Response(null, {
    status: 302, headers: { location: 'https://other.example.test' },
  }));
  const result = await client.public.alphaMessages.getStatus({ messageId });
  assert.equal(result.ok, false);
  assert.equal(seen.length, 1);
});

test('malformed successful responses fail strict validation', async () => {
  const { client, seen } = fixture(() => new Response('{}', {
    headers: { 'content-type': 'application/json' },
  }));
  const result = await client.public.alphaMessages.getStatus({ messageId });
  assert.equal(result.ok, false);
  assert.equal(seen.length, 1);
});

test('workflow credentials cannot be replaced with the alpha API key', async () => {
  const { client, seen } = fixture(() => { throw new Error('must not send'); });
  const result = await client.workflow.tools.readiness();
  assert.equal(result.ok, false);
  assert.equal(result.error.category, 'AUTH_FAILED');
  assert.equal(seen.length, 0);
});

test('owner mutations carry matching CSRF cookies and configured Origin', async () => {
  const seen = [];
  const client = new ZrotextClient({
    baseUrl: 'https://gateway.example.test',
    auth: { ownerSession: {
      '__Host-zrotext_session': 'synthetic-session',
      '__Host-zrotext_csrf': 'synthetic-csrf',
      origin: 'https://owner.example.test',
    } },
    fetch: async (url, init) => { seen.push(init); return new Response(null, { status: 204 }); },
  });
  const result = await client.public.webhooks.enable({ endpointId: messageId });
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(seen.length, 1);
  const headers = new Headers(seen[0].headers);
  assert.equal(headers.get('origin'), 'https://owner.example.test');
  assert.equal(headers.get('x-zrotext-csrf'), 'synthetic-csrf');
  assert.match(headers.get('cookie'), /__Host-zrotext_csrf=synthetic-csrf/);
  assert.match(headers.get('cookie'), /__Host-zrotext_session=synthetic-session/);
});

test('missing owner CSRF fails before transport', async () => {
  let calls = 0;
  const client = new ZrotextClient({
    auth: { ownerSession: { '__Host-zrotext_session': 'synthetic-session' } },
    fetch: async () => { calls++; throw new Error('must not send'); },
  });
  const result = await client.public.webhooks.enable({ endpointId: messageId });
  assert.equal(result.ok, false);
  assert.equal(calls, 0);
});

test('submission requires confirmation and preserves caller idempotency on ambiguity', async () => {
  const { client, seen } = fixture(() => new Response(null, { status: 503 }));
  const args = {
    client_message_id: messageId, device_id: messageId,
    recipient_e164: '+15550100001', test_case_id: 'synthetic',
    expires_at_ms: Date.now() + 60000,
  };
  const opts = { idempotencyKey: 'synthetic.intent-1' };
  const rejected = await client.public.alphaMessages.submit(args, opts);
  assert.equal(rejected.ok, false);
  assert.equal(seen.length, 0);
  const preview = await client.public.alphaMessages.submit.preview(args, opts);
  assert.equal(preview.ok, true, JSON.stringify(preview));
  const result = await client.public.alphaMessages.submit(args, {
    ...opts, confirm: preview.value.confirmation_token,
  });
  assert.equal(result.ok, false);
  assert.equal(result.error.category, 'OUTCOME_UNKNOWN', JSON.stringify(result));
  assert.equal(seen.length, 1);
  assert.equal(new Headers(seen[0].headers).get('idempotency-key'), opts.idempotencyKey);
  assert.deepEqual(JSON.parse(seen[0].body), args);
});
