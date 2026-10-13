import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import test from 'node:test';
import { ZrotextClient } from '@elysra/zrotext';

const id = '11111111-2222-4333-8444-555555555555';
const auth = {
  bearerAuth: 'synthetic-bearer',
  ownerSession: {
    '__Host-zrotext_session': 'synthetic-session',
    '__Host-zrotext_csrf': 'synthetic-csrf', origin: 'https://owner.example.test',
  },
};
const status = { message_id: id, device_id: id, state: 'unknown',
  state_version: 1, created_at_ms: 1, updated_at_ms: 1 };

async function fixture(t, handler, options = {}) {
  const seen = [];
  const server = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    seen.push({ url: request.url, method: request.method, headers: request.headers, body });
    handler(request, response, seen.length);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  return { seen, baseUrl, client: new ZrotextClient({ baseUrl, auth, validateResponses: 'strict', ...options }) };
}

function json(response, value, code = 200) {
  response.writeHead(code, { 'content-type': 'application/json' });
  response.end(JSON.stringify(value));
}

test('installed npm sends real bearer authentication and encoded path', async t => {
  const { client, seen } = await fixture(t, (_, response) => json(response, status));
  assert.equal((await client.public.alphaMessages.getStatus({ messageId: id })).ok, true);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].headers.authorization, 'Bearer synthetic-bearer');
  assert.equal(seen[0].headers.cookie, undefined);
  assert.equal(seen[0].url, `/v1/alpha/messages/${id}`);
});

test('installed npm preflight validation and absent credentials send nothing', async t => {
  const { client, seen } = await fixture(t, (_, response) => json(response, status), { auth: {} });
  assert.equal((await client.public.alphaMessages.getStatus({ messageId: id })).error.category, 'AUTH_FAILED');
  assert.equal((await client.public.alphaMessages.getStatus({ messageId: 'invalid' })).ok, false);
  assert.equal(seen.length, 0);
});

test('installed npm traverses owner pages with cookies and opaque cursor', async t => {
  const { client, seen } = await fixture(t, (_, response, count) =>
    json(response, { messages: [], next_cursor: count === 1 ? id : null }));
  const pages = [];
  for await (const page of client.public.ownerMessages.list.pages()) pages.push(page);
  assert.equal(pages.length, 2);
  assert.ok(pages.every(page => page.ok));
  assert.equal(seen.length, 2);
  assert.equal(new URL(seen[0].url, 'https://example.test').searchParams.has('before'), false);
  assert.equal(new URL(seen[1].url, 'https://example.test').searchParams.get('before'), id);
  for (const request of seen) {
    assert.equal(request.headers['x-zrotext-csrf'], 'synthetic-csrf');
    assert.match(request.headers.cookie, /__Host-zrotext_session=synthetic-session/);
    assert.equal(request.headers.authorization, undefined);
  }
});

test('installed npm rejects malformed JSON and invalid successful schema', async t => {
  for (const body of ['{', '{}']) {
    const { client, seen } = await fixture(t, (_, response) => {
      response.writeHead(200, { 'content-type': 'application/json' }); response.end(body);
    });
    assert.equal((await client.public.alphaMessages.getStatus({ messageId: id })).ok, false);
    assert.equal(seen.length, 1);
  }
});

test('installed npm does not follow cross-origin redirects', async t => {
  const destination = await fixture(t, (_, response) => json(response, status));
  const { client, seen } = await fixture(t, (_, response) => {
    response.writeHead(302, { location: destination.baseUrl + '/stolen' }); response.end();
  });
  assert.equal((await client.public.alphaMessages.getStatus({ messageId: id })).ok, false);
  assert.equal(seen.length, 1);
  assert.equal(destination.seen.length, 0);
});

// Execute and report this unmet replacement contract, rather than omitting it
// or treating the runtime's five followed hops as acceptable behavior.
test('installed npm refuses same-origin redirects', {
  todo: 'Blocked by Tungsten #65; package compatibility remains unqualified',
}, async t => {
  const { client, seen } = await fixture(t, (_, response) => {
    response.writeHead(302, { location: '/redirected' }); response.end();
  });
  assert.equal((await client.public.alphaMessages.getStatus({ messageId: id })).ok, false);
  assert.equal(seen.length, 1);
});

test('installed npm bounds a stalled response body without retry', { timeout: 5000 }, async t => {
  const { client, seen } = await fixture(t, (_, response) => {
    response.writeHead(200, { 'content-type': 'application/json' }); response.write('{');
  }, { timeoutMs: 150 });
  const start = performance.now();
  assert.equal((await client.public.alphaMessages.getStatus({ messageId: id })).ok, false);
  assert.ok(performance.now() - start < 3000);
  assert.equal(seen.length, 1);
});

test('installed npm preserves disabled gates and does not retry rate limits', async t => {
  const limited = await fixture(t, (_, response) => json(response, { error: 'rate_limited' }, 429));
  assert.equal((await limited.client.public.alphaMessages.getStatus({ messageId: id })).ok, false);
  assert.equal(limited.seen.length, 1);
  const disabled = await fixture(t, (_, response) => { response.writeHead(404); response.end(); });
  assert.equal((await disabled.client.sealed.devices.list()).error.category, 'GATE_DISABLED');
  assert.equal(disabled.seen.length, 1);
});

test('installed npm confirms one uncertain send with caller-owned idempotency', async t => {
  const { client, seen } = await fixture(t, (request) => request.socket.destroy());
  const args = { client_message_id: id, device_id: id, recipient_e164: '+15550100001',
    test_case_id: 'synthetic', expires_at_ms: Date.now() + 60000 };
  const options = { idempotencyKey: 'synthetic-intent' };
  assert.equal((await client.public.alphaMessages.submit(args)).error.category, 'VALIDATION_FAILED');
  assert.equal((await client.public.alphaMessages.submit(args, options)).error.category, 'CONFIRMATION_REQUIRED');
  assert.equal(seen.length, 0);
  const preview = await client.public.alphaMessages.submit.preview(args, options);
  assert.equal(preview.ok, true);
  const result = await client.public.alphaMessages.submit(args, { ...options, confirm: preview.value.confirmation_token });
  assert.equal(result.error.category, 'OUTCOME_UNKNOWN');
  assert.equal(result.error.retryable, 'same_key_only');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].headers['idempotency-key'], options.idempotencyKey);
  assert.deepEqual(JSON.parse(seen[0].body), args);
  const diagnostic = JSON.stringify(result.error);
  for (const secret of ['synthetic-bearer', 'synthetic-session', options.idempotencyKey])
    assert.ok(!diagnostic.includes(secret));
});
