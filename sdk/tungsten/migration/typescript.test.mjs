import assert from 'node:assert/strict';
import test from 'node:test';
import { AlphaClient, AlphaOutcomeUnknownError } from '../../typescript/dist/alpha-client.js';
import { ZrotextClient } from '../generated/typescript/dist/client.js';
import * as example from './alpha-typescript.mjs';

const id = '11111111-2222-4333-8444-555555555555';
const intent = { clientMessageId: id, deviceId: id, recipientE164: '+15550100001', testCaseId: 'synthetic', expiresAtMs: 4102444800000 };
const status = { message_id: id, device_id: id, state: 'unknown', state_version: 1, created_at_ms: 1, updated_at_ms: 1 };
const json = (value, code = 200) => new Response(JSON.stringify(value), { status: code, headers: { 'content-type': 'application/json' } });
function clients(handler) {
  const seen = [];
  const fetch = async (url, init) => { seen.push({ url: String(url), ...init }); return handler(url, init); };
  return {
    seen,
    legacy: new AlphaClient({ baseUrl: 'https://gateway.example.test', apiKey: 'synthetic-token', fetch, timeoutMs: 35000 }),
    generated: new ZrotextClient({ baseUrl: 'https://gateway.example.test', auth: { bearerAuth: 'synthetic-token' }, fetch, validateResponses: 'strict', timeoutMs: 35000 }),
  };
}
test('real legacy and generated status examples expose different result shapes on the same wire', async () => {
  const { legacy, generated, seen } = clients(() => json(status));
  const before = await example.readLegacyStatus(legacy, id);
  const after = await example.readGeneratedStatus(generated, id);
  assert.equal(before.messageId, id);
  assert.equal(after.ok, true);
  assert.equal(after.value.message_id, id);
  assert.ok(example.needsReconciliation(before.state) && example.needsReconciliation(after.value.state));
  assert.equal(seen.length, 2);
  assert.equal(seen[0].url, seen[1].url);
  for (const request of seen) assert.equal(new Headers(request.headers).get('authorization'), 'Bearer synthetic-token');
});
test('reviewed generated submit preserves the legacy body and caller-owned replay identity', async () => {
  const { legacy, generated, seen } = clients(() => json({ message_id: id, created: false }, 202));
  const key = 'synthetic-intent-1';
  const before = await example.submitLegacy(legacy, intent, key);
  const missing = await example.submitGeneratedReviewed(generated, intent, key, undefined);
  assert.equal(missing.ok, false);
  assert.equal(missing.error.category, 'CONFIRMATION_REQUIRED');
  assert.equal(seen.length, 1);
  const preview = await example.previewGenerated(generated, intent, key);
  assert.equal(preview.ok, true);
  assert.equal(seen.length, 1); // Local preview did not submit.
  const after = await example.submitGeneratedReviewed(generated, intent, key, preview.value.confirmation_token);
  assert.equal(before.messageId, after.value.message_id);
  assert.deepEqual(JSON.parse(seen[0].body), JSON.parse(seen[1].body));
  for (const request of seen) assert.equal(new Headers(request.headers).get('idempotency-key'), key);
});
test('ambiguity remains an exception versus Err and never causes an automatic retry', async () => {
  const { legacy, generated, seen } = clients(() => { throw new TypeError('synthetic transport interruption'); });
  await assert.rejects(example.submitLegacy(legacy, intent, 'synthetic-intent-2'), AlphaOutcomeUnknownError);
  const preview = await example.previewGenerated(generated, intent, 'synthetic-intent-2');
  const result = await example.submitGeneratedReviewed(generated, intent, 'synthetic-intent-2', preview.value.confirmation_token);
  assert.equal(result.ok, false);
  assert.equal(result.error.category, 'OUTCOME_UNKNOWN');
  assert.equal(seen.length, 2);
});
test('strict generated validation refuses malformed status rather than returning a success model', async () => {
  const { generated, seen } = clients(() => json({}));
  const result = await example.readGeneratedStatus(generated, id);
  assert.equal(result.ok, false);
  assert.equal(seen.length, 1);
});

test('replacement blocker: generated reads follow same-origin redirects that legacy refuses', async () => {
  const seen = [];
  const fetch = async (url, init) => {
    seen.push(String(url));
    if (String(url).endsWith('/redirected')) return json(status);
    // Match the native fetch contract for the legacy redirect:error policy.
    if (init.redirect === 'error') throw new TypeError('redirect refused');
    return new Response(null, { status: 302, headers: { location: '/redirected' } });
  };
  const legacy = new AlphaClient({ baseUrl: 'https://gateway.example.test', apiKey: 'synthetic-token', fetch });
  const generated = new ZrotextClient({ baseUrl: 'https://gateway.example.test', auth: { bearerAuth: 'synthetic-token' }, fetch, validateResponses: 'strict' });
  await assert.rejects(example.readLegacyStatus(legacy, id));
  assert.equal(seen.length, 1);
  const result = await example.readGeneratedStatus(generated, id);
  assert.equal(result.ok, true);
  assert.equal(seen.length, 3);
  assert.equal(seen[2], 'https://gateway.example.test/redirected');
});
