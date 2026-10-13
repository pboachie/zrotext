// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { getEventListeners } from 'node:events';
import { readFile } from 'node:fs/promises';
import { WorkflowToolClient } from '../dist/workflow-tool-client.js';

const id = '11111111-2222-4333-8444-555555555555';
const params = { request_id: id, context_id: id };
const key = { account_id: id, action_id: id, revision: 1, binding_digest: 'ab'.repeat(32) };
const contact = { kind: 'contact', result: { contact_id: id, purpose: 'transactional', peer_digest: 'ab'.repeat(32) } };
const reply = (value = contact, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
const client = fetchImpl => new WorkflowToolClient({ origin: 'https://gateway.example', credential: 'ztw_' + Buffer.alloc(32, 7).toString('base64url'), fetchImpl });
const unknown = e => e.code === 'response_unknown' && e.state === 'unknown' && e.attempts === 1 && !e.message.includes('private');
const clean = signal => assert.equal(getEventListeners(signal, 'abort').length, 0);

test('pre-aborted calls, readiness and cancel send nothing', async () => {
  const controller = new AbortController(); controller.abort(new Error('private reason'));
  let calls = 0;
  const c = client(async () => { calls++; return reply(); });
  for (const action of [() => c.readiness(controller.signal), () => c.call('workflow.contact.read', params, 3, controller.signal),
    () => c.cancel(id, key, controller.signal)]) {
    await assert.rejects(action(), e => e.code === 'unavailable' && e.state === 'refused' && e.attempts === 0);
    clean(controller.signal);
  }
  assert.equal(calls, 0);
});

test('in-flight mutation cancellation aborts transport and suppresses ignored late success', async () => {
  const controller = new AbortController();
  let release, transportSignal, calls = 0;
  const c = client(async (_, init) => { calls++; transportSignal = init.signal; return new Promise(resolve => { release = resolve; }); });
  const pending = c.cancel(id, key, controller.signal);
  controller.abort(new Error('private reason'));
  await assert.rejects(pending, unknown);
  assert.equal(transportSignal.aborted, true); assert.equal(calls, 1); clean(controller.signal);
  let cancelled = false;
  release(new Response(new ReadableStream({ cancel() { cancelled = true; } }), { headers: { 'content-type': 'application/json' } }));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(cancelled, true);
});

test('readiness cancellation and stalled response bodies are bounded with reader cleanup', async () => {
  for (const body of [false, true]) {
    const controller = new AbortController(); let cancelled = false, transportSignal;
    const c = client(async (_, init) => {
      transportSignal = init.signal;
      return body ? new Response(new ReadableStream({ cancel() { cancelled = true; } }), { headers: { 'content-type': 'application/json' } }) : new Promise(() => {});
    });
    const pending = c.readiness(controller.signal);
    await new Promise(resolve => setImmediate(resolve));
    controller.abort(); await assert.rejects(pending, unknown);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(transportSignal.aborted, true); if (body) assert.equal(cancelled, true); clean(controller.signal);
  }
});

test('revocation during an explicit rate refusal never starts another attempt', async () => {
  const controller = new AbortController(); let calls = 0;
  const c = client(async () => {
    calls++;
    const response = reply({ error: { code: 'rate_limited' } }, 429);
    // This is the status observation immediately after complete JSON decoding.
    Object.defineProperty(response, 'status', { get() { controller.abort(); return 429; } });
    return response;
  });
  await assert.rejects(c.call('workflow.contact.read', params, 3, controller.signal), e =>
    e.attempts === 1 && (e.state === 'unknown' || e.code === 'rate_limited' && e.state === 'refused'));
  assert.equal(calls, 1); clean(controller.signal);
});

test('successful and rejected requests remove caller listeners and preserve default single attempts', async () => {
  for (const rejected of [false, true]) {
    const controller = new AbortController(); let calls = 0;
    const c = client(async () => { calls++; return rejected ? reply({ error: { code: 'rate_limited' } }, 429) : reply(); });
    const pending = c.call('workflow.contact.read', params, undefined, controller.signal);
    if (rejected) await assert.rejects(pending, e => e.code === 'rate_limited' && e.state === 'refused' && e.attempts === 1);
    else assert.deepEqual(await pending, contact);
    assert.equal(calls, 1); clean(controller.signal); controller.abort();
  }
});

test('invalid signal configuration never dispatches', async () => {
  let calls = 0; const c = client(async () => { calls++; return reply(); });
  for (const signal of [null, {}, { aborted: false }, true]) {
    await assert.rejects(c.call('workflow.contact.read', params, 1, signal), e => e.code === 'invalid_request' && e.attempts === 0);
  }
  assert.equal(calls, 0);
});

test('revocation during asynchronous proposal digest sends nothing', async () => {
  const vector = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/workflow-action-01.json', import.meta.url)));
  const controller = new AbortController(); let calls = 0;
  const c = client(async () => { calls++; return reply(); });
  const descriptor = { ...vector.action, account_id: id, action_id: id, line_id: id,
    recipient_id: id, purpose_id: '00000000-0000-0000-0000-000000000001', content_ref: id, routine_id: id };
  const pending = c.call('workflow.action.propose', { request_id: id, descriptor }, 1, controller.signal);
  controller.abort();
  await assert.rejects(pending, e => e.code === 'unavailable' && e.state === 'refused' && e.attempts === 0);
  assert.equal(calls, 0); clean(controller.signal);
});
