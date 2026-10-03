// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { WorkflowToolClient } from '../dist/workflow-tool-client.js';
import { validateWorkflowRequest, validateWorkflowResponse } from '../dist/workflow-tools.js';
const uuid = n => `${String(n).repeat(8)}-${String(n).repeat(4)}-${String(n).repeat(4)}-${String(n).repeat(4)}-${String(n).repeat(12)}`;
const params = { request_id: uuid(1), key: { account_id: uuid(2), action_id: uuid(3), revision: 1, binding_digest: 'ab'.repeat(32) }, occurrence_id: uuid(4) };
test('offline phone is a strict waiting result without implied readiness or automatic retry', async () => {
  let calls = 0;
  const client = new WorkflowToolClient({ origin: 'https://gateway.example', credential: 'ztw_' + Buffer.alloc(32, 7).toString('base64url'),
    fetchImpl: async () => { calls++; return new Response(JSON.stringify({ kind: 'send', result: { state: 'waiting_phone' } }), { headers: { 'content-type': 'application/json' } }); } });
  assert.deepEqual(await client.call('workflow.action.send', params), { kind: 'send', result: { state: 'waiting_phone' } });
  assert.equal(calls, 1);
  for (const field of ['phone_ready', 'renderer_available', 'approved', 'actor_id']) {
    assert.throws(() => validateWorkflowRequest('workflow.action.send', { ...params, [field]: true }));
    assert.throws(() => validateWorkflowResponse('workflow.action.send', { kind: 'send', result: { state: 'waiting_phone', [field]: true } }));
  }
  for (const state of ['waiting_renderer', 'sent', 'ready', 'delivered']) {
    assert.throws(() => validateWorkflowResponse('workflow.action.send', { kind: 'send', result: { state } }));
  }
});
