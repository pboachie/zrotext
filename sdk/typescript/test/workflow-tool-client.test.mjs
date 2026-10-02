// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { WorkflowToolClient, WorkflowToolError, workflowTools, workflowFunctions } from '../dist/workflow-tool-client.js';
import { validateWorkflowRequest, validateWorkflowResponse } from '../dist/workflow-tools.js';
import { workflowActionDigest } from '../dist/workflow-decisions.js';
import { webcrypto } from 'node:crypto';
globalThis.crypto ??= webcrypto;
const uuid = n => `${String(n).repeat(8)}-${String(n).repeat(4)}-${String(n).repeat(4)}-${String(n).repeat(4)}-${String(n).repeat(12)}`;
const params = { request_id: uuid(1), context_id: uuid(2) };
const credential = 'ztw_' + Buffer.alloc(32, 7).toString('base64url');
const contact = { kind: 'contact', result: { contact_id: uuid(3), purpose: 'transactional', peer_digest: 'ab'.repeat(32) } };
const reply = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
const client = fetchImpl => new WorkflowToolClient({ origin: 'https://gateway.example', credential, fetchImpl });
test('status distinguishes exact delivery lifecycle from action phase and unavailable metadata', () => {
  const action = { key: { account_id: uuid(1), action_id: uuid(2), revision: 1, binding_digest: 'ab'.repeat(32) }, record_version: 1, phase: 'approved' };
  for (const state of ['accepted', 'queued', 'claimed', 'submitting', 'submitted', 'delivered', 'delivery_unknown', 'unknown', 'failed', 'cancelled', 'expired']) {
    validateWorkflowResponse('workflow.action.status', { kind: 'action', result: { ...action, delivery: {
      availability: 'available', message_id: uuid(3), dispatch_id: uuid(4), state, state_version: 1, accepted_at_ms: 1, updated_at_ms: 2,
    } } });
  }
  for (const availability of ['not_bound', 'unavailable']) {
    validateWorkflowResponse('workflow.action.status', { kind: 'action', result: { ...action, delivery: { availability } } });
  }
  assert.throws(() => validateWorkflowResponse('workflow.action.status', { kind: 'action', result: action }), /unexpected_response/);
  assert.throws(() => validateWorkflowResponse('workflow.action.status', { kind: 'action', result: { ...action, delivery: { availability: 'delivered' } } }), /unexpected_response/);
  validateWorkflowResponse('workflow.action.propose', { kind: 'action', result: action });
});
function readiness() {
  return { available: true, methods: workflowTools.map(tool => ({ method: tool.name,
    operation: tool.name === 'workflow.action.cancel' ? 'send' : tool.name.replace('workflow.', '').replace('action.', '').replaceAll('.', '_'),
    read_only_hint: tool.annotations.readOnlyHint, destructive_hint: tool.annotations.destructiveHint,
    idempotent_hint: true, implementation: 'library_candidate', transport_mounted: true, permission_granted: false })),
  scope: { context_id: uuid(2), device_id: uuid(3), line_id: uuid(4) }, send_semantics: 'owner_bound_prepared_only' };
}
test('actual request snapshots and credential remain outside model inputs and redirects', async () => {
  let captured;
  const input = { ...params };
  const pending = client(async (url, init) => { captured = { url, init }; return reply(contact); }).call('workflow.contact.read', input);
  input.context_id = uuid(4);
  assert.deepEqual(await pending, contact);
  assert.equal(captured.url, 'https://gateway.example/v1/workflow/tools');
  assert.deepEqual(JSON.parse(captured.init.body), { method: 'workflow.contact.read', params });
  assert.equal(captured.init.headers.Authorization, `Bearer ${credential}`);
  assert.equal(captured.init.redirect, 'error');
  assert.equal(captured.init.credentials, 'omit');
  assert.equal(captured.init.cache, 'no-store');
  assert.ok(!captured.init.body.includes(credential));
  assert.equal(JSON.stringify(client(async () => reply(contact))), '{}');
});
test('all unknown caller authority and plaintext fields are refused before HTTP', async () => {
  let calls = 0;
  const c = client(async () => { calls++; return reply(contact); });
  for (const field of ['owner', 'credential', 'permissions', 'plaintext', 'approved', 'message_id']) {
    await assert.rejects(c.call('workflow.contact.read', { ...params, [field]: true }), e => e.code === 'invalid_request' && e.attempts === 0);
  }
  for (const method of ['workflow.action.approve', 'workflow.action.cancel', 'send', 'constructor']) {
    await assert.rejects(c.call(method, params), e => e.code === 'invalid_request');
  }
  assert.equal(calls, 0);
});
test('operation schemas match the actual eight Rust methods and provider functions', async () => {
  const rust = await readFile(new URL('../../../crates/server/src/workflow_runtime/contracts.rs', import.meta.url), 'utf8');
  const methods = Array.from(rust.slice(0, rust.indexOf('pub enum Implementation')).matchAll(/rename = "(workflow\.[^"]+)"/g), match => match[1]);
  assert.deepEqual(workflowTools.map(tool => tool.name), methods);
  assert.deepEqual(workflowFunctions.map(tool => tool.parameters), workflowTools.map(tool => tool.inputSchema));
  assert.throws(() => { workflowTools[0].inputSchema.required.length = 0; });
});
test('readiness proves fresh scope metadata rather than a send permission', async () => {
  const value = readiness();
  assert.deepEqual(await client(async () => reply(value)).readiness(), value);
  for (const edit of [v => v.methods.pop(), v => v.methods[1] = v.methods[0], v => v.methods[0].permission_granted = 'true',
    v => v.scope.owner = uuid(1), v => v.send_semantics = 'delivered', v => v.methods[0].transport_mounted = false]) {
    const malformed = structuredClone(value); edit(malformed);
    await assert.rejects(client(async () => reply(malformed)).readiness(), e => e.state === 'unknown');
  }
});
test('only explicit rate refusal retries the identical request identity and bytes', async () => {
  const requests = [];
  const c = client(async (_, init) => { requests.push(init.body); return requests.length === 1
    ? reply({ error: { code: 'rate_limited' } }, 429) : reply(contact); });
  assert.deepEqual(await c.call('workflow.contact.read', params, 3), contact);
  assert.equal(requests.length, 2);
  assert.equal(requests[0], requests[1]);
  let calls = 0;
  await assert.rejects(client(async () => { calls++; return reply({ error: { code: 'unavailable' } }, 503); })
    .call('workflow.contact.read', params, 3), e => e.code === 'unavailable' && e.state === 'unknown');
  assert.equal(calls, 1);
});
test('malformed or interrupted replies remain unknown and never resend', async () => {
  for (const response of [() => { throw new Error('private diagnostic'); }, () => reply({ ...contact, owner: true }),
    () => reply({ kind: 'send', result: { state: 'delivered' } }), () => reply({ error: { code: 'forbidden', detail: credential } }, 403),
    () => new Response('x'.repeat(131073), { headers: { 'content-type': 'application/json' } }),
    () => new Response('{"kind":"contact"}', { headers: { 'content-type': 'text/plain' } }),
    () => reply({ error: { code: 'forbidden' } }, 503)]) {
    let calls = 0;
    await assert.rejects(client(async () => { calls++; return response(); }).call('workflow.contact.read', params, 3),
      e => e instanceof WorkflowToolError && e.state === 'unknown' && !e.message.includes(credential) && !e.message.includes('private diagnostic'));
    assert.equal(calls, 1);
  }
});
test('timeout bounds transport and body reads even when a trusted seam ignores abort', async () => {
  for (const fetchImpl of [async () => new Promise(() => {}), async () => new Response(new ReadableStream({ start() {} }),
    { headers: { 'content-type': 'application/json' } })]) {
    const c = new WorkflowToolClient({ origin: 'https://gateway.example', credential, timeoutMs: 25, fetchImpl });
    await assert.rejects(c.call('workflow.contact.read', params, 3), e => e.code === 'response_unknown' && e.attempts === 1);
  }
});
test('origin and auth realm validation never exposes invalid credentials', () => {
  for (const origin of ['http://gateway.example', 'https://owner@gateway.example', 'https://gateway.example/path', 'https://gateway.example?key=x']) {
    assert.throws(() => new WorkflowToolClient({ origin, credential }), e => e.code === 'invalid_configuration' && !e.message.includes(origin));
  }
  for (const value of [credential.replace('ztw_', 'ztk_'), credential + '=', credential + '\n', 'ztw_' + 'a'.repeat(43)]) {
    assert.throws(() => new WorkflowToolClient({ origin: 'https://gateway.example', credential: value }), e => e.code === 'invalid_configuration');
  }
});
test('exact proposal and scheduling validation never widens owner timing authority', async () => {
  const vector = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/workflow-action-01.json', import.meta.url)));
  const descriptor = { ...vector.action, account_id: uuid(1), action_id: uuid(2), line_id: uuid(3),
    recipient_id: uuid(4), purpose_id: '00000000-0000-0000-0000-000000000001', content_ref: uuid(5), routine_id: uuid(6) };
  assert.doesNotThrow(() => validateWorkflowRequest('workflow.action.propose', { request_id: uuid(1), descriptor }));
  const key = { account_id: uuid(1), action_id: uuid(2), revision: 1, binding_digest: 'ab'.repeat(32) };
  const policy = { timezone: 'UTC', first_local_date: '2027-01-01', opens_minute: 500, closes_minute: 600,
    repeat_every_days: null, max_occurrences: 1, pacing_seconds: 60 };
  const request = { request_id: uuid(1), key, policy, series_id: uuid(3), ordinal: 0 };
  assert.doesNotThrow(() => validateWorkflowRequest('workflow.action.schedule', request));
  for (const value of [{ ...request, ordinal: 1 }, { ...request, policy: { ...policy, max_occurrences: 2 } },
    { ...request, key: { ...key, approved: true } }]) assert.throws(() => validateWorkflowRequest('workflow.action.schedule', value));
});
test('Python functions and canonical digest reuse the same SDK and protocol vector', async () => {
  const vector = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/workflow-action-01.json', import.meta.url)));
  const source = `import sys,json
sys.path.insert(0,sys.argv[1])
from workflow_client import workflow_functions,action_digest,WorkflowClient,WorkflowError
v=json.load(sys.stdin)
assert action_digest(v["action"])==v["binding_digest"]
assert len(workflow_functions())==8
c=WorkflowClient("https://gateway.example", "secret-not-a-valid-credential")
assert "secret" not in repr(c)
try:
 c.call("send", {"plaintext":"synthetic"})
 raise AssertionError("accepted")
except WorkflowError as error:
 assert error.code=="invalid_configuration"
`;
  const result = spawnSync('python', ['-B', '-c', source, fileURLToPath(new URL('../../python/', import.meta.url))],
    { input: JSON.stringify(vector), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});
test('shape-valid foreign context, action, proposal and occurrence responses are unknown without resend', async () => {
  const vector = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/workflow-action-01.json', import.meta.url)));
  const descriptor = { ...vector.action, account_id: uuid(1), action_id: uuid(2), line_id: uuid(3),
    recipient_id: uuid(4), purpose_id: '00000000-0000-0000-0000-000000000001', content_ref: uuid(5), routine_id: uuid(6) };
  const key = { account_id: uuid(1), action_id: uuid(2), revision: 1, binding_digest: await workflowActionDigest(descriptor) };
  const state = { kind: 'action', result: { key, record_version: 1, phase: 'proposed' } };
  const policy = { timezone: 'UTC', first_local_date: '2027-01-01', opens_minute: 500, closes_minute: 600,
    repeat_every_days: null, max_occurrences: 1, pacing_seconds: 60 };
  const cases = [
    ['workflow.context.content', params, { kind: 'context_content', result: { context_id: uuid(9), revision: 1, envelope_base64url: 'YQ' } }],
    ['workflow.context.content', params, { kind: 'context_content', result: { context_id: params.context_id, revision: 1, envelope_base64url: 'YR' } }],
    ['workflow.context.metadata', params, { kind: 'context_metadata', result: { context_id: uuid(9), source_content_digest: 'ab'.repeat(32),
      revision: 1, kind: 1, expires_at_ms: 1, binding_generation: 1, trust_generation: 1, manifest_version: 1 } }],
    ['workflow.action.status', { ...params, action_id: uuid(9) }, state],
    ...['account_id', 'action_id', 'revision', 'binding_digest'].map(field => ['workflow.action.propose', { request_id: uuid(1), descriptor },
      { ...state, result: { ...state.result, key: { ...key, [field]: field === 'revision' ? 2 : field === 'binding_digest' ? 'cd'.repeat(32) : uuid(9) } } }]),
    ['workflow.action.schedule', { request_id: uuid(1), key, policy, series_id: uuid(3), ordinal: 0 },
      { kind: 'occurrence', result: { occurrence_id: uuid(4), series_id: uuid(9), ordinal: 0, phase: 'waiting_window', opens_at_ms: null, closes_at_ms: null, expires_at_ms: 1 } }],
  ];
  for (const [method, request, response] of cases) {
    let calls = 0;
    await assert.rejects(client(async () => { calls++; return reply(response); }).call(method, request, 3),
      error => error.state === 'unknown' && error.code === 'response_unknown' && error.attempts === 1);
    assert.equal(calls, 1);
  }
  assert.deepEqual(await client(async () => reply(state)).call('workflow.action.propose', { request_id: uuid(1), descriptor }), state);
});

test('scheduling accepts current service phases but unknown phases never succeed or resend', async () => {
  const migration = await readFile(new URL('../../../deploy/compose/migrations/077_encrypted_schedule.sql', import.meta.url), 'utf8');
  const phaseConstraint = migration.match(/phase text NOT NULL CHECK\(phase IN \(([^)]+)\)\)/);
  assert.ok(phaseConstraint, 'canonical occurrence phase constraint exists');
  const phases = Array.from(phaseConstraint[1].matchAll(/'([^']+)'/g), match => match[1]);
  const request = { request_id: uuid(1), key: { account_id: uuid(1), action_id: uuid(2), revision: 1, binding_digest: 'ab'.repeat(32) },
    policy: { timezone: 'UTC', first_local_date: '2027-01-01', opens_minute: 1, closes_minute: 2,
      repeat_every_days: null, max_occurrences: 1, pacing_seconds: 60 }, series_id: uuid(3), ordinal: 0 };
  const occurrence = phase => ({ kind: 'occurrence', result: { occurrence_id: uuid(4), series_id: request.series_id,
    ordinal: request.ordinal, phase, opens_at_ms: 1, closes_at_ms: 2, expires_at_ms: 3 } });
  for (const phase of ['delivered_by_carrier', 'sent', 'waiting', 'future_phase']) {
    let calls = 0;
    await assert.rejects(client(async () => { calls++; return reply(occurrence(phase)); })
      .call('workflow.action.schedule', request, 3), error =>
      error instanceof WorkflowToolError && error.code === 'response_unknown' && error.state === 'unknown' && error.attempts === 1);
    assert.equal(calls, 1);
  }
  for (const phase of phases) {
    assert.deepEqual(await client(async () => reply(occurrence(phase))).call('workflow.action.schedule', request), occurrence(phase));
  }
  const schema = workflowTools.find(tool => tool.name === 'workflow.action.schedule').outputSchema;
  assert.deepEqual(schema.properties.result.properties.phase.enum, phases);
});

test('cancel rejects caller queue identity and binds all returned key fields', async () => {
 const key = {account_id:uuid(1),action_id:uuid(2),revision:1,binding_digest:'ab'.repeat(32)};
 const out={kind:'cancel',result:{key,message_id:uuid(3),state:'cancelled'}};
 let calls=0; const c=client(async (_url,init)=>{calls++;assert.deepEqual(JSON.parse(init.body),{method:'workflow.action.cancel',params:{request_id:uuid(4),key}});return reply(out);});
 assert.deepEqual(await c.cancel(uuid(4),key),out);
 for(const field of ['message_id','dispatch_id','actor','occurrence_id']) await assert.rejects(c.call('workflow.action.cancel',{request_id:uuid(4),key,[field]:uuid(5)}),e=>e.code==='invalid_request'&&e.attempts===0);
 assert.equal(calls,1);
 for(const field of ['account_id','action_id','revision','binding_digest']) {const wrong=structuredClone(out);wrong.result.key[field]=field==='revision'?2:field==='binding_digest'?'cd'.repeat(32):uuid(6);await assert.rejects(client(async()=>reply(wrong)).cancel(uuid(4),key),e=>e.state==='unknown');}
});
