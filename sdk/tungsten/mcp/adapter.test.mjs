import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createSession, workflowCatalog } from './adapter.mjs';
import { createSession as guardedSession, configuredClient, tools as guardedTools } from '../../mcp/server.mjs';
import { WorkflowToolError } from '../../typescript/dist/workflow-tool-client.js';
import { serve } from './server.mjs';
const manifest = { manifestVersion: 1, api: 'zrotext', tools: [
  { name: 'public_webhooks_list', kind: 'operation', target: 'public.listWebhookEndpoints' },
  { name: 'workflow_tools_readiness', kind: 'operation', target: 'workflow.workflowReadiness', description: 'UNTRUSTED', inputSchema: {} },
  { name: 'workflow_tools_action_send', kind: 'operation', target: 'workflow.action.send' },
  { name: 'workflow_tools_contact_read', kind: 'operation', target: 'workflow.contact.read' },
] };
const call = (name, args = {}) => ({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name, arguments: args } });
async function ready(session) {
  await session({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {
    protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } } });
  await session({ jsonrpc: '2.0', method: 'notifications/initialized' });
  return session;
}
test('catalog uses guarded schemas and omits owner operations', () => {
  const catalog = workflowCatalog(manifest);
  assert.equal(catalog.length, 3);
  assert.ok(catalog.every(tool => tool.alias.startsWith('workflow_tools_')));
  assert.ok(!JSON.stringify(catalog).includes('UNTRUSTED'));
  assert.throws(() => workflowCatalog({ ...manifest, tools: [manifest.tools[1], manifest.tools[1]] }));
  assert.throws(() => workflowCatalog({ ...manifest, tools: [{ ...manifest.tools[1], name: 'public_owner' }] }));
});
test('unconfigured workflow transport refuses with zero attempts', async () => {
  assert.equal(await configuredClient({}), undefined);
  const session = await ready(createSession(manifest));
  const response = await session(call('workflow_tools_contact_read', { request_id: '11111111-2222-4333-8444-555555555555', context_id: '11111111-2222-4333-8444-555555555555' }));
  assert.deepEqual(response.result.structuredContent, { available: false, code: 'unavailable', state: 'refused', attempts: 0 });
});
test('owner and legacy names cannot reach the trusted client', async () => {
  let calls = 0;
  const session = await ready(createSession(manifest, { client: { readiness() { calls++; }, call() { calls++; } } }));
  for (const name of ['public_webhooks_list', 'zrotext_readiness', 'workflow.contact.read', 'macro_bootstrap']) {
    assert.equal((await session(call(name))).error.code, -32602);
  }
  assert.equal(calls, 0);
});
test('confirmation and credential injection retain guarded refusal with no transport', async () => {
  let calls = 0;
  const session = await ready(createSession(manifest, { client: { call() { calls++; } } }));
  for (const args of [{ confirm: 'yes' }, { credential: 'secret' }, { approval: true }]) {
    const response = await session(call('workflow_tools_action_send', args));
    assert.equal(response.result.structuredContent.code, 'invalid_request');
    assert.equal(response.result.structuredContent.attempts, 0);
  }
  assert.equal(calls, 0);
});
test('readiness and exception redaction match guarded semantics exactly', async () => {
  for (const client of [{ readiness: async () => ({ ready: false }) }, { readiness: async () => { throw new Error('PRIVATE_SECRET'); } }]) {
    const adapter = await ready(createSession(manifest, { client }));
    const guarded = await ready(guardedSession({ client }));
    const result = await adapter(call('workflow_tools_readiness'));
    assert.deepEqual(result, await guarded(call('zrotext_readiness')));
    assert.ok(!JSON.stringify(result).includes('PRIVATE_SECRET'));
  }
});
test('initialization cannot be bypassed and list contains only allowed aliases', async () => {
  const session = createSession(manifest);
  assert.equal((await session(call('workflow_tools_readiness'))).error.code, -32000);
  await ready(session);
  const result = await session({ jsonrpc: '2.0', id: 3, method: 'tools/list' });
  assert.deepEqual(result.result.tools.map(t => t.name), workflowCatalog(manifest).map(t => t.alias));
});
test('stdio parser bounds frames and never echoes invalid request content', async () => {
  const output = [];
  await serve([Buffer.from('PRIVATE_SECRET\n')], text => output.push(text), () => {});
  assert.ok(!output.join('').includes('PRIVATE_SECRET'));
  await assert.rejects(serve([Buffer.alloc(65537, 65)], () => {}, () => {}), /Frame too large/);
});
test('HTTP flags and remote mode are refused before catalog or credentials load', () => {
  for (const [args, extra] of [[['--http', '8080'], {}], [[], { ZROTEXT_MCP_MODE: 'http' }]]) {
    const result = spawnSync(process.execPath, [fileURLToPath(new URL('./server.mjs', import.meta.url)), ...args], {
      encoding: 'utf8', env: { ...process.env, ...extra }, input: '' });
    assert.equal(result.status, 2, result.stderr);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr.trim(), 'Only local stdio is supported.');
  }
});

test('reviewed send binding is delegated unchanged, never upgraded to approval', async () => {
  const received = [];
  const args = { request_id: '11111111-2222-4333-8444-555555555555', key: {
    account_id: '11111111-2222-4333-8444-555555555555', action_id: '11111111-2222-4333-8444-555555555555',
    revision: 1, binding_digest: 'a'.repeat(64) } };
  const client = { call: async (method, value) => { received.push({ method, value }); return { state: 'unknown' }; } };
  const session = await ready(createSession(manifest, { client }));
  await session(call('workflow_tools_action_send', args));
  assert.deepEqual(received, [{ method: 'workflow.action.send', value: args }]);
});

// Independent closed inventory: an added/removed supported tool must be reviewed.
const methods = ['contact.read', 'context.metadata', 'context.content', 'action.propose',
  'action.status', 'action.schedule', 'action.send', 'action.cancel'];
const alias = method => `workflow_tools_${method.replaceAll('.', '_')}`;
const fullManifest = { manifestVersion: 1, api: 'zrotext', tools: [manifest.tools[1],
  ...methods.map(method => ({ name: alias(method), kind: 'operation', target: `workflow.${method}` }))] };
const identity = '11111111-2222-4333-8444-555555555555';
const boundKey = { account_id: identity, action_id: identity, revision: 1, binding_digest: 'ab'.repeat(32) };
const descriptor = { account_id: identity, action_id: identity, revision: 1, line_id: identity,
  recipient_id: identity, purpose_id: identity, content_ref: identity, content_digest: 'ab'.repeat(32),
  content_version: 1, not_before: 10, expires_at: 100, timezone: 'UTC', window_id: 'synthetic-window',
  routine_id: identity, authority_generation: 1, commitment: 'informational' };
const policy = { timezone: 'UTC', first_local_date: '2027-01-01', opens_minute: 500, closes_minute: 600,
  repeat_every_days: null, max_occurrences: 1, pacing_seconds: 60 };
const requests = new Map([
  ...methods.slice(0, 3).map(method => [method, { request_id: identity, context_id: identity }]),
  ['action.propose', { request_id: identity, descriptor }],
  ['action.status', { request_id: identity, context_id: identity, action_id: identity }],
  ['action.schedule', { request_id: identity, key: boundKey, policy, series_id: identity, ordinal: 0 }],
  ['action.send', { request_id: identity, key: boundKey, occurrence_id: null }],
  ['action.cancel', { request_id: identity, key: boundKey }],
]);

test('all nine advertised contracts match guarded schemas and annotations exactly', async () => {
  assert.deepEqual(guardedTools.filter(tool => tool.name.startsWith('workflow.')).map(tool => tool.name),
    methods.map(method => `workflow.${method}`));
  const session = await ready(createSession(fullManifest));
  const listed = (await session({ jsonrpc: '2.0', id: 3, method: 'tools/list' })).result.tools;
  assert.equal(listed.length, 9);
  for (const definition of listed) {
    const method = methods.find(value => alias(value) === definition.name);
    const name = method ? `workflow.${method}` : 'zrotext_readiness';
    assert.deepEqual({ ...definition, name }, guardedTools.find(tool => tool.name === name));
  }
  // Discovery returns copies; callers cannot loosen validation or future discovery.
  listed[1].inputSchema.required.length = 0;
  const repeated = (await session({ jsonrpc: '2.0', id: 4, method: 'tools/list' })).result.tools;
  assert.ok(repeated[1].inputSchema.required.length > 0);
});

test('every workflow alias forwards exact nested arguments and preserves trusted results', async () => {
  for (const [method, original] of requests) {
    const traces = [[], []];
    // Trusted client outputs are opaque at this alias boundary. Actual response
    // validation and TLS correlation remain the installed transport test's job.
    const output = { kind: 'synthetic-boundary-result', method };
    const clients = traces.map(trace => ({ call: async (name, args) => {
      trace.push(structuredClone({ name, args })); return output;
    } }));
    const generated = await ready(createSession(fullManifest, { client: clients[0] }));
    const maintained = await ready(guardedSession({ client: clients[1] }));
    const args = structuredClone(original);
    const actual = await generated(call(alias(method), args));
    assert.deepEqual(actual, await maintained(call(`workflow.${method}`, structuredClone(original))), method);
    assert.deepEqual(actual.result.structuredContent, output, method);
    assert.deepEqual(traces[0], [{ name: `workflow.${method}`, args: original }], method);
    assert.deepEqual(traces[0], traces[1], method);
    assert.deepEqual(args, original, method);
  }
});

test('all workflow aliases refuse authority injection and malformed identity before transport', async () => {
  let attempts = 0;
  const client = { call: async () => { attempts++; throw new Error('must not dispatch'); } };
  const generated = await ready(createSession(fullManifest, { client }));
  const maintained = await ready(guardedSession({ client }));
  for (const [method, original] of requests) {
    const cases = [null, [], {}, { ...original, request_id: '00000000-0000-0000-0000-000000000000' },
      ...['credential', 'actor', 'approved', 'confirm', 'plaintext', 'message_id'].map(field => ({ ...original, [field]: true }))];
    for (const args of cases) {
      const actual = await generated(call(alias(method), args));
      assert.deepEqual(actual, await maintained(call(`workflow.${method}`, args)), method);
      assert.deepEqual(actual.result.structuredContent,
        { available: false, code: 'invalid_request', state: 'refused', attempts: 0 }, method);
    }
  }
  for (const [method, args] of [
    ['action.propose', { ...requests.get('action.propose'), descriptor: { ...descriptor, expires_at: 10 } }],
    ['action.schedule', { ...requests.get('action.schedule'), ordinal: 1 }],
    ['action.schedule', { ...requests.get('action.schedule'), policy: { ...policy, closes_minute: 500 } }],
    ['action.send', { ...requests.get('action.send'), key: { ...boundKey, revision: 129 } }],
    ['action.cancel', { ...requests.get('action.cancel'), key: { ...boundKey, approved: true } }],
  ]) {
    const actual = await generated(call(alias(method), args));
    assert.deepEqual(actual, await maintained(call(`workflow.${method}`, args)), method);
    assert.equal(actual.result.structuredContent.code, 'invalid_request', method);
  }
  assert.equal(attempts, 0);
});

test('all workflow aliases preserve refusal versus uncertain outcome without retry or disclosure', async () => {
  const outcomes = [['forbidden', 'refused', 1], ['invalid_request', 'refused', 0],
    ['unavailable', 'unknown', 1], ['response_unknown', 'unknown', 1]];
  for (const [method, args] of requests) {
    for (const outcome of [...outcomes, null]) {
      const counts = [0, 0];
      const clients = counts.map((_, index) => ({ call: async () => {
        counts[index]++;
        throw outcome ? new WorkflowToolError(...outcome) : new Error('PRIVATE_PROVIDER_DETAIL');
      } }));
      const generated = await ready(createSession(fullManifest, { client: clients[0] }));
      const maintained = await ready(guardedSession({ client: clients[1] }));
      const actual = await generated(call(alias(method), args));
      assert.deepEqual(actual, await maintained(call(`workflow.${method}`, args)), method);
      const [code, state, attempts] = outcome ?? ['unavailable', 'unknown', 1];
      assert.deepEqual(actual.result.structuredContent, { available: false, code, state, attempts }, method);
      assert.equal(actual.result.isError, true);
      assert.deepEqual(counts, [1, 1]);
      assert.ok(!JSON.stringify(actual).includes('PRIVATE_PROVIDER_DETAIL'));
    }
  }
});
