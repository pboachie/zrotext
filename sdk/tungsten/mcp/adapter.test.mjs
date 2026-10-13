import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createSession, workflowCatalog } from './adapter.mjs';
import { createSession as guardedSession, configuredClient } from '../../mcp/server.mjs';
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
