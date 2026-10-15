// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import test from 'node:test';
import { registerWorkflowTools } from './index.mjs';
import { workflowTools } from '../../typescript/dist/workflow-tools.js';

const alias = method => 'workflow_tools_' + method.slice('workflow.'.length).replaceAll('.', '_');
const manifest = { catalogVersion: 1, api: 'zrotext', tools: [
  ...workflowTools.map(t => ({ name: alias(t.name), target: t.name, kind: 'operation', description: 'UNTRUSTED', inputSchema: {} })),
  { name: 'public_webhooks_create', target: 'public.createWebhookEndpoint', kind: 'operation' },
  { name: 'sealed_messages_submit', target: 'sealed.submitSealedOutbound', kind: 'operation' },
] };
const id = '11111111-2222-4333-8444-555555555555';
const args = { request_id: id, context_id: id };
const response = { kind: 'contact', result: { contact_id: id, purpose: 'transactional', peer_digest: 'ab'.repeat(32) } };
function fixture() {
  const entries = new Map([['other_application_tool', {}]]);
  let calls = 0, permission = true;
  const signal = new AbortController();
  const registry = { kind: 'document', async registerTool(tool, { signal }) {
    signal.throwIfAborted();
    if (entries.has(tool.name)) throw new Error('duplicate');
    entries.set(tool.name, tool);
    signal.addEventListener('abort', () => entries.delete(tool.name), { once: true });
  } };
  const transport = { isAuthorized: () => permission, async call() { calls++; return response; } };
  return { entries, signal, registry, transport, calls: () => calls,
    revoke: () => { permission = false; signal.abort(); },
    deny: () => { permission = false; },
    options: { manifest, registry, transport, signal: signal.signal, allowlist: ['workflow_tools_contact_read'] } };
}

test('import never probes browser globals or registers tools', async () => {
  const originals = ['document', 'navigator'].map(key => [key, Object.getOwnPropertyDescriptor(globalThis, key)]);
  try {
    for (const [key] of originals) Object.defineProperty(globalThis, key, { configurable: true, get() { throw new Error('global accessed'); } });
    await import('./index.mjs?no-browser-effects');
  } finally {
    for (const [key, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else delete globalThis[key];
    }
  }
});

test('unsupported, missing authority and already revoked scopes never register', async () => {
  const f = fixture();
  await assert.rejects(registerWorkflowTools({ ...f.options, registry: undefined }), e => e.code === 'unsupported');
  await assert.rejects(registerWorkflowTools({ ...f.options, signal: undefined }), e => e.code === 'invalid_configuration');
  f.deny();
  await assert.rejects(registerWorkflowTools(f.options), e => e.code === 'unauthorized');
  assert.equal(f.entries.size, 1);
  assert.equal(f.calls(), 0);
});

test('only explicit reviewed workflow aliases register and use original guarded schemas', async () => {
  const f = fixture();
  const scope = await registerWorkflowTools(f.options);
  const tool = f.entries.get('workflow_tools_contact_read');
  assert.deepEqual(tool.inputSchema, workflowTools[0].inputSchema);
  assert.ok(!JSON.stringify(tool).includes('UNTRUSTED'));
  assert.deepEqual(scope.registeredNames, ['workflow_tools_contact_read']);
  assert.deepEqual((await tool.execute(args)).structuredContent, response);
  scope.close(); scope.close();
  assert.deepEqual([...f.entries.keys()], ['other_application_tool']);
});

test('owner, sealed, raw legacy names, duplicate names and disguised targets refuse', async () => {
  const f = fixture();
  for (const allowlist of [[], ['public_webhooks_create'], ['sealed_messages_submit'], ['workflow.contact.read'],
    ['workflow_tools_contact_read', 'workflow_tools_contact_read']]) {
    await assert.rejects(registerWorkflowTools({ ...f.options, allowlist }), e => e.code === 'invalid_catalog');
  }
  const altered = structuredClone(manifest);
  altered.tools[0].target = 'public.createWebhookEndpoint';
  await assert.rejects(registerWorkflowTools({ ...f.options, manifest: altered }), e => e.code === 'invalid_catalog');
  assert.equal(f.entries.size, 1);
});

test('credential, approval and unknown arguments refuse before transport', async () => {
  const f = fixture();
  const scope = await registerWorkflowTools(f.options);
  const tool = f.entries.get('workflow_tools_contact_read');
  for (const field of ['credential', 'approved', 'confirmationToken', 'owner', 'plaintext']) {
    const result = await tool.execute({ ...args, [field]: 'PRIVATE' });
    assert.deepEqual(result.structuredContent, { available: false, code: 'invalid_request', state: 'refused', attempts: 0 });
    assert.ok(!JSON.stringify(result).includes('PRIVATE'));
  }
  assert.equal(f.calls(), 0);
  scope.close();
});

test('revocation removes tools and retained callbacks cannot dispatch', async () => {
  const f = fixture();
  await registerWorkflowTools(f.options);
  const retained = f.entries.get('workflow_tools_contact_read');
  f.revoke();
  assert.deepEqual([...f.entries.keys()], ['other_application_tool']);
  assert.equal((await retained.execute(args)).structuredContent.attempts, 0);
  assert.equal(f.calls(), 0);
});

test('permission loss detected at invocation closes the whole registration', async () => {
  const f = fixture();
  await registerWorkflowTools(f.options);
  const tool = f.entries.get('workflow_tools_contact_read');
  f.deny();
  assert.equal((await tool.execute(args)).structuredContent.code, 'unauthorized');
  assert.deepEqual([...f.entries.keys()], ['other_application_tool']);
  assert.equal(f.calls(), 0);
});

test('revocation interrupts an uncooperative call and hides late output without claiming cancellation', async () => {
  const f = fixture();
  let started, finish, receivedSignal;
  const entered = new Promise(resolve => { started = resolve; });
  f.transport.call = async (_method, _args, { signal }) => {
    receivedSignal = signal; started();
    return new Promise(resolve => { finish = resolve; });
  };
  const scope = await registerWorkflowTools({ ...f.options, allowlist: ['workflow_tools_action_send'] });
  const pending = f.entries.get('workflow_tools_action_send').execute({ request_id: id,
    key: { account_id: id, action_id: id, revision: 1, binding_digest: 'a'.repeat(64) } });
  await entered;
  f.revoke();
  assert.equal(receivedSignal.aborted, true);
  assert.deepEqual((await pending).structuredContent, { available: false, code: 'response_unknown', state: 'unknown', attempts: 1 });
  finish({ kind: 'send', result: { state: 'prepared', message_id: id, dispatch_id: id } });
  scope.close();
});

test('malformed responses and transport failures are redacted without retries', async () => {
  for (const bad of [async () => ({ unexpectedField: 'PRIVATE' }), async () => { throw new Error('PRIVATE'); }]) {
    const f = fixture(); let attempts = 0;
    f.transport.call = () => { attempts++; return bad(); };
    const scope = await registerWorkflowTools(f.options);
    const value = await f.entries.get('workflow_tools_contact_read').execute(args);
    assert.equal(value.structuredContent.state, 'unknown');
    assert.ok(!JSON.stringify(value).includes('PRIVATE'));
    assert.equal(attempts, 1);
    scope.close();
  }
});

test('partial registration failure rolls back only this scope', async () => {
  const f = fixture();
  const original = f.registry.registerTool;
  let registered = 0;
  f.registry.registerTool = async (...args) => {
    if (++registered === 2) throw new Error('PRIVATE');
    return original(...args);
  };
  await assert.rejects(registerWorkflowTools({ ...f.options,
    allowlist: ['workflow_tools_contact_read', 'workflow_tools_context_metadata'] }), e =>
      e.code === 'registration_failed' && !e.message.includes('PRIVATE'));
  assert.deepEqual([...f.entries.keys()], ['other_application_tool']);
});

test('abort while registration waits cannot restore stale tools', async () => {
  const f = fixture(); let entered;
  const started = new Promise(resolve => { entered = resolve; });
  f.registry.registerTool = async (_tool, { signal }) => { entered(); await new Promise(resolve => signal.addEventListener('abort', resolve, { once: true })); };
  const pending = registerWorkflowTools(f.options);
  await started; f.revoke();
  await assert.rejects(pending, e => e.code === 'registration_failed');
  assert.equal(f.entries.size, 1);
});

test('native call cancellation before dispatch makes no transport attempt', async () => {
  const f = fixture();
  const scope = await registerWorkflowTools(f.options);
  const abort = new AbortController(); abort.abort();
  const value = await f.entries.get('workflow_tools_contact_read').execute(args, { signal: abort.signal });
  assert.equal(value.structuredContent.attempts, 0);
  assert.equal(f.calls(), 0);
  scope.close();
});

test('deadline aborts an uncooperative dispatched call without implying no effect', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture(); let started, receivedSignal;
  const entered = new Promise(resolve => { started = resolve; });
  f.transport.call = async (_method, _args, { signal }) => {
    receivedSignal = signal; started();
    return new Promise(() => {});
  };
  const scope = await registerWorkflowTools(f.options);
  const pending = f.entries.get('workflow_tools_contact_read').execute(args);
  await entered;
  t.mock.timers.tick(10000);
  assert.equal(receivedSignal.aborted, true);
  assert.deepEqual((await pending).structuredContent,
    { available: false, code: 'response_unknown', state: 'unknown', attempts: 1 });
  scope.close();
});
