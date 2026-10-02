// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSession, configuredClient, tools } from '../../mcp/server.mjs';
import { workflowTools, WorkflowToolError } from '../dist/workflow-tool-client.js';
const uuid = digit => `${digit.repeat(8)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(12)}`;
const rpc = (method, params) => ({ jsonrpc: '2.0', id: 1, method, params });
function session(client) {
  const call = createSession({ client });
  call(rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'workflow-test', version: '1' } }));
  call({ jsonrpc: '2.0', method: 'notifications/initialized' });
  return call;
}
test('eight shared workflow tool schemas are reused without adding actor or credentials', () => {
  for (const definition of workflowTools) {
    const advertised = tools.find(tool => tool.name === definition.name);
    assert.equal(advertised.outputSchema.type, 'object', 'MCP tool discovery requires an object output schema');
    assert.equal(advertised.inputSchema, definition.inputSchema);
    assert.equal(advertised.annotations, definition.annotations);
    assert.equal(advertised.outputSchema.anyOf[0], definition.outputSchema);
  }
});
test('configured MCP calls actual client boundary with exact request identity and no alternate send', async () => {
  const input = { context_id: uuid('a'), request_id: uuid('b') };
  const output = { kind: 'context_metadata', result: { context_id: input.context_id, revision: 1 } };
  const seen = [];
  const call = session({ async call(method, params) { seen.push({ method, params }); return output; } });
  const reply = await call(rpc('tools/call', { name: 'workflow.context.metadata', arguments: input }));
  assert.deepEqual(seen, [{ method: 'workflow.context.metadata', params: input }]);
  assert.deepEqual(reply.result.structuredContent, output);
  assert.equal(reply.result.isError, false);
  for (const args of [{ ...input, authorized: true }, { ...input, credential: 'synthetic' }, { ...input, actor: uuid('c') }]) {
    const refused = await call(rpc('tools/call', { name: 'workflow.context.metadata', arguments: args }));
    assert.equal(refused.result.isError, true);
    assert.equal(refused.result.structuredContent.code, 'invalid_request');
  }
  assert.equal(seen.length, 1);
  assert.equal(call(rpc('tools/call', { name: 'workflow.action.approve', arguments: input })).error.code, -32602);
});
test('transport ambiguity remains unknown and errors never leak provider messages or retry', async () => {
  let attempts = 0;
  const call = session({ async call() { attempts++; throw new WorkflowToolError('unavailable', 'unknown', 1); } });
  const reply = await call(rpc('tools/call', { name: 'workflow.action.status', arguments: { context_id: uuid('a'), request_id: uuid('b'), action_id: uuid('c') } }));
  assert.deepEqual(reply.result.structuredContent, { available: false, code: 'unavailable', state: 'unknown', attempts: 1 });
  assert.equal(attempts, 1);
  const uncertain = session({ async call() { throw new WorkflowToolError('response_unknown', 'unknown', 1); } });
  const response = await uncertain(rpc('tools/call', { name: 'workflow.action.status', arguments: { context_id: uuid('a'), request_id: uuid('b'), action_id: uuid('c') } }));
  const refusal = tools.find(tool => tool.name === 'workflow.action.status').outputSchema.anyOf[1];
  assert.ok(refusal.properties.code.enum.includes(response.result.structuredContent.code));
  assert.equal(response.result.structuredContent.state, 'unknown');
  const hidden = session({ async readiness() { throw new Error('private provider detail'); } });
  const failure = await hidden(rpc('tools/call', { name: 'zrotext_readiness', arguments: {} }));
  assert.doesNotMatch(JSON.stringify(failure), /private provider/);
  assert.equal(failure.result.structuredContent.state, 'refused');
});
test('startup configuration consumes only a bounded private workflow credential file', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'zrotext-mcp-config-'));
  try {
    const file = join(folder, 'credential');
    assert.equal(await configuredClient({}), undefined);
    await assert.rejects(configuredClient({ ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test' }));
    await writeFile(file, 'ztw_' + Buffer.alloc(32, 9).toString('base64url') + '\n', { mode: 0o600 });
    const configured = await configuredClient({ ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test', ZROTEXT_WORKFLOW_CREDENTIAL_FILE: file });
    assert.equal(typeof configured.call, 'function');
    await writeFile(file, 'ztk_' + Buffer.alloc(32, 9).toString('base64url'));
    await assert.rejects(configuredClient({ ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test', ZROTEXT_WORKFLOW_CREDENTIAL_FILE: file }));
    await writeFile(file, 'x'.repeat(129));
    await assert.rejects(configuredClient({ ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test', ZROTEXT_WORKFLOW_CREDENTIAL_FILE: file }));
    if (process.platform !== 'win32') {
      await writeFile(file, 'ztw_' + Buffer.alloc(32, 9).toString('base64url'));
      await chmod(file, 0o644);
      await assert.rejects(configuredClient({ ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test', ZROTEXT_WORKFLOW_CREDENTIAL_FILE: file }));
    }
  } finally { await rm(folder, { recursive: true }); }
});


test('startup refuses a FIFO credential path without waiting for a writer', { skip: process.platform === 'win32' }, async () => {
  const folder = await mkdtemp(join(tmpdir(), 'zrotext-mcp-fifo-'));
  const fifo = join(folder, 'credential');
  let child;
  try {
    const created = spawnSync('mkfifo', [fifo], { encoding: 'utf8' });
    assert.equal(created.status, 0, 'the POSIX fixture must create its owned FIFO');
    const source = `const { configuredClient } = await import(process.argv[1]);
      try { await configuredClient({ ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test', ZROTEXT_WORKFLOW_CREDENTIAL_FILE: process.argv[2] }); process.exitCode = 3; }
      catch (error) { process.exitCode = error.message === 'invalid_configuration' ? 0 : 2; }`;
    child = spawn(process.execPath, ['--input-type=module', '-e', source, new URL('../../mcp/server.mjs', import.meta.url).href, fifo], { stdio: 'ignore' });
    const code = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('credential startup waited for a FIFO writer')); }, 5000);
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('exit', code => { clearTimeout(timer); resolve(code); });
    });
    assert.equal(code, 0, 'non-regular credentials must be refused before reading');
  } finally {
    if (child && child.exitCode === null) child.kill('SIGKILL');
    await rm(folder, { recursive: true });
  }
});

test('MCP cancel preserves action identity and denies caller message identifiers',async()=>{
 const key={account_id:uuid('a'),action_id:uuid('b'),revision:1,binding_digest:'ab'.repeat(32)},input={request_id:uuid('c'),key};let calls=0;
 const output={kind:'cancel',result:{key,message_id:uuid('d'),state:'cancelled'}};
 const call=session({async call(method,params){calls++;assert.equal(method,'workflow.action.cancel');assert.deepEqual(params,input);return output;}});
 const actual=await call(rpc('tools/call',{name:'workflow.action.cancel',arguments:input}));assert.deepEqual(actual.result.structuredContent,output);
 for(const field of ['message_id','dispatch_id','actor']) {const denied=await call(rpc('tools/call',{name:'workflow.action.cancel',arguments:{...input,[field]:uuid('e')}}));assert.ok(denied.error||denied.result?.isError);}
 assert.equal(calls,1);
});
