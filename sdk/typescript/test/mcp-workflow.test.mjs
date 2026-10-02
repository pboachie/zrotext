// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawn, spawnSync } from 'node:child_process';
import fs, { mkdtemp, writeFile, rm, chmod, mkdir, symlink, rename } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, parse } from 'node:path';
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
  const previousCwd = process.cwd(); process.chdir(folder);
  try {
    const file = join(folder, 'credential');
    assert.equal(await configuredClient({}), undefined);
    await assert.rejects(configuredClient({ ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test' }));
    await writeFile(file, 'ztw_' + Buffer.alloc(32, 9).toString('base64url') + '\n', { mode: 0o600 });
    const configured = await configuredClient({ ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test', ZROTEXT_WORKFLOW_CREDENTIAL_ROOT: folder, ZROTEXT_WORKFLOW_CREDENTIAL_FILE: file });
    assert.equal(typeof configured.call, 'function');
    const relativeClient = await configuredClient({ ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test',
      ZROTEXT_WORKFLOW_CREDENTIAL_ROOT: folder, ZROTEXT_WORKFLOW_CREDENTIAL_FILE: 'credential' });
    assert.equal(typeof relativeClient.call, 'function');
    await writeFile(file, 'ztk_' + Buffer.alloc(32, 9).toString('base64url'));
    await assert.rejects(configuredClient({ ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test', ZROTEXT_WORKFLOW_CREDENTIAL_ROOT: folder, ZROTEXT_WORKFLOW_CREDENTIAL_FILE: file }));
    await writeFile(file, 'x'.repeat(129));
    await assert.rejects(configuredClient({ ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test', ZROTEXT_WORKFLOW_CREDENTIAL_ROOT: folder, ZROTEXT_WORKFLOW_CREDENTIAL_FILE: file }));
    if (process.platform !== 'win32') {
      await writeFile(file, 'ztw_' + Buffer.alloc(32, 9).toString('base64url'));
      await chmod(file, 0o644);
      await assert.rejects(configuredClient({ ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test', ZROTEXT_WORKFLOW_CREDENTIAL_ROOT: folder, ZROTEXT_WORKFLOW_CREDENTIAL_FILE: file }));
    }
  } finally { process.chdir(previousCwd); await rm(folder, { recursive: true }); }
});


test('startup refuses a FIFO credential path without waiting for a writer', { skip: process.platform === 'win32' }, async () => {
  const folder = await mkdtemp(join(tmpdir(), 'zrotext-mcp-fifo-'));
  const fifo = join(folder, 'credential');
  let child;
  try {
    const created = spawnSync('mkfifo', [fifo], { encoding: 'utf8' });
    assert.equal(created.status, 0, 'the POSIX fixture must create its owned FIFO');
    const source = `const { configuredClient } = await import(process.argv[1]);
      try { await configuredClient({ ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test', ZROTEXT_WORKFLOW_CREDENTIAL_ROOT: process.argv[3], ZROTEXT_WORKFLOW_CREDENTIAL_FILE: process.argv[2] }); process.exitCode = 3; }
      catch (error) { process.exitCode = error.message === 'invalid_configuration' ? 0 : 2; }`;
    child = spawn(process.execPath, ['--input-type=module', '-e', source, new URL('../../mcp/server.mjs', import.meta.url).href, fifo, folder], { stdio: 'ignore', cwd: folder });
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


test('startup credential paths stay within an independent operator root', async () => {
 const folder=await mkdtemp(join(tmpdir(),'zrotext-mcp-boundary-'));
 const previousCwd=process.cwd();process.chdir(folder);
 const root=join(folder,'private'),sibling=join(folder,'private-sibling');
 await mkdir(root,{mode:0o700});await mkdir(sibling,{mode:0o700});
 const value='ztw_'+Buffer.alloc(32,9).toString('base64url');
 const inside=join(root,'credential'),outside=join(sibling,'credential');
 await writeFile(inside,value,{mode:0o600});await writeFile(outside,value,{mode:0o600});
 const configure=file=>configuredClient({ZROTEXT_WORKFLOW_ORIGIN:'https://example.test',ZROTEXT_WORKFLOW_CREDENTIAL_ROOT:root,ZROTEXT_WORKFLOW_CREDENTIAL_FILE:file});
 try {
  assert.equal(typeof (await configure(inside)).call,'function');
  assert.equal(typeof (await configure('credential')).call,'function');
  for(const file of [outside,join(root,'..','private-sibling','credential'),'../private-sibling/credential',root,'credential\0','credential\n','credential\t','credential\x7f']) await assert.rejects(configure(file),{message:'invalid_configuration'});
  await assert.rejects(configuredClient({ZROTEXT_WORKFLOW_ORIGIN:'https://example.test',ZROTEXT_WORKFLOW_CREDENTIAL_ROOT:'relative',ZROTEXT_WORKFLOW_CREDENTIAL_FILE:inside}),{message:'invalid_configuration'});
  await assert.rejects(configuredClient({ZROTEXT_WORKFLOW_CREDENTIAL_ROOT:root}),{message:'invalid_configuration'});
 } finally {process.chdir(previousCwd);await rm(folder,{recursive:true});}
});

test('startup refuses credentials in a root writable by other users',
 { skip: process.platform === 'win32' }, async () => {
 const root = await mkdtemp(join(tmpdir(), 'zrotext-mcp-root-mode-'));
 const previousCwd = process.cwd(); process.chdir(root);
 const file = join(root, 'credential');
 const options = { ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test',
   ZROTEXT_WORKFLOW_CREDENTIAL_ROOT: root, ZROTEXT_WORKFLOW_CREDENTIAL_FILE: file };
 try {
  await writeFile(file, 'ztw_' + Buffer.alloc(32, 9).toString('base64url'), { mode: 0o600 });
  await chmod(root, 0o777);
  await assert.rejects(configuredClient(options), { message: 'invalid_configuration' });
  await chmod(root, 0o700);
  assert.equal(typeof (await configuredClient(options)).call, 'function');
 } finally { process.chdir(previousCwd); await rm(root, { recursive: true }); }
});

test('startup rejects intermediate directory symlinks escaping the credential root', async () => {
 const folder=await mkdtemp(join(tmpdir(),'zrotext-mcp-dirlink-'));
 const previousCwd=process.cwd();process.chdir(folder);
 const root=join(folder,'private'),outside=join(folder,'outside');await mkdir(root,{mode:0o700});await mkdir(outside,{mode:0o700});
 await writeFile(join(outside,'credential'),'ztw_'+Buffer.alloc(32,9).toString('base64url'),{mode:0o600});
 try {
  await symlink(outside,join(root,'intermediate'),process.platform==='win32'?'junction':'dir');
  await assert.rejects(configuredClient({ZROTEXT_WORKFLOW_ORIGIN:'https://example.test',ZROTEXT_WORKFLOW_CREDENTIAL_ROOT:root,ZROTEXT_WORKFLOW_CREDENTIAL_FILE:'intermediate/credential'}),{message:'invalid_configuration'});
 } finally {process.chdir(previousCwd);await rm(folder,{recursive:true});}
});

test('startup rejects final file symlinks escaping the credential root', async t=>{
 const folder=await mkdtemp(join(tmpdir(),'zrotext-mcp-filelink-'));
 const previousCwd=process.cwd();process.chdir(folder);
 const root=join(folder,'private'),outside=join(folder,'outside');await mkdir(root,{mode:0o700});await mkdir(outside,{mode:0o700});
 const credential=join(outside,'credential');await writeFile(credential,'ztw_'+Buffer.alloc(32,9).toString('base64url'),{mode:0o600});
 try {
  try {await symlink(credential,join(root,'final'),'file');}
  catch(error){if(process.platform==='win32'&&['EPERM','EACCES'].includes(error.code)){t.skip('Windows account cannot create synthetic file symlinks');return;}throw error;}
  await assert.rejects(configuredClient({ZROTEXT_WORKFLOW_ORIGIN:'https://example.test',ZROTEXT_WORKFLOW_CREDENTIAL_ROOT:root,ZROTEXT_WORKFLOW_CREDENTIAL_FILE:'final'}),{message:'invalid_configuration'});
 } finally {process.chdir(previousCwd);await rm(folder,{recursive:true});}
});

// Substitute an owned file at the real filesystem open boundary, not its credential parser.
test('startup refuses replacement of the validated private credential file before opening', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'zrotext-mcp-replacement-'));
  const previousCwd = process.cwd(); process.chdir(folder);
  const file = join(folder, 'credential');
  const originalOpen = fs.open;
  let replaced = false;
  try {
    await writeFile(file, 'ztw_' + Buffer.alloc(32, 9).toString('base64url'), { mode: 0o600 });
    fs.open = async (path, ...args) => {
      if (path === file && !replaced) {
        replaced = true;
        await rename(file, join(folder, 'previous-credential'));
        await writeFile(file, 'ztw_' + Buffer.alloc(32, 10).toString('base64url'), { mode: 0o600 });
      }
      return originalOpen(path, ...args);
    };
    await assert.rejects(configuredClient({
      ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test', ZROTEXT_WORKFLOW_CREDENTIAL_ROOT: folder, ZROTEXT_WORKFLOW_CREDENTIAL_FILE: file,
    }), { message: 'invalid_configuration' });
    assert.equal(replaced, true, 'the real file replacement must occur before opening');
  } finally {
    fs.open = originalOpen;
    process.chdir(previousCwd);
    await rm(folder, { recursive: true });
  }
});


test('startup rejects credential roots outside the independently selected cwd', async () => {
 const folder=await mkdtemp(join(tmpdir(),'zrotext-mcp-root-anchor-'));
 const anchor=join(folder,'private'),sibling=join(folder,'private-sibling');await mkdir(anchor,{mode:0o700});await mkdir(sibling,{mode:0o700});
 await writeFile(join(sibling,'credential'),'ztw_'+Buffer.alloc(32,9).toString('base64url'),{mode:0o600});
 const previousCwd=process.cwd();process.chdir(anchor);
 const originalRealpath=fs.realpath;let filesystemSelections=0;
 fs.realpath=async(...args)=>{filesystemSelections++;return originalRealpath(...args);};
 try {
  for(const root of [sibling,join(anchor,'..','private-sibling')]) await assert.rejects(configuredClient({ZROTEXT_WORKFLOW_ORIGIN:'https://example.test',ZROTEXT_WORKFLOW_CREDENTIAL_ROOT:root,ZROTEXT_WORKFLOW_CREDENTIAL_FILE:'credential'}),{message:'invalid_configuration'});
  assert.equal(filesystemSelections,0,'outside roots must be refused before filesystem selection');
  await symlink(sibling,join(anchor,'external-root'),process.platform==='win32'?'junction':'dir');
  await assert.rejects(configuredClient({ZROTEXT_WORKFLOW_ORIGIN:'https://example.test',ZROTEXT_WORKFLOW_CREDENTIAL_ROOT:join(anchor,'external-root'),ZROTEXT_WORKFLOW_CREDENTIAL_FILE:'credential'}),{message:'invalid_configuration'});
 } finally {fs.realpath=originalRealpath;process.chdir(previousCwd);await rm(folder,{recursive:true});}
});


test('a filesystem-root cwd cannot authorize arbitrary custom credential roots', async()=>{
 const folder=await mkdtemp(join(tmpdir(),'zrotext-mcp-volume-'));
 const previousCwd=process.cwd();process.chdir(parse(folder).root);
 try {await assert.rejects(configuredClient({ZROTEXT_WORKFLOW_ORIGIN:'https://example.test',ZROTEXT_WORKFLOW_CREDENTIAL_ROOT:folder,ZROTEXT_WORKFLOW_CREDENTIAL_FILE:'credential'}),{message:'invalid_configuration'});}
 finally {process.chdir(previousCwd);await rm(folder,{recursive:true});}
});
