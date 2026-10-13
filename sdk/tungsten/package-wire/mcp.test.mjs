import assert from 'node:assert/strict';
import { readFileSync, realpathSync, existsSync, mkdtempSync, writeFileSync, chmodSync } from 'node:fs';
import { spawnSync, spawn, execFileSync } from 'node:child_process';
import { dirname, resolve, sep, join } from 'node:path';
import { createServer } from 'node:https';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { workflowCatalog } from '@elysra/zrotext-mcp';

const entry = fileURLToPath(import.meta.resolve('@elysra/zrotext-mcp/stdio'));
const root = resolve(dirname(entry), '../../../..');
const metadata = JSON.parse(readFileSync(resolve(root, 'package.json')));
const catalog = JSON.parse(readFileSync(resolve(root, 'lib/sdk/tungsten/generated/mcp/manifest.json')));
const init = { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
  protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'installed-test', version: '1' } } };
const ready = { jsonrpc: '2.0', method: 'notifications/initialized' };
const id = '11111111-2222-4333-8444-555555555555';

function invoke(messages, extra = {}) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    !key.startsWith('ZROTEXT_') && !['NODE_OPTIONS', 'NODE_PATH'].includes(key)));
  const result = spawnSync(process.execPath, [entry], {
    env: { ...env, ...extra }, encoding: 'utf8', timeout: 10000,
    input: messages.map(value => JSON.stringify(value)).join('\n') + '\n',
  });
  return result;
}

test('installed archive has ordinary package identity and npm executable', () => {
  assert.equal(metadata.name, '@elysra/zrotext-mcp');
  assert.equal(metadata.license, 'AGPL-3.0-only');
  assert.equal(resolve(root, metadata.bin['zrotext-mcp']), entry);
  assert.ok(realpathSync(entry).startsWith(realpathSync('node_modules') + sep));
  assert.ok(existsSync(resolve('node_modules/.bin', process.platform === 'win32' ? 'zrotext-mcp.cmd' : 'zrotext-mcp')));
  assert.equal(workflowCatalog(catalog).length, 9);
  const pins = JSON.parse(readFileSync(resolve(root, 'npm-shrinkwrap.json'))).packages;
  const installed = JSON.parse(readFileSync('package-lock.json')).packages;
  for (const [name, pin] of Object.entries(pins)) {
    if (!name) continue;
    const matches = Object.entries(installed).filter(([path]) => path.endsWith(name));
    assert.equal(matches.length, 1, name);
    assert.equal(matches[0][1].version, pin.version);
    assert.equal(matches[0][1].integrity, pin.integrity);
  }
});

test('installed stdio uses actual generated catalog but preserves guarded refusal', () => {
  const result = invoke([init, ready, { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'workflow_tools_contact_read',
      arguments: { request_id: id, context_id: id } } },
    { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'public_webhooks_list', arguments: {} } },
    { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'workflow_tools_action_send',
      arguments: { confirm: 'yes', credential: 'synthetic-private' } } }]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  const replies = result.stdout.trim().split('\n').map(JSON.parse);
  assert.deepEqual(replies.map(value => value.id), [1, 2, 3, 4, 5]);
  assert.deepEqual(replies[1].result.tools.map(tool => tool.name), workflowCatalog(catalog).map(tool => tool.alias));
  assert.deepEqual(replies[2].result.structuredContent,
    { available: false, code: 'unavailable', state: 'refused', attempts: 0 });
  assert.equal(replies[3].error.code, -32602);
  assert.equal(replies[4].result.structuredContent.code, 'invalid_request');
  assert.equal(replies[4].result.structuredContent.attempts, 0);
  assert.ok(!result.stdout.includes('synthetic-private'));
});

test('installed server refuses malformed operator configuration without disclosure', () => {
  const result = invoke([init], { ZROTEXT_WORKFLOW_ORIGIN: 'https://example.test',
    ZROTEXT_WORKFLOW_CREDENTIAL_FILE: 'synthetic-private-relative-path' });
  assert.equal(result.status, 2);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr.trim(), 'Generated workflow adapter unavailable.');
});

test('installed stdio preserves scoped TLS authority and uncertain send semantics', { timeout: 30000 }, async t => {
  // Owned consumer scratch is removed by the enclosing package runner. Synthetic
  // credential/certificate material never enters the archive or test output.
  const directory = mkdtempSync(resolve('mcp-credentials-'));
  chmodSync(directory, 0o700);
  const openssl = process.platform === 'win32'
    ? join('C:', 'Program Files', 'Git', 'usr', 'bin', 'openssl.exe') : 'openssl';
  execFileSync(openssl, ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
    '-keyout', 'key.pem', '-out', 'cert.pem'], { cwd: directory, stdio: 'pipe', timeout: 15000 });
  const credential = `ztw_${Buffer.alloc(32, 7).toString('base64url')}`;
  writeFileSync(join(directory, 'token'), credential, { mode: 0o600 });
  const requests = [];
  let mode = 'ok';
  const server = createServer({ key: readFileSync(join(directory, 'key.pem')),
    cert: readFileSync(join(directory, 'cert.pem')) }, async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    requests.push({ path: request.url, method: request.method, authorization: request.headers.authorization,
      body: JSON.parse(body) });
    if (mode === 'lost') { request.socket.destroy(); return; }
    response.writeHead(mode === 'refuse' ? 403 : 200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(mode === 'refuse' ? { error: { code: 'forbidden' } }
      : { kind: 'send', result: { state: 'waiting_owner_binding' } }));
  });
  server.on('tlsClientError', () => {});
  await new Promise(resolveReady => server.listen(0, 'localhost', resolveReady));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolveClosed => server.close(resolveClosed));
  });
  const args = { request_id: id, key: { account_id: id, action_id: id, revision: 1, binding_digest: 'a'.repeat(64) } };
  const messages = [init, ready, { jsonrpc: '2.0', id: 3, method: 'tools/call',
    params: { name: 'workflow_tools_action_send', arguments: args } }];
  async function send(trusted = true) {
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
      !key.startsWith('ZROTEXT_') && !['NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS'].includes(key)));
    Object.assign(env, { ZROTEXT_WORKFLOW_ORIGIN: `https://localhost:${server.address().port}`,
      ZROTEXT_WORKFLOW_CREDENTIAL_ROOT: directory, ZROTEXT_WORKFLOW_CREDENTIAL_FILE: 'token',
      NODE_TLS_REJECT_UNAUTHORIZED: '1' });
    if (trusted) env.NODE_EXTRA_CA_CERTS = join(directory, 'cert.pem');
    const result = await new Promise((resolveResult, reject) => {
      const child = spawn(process.execPath, [entry], { env, stdio: ['pipe', 'pipe', 'pipe'] });
      let stdout = '', stderr = '';
      const timer = setTimeout(() => { child.kill(); reject(new Error('Bounded installed MCP deadline')); }, 10000);
      child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > 196608) child.kill(); });
      child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 196608) child.kill(); });
      child.on('error', error => { clearTimeout(timer); reject(error); });
      child.on('close', code => { clearTimeout(timer); resolveResult({ code, stdout, stderr }); });
      child.stdin.end(messages.map(value => JSON.stringify(value)).join('\n') + '\n');
    });
    assert.equal(result.code, 0, result.stderr);
    assert.ok(!(result.stdout + result.stderr).includes(credential));
    const replies = result.stdout.trim().split('\n').map(JSON.parse);
    assert.deepEqual(replies.map(value => value.id), [1, 3]);
    return replies[1].result.structuredContent;
  }
  assert.deepEqual(await send(), { kind: 'send', result: { state: 'waiting_owner_binding' } });
  assert.equal(requests.length, 1);
  assert.deepEqual(requests[0], { path: '/v1/workflow/tools', method: 'POST',
    authorization: `Bearer ${credential}`, body: { method: 'workflow.action.send', params: args } });
  mode = 'refuse';
  assert.deepEqual(await send(), { available: false, code: 'forbidden', state: 'refused', attempts: 1 });
  assert.equal(requests.length, 2);
  mode = 'lost';
  assert.deepEqual(await send(), { available: false, code: 'response_unknown', state: 'unknown', attempts: 1 });
  assert.equal(requests.length, 3);
  assert.equal((await send(false)).available, false);
  assert.equal(requests.length, 3, 'Untrusted TLS must never reach the policy fixture');
});
