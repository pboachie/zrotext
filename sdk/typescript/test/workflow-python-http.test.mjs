// SPDX-License-Identifier: AGPL-3.0-only
// Real local HTTPS transport into a synthetic policy fixture, not gateway/PG acceptance.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createServer } from 'node:https';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import { workflowTools } from '../dist/workflow-tool-client.js';
import { workflowActionDigest } from '../dist/workflow-decisions.js';

globalThis.crypto ??= webcrypto;
const id = n => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const credential = `ztw_${Buffer.alloc(32, 7).toString('base64url')}`;
const revoked = `ztw_${Buffer.alloc(32, 8).toString('base64url')}`;
const diagnostic = 'synthetic-private-diagnostic';
const python = process.platform === 'win32' ? 'python' : 'python3';
const pythonPath = fileURLToPath(new URL('../../python/', import.meta.url));
const descriptor = { account_id: id(1), action_id: id(2), revision: 1, line_id: id(3), recipient_id: id(4),
  purpose_id: '00000000-0000-0000-0000-000000000001', content_ref: id(5), content_digest: 'ab'.repeat(32),
  content_version: 1, not_before: 10, expires_at: 100, timezone: 'UTC', window_id: 'window-a',
  routine_id: id(6), authority_generation: 1, commitment: 'informational' };
let directory, tls, key;
before(async () => {
  directory = await mkdtemp(join(tmpdir(), 'zrotext-workflow-tls-'));
  const run = args => process.platform === 'win32'
    ? execFileSync(join('C:', 'Program Files', 'Git', 'usr', 'bin', 'openssl.exe'), args,
      { cwd: directory, timeout: 15000, stdio: 'pipe' })
    : execFileSync('openssl', args, { cwd: directory, timeout: 15000, stdio: 'pipe' });
  run(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Synthetic Workflow Test CA',
    '-keyout', 'ca.key', '-out', 'ca.pem']);
  run(['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-keyout', 'leaf.key', '-out', 'leaf.csr']);
  await writeFile(join(directory, 'leaf.ext'), 'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
  run(['x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-days', '1',
    '-extfile', 'leaf.ext', '-out', 'leaf.pem']);
  tls = { key: await readFile(join(directory, 'leaf.key')), cert: await readFile(join(directory, 'leaf.pem')) };
  key = { account_id: id(1), action_id: id(2), revision: 1, binding_digest: await workflowActionDigest(descriptor) };
});
after(async () => {
  // mkdtemp returned this test's exclusive directory; no shared cache or checkout deletion.
  if (directory) {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    assert.equal(basename(directory).startsWith('zrotext-workflow-tls-'), true);
    await rm(directory, { recursive: true, force: true });
  }
});

function invoke(origin, operation, trusted = true) {
  const script = `import json,sys
from workflow_client import WorkflowClient,WorkflowError
r=json.load(sys.stdin)
c=WorkflowClient(r['origin'],r['credential'],r['timeout'])
try:
 if r['op']=='readiness': out=c.readiness()
 elif r['op']=='preview': out=c.preview(r['request_id'],r['descriptor'])
 elif r['op']=='status': out=c.status(r['request_id'],r['context_id'],r['action_id'])
 elif r['op']=='cancel': out=c.cancel(r['request_id'],r['key'])
 elif r['op']=='submit': out=c.submit(r['request_id'],r['key'])
 else: out=c.call(r['method'],r['params'],r.get('max_attempts',1))
 print(json.dumps({'ok':True,'result':out}))
except WorkflowError as error:
 print(json.dumps({'ok':False,'error':{'code':error.code,'state':error.state,'attempts':error.attempts},'repr':repr(c),'message':str(error)}))
`;
  return new Promise((resolveResult, reject) => {
    const env = { ...process.env, PYTHONPATH: pythonPath };
    delete env.NODE_EXTRA_CA_CERTS;
    if (trusted) env.NODE_EXTRA_CA_CERTS = join(directory, 'ca.pem');
    const child = spawn(python, ['-B', '-c', script], { env, stdio: ['pipe', 'pipe', 'pipe'] });
    const timer = setTimeout(() => { child.kill(); reject(new Error('bounded Python bridge deadline')); }, 20000);
    let stdout = '', stderr = '';
    child.stdout.on('data', bytes => { stdout += bytes; if (stdout.length > 196608) child.kill(); });
    child.stderr.on('data', bytes => { stderr += bytes; if (stderr.length > 65536) child.kill(); });
    child.on('error', error => { clearTimeout(timer); reject(error); });
    child.on('close', code => {
      clearTimeout(timer);
      try {
        assert.equal(code, 0, 'Python bridge must exit successfully');
        for (const secret of [credential, revoked, diagnostic]) {
          assert.equal(stdout.includes(secret), false, 'stdout must redact private data');
          assert.equal(stderr.includes(secret), false, 'stderr must redact private data');
        }
        resolveResult(JSON.parse(stdout));
      } catch (error) { reject(error); }
    });
    child.stdin.end(JSON.stringify({ origin, credential, timeout: 5000, ...operation }));
  });
}

async function fixture(t, handler) {
  const requests = [], sockets = new Set();
  const server = createServer(tls, async (request, response) => {
    let bytes = '';
    for await (const chunk of request) bytes += chunk;
    const body = bytes ? JSON.parse(bytes) : null;
    requests.push({ method: request.method, path: request.url, body });
    const reply = (status, value) => { response.writeHead(status, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(value)); };
    if (request.headers.authorization !== `Bearer ${credential}`) return reply(401, { error: { code: 'unauthorized' } });
    if (request.url !== '/v1/workflow/tools') return reply(404, { error: { code: 'not_found' } });
    handler(request, body, reply);
  });
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  server.on('tlsClientError', () => {});
  await new Promise(resolveReady => server.listen(0, 'localhost', resolveReady));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise(resolveClosed => server.close(resolveClosed));
  });
  return { origin: `https://localhost:${server.address().port}`, requests };
}

test('Python uses the shared TLS transport for readiness, proposal, status and owner-bound send metadata', { timeout: 30000 }, async t => {
  const { origin, requests } = await fixture(t, (request, body, reply) => {
    if (request.method === 'GET') return reply(200, { available: true,
      methods: workflowTools.map(tool => ({ method: tool.name, operation: tool.name === 'workflow.action.cancel' ? 'send' : tool.name.replace('workflow.', '').replace('action.', '').replaceAll('.', '_'),
        read_only_hint: tool.annotations.readOnlyHint, destructive_hint: tool.annotations.destructiveHint,
        idempotent_hint: true, implementation: 'library_candidate', transport_mounted: true, permission_granted: false })),
      scope: { context_id: id(5), device_id: id(7), line_id: id(3) }, send_semantics: 'owner_bound_prepared_only' });
    if (body.method === 'workflow.action.send') return reply(200, { kind: 'send', result: { state: 'waiting_owner_binding' } });
    reply(200, { kind: 'action', result: { key, record_version: 1, phase: 'proposed' } });
  });
  const ready = await invoke(origin, { op: 'readiness' });
  assert.equal(ready.ok, true); assert.equal(ready.result.methods.length, 8);
  assert.equal(ready.result.methods.every(method => !method.permission_granted), true);
  const preview = await invoke(origin, { op: 'preview', request_id: id(8), descriptor });
  assert.deepEqual(preview.result.result.key, key);
  const status = await invoke(origin, { op: 'status', request_id: id(9), context_id: id(5), action_id: id(2) });
  assert.equal(status.result.result.phase, 'proposed');
  const send = await invoke(origin, { op: 'submit', request_id: id(10), key });
  assert.deepEqual(send.result, { kind: 'send', result: { state: 'waiting_owner_binding' } });
  assert.deepEqual(requests.map(request => request.method), ['GET', 'POST', 'POST', 'POST']);
  assert.deepEqual(requests[1].body.params, { request_id: id(8), descriptor });
  assert.deepEqual(requests[3].body.params.key, key);
});

test('Python preserves scope refusals and revoked credentials without leaking diagnostics', { timeout: 30000 }, async t => {
  const { origin, requests } = await fixture(t, (_request, body, reply) => {
    reply(body.params.context_id === id(99) ? 404 : 403,
      { error: { code: body.params.context_id === id(99) ? 'not_found' : 'forbidden' } });
  });
  const foreign = await invoke(origin, { op: 'status', request_id: id(8), context_id: id(99), action_id: id(2) });
  assert.deepEqual(foreign.error, { code: 'not_found', state: 'refused', attempts: 1 });
  const denied = await invoke(origin, { op: 'submit', request_id: id(9), key });
  assert.deepEqual(denied.error, { code: 'forbidden', state: 'refused', attempts: 1 });
  const withdrawn = await invoke(origin, { op: 'readiness', credential: revoked });
  assert.deepEqual(withdrawn.error, { code: 'unauthorized', state: 'refused', attempts: 1 });
  assert.equal(requests.length, 3);
});

test('committed transport timeout or diagnostic response stays unknown and is never resent', { timeout: 30000 }, async t => {
  const { origin, requests } = await fixture(t, (_request, body, reply) => {
    if (body.params.request_id === id(8)) return; // Synthetic acceptance before lost response.
    reply(403, { error: { code: 'forbidden', diagnostic: `${diagnostic}:${credential}` } });
  });
  const params = { request_id: id(8), key, occurrence_id: null };
  const timed = await invoke(origin, { op: 'call', method: 'workflow.action.send', params, max_attempts: 3, timeout: 1000 });
  assert.deepEqual(timed.error, { code: 'response_unknown', state: 'unknown', attempts: 1 });
  assert.equal(requests.length, 1); assert.deepEqual(requests[0].body.params, params);
  const malformed = await invoke(origin, { op: 'submit', request_id: id(9), key });
  assert.deepEqual(malformed.error, { code: 'response_unknown', state: 'unknown', attempts: 1 });
  assert.equal(requests.length, 2);
});

test('untrusted TLS and malformed caller scope fail without an HTTP effect', { timeout: 30000 }, async t => {
  const { origin, requests } = await fixture(t, (_request, _body, reply) => reply(200, {}));
  const untrusted = await invoke(origin, { op: 'readiness' }, false);
  assert.deepEqual(untrusted.error, { code: 'response_unknown', state: 'unknown', attempts: 1 });
  const invalid = await invoke(origin, { op: 'submit', request_id: id(8), key: { ...key, account_id: 'foreign-account' } });
  assert.deepEqual(invalid.error, { code: 'invalid_request', state: 'refused', attempts: 0 });
  assert.equal(requests.length, 0);
});

test('Python cancel uses exact key and rejects mismatched response identity', {timeout:30000}, async t=>{
 const {origin,requests}=await fixture(t,(_request,body,reply)=>{const actual=structuredClone(key);if(body.params.request_id===id(12))actual.binding_digest='ef'.repeat(32);reply(200,{kind:'cancel',result:{key:actual,message_id:id(11),state:'cancelled'}});});
 const out=await invoke(origin,{op:'cancel',request_id:id(10),key});assert.equal(out.ok,true);assert.equal(out.result.result.state,'cancelled');assert.deepEqual(requests[0].body,{method:'workflow.action.cancel',params:{request_id:id(10),key}});
 const wrong=await invoke(origin,{op:'cancel',request_id:id(12),key});assert.equal(wrong.ok,false);assert.equal(wrong.error.state,'unknown');
});
