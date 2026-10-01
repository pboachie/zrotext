import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { createSession, tools } from '../../mcp/server.mjs';
import { parseDraftEnvelope } from '../dist/draft01.js';
const vector = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/ztse-draft-01.json', import.meta.url)));
const bytes = Buffer.from(vector.outbound.envelopeHex, 'hex');
const envelopeBase64 = bytes.toString('base64');
const rpc = (method, params, id = 1) => ({ jsonrpc: '2.0', id, method, params });
function ready() {
  const session = createSession();
  assert.equal(session(rpc('initialize', { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } })).result.protocolVersion, '2025-11-25');
  assert.equal(session({ jsonrpc: '2.0', method: 'notifications/initialized' }), undefined);
  return session;
}
test('MCP lifecycle refuses tools before readiness and negotiates supported versions', () => {
  const session = createSession();
  assert.equal(session(rpc('tools/list')).error.code, -32000);
  assert.equal(session(rpc('initialize', {})).error.code, -32602);
  const initialized = session(rpc('initialize', { protocolVersion: 'future', capabilities: {}, clientInfo: { name: 'test', version: '1' } }));
  assert.equal(initialized.result.protocolVersion, '2025-11-25');
  assert.deepEqual(initialized.result.capabilities, { tools: { listChanged: false } });
  assert.equal(session(rpc('tools/list')).error.code, -32000);
  session({ jsonrpc: '2.0', method: 'notifications/initialized' });
  assert.equal(session(rpc('tools/list')).result.tools.length, 6);
  assert.equal(session(rpc('initialize', {})).error.code, -32602);
});
test('tool discovery has closed schemas and no administration or secret inputs', () => {
  assert.deepEqual(ready()(rpc('tools/list')).result.tools, tools);
  for (const tool of tools) {
    assert.equal(tool.inputSchema.additionalProperties, false);
    assert.equal(tool.outputSchema.additionalProperties, false);
    assert.equal(tool.annotations.openWorldHint, false);
    assert.doesNotMatch(JSON.stringify(tool.inputSchema), /bearer|privateKey|recipientList|password/);
  }
});
test('SDK preview returns unsigned operation identity without content or trust claims', () => {
  const output = ready()(rpc('tools/call', { name: 'zrotext_preview', arguments: { envelopeBase64 } })).result;
  const unsigned = parseDraftEnvelope(Uint8Array.from(bytes)).unsigned;
  assert.deepEqual(output.structuredContent, { available: false, code: 'preview_only', state: 'draft', cryptoVerified: false,
    operationDigest: createHash('sha256').update(unsigned).digest('hex'), byteLength: bytes.length });
  assert.equal(output.content[0].text, JSON.stringify(output.structuredContent));
  assert.doesNotMatch(JSON.stringify(output), /envelopeBase64|peer|signature|keyId/);
});
test('refusals reject plaintext, extra policy fields and noncanonical bytes', () => {
  const session = ready();
  for (const args of [{ envelopeBase64: 'plaintext' }, { envelopeBase64, grant: true }, { envelopeBase64: envelopeBase64 + '?' },
    { envelopeBase64: Buffer.from(vector.inbound.envelopeHex, 'hex').toString('base64') }]) {
    assert.equal(session(rpc('tools/call', { name: 'zrotext_preview', arguments: args })).result.structuredContent.code, 'invalid_request');
  }
});
test('no client fields enable sending and cancellation never claims success', () => {
  const session = ready();
  for (const name of ['zrotext_readiness', 'zrotext_selected_line', 'zrotext_submit', 'zrotext_status', 'zrotext_cancel']) {
    const args = name === 'zrotext_submit' ? { envelopeBase64 } : name === 'zrotext_status' || name === 'zrotext_cancel' ?
      { messageId: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' } : {};
    const output = session(rpc('tools/call', { name, arguments: args })).result;
    assert.equal(output.structuredContent.available, false);
    assert.equal(output.structuredContent.code, 'unavailable');
    if (name === 'zrotext_cancel') assert.deepEqual(output.structuredContent, { available: false, code: 'unavailable', state: 'unknown', cancelled: false });
    if (name === 'zrotext_status') assert.equal(output.structuredContent.state, 'unknown');
  }
});
test('stdio emits only NDJSON responses and notifications stay silent', () => {
  const requests = [rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'node-client', version: process.version } }),
    { jsonrpc: '2.0', method: 'notifications/initialized' }, rpc('tools/list', {}, 2), rpc('tools/call', { name: 'zrotext_readiness' }, 3)];
  const run = spawnSync(process.execPath, [fileURLToPath(new URL('../../mcp/server.mjs', import.meta.url))],
    { input: requests.map(r => JSON.stringify(r)).join('\n') + '\n', encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.stderr, '');
  const responses = run.stdout.trim().split('\n').map(JSON.parse);
  assert.deepEqual(responses.map(r => r.id), [1, 2, 3]);
  assert.equal(responses[0].result.protocolVersion, '2025-06-18');
});
test('stdio malformed input is redacted and frames are bounded', () => {
  const path = fileURLToPath(new URL('../../mcp/server.mjs', import.meta.url));
  const run = spawnSync(process.execPath, [path], { input: 'secret malformed body\n', encoding: 'utf8' });
  assert.equal(JSON.parse(run.stdout).error.code, -32700);
  assert.doesNotMatch(run.stdout + run.stderr, /secret/);
  const large = spawnSync(process.execPath, [path], { input: 'x'.repeat(65537), encoding: 'utf8' });
  assert.equal(large.status, 2);
  assert.equal(large.stdout, '');
});
test('readiness reports missing gates and protocol errors stay bounded', () => {
  const session = ready();
  const readiness = session(rpc('tools/call', { name: 'zrotext_readiness' })).result;
  assert.deepEqual(readiness.structuredContent.requiredGates, ['scoped_policy', 'sealed_runtime', 'line_activation', 'release']);
  assert.equal(session(null).error.code, -32600);
  assert.equal(session([]).error.code, -32600);
  assert.equal(session(rpc('unknown')).error.code, -32601);
  assert.equal(session(rpc('tools/call', { name: 'owner_admin' })).error.code, -32602);
  assert.equal(session(rpc('tools/list', { cursor: 'unknown' })).error.code, -32602);
});
