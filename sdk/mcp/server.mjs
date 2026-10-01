import { createHash, webcrypto } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { parseDraftEnvelope } from '../typescript/dist/draft01.js';
globalThis.crypto ??= webcrypto;

const object = (properties = {}, required = []) => ({ type: 'object', properties, required, additionalProperties: false });
const identity = { type: 'string', pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' };
const envelope = { type: 'string', minLength: 568, maxLength: 49152, description: 'Existing SDK profile-01 sealed envelope, canonical base64. Never plaintext or private keys.' };
const outputSchema = object({
  available: { type: 'boolean' }, code: { type: 'string', enum: ['unavailable', 'invalid_request', 'preview_only'] },
  requiredGates: { type: 'array', items: { type: 'string', enum: ['scoped_policy', 'sealed_runtime', 'line_activation', 'release'] } },
  state: { type: 'string', enum: ['draft', 'accepted', 'queued', 'submitted', 'delivered', 'unknown'] },
  cancelled: { type: 'boolean' }, cryptoVerified: { type: 'boolean' },
  operationDigest: { type: 'string', pattern: '^[0-9a-f]{64}$' }, byteLength: { type: 'integer', minimum: 0 },
}, ['available', 'code']);
const definitions = [
  ['zrotext_readiness', 'Report scoped runtime availability and required gates.', object(), true],
  ['zrotext_selected_line', 'Read only the selected authorized line metadata when available.', object(), true],
  ['zrotext_preview', 'Locally inspect SDK envelope syntax and unsigned operation identity; no trust or permission grant.', object({ envelopeBase64: envelope }, ['envelopeBase64']), true],
  ['zrotext_submit', 'Request permitted sealed submission. Unavailable until scoped gateway policy is integrated.', object({ envelopeBase64: envelope }, ['envelopeBase64']), false],
  ['zrotext_status', 'Read message metadata. Missing authority/storage reports unknown, never delivered.', object({ messageId: identity }, ['messageId']), true],
  ['zrotext_cancel', 'Request cancellation before dispatch; unavailable state never claims cancellation.', object({ messageId: identity }, ['messageId']), false],
];
export const tools = definitions.map(([name, description, inputSchema, readOnlyHint]) => ({
  name, description, inputSchema, outputSchema,
  annotations: { readOnlyHint, destructiveHint: !readOnlyHint, idempotentHint: true, openWorldHint: false },
}));
function validArguments(schema, args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) return false;
  if (Object.keys(args).some(key => !Object.hasOwn(schema.properties, key)) || schema.required.some(key => !Object.hasOwn(args, key))) return false;
  for (const [key, value] of Object.entries(args)) {
    const field = schema.properties[key];
    if (typeof value !== 'string' || (field.minLength && value.length < field.minLength) ||
        (field.maxLength && value.length > field.maxLength) || (field.pattern && !new RegExp(field.pattern).test(value))) return false;
  }
  return true;
}
function result(body, isError = false) {
  return { content: [{ type: 'text', text: JSON.stringify(body) }], structuredContent: body, isError };
}
function callTool(params) {
  const tool = tools.find(item => item.name === params?.name);
  if (!tool) return { error: { code: -32602, message: 'Unknown tool' } };
  const args = params.arguments ?? {};
  if (Object.keys(params).some(key => !['name', 'arguments', '_meta'].includes(key)) || !validArguments(tool.inputSchema, args)) {
    return { result: result({ available: false, code: 'invalid_request' }, true) };
  }
  if (tool.name === 'zrotext_preview') {
    try {
      const bytes = Buffer.from(args.envelopeBase64, 'base64');
      if (bytes.toString('base64') !== args.envelopeBase64) throw new Error();
      const parsed = parseDraftEnvelope(Uint8Array.from(bytes));
      if (parsed.kind !== 1) throw new Error();
      return { result: result({ available: false, code: 'preview_only', state: 'draft', cryptoVerified: false,
        operationDigest: createHash('sha256').update(parsed.unsigned).digest('hex'), byteLength: bytes.length }) };
    } catch {
      return { result: result({ available: false, code: 'invalid_request' }, true) };
    }
  }
  const body = { available: false, code: 'unavailable' };
  if (tool.name === 'zrotext_readiness') body.requiredGates = ['scoped_policy', 'sealed_runtime', 'line_activation', 'release'];
  if (tool.name === 'zrotext_status' || tool.name === 'zrotext_cancel') body.state = 'unknown';
  if (tool.name === 'zrotext_cancel') body.cancelled = false;
  return { result: result(body, tool.name !== 'zrotext_readiness') };
}

/** One process = one client session. No owner credentials or network access. */
export function createSession() {
  let phase = 'new';
  return request => {
    const id = request?.id ?? null;
    const failure = (code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
    if (!request || typeof request !== 'object' || Array.isArray(request) || request.jsonrpc !== '2.0' ||
        typeof request.method !== 'string' || (Object.hasOwn(request, 'id') && typeof request.id !== 'string' && !Number.isSafeInteger(request.id))) {
      return { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid request' } };
    }
    if (!Object.hasOwn(request, 'id')) {
      if (request.method === 'notifications/initialized' && phase === 'initializing') phase = 'ready';
      return undefined;
    }
    if (request.method === 'ping') return { jsonrpc: '2.0', id, result: {} };
    if (request.method === 'initialize') {
      if (phase !== 'new' || typeof request.params?.protocolVersion !== 'string' ||
          !request.params?.clientInfo || typeof request.params.clientInfo.name !== 'string' ||
          typeof request.params.clientInfo.version !== 'string' || !request.params.capabilities ||
          typeof request.params.capabilities !== 'object' || Array.isArray(request.params.capabilities)) return failure(-32602, 'Invalid initialization');
      phase = 'initializing';
      const version = ['2025-11-25', '2025-06-18'].includes(request.params.protocolVersion) ? request.params.protocolVersion : '2025-11-25';
      return { jsonrpc: '2.0', id, result: { protocolVersion: version, capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'zrotext-scoped-tools', version: '0.0.0-experimental' },
        instructions: 'Local preview only. Scoped sending is unavailable. Tool annotations confer no authority.' } };
    }
    if (phase !== 'ready') return failure(-32000, 'Initialization required');
    if (request.method === 'tools/list') {
      if (request.params && Object.keys(request.params).some(key => key !== '_meta')) return failure(-32602, 'Invalid pagination');
      return { jsonrpc: '2.0', id, result: { tools } };
    }
    if (request.method === 'tools/call') return { jsonrpc: '2.0', id, ...callTool(request.params) };
    return failure(-32601, 'Method not found');
  };
}

async function main() {
  if (process.argv.length !== 2) { process.stderr.write('Only local stdio is supported.\n'); process.exitCode = 2; return; }
  const session = createSession();
  let pending = Buffer.alloc(0);
  const send = async response => {
    if (response && !process.stdout.write(JSON.stringify(response) + '\n')) {
      await new Promise(resolve => process.stdout.once('drain', resolve));
    }
  };
  for await (const chunk of process.stdin) {
    pending = Buffer.concat([pending, chunk]);
    let end;
    while ((end = pending.indexOf(10)) !== -1) {
      const line = pending.subarray(0, end);
      pending = pending.subarray(end + 1);
      if (line.length > 65536) { process.exitCode = 2; return; }
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(line);
        await send(session(JSON.parse(text)));
      } catch {
        await send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      }
    }
    if (pending.length > 65536) { process.exitCode = 2; return; }
  }
  if (pending.length) { await send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Unterminated message' } }); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
