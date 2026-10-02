import { createHash, webcrypto } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { parseDraftEnvelope } from '../typescript/dist/draft01.js';
import { WorkflowToolClient, WorkflowToolError, workflowTools, workflowReadinessSchema } from '../typescript/dist/workflow-tool-client.js';
import { validateWorkflowRequest } from '../typescript/dist/workflow-tools.js';
globalThis.crypto ??= webcrypto;

const object = (properties = {}, required = []) => ({ type: 'object', properties, required, additionalProperties: false });
const identity = { type: 'string', pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' };
const envelope = { type: 'string', minLength: 568, maxLength: 49152, description: 'Existing SDK profile-01 sealed envelope, canonical base64. Never plaintext or private keys.' };
const outputSchema = object({
  available: { type: 'boolean' }, code: { type: 'string', enum: ['unavailable', 'invalid_request', 'preview_only', 'unsupported'] },
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
const refusalSchema = object({ available: { const: false }, code: { type: 'string', enum: ['unavailable', 'invalid_request', 'unauthorized', 'forbidden', 'not_found', 'conflict', 'rate_limited', 'unsupported', 'response_unknown', 'invalid_configuration'] }, state: { enum: ['refused', 'unknown'] }, attempts: { type: 'integer', minimum: 0, maximum: 3 } }, ['available', 'code', 'state', 'attempts']);
const legacyTools = definitions.map(([name, description, inputSchema, readOnlyHint]) => ({
  name, description, inputSchema, outputSchema,
  annotations: { readOnlyHint, destructiveHint: !readOnlyHint, idempotentHint: true, openWorldHint: false },
}));
legacyTools.find(tool => tool.name === 'zrotext_readiness').outputSchema = { type: 'object', anyOf: [outputSchema, workflowReadinessSchema, refusalSchema] };
legacyTools.find(tool => tool.name === 'zrotext_selected_line').outputSchema = { type: 'object', anyOf: [outputSchema, object({ context_id: identity, device_id: identity, line_id: identity }, ['context_id', 'device_id', 'line_id']), refusalSchema] };
export const tools = [...legacyTools, ...workflowTools.map(tool => ({ ...tool, outputSchema: { type: 'object', anyOf: [tool.outputSchema, refusalSchema] } }))];
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
function callTool(params, client) {
  const tool = tools.find(item => item.name === params?.name);
  if (!tool) return { error: { code: -32602, message: 'Unknown tool' } };
  const args = params.arguments ?? {};
  const workflow = workflowTools.some(item => item.name === tool.name);
  let valid = false;
  try { if (workflow) { validateWorkflowRequest(tool.name, args); valid = true; } else valid = validArguments(tool.inputSchema, args); } catch { /* Redacted shape refusal. */ }
  if (Object.keys(params).some(key => !['name', 'arguments', '_meta'].includes(key)) || !valid) {
    return { result: result(workflow ? { available: false, code: 'invalid_request', state: 'refused', attempts: 0 } : { available: false, code: 'invalid_request' }, true) };
  }
  if (workflow || (client && ['zrotext_readiness', 'zrotext_selected_line'].includes(tool.name))) {
    if (!client) return { result: result({ available: false, code: 'unavailable', state: 'refused', attempts: 0 }, true) };
    return (async () => {
      try {
        const value = workflow ? await client.call(tool.name, args) : await client.readiness();
        return { result: result(tool.name === 'zrotext_selected_line' ? value.scope : value) };
      } catch (error) {
        const known = error instanceof WorkflowToolError;
        return { result: result({ available: false, code: known ? error.code : 'unavailable', state: known ? error.state : (workflow ? 'unknown' : 'refused'), attempts: known ? error.attempts : 1 }, true) };
      }
    })();
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

/** One process = one client session and one independently issued service grant. */
export function createSession({ client } = {}) {
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
        instructions: 'Workflow tools use the configured customer service grant and current authority. Proposals are not approval; send prepares only an existing owner-bound message. Workflow cancellation withdraws only the same grant’s exact prepared output before its execution grant. Legacy envelope submission and UUID-only cancellation are unavailable. Tool annotations confer no authority.' } };
    }
    if (phase !== 'ready') return failure(-32000, 'Initialization required');
    if (request.method === 'tools/list') {
      if (request.params && Object.keys(request.params).some(key => key !== '_meta')) return failure(-32602, 'Invalid pagination');
      return { jsonrpc: '2.0', id, result: { tools } };
    }
    if (request.method === 'tools/call') {
      const output = callTool(request.params, client);
      return output instanceof Promise ? output.then(value => ({ jsonrpc: '2.0', id, ...value })) : { jsonrpc: '2.0', id, ...output };
    }
    return failure(-32601, 'Method not found');
  };
}

async function main() {
  if (process.argv.length !== 2) { process.stderr.write('Only local stdio is supported.\n'); process.exitCode = 2; return; }
  let client;
  try { client = await configuredClient(); } catch { process.stderr.write('Invalid workflow configuration.\n'); process.exitCode = 2; return; }
  const session = createSession({ client });
  let pending = Buffer.alloc(0);
  const send = async response => {
    if (!response) return;
    let serialized = JSON.stringify(response);
    if (Buffer.byteLength(serialized, 'utf8') > 262144) serialized = JSON.stringify({ jsonrpc: '2.0', id: response.id, error: { code: -32603, message: 'Response unavailable' } });
    if (!process.stdout.write(serialized + '\n')) {
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
        await send(await session(JSON.parse(text)));
      } catch {
        await send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      }
    }
    if (pending.length > 65536) { process.exitCode = 2; return; }
  }
  if (pending.length) { await send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Unterminated message' } }); }
}

/** Startup-only customer configuration. Never accept secrets in MCP requests. */
export async function configuredClient(env = process.env) {
  const origin = env.ZROTEXT_WORKFLOW_ORIGIN;
  const file = env.ZROTEXT_WORKFLOW_CREDENTIAL_FILE;
  if (!origin && !file) return undefined;
  if (!origin || !file) throw new Error('invalid_configuration');
  const handle = await open(file, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > 128 || (process.platform !== 'win32' && (info.mode & 0o077) !== 0)) throw new Error('invalid_configuration');
    const buffer = Buffer.alloc(129);
    try {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      if (bytesRead > 128) throw new Error('invalid_configuration');
      const credential = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, bytesRead)).replace(/\r?\n$/, '');
      return new WorkflowToolClient({ origin, credential });
    } finally { buffer.fill(0); }
  } finally { await handle.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
