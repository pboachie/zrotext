// SPDX-License-Identifier: AGPL-3.0-only
// The Python bridge uses the SDK's exact transport, schemas and crypto primitives.
import { WorkflowToolClient, workflowFunctions, WorkflowToolError } from '../typescript/dist/workflow-tool-client.js';
import { workflowActionDigest } from '../typescript/dist/workflow-decisions.js';
import { webcrypto } from 'node:crypto';
globalThis.crypto ??= webcrypto;
let size = 0;
const chunks = [];
try {
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 98304) throw new Error();
    chunks.push(chunk);
  }
  const request = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
  if (!request || typeof request !== 'object' || Array.isArray(request)) throw new Error();
  const keys = Object.keys(request).sort().join(',');
  let result;
  if (request.op === 'functions' && keys === 'op') result = workflowFunctions;
  else if (request.op === 'action_digest' && keys === 'descriptor,op') result = await workflowActionDigest(request.descriptor);
  else {
    if (!['call', 'readiness'].includes(request.op) || keys !== (request.op === 'call'
      ? 'credential,maxAttempts,method,op,origin,params,timeoutMs' : 'credential,op,origin,timeoutMs')) throw new Error();
    const client = new WorkflowToolClient({ origin: request.origin, credential: request.credential, timeoutMs: request.timeoutMs });
    result = request.op === 'readiness' ? await client.readiness() : await client.call(request.method, request.params, request.maxAttempts);
  }
  process.stdout.write(JSON.stringify({ ok: true, result }));
} catch (error) {
  const body = error instanceof WorkflowToolError
    ? { code: error.code, state: error.state, attempts: error.attempts }
    : { code: 'invalid_request', state: 'refused', attempts: 0 };
  process.stdout.write(JSON.stringify({ ok: false, error: body }));
}
