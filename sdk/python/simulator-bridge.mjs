// Private process bridge: bounded stdin, fixture-only adapter, redacted output.
import { webcrypto } from 'node:crypto';
import { simulateSubmission } from '../typescript/dist/agent-adapter.js';
globalThis.crypto ??= webcrypto;
let input = '';
try {
  for await (const chunk of process.stdin) {
    input += chunk.toString('utf8');
    if (Buffer.byteLength(input) > 65536) throw new Error();
  }
  const request = JSON.parse(input);
  if (request === null || typeof request !== 'object' || Array.isArray(request) ||
      Object.keys(request).sort().join(',') !== 'envelope,maxAttempts,responses' ||
      typeof request.envelope !== 'string') throw new Error();
  const bytes = Buffer.from(request.envelope, 'base64');
  if (bytes.toString('base64') !== request.envelope) throw new Error();
  const result = await simulateSubmission(
    Uint8Array.from(bytes),
    request.responses, request.maxAttempts,
  );
  process.stdout.write(JSON.stringify(result));
} catch {
  process.stdout.write(JSON.stringify({ synthetic: true, state: 'refused', attempts: 0, code: 'invalid_request' }));
}
