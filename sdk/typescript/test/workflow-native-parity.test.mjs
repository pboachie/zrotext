// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import { workflowTools, workflowReadinessSchema, matchesSchema, validateWorkflowRequest } from '../dist/workflow-tools.js';
import { workflowActionDigest } from '../dist/workflow-decisions.js';
globalThis.crypto ??= webcrypto;
const pythonRoot = fileURLToPath(new URL('../../python/', import.meta.url));
function python(source, input) {
  const result = spawnSync(process.platform === 'win32' ? 'python' : 'python3', ['-I', '-B', '-c',
    'import sys,json\nsys.path.insert(0,sys.argv[1])\nimport workflow_validation as v\n' + source, pythonRoot],
  { input: JSON.stringify(input), encoding: 'utf8', maxBuffer: 2 * 1024 * 1024 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}
function sample(schema) {
  if (schema.anyOf) return sample(schema.anyOf[0]);
  if (schema.enum) return schema.enum[0];
  if (schema.type === 'object') return Object.fromEntries(Object.entries(schema.properties).map(([key, item]) => [key, sample(item)]));
  if (schema.type === 'integer') return schema.minimum ?? 0;
  if (schema.type === 'null') return null;
  if (schema.type === 'boolean') return false;
  if (schema.minLength === 36) return '10000000-0000-4000-8000-000000000001';
  if (schema.minLength === 64) return 'ab'.repeat(32);
  if (schema.minLength === 10) return '2027-01-01';
  return 'UTC';
}
test('checked Python contract exactly matches executable TypeScript schemas and annotations', async () => {
  const checked = JSON.parse(await readFile(new URL('../../python/workflow_contract.json', import.meta.url)));
  assert.deepEqual(checked, { tools: workflowTools, readiness: workflowReadinessSchema });
});
test('native request and schema verdicts match TypeScript across every tool and malformed field', () => {
  const cases = [];
  for (const tool of workflowTools) {
    for (const [direction, schema] of [['request', tool.inputSchema], ['response', tool.outputSchema]]) {
      const valid = sample(schema);
      const candidates = [valid, null, [], true, 1, 'unexpected', { ...valid, unrecognized: true }];
      for (const key of Object.keys(valid)) {
        const missing = structuredClone(valid); delete missing[key]; candidates.push(missing);
        for (const value of [null, [], true, 1.5, 2 ** 53, {}, '\uD800', 'a\n']) candidates.push({ ...valid, [key]: value });
      }
      for (const value of candidates) {
        let expected;
        if (direction === 'request') { try { validateWorkflowRequest(tool.name, value); expected = true; } catch { expected = false; } }
        else expected = matchesSchema(schema, value);
        cases.push({ method: tool.name, direction, value, expected });
      }
    }
  }
  const actual = python(`out=[]
for item in json.load(sys.stdin):
 try:
  if item['direction']=='request': v.request(item['method'],item['value']); accepted=True
  else: accepted=v.matches(v.TOOLS[item['method']]['outputSchema'],item['value'])
 except (ValueError,TypeError,KeyError,OverflowError): accepted=False
 out.append(accepted)
print(json.dumps(out))`, cases);
  assert.deepEqual(actual, cases.map(item => item.expected));
});
test('native canonical digest preserves every ASCII escape and shared action mutations', async () => {
  const vector = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/workflow-action-01.json', import.meta.url)));
  const values = [vector.action, ...Object.entries(vector.field_edits).map(([key, value]) => ({ ...vector.action, [key]: value })),
    ...Array.from({ length: 128 }, (_, code) => ({ ...vector.action, window_id: 'a' + String.fromCharCode(code) }))];
  const expected = await Promise.all(values.map(workflowActionDigest));
  const actual = python('print(json.dumps([v.action_digest(item) for item in json.load(sys.stdin)]))', values);
  assert.deepEqual(actual, expected);
});
