import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { agentReadiness, simulateSubmission } from '../dist/agent-adapter.js';
globalThis.crypto ??= webcrypto;
const fixture = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/ztse-draft-01.json', import.meta.url)));
const outbound = Uint8Array.from(Buffer.from(fixture.outbound.envelopeHex, 'hex'));
const accepted = { status: 202, body: { message_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', created: true } };
test('readiness cannot activate sending', () => {
  assert.deepEqual(agentReadiness(), { synthetic: true, available: false, code: 'unavailable' });
});
test('bounded retry preserves both caller snapshots', async () => {
  const bytes = Uint8Array.from(outbound);
  const responses = [{ status: 429, body: { code: 'rate_limited' } }, structuredClone(accepted)];
  const result = simulateSubmission(bytes, responses, 2);
  bytes.fill(0);
  responses[1].body.message_id = 'edited';
  assert.deepEqual(await result, { synthetic: true, state: 'accepted', attempts: 2,
    messageId: accepted.body.message_id, created: true });
});
test('ambiguous disconnect and malformed replies stop without retry', async () => {
  for (const reply of ['disconnect', { status: 202, body: { message_id: 'bad', created: true } },
    { status: 403, body: { code: 'forbidden', content: 'untrusted' } }]) {
    assert.deepEqual(await simulateSubmission(outbound, [reply, accepted], 2),
      { synthetic: true, state: 'unknown', attempts: 1, code: 'submission_unknown' });
  }
});
test('policy refusal never retries or claims acceptance', async () => {
  assert.deepEqual(await simulateSubmission(outbound, [{ status: 403, body: { code: 'forbidden' } }, accepted], 2),
    { synthetic: true, state: 'refused', attempts: 1, code: 'forbidden' });
});
test('invalid envelopes and excessive retry bounds are rejected locally', async () => {
  const inbound = Uint8Array.from(Buffer.from(fixture.inbound.envelopeHex, 'hex'));
  for (const bytes of [new Uint8Array(), inbound, 'plaintext']) {
    assert.equal((await simulateSubmission(bytes, [accepted])).attempts, 0);
  }
  for (const cap of [0, 4, true, 1.5]) {
    assert.equal((await simulateSubmission(outbound, [accepted], cap)).code, 'invalid_request');
  }
});
test('Python wrapper shares vector acceptance, refusal and unknown handling', () => {
  const code = `import sys,json\nsys.path.insert(0,sys.argv[1])\nfrom agent_simulator import simulate_submission\nr=json.load(sys.stdin)\nprint(json.dumps(simulate_submission(bytes.fromhex(r['hex']),r['responses'],2)))`;
  for (const responses of [[accepted], ['disconnect', accepted], [{ status: 403, body: { code: 'forbidden' } }]]) {
    const run = spawnSync('python', ['-B', '-c', code, fileURLToPath(new URL('../../python/', import.meta.url))],
      { input: JSON.stringify({ hex: fixture.outbound.envelopeHex, responses }), encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
    const output = JSON.parse(run.stdout);
    assert.equal(output.synthetic, true);
    assert.equal(output.attempts, 1);
    assert.equal(output.state, responses[0] === 'disconnect' ? 'unknown' : responses[0].status === 403 ? 'refused' : 'accepted');
  }
});
test('Python rejects invalid bounds and never exposes local failure details', () => {
  const code = `import sys\nsys.path.insert(0,sys.argv[1])\nfrom agent_simulator import simulate_submission,AdapterError\nfor args in [(b'',[],True),(b'',[],4),(b'x'*36865,[],1),('plaintext',[],1),(b'',list(range(4)),1),(b'',[object()],1)]:\n try:\n  simulate_submission(*args)\n  raise AssertionError('accepted invalid input')\n except AdapterError as error:\n  assert str(error) in ('invalid_request','adapter_unavailable')`;
  const run = spawnSync('python', ['-B', '-c', code, fileURLToPath(new URL('../../python/', import.meta.url))], { encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
});
