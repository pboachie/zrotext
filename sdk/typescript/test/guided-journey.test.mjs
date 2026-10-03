// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {spawnSync} from 'node:child_process';
import {mkdtemp, readdir, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {guidedJourney} from '../examples/guided-journey.mjs';

const expected = ['accepted', 'accepted', 'reply_routed_for_review', 'replayed',
  'awaiting_authenticated_exact_approval', 'action_identity_conflict', 'unverified_or_foreign_event',
  'signature_refused', 'content_unavailable', 'owner_review', 'metadata_only_stop', 'opted_out',
  'revoked', 'expired', 'unknown', 'unknown'];

test('guided composition verifies reply and preserves once-only identities across restart', async () => {
  const result = await guidedJourney();
  assert.deepEqual(result.steps.map(row => row.state), expected);
  assert.deepEqual(result.accounting, {notificationIdentities: 1, notificationAttempts: 1,
    replyIdentities: 2, replyTurns: 1, unknownIdentities: 1, unknownAttempts: 1});
  assert.ok(result.steps.every(row => row.synthetic === true && row.available === false && row.modelProviderAccess === 'none'));
  assert.equal(result.ownerApproval, 'unavailable');
  assert.equal(result.radioSubmission, 'unavailable');
  assert.equal(result.carrierDelivery, 'unverified');
});

test('supported guided command needs no configuration and removes its ephemeral checkpoint', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'zrotext-guided-command-test-'));
  t.after(() => rm(directory, {recursive: true, force: true}));
  const script = fileURLToPath(new URL('../../../scripts/agent_setup.py', import.meta.url));
  const fixture = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/ztse-draft-01.json', import.meta.url), 'utf8'));
  const environment = {...process.env, TEMP: directory, TMP: directory, TMPDIR: directory,
    ZROTEXT_WORKFLOW_CREDENTIAL_FILE: 'SYNTHETIC_MUST_NOT_OPEN', SEALED_WEBHOOK_DELIVERY_ENABLED: 'true',
    NODE_OPTIONS: '--invalid-synthetic-option'};
  const run = () => spawnSync('python', ['-B', script, 'journey'], {encoding: 'utf8', env: environment, timeout: 60000});
  const first = run();
  assert.equal(first.status, 0, first.stderr);
  assert.equal(first.stderr, '');
  const result = JSON.parse(first.stdout);
  assert.equal(result.mode, 'guided-local-fixture');
  assert.deepEqual(result.steps.map(row => row.state), expected);
  assert.match(result.nodeVersion, /^v\d+\./);
  assert.match(result.pythonVersion, /^3\./);
  assert.ok(result.elapsedSeconds >= 0);
  for (const secret of [fixture.archiveIkmHex, fixture.outbound.envelopeHex, fixture.inbound.envelopeHex,
    'SYNTHETIC_MUST_NOT_OPEN']) assert.equal(first.stdout.includes(secret), false);
  assert.deepEqual(await readdir(directory), []);
  const second = run();
  assert.equal(second.status, 0, second.stderr);
  assert.deepEqual(JSON.parse(second.stdout).steps, result.steps);
  assert.deepEqual(await readdir(directory), []);
  const refused = spawnSync('python', ['-B', script, 'journey', '--config', 'synthetic.json'],
    {encoding: 'utf8', env: environment, timeout: 60000});
  assert.equal(refused.status, 2);
  assert.equal(JSON.parse(refused.stdout).code, 'journey_configuration_unavailable');
  assert.deepEqual(await readdir(directory), []);
});
