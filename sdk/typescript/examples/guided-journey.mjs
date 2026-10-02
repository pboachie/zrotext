// SPDX-License-Identifier: AGPL-3.0-only
// Local fixture composition only. No network transport, credential input or radio.
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {AgentRecipe} from '../dist/agent-recipe.js';
import {FileRecipeStore, recipeScope, verifyFixtureReply} from './recipe-simulator.mjs';

export async function guidedJourney() {
  const root = await mkdtemp(join(tmpdir(), 'zrotext-guided-fixture-'));
  try {
    const fixture = JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/ztse-draft-01.json', import.meta.url), 'utf8'));
    const outbound = Uint8Array.from(Buffer.from(fixture.outbound.envelopeHex, 'hex'));
    const now = () => recipeScope.expiresAt - 60000;
    const store = name => new FileRecipeStore(join(root, name));
    const recipe = (name, clock = now) => new AgentRecipe(recipeScope, store(name), clock);
    const rows = [];
    const record = (step, result) => rows.push({step, ...result});
    const notification = recipe('journey');
    record('task_notification', await notification.taskCompletion('job_fixture', outbound));
    record('notification_replay', await recipe('journey').taskCompletion('job_fixture', outbound));
    const event = await verifyFixtureReply();
    record('verified_fixture_reply', await notification.verifiedReply(event));
    record('reply_replay_after_restart', await recipe('journey').verifiedReply(event));
    record('next_action_owner_review', await notification.ownerProposal(event.actionId));

    // This is identity conflict, not a claim that an owner has approved anything.
    const edited = Uint8Array.from(outbound);
    edited[edited.length - 65] ^= 1;
    record('edited_notification_identity', await notification.taskCompletion('job_fixture', edited));
    record('foreign_reply', await notification.verifiedReply({...event, eventId: 'foreign_fixture', lineId: 'foreign_fixture'}));
    const tampered = Uint8Array.from(Buffer.from(fixture.inbound.envelopeHex, 'hex'));
    tampered[tampered.length - 1] ^= 1;
    try {
      await verifyFixtureReply(tampered);
      throw new Error('tampered_fixture_accepted');
    } catch (error) {
      if (error.message === 'tampered_fixture_accepted') throw error;
      record('tampered_reply', {synthetic: true, available: false, state: 'signature_refused', content: 'unavailable', modelProviderAccess: 'none'});
    }
    record('unavailable_content', await recipe('missing_content').verifiedReply({...event, contentAvailable: false}));
    record('ambiguous_reply', await recipe('ambiguous').verifiedReply({...event, activeRequest: false}));
    record('opt_out', await notification.verifiedReply({...event, eventId: 'stop_fixture', kind: 'stop', contentAvailable: false}));
    record('notification_after_opt_out', await recipe('journey').taskCompletion('after_stop', outbound));
    await store('revoked').transact(async checkpoint => { checkpoint.revoked = true; });
    record('revoked_access', await recipe('revoked').taskCompletion('revoked_job', outbound));
    record('offline_expiry', await recipe('offline', () => recipeScope.expiresAt).taskCompletion('offline_job', outbound));
    record('unknown_submission', await recipe('unknown').taskCompletion('unknown_job', outbound, true));
    record('unknown_replay_after_restart', await recipe('unknown').taskCompletion('unknown_job', outbound));
    const checkpoint = async name => JSON.parse(await readFile(join(root, name, 'checkpoint.json'), 'utf8'));
    const main = await checkpoint('journey');
    const unknown = await checkpoint('unknown');
    return {
      synthetic: true, version: 1, mode: 'guided-local-fixture', available: false,
      transport: 'shared-synthetic-adapter', replyTrust: 'pinned-public-test-vector-only',
      ownerApproval: 'unavailable', radioSubmission: 'unavailable', carrierDelivery: 'unverified',
      modelProviderAccess: 'none', checkpointLifetime: 'one-command', steps: rows,
      accounting: {notificationIdentities: Object.keys(main.notifications).length,
        notificationAttempts: main.notifications.job_fixture.result.attempts,
        replyIdentities: Object.keys(main.events).length, replyTurns: main.turns,
        unknownIdentities: Object.keys(unknown.notifications).length,
        unknownAttempts: unknown.notifications.unknown_job.result.attempts}
    };
  } finally {
    // Only this invocation's mkdtemp directory, never a caller-supplied path.
    await rm(root, {recursive: true, force: true});
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  if (process.argv.length !== 2) {
    console.error('Synthetic journey refused: arguments are unavailable.');
    process.exitCode = 2;
  } else {
    try { console.log(JSON.stringify(await guidedJourney())); }
    catch { console.error('Synthetic journey unavailable.'); process.exitCode = 2; }
  }
}
