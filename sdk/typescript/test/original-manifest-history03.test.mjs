// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, key, b64, text } from './manifest-history03-fixture.mjs';
import { verifyOriginalManifestHistory03 as original } from '../dist/original-manifest-history03.js';
import { startAcceptedManifestHistory03 as start, continueAcceptedManifestHistory03 as next,
  acceptedManifestHistoryCheckpoint03 as checkpoint, acceptedManifestHistoryCursor03 as cursor } from '../dist/accepted-manifest-history03.js';
const candidate = f => ({ v: 1, kind: 'manifest_original03', line_id: text(f.line), binding_id: text(f.binding), evidence: f.evidence });
test('actual original registration activation and election rebuild historical seed after later setup expiry', async () => {
  const f = await fixture({ originalProofs: true });
  // The original signed manifest ends at2000000; a later explicit root-approved
  // enrollment is accepted after that historical window has elapsed.
  await f.step(await key(), 2050000n);
  const result = await original(candidate(f), f.compared);
  assert.equal(result.originalUserHex, Buffer.from(f.user).toString('hex'));
  const history = await next(await start(result.seed), f.page());
  assert.equal(cursor(history).complete, true); assert.equal(checkpoint(history).acceptedMs, f.acceptedMs);
  assert.equal(Object.hasOwn(result, 'currentAuthority'), false);
  assert.equal(Object.hasOwn(result, 'physical_selection'), false);
});
test('independent checkpoint phone root origin and original signature changes refuse before history', async () => {
  const f = await fixture({ originalProofs: true });
  for (const name of ['rootFingerprint', 'pairedSigningPoint', 'priorDigest', 'accountId', 'deviceId', 'lineId']) {
    const selected = structuredClone(f.compared); selected[name][1] ^= 1; await assert.rejects(original(candidate(f), selected));
  }
  await assert.rejects(original(candidate(f), { ...f.compared, priorVersion: 2n }));
  await assert.rejects(original(candidate(f), { ...f.compared, origin: 'https://other.invalid' }));
  for (const name of ['registration_evidence', 'activation_evidence', 'bundle', 'accepted_manifest03']) {
    const c = structuredClone(candidate(f)), bytes = Uint8Array.from(Buffer.from(c.evidence[name], 'base64url')); bytes[bytes.length - 4] ^= 1;
    c.evidence[name] = b64(bytes); await assert.rejects(original(c, f.compared));
  }
});
test('retained middle checkpoint is proven through later full history and refuses rollback or prefix fork', async () => {
  const f = await fixture({ originalProofs: true }), browser = await key();
  for (let i = 0; i < 11; i++) await f.step(browser);
  const result = await original(candidate(f), f.compared), minimum = f.rows[2].position;
  let h = await start({ ...result.seed, minimum });
  h = await next(h, f.page(0, 8)); h = await next(h, f.page(8, 11));
  assert.equal(cursor(h).complete, true); assert.equal(checkpoint(h).position.version, f.version);
  const bad = { ...minimum, ancestry: minimum.ancestry.slice() }; bad.ancestry[0] ^= 1;
  await assert.rejects(next(await start({ ...result.seed, minimum: bad }), f.page(0, 8)));
  await assert.rejects(next(await start({ ...result.seed, minimum: { ...minimum, version: 99n } }), f.page(0, 8)).then(v => next(v, f.page(8, 11))));
});
test('captured comparison and checkpoint arrays cannot mutate an asynchronous verification', async () => {
  const f = await fixture({ originalProofs: true }), c = candidate(f), selected = structuredClone(f.compared);
  const pending = original(c, selected); selected.rootFingerprint.fill(0); c.evidence = {};
  const result = await pending, h = await start(result.seed), before = checkpoint(h);
  before.position.digest.fill(0); before.signedManifest.fill(0);
  assert.notEqual(b64(checkpoint(h).position.digest), b64(before.position.digest));
});
