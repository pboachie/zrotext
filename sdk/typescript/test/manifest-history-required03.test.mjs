// SPDX-License-Identifier: AGPL-3.0-only
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixture, key } from './manifest-history03-fixture.mjs';
import { startAcceptedManifestHistory03, continueAcceptedManifestHistory03, acceptedManifestHistoryRequiredCheckpoint03 } from '../dist/accepted-manifest-history03.js';
test('complete snapshot separately traverses saved highwater and an earlier original-attempt checkpoint inside a page', async () => {
  const f = await fixture(), signer = await key(); for (let i = 0; i < 19; i++) await f.step(signer);
  const required = f.rows[2].position, minimum = f.rows[15].position;
  let h = await startAcceptedManifestHistory03({ ...f.seed, minimum, required });
  h = await continueAcceptedManifestHistory03(h, f.page(0, 8)); assert.throws(() => acceptedManifestHistoryRequiredCheckpoint03(h));
  h = await continueAcceptedManifestHistory03(h, f.page(8, 16)); h = await continueAcceptedManifestHistory03(h, f.page(16, 19));
  const c = acceptedManifestHistoryRequiredCheckpoint03(h); assert.deepEqual(c.position, required); assert.equal(c.acceptedMs, f.rows[2].acceptedMs);
  c.position.digest.fill(0); c.signedManifest.fill(0); assert.deepEqual(acceptedManifestHistoryRequiredCheckpoint03(h).position, required);
});
test('wrong target prefix, missing target and rolled-back saved highwater refuse independently', async () => {
  const f = await fixture(), signer = await key(); for (let i = 0; i < 4; i++) await f.step(signer);
  for (const [minimum, required] of [[f.rows[3].position, { ...f.rows[1].position, ancestry: new Uint8Array(32).fill(1) }],
    [f.rows[3].position, { ...f.rows[3].position, version: 100n }],
    [{ ...f.rows[3].position, ancestry: new Uint8Array(32).fill(1) }, f.rows[1].position]]) {
    const h = await startAcceptedManifestHistory03({ ...f.seed, minimum, required }); await assert.rejects(continueAcceptedManifestHistory03(h, f.page()));
  }
});
