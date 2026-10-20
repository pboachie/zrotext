// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fixture, key, b64, frame, sign, sha, hash, num } from './manifest-history03-fixture.mjs';
import { manifestInstallSigningBytes03 } from '../dist/manifest-install03.js';
import { verifiedAcceptedElectionIdentity03 } from '../dist/payload-profile-election03.js';
import { startAcceptedManifestHistory03 as start, continueAcceptedManifestHistory03 as advance,
  acceptedManifestHistoryCursor03 as cursor, requireAcceptedManifestHistoryCurrent03 as current } from '../dist/accepted-manifest-history03.js';

test('genuine original election preserves exact full accepted enrollment renewal replacement through snapshot pages', async () => {
  const f = await fixture(), browser = await key();
  await f.step(browser); await f.step(browser, 2100001n); await f.step(await key());
  const initial = await start(f.seed), first = await advance(initial, f.page(0, 1));
  assert.equal(cursor(initial).after.version, 2n); assert.equal(cursor(first).complete, false);
  await assert.rejects(current(first, f.authority(), f.signed, f.prefix, f.acceptedMs + 100n));
  const last = await advance(first, f.page(1)); assert.equal(cursor(last).after.version, 5n); assert.equal(cursor(last).complete, true);
  await current(last, f.authority(), f.signed, f.prefix, f.acceptedMs + 100n);
  const exposed = cursor(last); exposed.after.digest.fill(0);
  assert.notDeepEqual(cursor(last).after.digest, exposed.after.digest);
  const a = verifiedAcceptedElectionIdentity03(f.proof); a.accountId.fill(0);
  assert.notDeepEqual(verifiedAcceptedElectionIdentity03(f.proof).accountId, a.accountId);
});

test('more than32 historical renewals remain usable through bounded8-entry pages without a lifetime quota', async () => {
  const f = await fixture(), browser = await key();
  for (let i = 0; i < 41; i++) await f.step(browser);
  let handle = await start(f.seed);
  for (let start = 0; start < 41; start += 8) handle = await advance(handle, f.page(start, Math.min(start + 8, 41)));
  assert.equal(cursor(handle).after.version, 43n); assert.equal(cursor(handle).complete, true);
  await current(handle, f.authority(), f.signed, f.prefix, f.acceptedMs + 100n);
});

test('no public projection or token supplies missing original election or original signed checkpoint', async () => {
  const f = await fixture();
  assert.throws(() => verifiedAcceptedElectionIdentity03({}));
  await assert.rejects(start({ ...f.seed, acceptedElection: {} }));
  await assert.rejects(start({ ...f.seed, firstManifest: {} }));
  await assert.rejects(start({ ...f.seed, originalEvidence: { ...f.evidence, accepted_ms: '10001' } }));
  const bad = Buffer.from(f.evidence.accepted_manifest03, 'base64url'); bad[bad.length - 1] ^= 1;
  await assert.rejects(start({ ...f.seed, originalEvidence: { ...f.evidence, accepted_manifest03: bad.toString('base64url') } }));
  await assert.rejects(start({ ...f.seed, origin: 'https://owner.invalid/path' }));
});

test('changed history signatures checkpoints prefix original evidence and whole snapshot refuse', async () => {
  const f = await fixture(), browser = await key(); await f.step(browser); await f.step(browser);
  const initial = await start(f.seed);
  for (const mutate of [
    p => p.entries[0].signature = b64(new Uint8Array(64).fill(1)),
    p => p.entries[0].accepted_ms = '1', p => p.entries[0].opening_id = p.line_id,
    p => p.evidence.activation_evidence = 'Ag', p => p.next_ancestry_sha256 = b64(new Uint8Array(32)),
    p => p.after_version = '1', p => p.tip_version = '3', p => p.tip_accepted_ms = '1',
    p => p.complete = false, p => p.entries.reverse(), p => p.entries[0].extra = true,
    p => p.password = 'synthetic', p => p.binding_generation = '8', p => p.compared_ms = '1',
  ]) { const page = f.page(); mutate(page); await assert.rejects(advance(initial, page)); }
  const first = await advance(initial, f.page(0, 1)), changed = f.page(1); changed.tip_ancestry_sha256 = b64(new Uint8Array(32).fill(3));
  await assert.rejects(advance(first, changed));
  const empty = f.page(0, 0); empty.complete = false;
  await assert.rejects(advance(initial, empty));
});

test('asynchronous history captures every candidate before crypto and rejects accessor shared or forged state', async () => {
  const f = await fixture(); await f.step(await key()); const initial = await start(f.seed);
  const page = f.page(), promise = advance(initial, page); page.entries[0].signature = 'AQ'; page.evidence.bundle = 'AQ';
  assert.equal(cursor(await promise).complete, true);
  const getter = f.page(); Object.defineProperty(getter.entries[0], 'statement', { enumerable: true, get() { throw Error('must not run'); } });
  await assert.rejects(advance(initial, getter));
  const list = f.page(); list.entries.push(list.entries[0]);
  await assert.rejects(advance(initial, list));
  await assert.rejects(advance({}, f.page()));
});

test('genuine new root and browser signatures cannot authorize an unrelated retained reader policy change', async () => {
  const f = await fixture(), browser = await key(); await f.step(browser); const initial = await start(f.seed), page = f.page(), row = page.entries[0];
  const received = Uint8Array.from(Buffer.from(row.successor_manifest03, 'base64url')), body = received.slice(0, -64);
  // A valid lifetime change to the existing archive record is outside the
  // deliberate role05-only policy even when the actual synthetic root signs it.
  new DataView(body.buffer).setBigUint64(153 + 149 + 132, 9001n);
  const signed = new Uint8Array([...body, ...await sign(f.root, frame('ZTSE/manifest/v3', body))]);
  const statement = Uint8Array.from(Buffer.from(row.statement, 'base64url')); statement.set(await sha(signed), 384);
  const signature = await sign(browser, await manifestInstallSigningBytes03(statement));
  const opening = Uint8Array.from(Buffer.from(row.opening_id.replaceAll('-', ''), 'hex'));
  const prefix = await hash('ZTSE/line/payload-profile/manifest-ancestry-step03/v1', f.firstPosition.ancestry, opening,
    await sha(statement), await sha(signature), await sha(signed), num(BigInt(row.accepted_ms)));
  row.statement = b64(statement); row.signature = b64(signature); row.successor_manifest03 = b64(signed);
  page.tip_digest = page.next_digest = b64(await sha(body)); page.tip_ancestry_sha256 = page.next_ancestry_sha256 = b64(prefix);
  await assert.rejects(advance(initial, page));
});

test('complete crypto still requires exact fresh separately selected current authority without rewriting old context', async () => {
  const f = await fixture(); await f.step(await key()); const handle = await advance(await start(f.seed), f.page()), now = f.acceptedMs + 100n;
  for (const c of [{ ...f.authority(), manifestVersion: 2n }, { ...f.authority(), bindingGeneration: 8n },
    { ...f.authority(), permissionExpiresAtMs: now }, { ...f.authority(), comparedAtMs: now + 1n }]) {
    await assert.rejects(current(handle, c, f.signed, f.prefix, now));
  }
  await assert.rejects(current(handle, f.authority(), f.signed, new Uint8Array(32), now));
  await assert.rejects(current(handle, f.authority(), f.signed, f.prefix, now - 1n));
  await current(handle, f.authority(), f.signed, f.prefix, now);
});
