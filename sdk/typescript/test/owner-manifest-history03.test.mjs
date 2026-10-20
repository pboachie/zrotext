// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fixture, key, b64, text } from './manifest-history03-fixture.mjs';
import { startAcceptedManifestHistory03 as start, acceptedManifestHistoryCursor03 as cursor,
  OwnerManifestHistoryClient03 as Client } from '../dist/accepted-manifest-history03.js';
const csrf = 'ztc_' + b64(new Uint8Array(32));
const response = v => new Response(typeof v === 'string' ? v : JSON.stringify(v), { headers: { 'content-type': 'application/json' } });
function client(f, fetchImpl, extra = {}) {
  return new Client({ origin: f.origin, accountId: text(f.account), userId: text(f.user), ownerSessionId: text(f.session),
    currentCsrf: () => csrf, signal: new AbortController().signal, fetchImpl, ...extra });
}

test('actual fixed transport reads exact cursor then genuine complete current with cookie CSRF and separate newkind', async () => {
  const f = await fixture(), k = await key(); await f.step(k); await f.step(k);
  const calls = [], wire = await f.wireCurrent();
  const c = client(f, async (url, options) => { calls.push({ url, options }); return response(url.endsWith('/history') ? f.page() : wire); });
  const initial = await start(f.seed), complete = await c.next(initial), result = await c.current(complete, () => f.acceptedMs + 100n);
  assert.equal(cursor(complete).complete, true); assert.equal(result.currentAuthority.manifestVersion, 4n);
  assert.equal(calls.length, 2); assert.equal(calls[0].url, f.origin + '/v1/account/sealed/payload-profile/manifests/history');
  assert.equal(calls[1].url.endsWith('/manifests/current'), true);
  const body = JSON.parse(calls[0].options.body); assert.equal(body.tip_version, null); assert.equal(body.tip_ancestry_sha256, null); assert.equal(body.after_version, '2');
  for (const { options } of calls) {
    assert.equal(options.method, 'POST'); assert.equal(options.credentials, 'same-origin'); assert.equal(options.redirect, 'error');
    assert.equal(options.cache, 'no-store'); assert.equal(options.headers['x-zrotext-csrf'], csrf);
    assert.equal(Object.hasOwn(JSON.parse(options.body), 'password'), false);
  }
});

test('snapshot page2 uses exact fixedtip and never retries a failed changed or undecodable read', async () => {
  const f = await fixture(), k = await key(); await f.step(k); await f.step(k);
  let calls = 0, secondBody;
  const c = client(f, async (_, options) => { calls++; if (calls === 1) return response(f.page(0, 1)); secondBody = JSON.parse(options.body); return response({ ...f.page(1), tip_version: '9' }); });
  const one = await c.next(await start(f.seed)); await assert.rejects(c.next(one));
  assert.equal(calls, 2); assert.equal(secondBody.tip_version, '4'); assert.equal(secondBody.after_version, '3'); assert.equal(typeof secondBody.tip_ancestry_sha256, 'string');
  for (const raw of ['{"v":1,"v":1}', '{"v":1,"\\u0076":1}', '[{}]', '{"__proto__":{}}', '{"v":1.0}', ' '.repeat(192 * 1024 + 1)]) {
    let attempts = 0; const malformed = client(f, async () => { attempts++; return response(raw); });
    await assert.rejects(malformed.next(await start(f.seed))); assert.equal(attempts, 1);
  }
});

test('current rejects altered actual actor oldparserkind evidence key identity and prefix without granting a context', async () => {
  const f = await fixture(); await f.step(await key()); const wire = await f.wireCurrent();
  for (const change of [{ kind: 'owner_selection03' }, { user_id: text(f.account) }, { owner_session_id: text(f.device) },
    { device_signing_key_id: b64(new Uint8Array(32).fill(3)) }, { manifest_ancestry_sha256: b64(new Uint8Array(32)) },
    { evidence: { ...wire.evidence, activation_evidence: 'Ag' } }, { physical_selection: { kind: 'original_v2', approved: true } },
    { compared_ms: '1' }, { permission_expires_ms: String(f.acceptedMs) }, { manifest_version: '2' }, { extra: true }]) {
    const c = client(f, async url => response(url.endsWith('/history') ? f.page() : { ...wire, ...change }));
    const complete = await c.next(await start(f.seed)); await assert.rejects(c.current(complete, () => f.acceptedMs + 100n));
  }
});

test('abort CSRF replacement deadline and parallel read refuse with no hidden retry or permanent mutation', async () => {
  const f = await fixture(); await f.step(await key()); const seed = await start(f.seed);
  let currentCsrf = csrf, calls = 0;
  const c = client(f, async () => { calls++; currentCsrf = 'ztc_' + b64(new Uint8Array(32).fill(1)); return response(f.page()); }, { currentCsrf: () => currentCsrf });
  await assert.rejects(c.next(seed)); assert.equal(calls, 1);
  const abort = new AbortController(); abort.abort();
  assert.throws(() => client(f, async () => response(f.page()), { signal: abort.signal }));
  let release; const pending = client(f, async () => { await new Promise(resolve => { release = resolve; }); return response(f.page()); });
  const first = pending.next(seed); await assert.rejects(pending.next(seed)); release(); await first;
  const timeout = client(f, async () => new Promise(() => {}), { timeoutMs: 10 });
  await assert.rejects(timeout.next(seed));
});

test('expiry and clock regression during the final actual cryptographic wait cannot release current authority', async () => {
  const f = await fixture(); await f.step(await key()); const wire = await f.wireCurrent();
  for (const jump of [BigInt(wire.permission_expires_ms), f.acceptedMs + 99n]) {
    let now = f.acceptedMs + 100n, verifies = 0;
    const c = client(f, async url => response(url.endsWith('/history') ? f.page() : wire));
    const complete = await c.next(await start(f.seed)), original = crypto.subtle.verify;
    crypto.subtle.verify = async (...args) => {
      const result = await Reflect.apply(original, crypto.subtle, args);
      if (++verifies === 2) now = jump;
      return result;
    };
    try { await assert.rejects(c.current(complete, () => now)); assert.equal(verifies, 2); }
    finally { crypto.subtle.verify = original; }
  }
});

test('a later successful current clock is retained across explicit reads and cannot regress to the earlier observation', async () => {
  const f = await fixture(); await f.step(await key()); const wire = await f.wireCurrent();
  const c = client(f, async url => response(url.endsWith('/history') ? f.page() : wire)), complete = await c.next(await start(f.seed));
  let samples = 0;
  await c.current(complete, () => f.acceptedMs + (++samples === 4 ? 200n : 100n));
  await assert.rejects(c.current(complete, () => f.acceptedMs + 150n));
});
