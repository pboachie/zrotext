// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { OwnerProfileElectionClient03 } from '../dist/owner-profile-election-client.js';
import { decodeManifestInstall03, encodeManifestInstall03, manifestInstallSigningBytes03 } from '../dist/manifest-install03.js';
import { browserSignerKeyId02, canonicalSignature02 } from '../dist/draft02-manifest.js';

const v = JSON.parse(readFileSync(new URL('../../../protocol/v1/vectors/sealed-profile03-manifest-install-01.json', import.meta.url)));
const row = v.successors[0], bytes = hex => Uint8Array.from(Buffer.from(hex, 'hex'));
const b64 = hex => Buffer.from(hex, 'hex').toString('base64url');
const original = Object.freeze({ v: 1, origin: v.canonical_origin, account_id: v.account_id, user_id: v.user_id,
  owner_session_id: v.owner_session_id, device_id: v.device_id, root_fingerprint: b64(v.root_fingerprint_hex),
  opening_id: row.opening_id, line_id: v.line_id, statement: b64(row.statement_hex), signature: b64(row.signature_hex), successor_manifest03: b64(row.successor_signed_hex) });
const receipt = () => ({ v: 1, opening_id: row.opening_id, line_id: v.line_id, binding_id: v.binding_id,
  election_digest: b64(v.election_commitment_hex), statement: original.statement, signature: original.signature,
  successor_manifest03: original.successor_manifest03, accepted_ms: row.accepted_ms, predecessor_version: row.predecessor_version,
  predecessor_digest: b64(row.predecessor_semantic_sha256), successor_version: row.successor_version,
  successor_digest: b64(row.successor_semantic_sha256), operation: row.operation,
  predecessor_ancestry_sha256: b64(row.predecessor_ancestry_sha256_hex), ancestry_sha256: b64(row.ancestry_sha256_hex) });
const credentials = { password: 'example', factor: '123456' };
const response = (body = receipt(), status = 201) => new Response(JSON.stringify(body), { status, headers: {
  'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } });
function client(fetchImpl, extra = {}) {
  return new OwnerProfileElectionClient03({ origin: v.canonical_origin, accountId: v.account_id, userId: v.user_id,
    ownerSessionId: v.owner_session_id, deviceId: v.device_id, rootFingerprint: bytes(v.root_fingerprint_hex),
    currentCsrf: () => 'ztc_' + Buffer.alloc(32, 1).toString('base64url'), saveRecovery: async () => { throw Error('wrong recovery family'); },
    signal: new AbortController().signal, fetchImpl, ...extra });
}

test('actual signed manifest and possession are retained publicly before a single exact credentialed request', async () => {
  const order = [], c = client(async (url, options) => {
    order.push('http'); assert.equal(url, v.canonical_origin + '/v1/account/sealed/payload-profile/manifests');
    assert.equal(options.credentials, 'same-origin'); assert.equal(options.redirect, 'error');
    assert.deepEqual(JSON.parse(options.body), { v: 1, opening_id: original.opening_id, statement: original.statement,
      signature: original.signature, successor_manifest03: original.successor_manifest03, ...credentials });
    return response();
  });
  try {
    assert.deepEqual(await c.installManifest(original, credentials, async record => {
      order.push('saved'); assert.deepEqual(record, original); assert.equal('password' in record, false); assert.equal('factor' in record, false);
    }), receipt());
    assert.deepEqual(order, ['saved', 'http']);
  } finally { c.close(); }
});

test('failed durable publication has zero HTTP and no factor transmission', async () => {
  let requests = 0; const c = client(async () => { requests++; return response(); });
  await assert.rejects(c.installManifest(original, credentials, async () => { throw Error('synthetic storage failure'); }));
  assert.equal(requests, 0); c.close();
});

test('unknown mutation preserves exact proof and fresh same-user sign-in only observes original history', async () => {
  let sent, saved;
  const first = client(async (_, options) => { sent = JSON.parse(options.body); throw Error('synthetic reply loss'); });
  await assert.rejects(first.installManifest(original, credentials, async record => { saved = record; }), error => error.outcome === 'unknown');
  assert.deepEqual(saved, original); assert.equal(sent.signature, original.signature); first.close();
  let requests = 0;
  const fresh = client(async (url, options) => {
    requests++; assert.ok(url.endsWith('/manifests/status')); const body = JSON.parse(options.body);
    assert.equal('password' in body, false); assert.equal('factor' in body, false); assert.equal('statement' in body, false);
    return response(receipt(), 200);
  }, { ownerSessionId: '00000000-0000-0000-0000-000000000099' });
  try {
    assert.deepEqual(await fresh.manifestStatus(saved), receipt());
    await assert.rejects(fresh.installManifest(saved, credentials, async () => {})); assert.equal(requests, 1);
  } finally { fresh.close(); }
});

test('not-found observation cannot prove a prior mutation was not accepted', async () => {
  const c = client(async () => response({ error: 'not_found' }, 404));
  try { await assert.rejects(c.manifestStatus(original), error => error.outcome === 'unknown'); } finally { c.close(); }
});

test('wrong scope extra secrets forged root or possession have zero storage and HTTP', async () => {
  for (const change of [{ line_id: v.account_id }, { password: 'example' },
    { signature: Buffer.alloc(64, 1).toString('base64url') }, { successor_manifest03: original.successor_manifest03.slice(0, -1) + 'A' }]) {
    let requests = 0, writes = 0; const c = client(async () => { requests++; return response(); });
    await assert.rejects(c.installManifest({ ...original, ...change }, credentials, async () => { writes++; }));
    assert.equal(requests, 0); assert.equal(writes, 0); c.close();
  }
});

test('changed original proof acceptance time or exact prefix is unknown after an HTTP mutation', async () => {
  for (const change of [{ signature: Buffer.alloc(64, 1).toString('base64url') }, { accepted_ms: row.expires_ms },
    { ancestry_sha256: Buffer.alloc(32, 1).toString('base64url') }, { predecessor_version: '1' }]) {
    const c = client(async () => response({ ...receipt(), ...change }));
    try { await assert.rejects(c.installManifest(original, credentials, async () => {}), error => error.outcome === 'unknown'); }
    finally { c.close(); }
  }
});

test('fixed operation deadline bounds a hung public storage callback before HTTP', async () => {
  let requests = 0, release;
  const waiting = new Promise(resolve => { release = resolve; });
  const c = client(async () => { requests++; return response(); }, { timeoutMs: 30 });
  try {
    await assert.rejects(c.installManifest(original, credentials, async () => waiting));
    assert.equal(requests, 0); release();
  } finally { c.close(); }
});

test('closed503 mutation is UNKNOWN with no automatic retry', async () => {
  let requests = 0; const c = client(async () => { requests++; return response({ error: 'temporarily_unavailable' }, 503); });
  try { await assert.rejects(c.installManifest(original, credentials, async () => {}), error => error.outcome === 'unknown' && error.code === 'temporarily_unavailable'); assert.equal(requests, 1); }
  finally { c.close(); }
});

test('genuine possession of another message key cannot replace the actual root-signed role5 record', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const point = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const s = await decodeManifestInstall03(bytes(row.statement_hex));
  const statement = await encodeManifestInstall03({ ...s, signerPoint: point, signerKeyId: await browserSignerKeyId02(point) });
  const signature = canonicalSignature02(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, await manifestInstallSigningBytes03(statement))));
  let requests = 0, writes = 0; const c = client(async () => { requests++; return response(); });
  try {
    await assert.rejects(c.installManifest({ ...original, statement: Buffer.from(statement).toString('base64url'), signature: Buffer.from(signature).toString('base64url') }, credentials, async () => { writes++; }));
    assert.equal(requests, 0); assert.equal(writes, 0);
  } finally { c.close(); }
});

test('deadline and close settle stalled crypto preparation without late recovery or HTTP', async () => {
  const real = crypto.subtle.verify.bind(crypto.subtle); let release;
  const held = new Promise(resolve => { release = resolve; });
  crypto.subtle.verify = async (...args) => { await held; return real(...args); };
  let requests = 0, writes = 0; const c = client(async () => { requests++; return response(); }, { timeoutMs: 30 });
  try {
    await assert.rejects(c.installManifest(original, credentials, async () => { writes++; }));
    assert.equal(requests, 0); assert.equal(writes, 0); release();
    await assert.rejects(c.manifestStatus(original));
  } finally { crypto.subtle.verify = real; release(); c.close(); }
});
