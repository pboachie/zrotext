// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { test } from 'node:test';
import 'fake-indexeddb/auto';
import { SealedApprovalKeyStore } from '../dist/sealed-approval-key-store.js';

const origin = 'https://owner.example';
const scope = Object.freeze({ origin, accountId: '11111111-1111-4111-8111-111111111111',
  originalUserId: '22222222-2222-4222-8222-222222222222', deviceId: '33333333-3333-4333-8333-333333333333',
  lineId: '44444444-4444-4444-8444-444444444444', rootFingerprint: 'ab'.repeat(32) });
const consent = { retain: true, newRegistration: true };
const options = () => ({ name: `sealed-approval-${randomUUID()}`, currentOrigin: () => origin });
const bytes = value => Uint8Array.from(Buffer.from(value, 'hex'));
async function raw(name, run) {
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
  });
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction('sealed-line-approval-v1', 'readwrite'); let result;
      run(tx.objectStore('sealed-line-approval-v1'), value => { result = value; });
      tx.oncomplete = () => resolve(result); tx.onabort = () => reject(tx.error);
    });
  } finally { db.close(); }
}
const storageKey = input => JSON.stringify(['origin', 'accountId', 'originalUserId', 'deviceId', 'lineId', 'rootFingerprint'].map(k => input[k]));

test('a committed nonextractable key survives closing and verifies against its original public point', async () => {
  const selected = options(), first = await SealedApprovalKeyStore.open(selected);
  const created = await first.create(scope, consent); first.close();
  const second = await SealedApprovalKeyStore.open(selected);
  try {
    assert.deepEqual(await second.metadata(scope), created);
    const lease = await second.load(scope, created.fingerprint);
    const message = new TextEncoder().encode('synthetic possession test');
    const signature = await lease.withKey(scope, created.fingerprint, async key => {
      assert.equal(key.extractable, false);
      await assert.rejects(crypto.subtle.exportKey('pkcs8', key));
      return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, message);
    });
    const publicKey = await crypto.subtle.importKey('raw', bytes(created.publicPoint), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    assert.equal(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, message), true);
    assert.equal('sessionId' in created.scope, false);
    lease.close();
    await assert.rejects(lease.withKey(scope, created.fingerprint, async () => true));
  } finally { second.close(); }
});

test('explicit new-registration retention consent is required and an existing key cannot be overwritten', async () => {
  const store = await SealedApprovalKeyStore.open(options());
  try {
    for (const bad of [{}, { retain: true }, { retain: false, newRegistration: true }, { retain: true, newRegistration: false }]) {
      await assert.rejects(store.create(scope, bad));
    }
    assert.equal(await store.metadata(scope), null);
    const original = await store.create(scope, consent);
    await assert.rejects(store.create(scope, consent));
    assert.deepEqual(await store.metadata(scope), original);
  } finally { store.close(); }
});

test('concurrent first creation has one durable winner and no overwrite', async () => {
  const selected = options(), first = await SealedApprovalKeyStore.open(selected), second = await SealedApprovalKeyStore.open(selected);
  try {
    const outcomes = await Promise.allSettled([first.create(scope, consent), second.create(scope, consent)]);
    assert.equal(outcomes.filter(x => x.status === 'fulfilled').length, 1);
    const winner = outcomes.find(x => x.status === 'fulfilled').value;
    assert.deepEqual(await first.metadata(scope), winner); assert.deepEqual(await second.metadata(scope), winner);
  } finally { first.close(); second.close(); }
});

test('missing and substituted scopes or fingerprints refuse without generating a replacement', async () => {
  const store = await SealedApprovalKeyStore.open(options());
  try {
    await assert.rejects(store.load(scope, 'cd'.repeat(32)));
    assert.equal(await store.metadata(scope), null);
    const original = await store.create(scope, consent);
    for (const field of ['accountId', 'originalUserId', 'deviceId', 'lineId']) {
      const changed = { ...scope, [field]: '55555555-5555-4555-8555-555555555555' };
      await assert.rejects(store.load(changed, original.fingerprint));
      assert.equal(await store.metadata(changed), null);
    }
    await assert.rejects(store.load({ ...scope, rootFingerprint: 'cd'.repeat(32) }, original.fingerprint));
    await assert.rejects(store.load(scope, 'cd'.repeat(32)));
    const lease = await store.load(scope, original.fingerprint); let called = false;
    await assert.rejects(lease.withKey({ ...scope, lineId: '55555555-5555-4555-8555-555555555555' }, original.fingerprint, async () => { called = true; }));
    assert.equal(called, false);
  } finally { store.close(); }
});

test('abort after add request success never publishes an uncommitted key', async () => {
  const selected = options(), store = await SealedApprovalKeyStore.open(selected), originalAdd = IDBObjectStore.prototype.add;
  let requestSucceeded = false;
  try {
    IDBObjectStore.prototype.add = function (...args) {
      const request = originalAdd.apply(this, args);
      request.addEventListener('success', () => { requestSucceeded = true; request.transaction.abort(); }, { once: true });
      return request;
    };
    await assert.rejects(store.create(scope, consent)); assert.equal(requestSucceeded, true);
    assert.equal(await store.metadata(scope), null);
  } finally { IDBObjectStore.prototype.add = originalAdd; store.close(); }
});

test('a different genuine private key cannot stand in for the retained public point', async () => {
  const selected = options(), store = await SealedApprovalKeyStore.open(selected);
  try {
    const original = await store.create(scope, consent);
    const different = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    await raw(selected.name, objectStore => {
      const get = objectStore.get(storageKey(scope)); get.onsuccess = () => objectStore.put({ ...get.result, privateKey: different.privateKey }, storageKey(scope));
    });
    await assert.rejects(store.load(scope, original.fingerprint));
    await assert.rejects(store.create(scope, consent));
  } finally { store.close(); }
});

test('extractable keys, altered scope and unknown stored schema refuse', async () => {
  for (const mutation of ['extractable', 'scope', 'schema']) {
    const selected = options(), store = await SealedApprovalKeyStore.open(selected);
    try {
      const original = await store.create(scope, consent);
      const extractable = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      await raw(selected.name, objectStore => {
        const get = objectStore.get(storageKey(scope));
        get.onsuccess = () => objectStore.put({ ...get.result, ...(mutation === 'extractable' ? { privateKey: extractable.privateKey }
          : mutation === 'scope' ? { scope: { ...scope, rootFingerprint: 'cd'.repeat(32) } } : { schema: 2 }) }, storageKey(scope));
      });
      await assert.rejects(store.load(scope, original.fingerprint)); await assert.rejects(store.create(scope, consent));
    } finally { store.close(); }
  }
});

test('closing during key use suppresses its late result and releases the lease', async () => {
  const store = await SealedApprovalKeyStore.open(options());
  const original = await store.create(scope, consent), lease = await store.load(scope, original.fingerprint);
  let release; const wait = new Promise(resolve => { release = resolve; });
  const pending = lease.withKey(scope, original.fingerprint, async () => { await wait; return 'late'; });
  store.close(); release(); await assert.rejects(pending);
});

test('an origin change or lifetime abort refuses subsequent key use', async () => {
  for (const change of ['origin', 'abort']) {
    let current = origin; const signal = new AbortController();
    const store = await SealedApprovalKeyStore.open({ ...options(), currentOrigin: () => current, signal: signal.signal });
    try {
      const original = await store.create(scope, consent), lease = await store.load(scope, original.fingerprint);
      if (change === 'origin') current = 'https://other.example'; else signal.abort();
      let called = false;
      await assert.rejects(lease.withKey(scope, original.fingerprint, async () => { called = true; })); assert.equal(called, false);
    } finally { store.close(); }
  }
});

test('capacity exhaustion retains every existing record and refuses a new key', async () => {
  const selected = options(), store = await SealedApprovalKeyStore.open(selected);
  try {
    const original = await store.create(scope, consent);
    await raw(selected.name, objectStore => {
      for (let i = 1; i < 128; i++) objectStore.add({ occupied: true }, `synthetic-occupied-${i}`);
    });
    await assert.rejects(store.create({ ...scope, lineId: '55555555-5555-4555-8555-555555555555' }, consent));
    assert.deepEqual(await store.metadata(scope), original);
  } finally { store.close(); }
});

test('scope getters, extra fields and noncanonical identities are refused before storage', async () => {
  const store = await SealedApprovalKeyStore.open(options()); let calls = 0;
  try {
    await assert.rejects(store.metadata({ ...scope, get lineId() { calls++; return scope.lineId; } }));
    assert.equal(calls, 0);
    for (const changed of [{ ...scope, sessionId: randomUUID() }, { ...scope, origin: origin + '/' }, { ...scope, rootFingerprint: 'AB'.repeat(32) },
      { ...scope, deviceId: '00000000-0000-0000-0000-000000000000' }]) await assert.rejects(store.metadata(changed));
  } finally { store.close(); }
});
