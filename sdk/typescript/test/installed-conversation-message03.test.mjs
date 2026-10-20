// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { captureConversationContext03, encodeConversationStatement03, prepareInstalledConversationMessage03 } from '../dist/conversation-interval03.js';
import { preparedOutboundEnvelopeSnapshot03, completeSealedOutboundEnvelope03 } from '../dist/sealed-envelope03.js';
import { prepareReviewedIntent03V2, reviewedIntentTranscript03V2, verifyReviewedIntent03V2, verifiedReviewedIntentSnapshot03V2 } from '../dist/reviewed-intent03.js';
import { fixture, uuid, clone, enc, frame, sha, sign, join, present, canonicalP256Signature, verifyAndOpen } from './fixtures/profile03-outbound-fixture.mjs';

const digest = n => new Uint8Array(32).fill(n);
async function setup() {
  const f = await fixture(), a = clone(f.authority), c = { currentAuthority: a, acceptedElection: f.proof, manifest: f.currentManifest,
    selectionEpoch: 1n, ownerUserId: uuid(140), ownerSessionId: uuid(160), canonicalOrigin: 'https://example.test',
    deviceSessionDigest: digest(11), physicalSelectionDigest: digest(12), archiveReaderKeyId: f.records[1].id.slice(),
    phoneSignerKeyId: f.records[3].id.slice(), browserSignerKeyId: f.records[4].id.slice(), ownerDeadlineMs: 90000n,
    peer: enc.encode('+12'), integrationReaders: [{ connectorId: uuid(180), readGrantId: uuid(200), keyId: f.records[2].id.slice() }], nowMs: present };
  const s = { accountId: a.accountId, deviceId: a.deviceId, lineId: a.lineId, bindingId: a.bindingId,
    intervalId: uuid(81), receiptId: uuid(82), ownerUserId: c.ownerUserId, ownerSessionId: c.ownerSessionId, openingId: uuid(83),
    bindingGeneration: a.bindingGeneration, vaultGeneration: a.vaultGeneration, manifestVersion: a.manifestVersion, selectionEpoch: 1n,
    issuedMs: present, setupExpiresMs: 50000n, intervalFromMs: present, intervalUntilMs: 80000n,
    selectedReaderKeyId: a.selectedReaderKeyId, archiveReaderKeyId: c.archiveReaderKeyId, phoneSignerKeyId: c.phoneSignerKeyId,
    browserSignerKeyId: c.browserSignerKeyId, rootFingerprint: a.rootFingerprint, manifestDigest: a.manifestDigest,
    electionCommitment: a.electionCommitment, electionBundleSha256: a.electionBundleSha256,
    ownerSessionDigest: await sha(frame('ZTSE/line/payload-profile/owner-session/v1', join(a.accountId, c.ownerUserId, c.ownerSessionId))),
    originDigest: await sha(enc.encode(c.canonicalOrigin)), deviceSessionDigest: c.deviceSessionDigest, physicalSelectionDigest: c.physicalSelectionDigest,
    nonce: digest(13), peer: c.peer, integrationReaders: c.integrationReaders };
  const statement = await encodeConversationStatement03(s);
  const request = { signature: await sign(f.records[4].k, 'zrotext/conversation/request03/v1', statement), timeMs: 31000n };
  const approval = { signature: await sign(f.records[3].k, 'zrotext/conversation/approve03/v1', join(statement, await sha(request.signature))), timeMs: 32000n };
  const installed = { signature: await sign(f.records[3].k, 'zrotext/conversation/install03/v1', join(statement, await sha(request.signature), await sha(approval.signature))), timeMs: 33000n };
  let now = 35000n; const abort = new AbortController();
  const input = { context: await captureConversationContext03(c), statement, request, approval, installed, messageId: uuid(88),
    observedMs: now, expiresMs: 40000n, content: 'Synthetic installed message', nowMs: () => now, signal: abort.signal };
  return { f, s, input, abort, setNow: n => { now = n; } };
}
const rawSign = async (f, bytes) => canonicalP256Signature(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, f.records[4].k.pair.privateKey, bytes)));

test('all original signatures and the same private selection derive unsigned ciphertext and exact V2 review', async () => {
  const { f, input } = await setup(), native = crypto.subtle.sign.bind(crypto.subtle), descriptor = Object.getOwnPropertyDescriptor(crypto.subtle, 'sign');
  let ecdsa = 0;
  Object.defineProperty(crypto.subtle, 'sign', { configurable: true, value: (...args) => { if (args[0].name === 'ECDSA') ecdsa++; return native(...args); } });
  let result;
  try { result = await prepareInstalledConversationMessage03(input); assert.equal(ecdsa, 0); }
  finally { if (descriptor) Object.defineProperty(crypto.subtle, 'sign', descriptor); else delete crypto.subtle.sign; }
  const snapshot = preparedOutboundEnvelopeSnapshot03(result.prepared), signature = await rawSign(f, snapshot.transcript);
  const out = await completeSealedOutboundEnvelope03({ prepared: result.prepared, signature, nowMs: input.nowMs() });
  await verifyAndOpen(f, out, input.content);
  result.statement.peer.fill(0); result.statement.browserSignerKeyId.fill(0); // Display projection cannot alter private handles.
  const intent = await prepareReviewedIntent03V2({ context: result.reviewContext, envelope: out.envelope,
    reviewIssuedMs: input.nowMs(), reviewExpiresMs: 39000n, smsCeiling: 6, nowMs: input.nowMs() });
  const proof = await verifyReviewedIntent03V2({ context: result.reviewContext, envelope: out.envelope, intent,
    signature: await rawSign(f, reviewedIntentTranscript03V2(intent)), nowMs: input.nowMs() });
  const checked = verifiedReviewedIntentSnapshot03V2(proof);
  assert.equal(checked.fields.smsCeiling, 6); assert.deepEqual(checked.fields.peer, enc.encode('+12'));
  assert.deepEqual(checked.fields.intervalId, uuid(81)); assert.deepEqual(checked.envelope, out.envelope);
});

test('every missing or changed original proof refuses before composition randomness', async () => {
  const p = await setup(), random = crypto.getRandomValues.bind(crypto), descriptor = Object.getOwnPropertyDescriptor(crypto, 'getRandomValues');
  let draws = 0; Object.defineProperty(crypto, 'getRandomValues', { configurable: true, value: value => { draws++; return random(value); } });
  try {
    for (const key of ['request', 'approval', 'installed']) {
      await assert.rejects(prepareInstalledConversationMessage03({ ...p.input, [key]: null }));
      const bad = p.input[key].signature.slice(); bad[2] ^= 1;
      await assert.rejects(prepareInstalledConversationMessage03({ ...p.input, [key]: { ...p.input[key], signature: bad } }));
    }
    assert.equal(draws, 0);
  } finally { if (descriptor) Object.defineProperty(crypto, 'getRandomValues', descriptor); else delete crypto.getRandomValues; }
});

test('installed time, whole interval, original acceptance ordering and genuine context cannot be substituted', async () => {
  const p = await setup();
  for (const change of [{ observedMs: 32999n }, { expiresMs: 80001n }, { context: {} }, { messageId: new Uint8Array(16) },
    { request: { ...p.input.request, timeMs: 32001n } }, { installed: { ...p.input.installed, timeMs: 50000n } },
    { signal: {} }, { extra: true }]) await assert.rejects(prepareInstalledConversationMessage03({ ...p.input, ...change }));
  const changed = p.input.statement.slice(); changed[8] ^= 1;
  await assert.rejects(prepareInstalledConversationMessage03({ ...p.input, statement: changed }));
});

test('withdrawal, expiry and clock regression after verification cannot release preparations', async () => {
  for (const mode of ['abort', 'expiry', 'rollback']) {
    const p = await setup(); let calls = 0;
    await assert.rejects(prepareInstalledConversationMessage03({ ...p.input, nowMs: () => {
      calls++; if (calls > 1) { if (mode === 'abort') p.abort.abort(); else p.setNow(mode === 'expiry' ? 80000n : 34999n); } return p.input.nowMs();
    } })); assert.ok(calls >= 2);
  }
});

test('a crypto wait that crosses Stop or permission expiry cannot release ciphertext handles', async () => {
  for (const mode of ['abort', 'expiry']) {
    const p = await setup(), native = crypto.subtle.encrypt.bind(crypto.subtle), descriptor = Object.getOwnPropertyDescriptor(crypto.subtle, 'encrypt');
    let calls = 0;
    Object.defineProperty(crypto.subtle, 'encrypt', { configurable: true, value: async (...args) => {
      const out = await native(...args); calls++; if (mode === 'abort') p.abort.abort(); else p.setNow(80000n); return out;
    } });
    try { await assert.rejects(prepareInstalledConversationMessage03(p.input)); assert.ok(calls > 0); }
    finally { if (descriptor) Object.defineProperty(crypto.subtle, 'encrypt', descriptor); else delete crypto.subtle.encrypt; }
  }
});

test('descriptor capture ignores Proxy getters and owns original signature and routing bytes before waits', async () => {
  const p = await setup(); let gets = 0;
  const proxied = new Proxy(p.input, { get() { gets++; throw Error('descriptor-only'); } });
  const pending = prepareInstalledConversationMessage03(proxied);
  p.input.messageId.fill(0); p.input.statement.fill(0); p.input.request.signature.fill(0); p.input.approval.signature.fill(0); p.input.installed.signature.fill(0);
  const result = await pending; assert.equal(gets, 0);
  assert.deepEqual(preparedOutboundEnvelopeSnapshot03(result.prepared).unsignedEnvelope.slice(26, 42), uuid(88));
});
