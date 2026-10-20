// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { encodeConversationStatement03, decodeConversationStatement03, captureConversationContext03,
  checkConversationStatement03, verifyConversationReceipts03, conversationRequestTranscript03,
  conversationDisclosure03, conversationDisclosureVersion03 } from '../dist/conversation-interval03.js';
import { authorizeInbound03 } from '../dist/draft03-manifest.js';
import { fixture, uuid, clone, enc, frame, sha, sign, join, present, manifest, verifyManifest03Successor } from './fixtures/profile03-outbound-fixture.mjs';

const digest = n => new Uint8Array(32).fill(n);
function contextInput(f) {
  return { currentAuthority: clone(f.authority), acceptedElection: f.proof, manifest: f.currentManifest, selectionEpoch: 1n,
    ownerUserId: uuid(140), ownerSessionId: uuid(160), canonicalOrigin: 'https://example.test', deviceSessionDigest: digest(11),
    physicalSelectionDigest: digest(12), archiveReaderKeyId: f.records[1].id.slice(), phoneSignerKeyId: f.records[3].id.slice(),
    browserSignerKeyId: f.records[4].id.slice(), ownerDeadlineMs: 90000n, peer: enc.encode('+12'),
    integrationReaders: [{ connectorId: uuid(180), readGrantId: uuid(200), keyId: f.records[2].id.slice() }], nowMs: present };
}
async function fields(f, c = contextInput(f)) {
  const a = c.currentAuthority;
  return { accountId: a.accountId, deviceId: a.deviceId, lineId: a.lineId, bindingId: a.bindingId,
    intervalId: uuid(81), receiptId: uuid(82), ownerUserId: c.ownerUserId, ownerSessionId: c.ownerSessionId, openingId: uuid(83),
    bindingGeneration: a.bindingGeneration, vaultGeneration: a.vaultGeneration, manifestVersion: a.manifestVersion, selectionEpoch: c.selectionEpoch,
    issuedMs: present, setupExpiresMs: 50000n, intervalFromMs: present, intervalUntilMs: 80000n,
    selectedReaderKeyId: a.selectedReaderKeyId, archiveReaderKeyId: c.archiveReaderKeyId, phoneSignerKeyId: c.phoneSignerKeyId,
    browserSignerKeyId: c.browserSignerKeyId, rootFingerprint: a.rootFingerprint, manifestDigest: a.manifestDigest,
    electionCommitment: a.electionCommitment, electionBundleSha256: a.electionBundleSha256,
    ownerSessionDigest: await sha(frame('ZTSE/line/payload-profile/owner-session/v1', join(a.accountId, c.ownerUserId, c.ownerSessionId))),
    originDigest: await sha(enc.encode(c.canonicalOrigin)), deviceSessionDigest: c.deviceSessionDigest,
    physicalSelectionDigest: c.physicalSelectionDigest, nonce: digest(13), peer: c.peer, integrationReaders: c.integrationReaders };
}
async function packet(f, c = contextInput(f)) {
  const s = await fields(f, c), statement = await encodeConversationStatement03(s);
  const request = { signature: await sign(f.records[4].k, 'zrotext/conversation/request03/v1', statement), timeMs: 31000n };
  const approval = { signature: await sign(f.records[3].k, 'zrotext/conversation/approve03/v1', join(statement, await sha(request.signature))), timeMs: 32000n };
  const installed = { signature: await sign(f.records[3].k, 'zrotext/conversation/install03/v1', join(statement, await sha(request.signature), await sha(approval.signature))), timeMs: 33000n };
  return { context: await captureConversationContext03(c), statement, request, approval, installed, nowMs: 35000n, pending: true };
}

test('exact ZTCA03 layout and disclosure independently match nine UUIDs, eight numbers and thirteen digests', async () => {
  const f = await fixture(), s = await fields(f), b = await encodeConversationStatement03(s), parsed = await decodeConversationStatement03(b);
  assert.equal(b.length, 692 + 3 + 64);
  assert.deepEqual(b.slice(0, 8), Uint8Array.of(90,84,67,65,3,3,3,0));
  assert.deepEqual(b.slice(8, 24), s.accountId);
  assert.deepEqual(b.slice(136, 152), s.openingId);
  assert.equal(new DataView(b.buffer).getBigUint64(152), s.bindingGeneration);
  assert.equal(new DataView(b.buffer).getBigUint64(208), s.intervalUntilMs);
  assert.deepEqual(b.slice(600, 632), s.nonce);
  assert.equal(b[632], 25); assert.equal(new TextDecoder().decode(b.slice(633, 658)), conversationDisclosureVersion03);
  assert.deepEqual(b.slice(658, 690), await sha(enc.encode(conversationDisclosure03)));
  assert.deepEqual(await encodeConversationStatement03(parsed), b);
  assert.deepEqual(conversationRequestTranscript03(b), frame('zrotext/conversation/request03/v1', b));
  parsed.accountId.fill(0); parsed.integrationReaders[0].keyId.fill(0);
  assert.deepEqual((await decodeConversationStatement03(b)).accountId, s.accountId);
});

test('genuine election, two-direction manifest authority and all three independent signatures verify', async () => {
  const f = await fixture(), p = await packet(f);
  const checked = await checkConversationStatement03(p.statement, p.context, present);
  assert.equal(checked.intervalUntilMs, 80000n);
  const result = await verifyConversationReceipts03(p);
  assert.deepEqual(result.browserSignerKeyId, f.records[4].id);
  result.phoneSignerKeyId.fill(0);
  assert.deepEqual((await verifyConversationReceipts03(p)).phoneSignerKeyId, f.records[3].id);
  assert.deepEqual(await verifyConversationReceipts03({ ...p, request: null, approval: null, installed: null }), checked);
  await verifyConversationReceipts03({ ...p, approval: null, installed: null });
  await verifyConversationReceipts03({ ...p, installed: null });
  await assert.rejects(checkConversationStatement03(p.statement, {}, present), /context/);
  await assert.rejects(verifyConversationReceipts03({ ...p, context: {} }), /context/);
});

test('historical setup expiry cannot renew present permission or change any original receipt time', async () => {
  const f = await fixture(), p = await packet(f);
  await verifyConversationReceipts03({ ...p, nowMs: 55000n, pending: false });
  await assert.rejects(verifyConversationReceipts03({ ...p, nowMs: 50000n }), /time/);
  await assert.rejects(verifyConversationReceipts03({ ...p, nowMs: 60000n, pending: false }));
  await assert.rejects(verifyConversationReceipts03({ ...p, nowMs: present - 1n }));
  for (const [name, timeMs] of [['request',29999n], ['request',50000n], ['approval',30999n], ['installed',31999n], ['installed',35001n]]) {
    await assert.rejects(verifyConversationReceipts03({ ...p, [name]: { ...p[name], timeMs } }), /time/);
  }
  for (const change of [s => s.setupExpiresMs = 60001n, s => s.intervalUntilMs = 90001n, s => s.issuedMs = s.intervalFromMs = 8000n]) {
    const s = await decodeConversationStatement03(p.statement); change(s);
    await assert.rejects(checkConversationStatement03(await encodeConversationStatement03(s), p.context, present));
  }
});

test('closed fields, exact framing, disclosure, positive ranges, peer and immutable handle separation refuse mutations', async () => {
  const f = await fixture(), s = await fields(f), b = await encodeConversationStatement03(s);
  for (const i of [0,4,5,6,7,632,633,658,690,694]) { const changed = b.slice(); changed[i] ^= 1; await assert.rejects(decodeConversationStatement03(changed), undefined, 'framing byte '+i); }
  for (const changed of [b.slice(0,-1), join(b,Uint8Array.of(0)), new Uint8Array(694), new Uint8Array(1093)]) await assert.rejects(decodeConversationStatement03(changed));
  for (const change of [x => x.extra = true, x => delete x.nonce, x => x.accountId.fill(0), x => x.selectionEpoch = 0n,
    x => x.selectionEpoch = 1n << 63n, x => x.selectionEpoch = 1, x => x.intervalFromMs++, x => x.setupExpiresMs = x.issuedMs,
    x => x.setupExpiresMs = x.issuedMs + 300001n, x => x.intervalUntilMs = x.issuedMs + 86400001n,
    x => x.intervalId = x.bindingId, x => x.receiptId = x.openingId, x => x.peer = enc.encode('+01'), x => x.peer = enc.encode('+1x'),
    x => Object.defineProperty(x,'nonce',{get(){throw Error('getter invoked');}})]) {
    const changed = clone(s); change(changed); await assert.rejects(encodeConversationStatement03(changed));
  }
});

test('every immutable selection, commitment, peer and mapping is compared against independently captured context', async () => {
  const f = await fixture(), p = await packet(f), original = await decodeConversationStatement03(p.statement);
  for (const name of ['accountId','deviceId','lineId','bindingId','ownerUserId','ownerSessionId','selectedReaderKeyId','archiveReaderKeyId',
    'phoneSignerKeyId','browserSignerKeyId','rootFingerprint','manifestDigest','electionCommitment','electionBundleSha256',
    'ownerSessionDigest','originDigest','deviceSessionDigest','physicalSelectionDigest','peer']) {
    const changed = clone(original); changed[name][changed[name].length-1] ^= 1;
    await assert.rejects(async () => checkConversationStatement03(await encodeConversationStatement03(changed),p.context,present), undefined,name);
  }
  for (const name of ['bindingGeneration','vaultGeneration','manifestVersion','selectionEpoch']) {
    const changed = clone(original); changed[name]++;
    await assert.rejects(checkConversationStatement03(await encodeConversationStatement03(changed),p.context,present),undefined,name);
  }
  for (const name of ['connectorId','readGrantId','keyId']) {
    const changed = clone(original); changed.integrationReaders[0][name][0] ^= 1;
    await assert.rejects(checkConversationStatement03(await encodeConversationStatement03(changed),p.context,present));
  }
  await assert.rejects(checkConversationStatement03(await encodeConversationStatement03({...original,integrationReaders:[]}),p.context,present));
});

test('receipt domains, selected role identities, signature order and strict low-S are independent', async () => {
  const f = await fixture(), p = await packet(f);
  for (const change of [x=>x.request=null, x=>x.approval=null, x=>[x.request.signature,x.approval.signature]=[x.approval.signature,x.request.signature],
    x=>x.installed.signature=x.approval.signature, x=>x.request.signature[0]^=1, x=>x.approval.signature.fill(0)]) {
    const changed = {...p,request:clone(p.request),approval:clone(p.approval),installed:clone(p.installed)}; change(changed);
    await assert.rejects(verifyConversationReceipts03(changed));
  }
  for (const [key,domain] of [[f.approval,'zrotext/conversation/request03/v1'],[f.root,'zrotext/conversation/request03/v1'],
    [f.records[3].k,'zrotext/conversation/request03/v1'],[f.records[4].k,'zrotext/conversation/request/v2']]) {
    const signature = await sign(key,domain,p.statement);
    await assert.rejects(verifyConversationReceipts03({...p,request:{signature,timeMs:p.request.timeMs}}));
  }
  const order=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n, signature=p.request.signature.slice();
  const low=BigInt('0x'+Buffer.from(signature.slice(32)).toString('hex'));
  signature.set(Buffer.from((order-low).toString(16).padStart(64,'0'),'hex'),32);
  await assert.rejects(verifyConversationReceipts03({...p,request:{...p.request,signature}}),/low-S/);
});

test('context requires genuine handles and current immutable inputs, not digests or a claimed phase', async () => {
  const f=await fixture();
  for (const change of [c=>c.manifest={},c=>c.acceptedElection={},c=>c.currentAuthority.bindingId[0]^=1,
    c=>c.currentAuthority.permissionExpiresAtMs=present,c=>c.ownerDeadlineMs=present,c=>c.selectionEpoch=false,c=>c.nowMs=1,
    c=>c.originDigest=digest(1),c=>c.ownerSessionDigest=digest(2),c=>c.ready=true,c=>c.deviceSessionDigest.fill(0),
    c=>c.physicalSelectionDigest.fill(0),c=>c.phoneSignerKeyId=c.browserSignerKeyId,c=>c.browserSignerKeyId=c.phoneSignerKeyId,
    c=>Object.defineProperty(c,'ownerUserId',{get(){throw Error('getter invoked');}})]) {
    const c=contextInput(f);change(c);await assert.rejects(captureConversationContext03(c));
  }
  for(const canonicalOrigin of ['http://example.test','https://example.test/','https://EXAMPLE.test','https://example.test:443'])
    await assert.rejects(captureConversationContext03({...contextInput(f),canonicalOrigin}));
});

test('mappings are sorted, independently unique, bounded and require both current read directions', async () => {
  const f=await fixture(), c=contextInput(f), item=c.integrationReaders[0];
  for(const integrationReaders of [[item,item],new Array(1),Array(7).fill(item),[{...item,connectorId:new Uint8Array(16)}],
    [{...item,extra:true}],[{...item,keyId:f.records[1].id}]]) await assert.rejects(captureConversationContext03({...c,integrationReaders}));
  const accessor=[item];Object.defineProperty(accessor,'0',{get(){throw Error('getter invoked');}});
  await assert.rejects(captureConversationContext03({...c,integrationReaders:accessor}));
  const extra=[item];extra.other=true;await assert.rejects(captureConversationContext03({...c,integrationReaders:extra}));
  for(const scope of [4,8]) {
    const records=f.records.map(r=>r.role===3?{...r,scope}:r), next=await manifest(f,3,3n,f.first.digest,records);
    const verified=await verifyManifest03Successor(next.bytes,f.currentManifest,present);
    await assert.rejects(captureConversationContext03({...c,manifest:verified,currentAuthority:{...c.currentAuthority,manifestVersion:3n,manifestDigest:next.digest}}));
  }
  const noMappings={...contextInput(f),integrationReaders:[]}, p=await packet(f,noMappings);
  await verifyConversationReceipts03(p); assert.equal(p.statement.length,695);
});

test('new inbound manifest policy checks real role04 and archive policy with no legacy fallback', async () => {
  const f=await fixture(), a=f.authority, claims={accountId:a.accountId,deviceId:a.deviceId,lineId:a.lineId,generation:1n,
    version:a.manifestVersion,digest:a.manifestDigest,signerKeyId:f.records[3].id,wraps:[{role:2,keyId:f.records[1].id},{role:3,keyId:f.records[2].id}]};
  const checked=authorizeInbound03(f.currentManifest,claims,present);assert.deepEqual(checked.signerPoint,f.records[3].k.point);
  checked.signerPoint.fill(0);checked.recipients[0].point.fill(0);
  assert.deepEqual(authorizeInbound03(f.currentManifest,claims,present).signerPoint,f.records[3].k.point);
  for(const change of [x=>x.deviceId=uuid(90),x=>x.lineId=uuid(91),x=>x.generation=2n,x=>x.signerKeyId=f.records[4].id,
    x=>x.wraps.push(x.wraps[1]),x=>x.wraps.shift(),x=>x.wraps[0]={role:1,keyId:f.records[0].id}]) {
    const x=clone(claims);change(x);assert.throws(()=>authorizeInbound03(f.currentManifest,x,present));
  }
  assert.throws(()=>authorizeInbound03(f.prior,claims,present));
});

test('inputs are owned before async crypto and shared/disguised backing storage never enters retained context',async()=>{
  const f=await fixture(), c=contextInput(f), raw=await fields(f,c), expected=await encodeConversationStatement03(raw);
  const encoding=encodeConversationStatement03(raw);raw.nonce.fill(0);raw.integrationReaders[0].connectorId.fill(0);
  assert.deepEqual(await encoding,expected);
  const c2=contextInput(f), pending=captureConversationContext03(c2);
  c2.ownerSessionId.fill(0);c2.deviceSessionDigest.fill(0);c2.currentAuthority.bindingId.fill(0);c2.integrationReaders.length=0;
  await checkConversationStatement03(expected,await pending,present);
  for(const name of ['ownerUserId','deviceSessionDigest','physicalSelectionDigest']) {
    const changed=contextInput(f), shared=new SharedArrayBuffer(changed[name].length), b=new Uint8Array(shared);b.set(changed[name]);
    Object.setPrototypeOf(shared,ArrayBuffer.prototype);changed[name]=b;await assert.rejects(captureConversationContext03(changed));
  }
  const bytes=expected.slice(), decoding=decodeConversationStatement03(bytes);bytes.fill(0);
  assert.deepEqual(await encodeConversationStatement03(await decoding),expected);
  const p=await packet(f), verification=verifyConversationReceipts03(p);p.statement.fill(0);p.request.signature.fill(0);p.approval.signature.fill(0);p.installed.signature.fill(0);
  await verification;
});
