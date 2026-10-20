// SPDX-License-Identifier: AGPL-3.0-only
// Genuine synthetic crypto/history; HTTP responses are a source-owned test seam.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fixture, key, uuid, b64, text, join, hash, sha, enc } from './manifest-history03-fixture.mjs';
import { startAcceptedManifestHistory03 as start, OwnerManifestHistoryClient03 as Client } from '../dist/accepted-manifest-history03.js';
import { encodeConversationStatement03, checkConversationStatement03, conversationDisclosure03 } from '../dist/conversation-interval03.js';

const csrf='ztc_'+b64(new Uint8Array(32)), binary=s=>Uint8Array.from(Buffer.from(s,'base64url'));
const response=v=>new Response(typeof v==='string'?v:JSON.stringify(v),{headers:{'content-type':'application/json'}});
async function setup(includeIntegration=false) {
  const f=await fixture({originalProofs:true,includeIntegration});await f.step(await key());
  const roles=new Map(Array.from({length:f.signed[152]},(_,i)=>{
    const r=f.signed.slice(153+i*149,153+(i+1)*149);return[r[0],{id:r.slice(1,33),point:r.slice(33,98)}];
  }));
  const current=await f.wireCurrent(), now=BigInt(current.compared_ms), selection={peer:enc.encode('+12'),
    archiveReaderKeyId:roles.get(2).id,phoneSignerKeyId:roles.get(4).id,browserSignerKeyId:roles.get(5).id,
    integrationReaders:includeIntegration?[{connectorId:uuid(181),readGrantId:uuid(182),keyId:roles.get(3).id}]:[]};
  const physical=await hash('ZTSE/line/payload-profile/physical-selection/v1',Uint8Array.of(1),f.account,f.device,f.line,f.binding,
    f.accepted.electionCommitment,binary(current.device_session_digest),f.oldBinding,await sha(binary(f.evidence.activation_evidence)));
  const fields={accountId:f.account,deviceId:f.device,lineId:f.line,bindingId:f.binding,intervalId:uuid(201),receiptId:uuid(202),
    ownerUserId:f.user,ownerSessionId:f.session,openingId:uuid(203),bindingGeneration:7n,vaultGeneration:1n,manifestVersion:f.version,selectionEpoch:1n,
    issuedMs:now,setupExpiresMs:now+3000n,intervalFromMs:now,intervalUntilMs:50000n,selectedReaderKeyId:f.reader,
    archiveReaderKeyId:selection.archiveReaderKeyId,phoneSignerKeyId:selection.phoneSignerKeyId,browserSignerKeyId:selection.browserSignerKeyId,
    rootFingerprint:f.fingerprint,manifestDigest:f.digest,electionCommitment:f.accepted.electionCommitment,electionBundleSha256:f.accepted.electionBundleSha256,
    ownerSessionDigest:binary(current.owner_session_digest),originDigest:binary(current.origin_digest),deviceSessionDigest:binary(current.device_session_digest),
    physicalSelectionDigest:physical,nonce:new Uint8Array(32).fill(4),peer:selection.peer,integrationReaders:selection.integrationReaders};
  const statement=await encodeConversationStatement03(fields), input={openingId:text(fields.openingId),intervalId:text(fields.intervalId),statement,selection};
  const readers=includeIntegration?[{connector_id:text(selection.integrationReaders[0].connectorId),read_grant_id:text(selection.integrationReaders[0].readGrantId),
    key_id:b64(roles.get(3).id),key_point:b64(roles.get(3).point),manifest_generation:'1',read_directions:12,
    registration_expires_ms:'80000',grant_expires_ms:'70000',key_valid_from_ms:'9000',key_valid_until_ms:'2000000'}]:[];
  const outer={v:1,kind:'owner_conversation_context03',opening_id:input.openingId,interval_id:input.intervalId,statement_sha256:b64(await sha(statement)),selection:current,
    owner_session_expires_ms:'60000',physical_selection_digest:b64(physical),compared_ms:current.compared_ms,permission_expires_ms:current.permission_expires_ms,readers};
  f.calls=[];f.now=now;f.body=v=>v;
  f.make=async(extra={})=>{
    const c=new Client({origin:f.origin,accountId:text(f.account),userId:text(f.user),ownerSessionId:text(f.session),currentCsrf:()=>csrf,
      signal:new AbortController().signal,fetchImpl:async(url,options)=>{
        f.calls.push({url,options});const body=JSON.parse(options.body);
        if(url.endsWith('/history'))return response(f.page());
        return response(await f.body({...structuredClone(outer),request_id:body.request_id}));
      },...extra});
    return{c,history:await c.next(await start(f.seed))};
  };
  return Object.assign(f,{input,fields,outer,roles,initialNow:now});
}

test('distinct context read correlates fresh request, retained original, real whole history and current physical source',async()=>{
  for(const mapped of [false,true]) {
    const f=await setup(mapped),{c,history}=await f.make(),result=await c.conversationContext(history,f.input,()=>f.now);
    assert.equal(f.calls.length,2);const call=f.calls[1],body=JSON.parse(call.options.body);
    assert.equal(call.url,f.origin+'/v1/owner/conversation/interval03/context');assert.deepEqual(Object.keys(body).sort(),['interval_id','opening_id','request_id','v']);
    assert.equal(body.opening_id,f.input.openingId);assert.equal(body.interval_id,f.input.intervalId);assert.match(body.request_id,/^[0-9a-f-]{36}$/);
    assert.equal(call.options.credentials,'same-origin');assert.equal(call.options.redirect,'error');assert.equal(call.options.headers['x-zrotext-csrf'],csrf);
    assert.equal(Object.hasOwn(body,'password'),false);assert.equal(result.permissionExpiresMs,BigInt(f.outer.permission_expires_ms));
    assert.ok(result.statement.intervalUntilMs>result.permissionExpiresMs);
    await checkConversationStatement03(f.input.statement,result.context,f.now);
    result.statement.physicalSelectionDigest.fill(0);
    await checkConversationStatement03(f.input.statement,result.context,f.now);
  }
});

test('replayed nonce, wrong original, owner identity, current prefix and held facts refuse without retry',async()=>{
  const f=await setup();
  for(const mutate of [r=>r.request_id=text(uuid(210)),r=>r.opening_id=text(uuid(211)),r=>r.interval_id=text(uuid(212)),
    r=>r.statement_sha256=b64(new Uint8Array(32)),r=>r.selection.owner_session_id=text(uuid(213)),
    r=>r.selection.manifest_ancestry_sha256=b64(new Uint8Array(32)),r=>r.physical_selection_digest=b64(new Uint8Array(32)),
    r=>r.selection.device_session_digest=b64(new Uint8Array(32).fill(6)),r=>r.owner_session_expires_ms='49999',
    r=>r.compared_ms=String(BigInt(r.compared_ms)+1n),r=>r.permission_expires_ms=String(BigInt(r.permission_expires_ms)+1n),
    r=>r.kind='interval_permission03',r=>r.installed=true,r=>delete r.readers]) {
    f.body=r=>{mutate(r);return r;};const {c,history}=await f.make(),before=f.calls.length;
    await assert.rejects(c.conversationContext(history,f.input,()=>f.now));assert.equal(f.calls.length,before+1);
  }
});

test('actual registry IDs, public point, both directions and whole interval bounds remain independently checked',async()=>{
  const f=await setup(true);
  for(const mutate of [r=>r.readers=[],r=>r.readers.push(r.readers[0]),r=>r.readers[0].connector_id=text(uuid(214)),
    r=>r.readers[0].read_grant_id=text(uuid(215)),r=>r.readers[0].key_id=b64(f.roles.get(2).id),
    r=>r.readers[0].key_point=b64(f.roles.get(4).point),r=>r.readers[0].read_directions=4,r=>r.readers[0].read_directions='12',
    r=>r.readers[0].manifest_generation='2',r=>r.readers[0].key_valid_from_ms=String(f.now+1n),
    r=>r.readers[0].registration_expires_ms='49999',r=>r.readers[0].grant_expires_ms='49999',r=>r.readers[0].key_valid_until_ms='49999',
    r=>r.readers[0].revoked=false]) {
    f.body=r=>{mutate(r);return r;};const {c,history}=await f.make();await assert.rejects(c.conversationContext(history,f.input,()=>f.now));
  }
});

test('independent original UI peer/key/mappings cannot be replaced by the unsigned statement',async()=>{
  const f=await setup(true);
  for(const mutate of [s=>s.peer=enc.encode('+13'),s=>s.archiveReaderKeyId=f.roles.get(3).id,s=>s.phoneSignerKeyId=f.roles.get(5).id,
    s=>s.browserSignerKeyId=f.roles.get(4).id,s=>s.integrationReaders=[],s=>s.integrationReaders[0].readGrantId=uuid(219)]) {
    const input=structuredClone(f.input);mutate(input.selection);const {c,history}=await f.make();
    await assert.rejects(c.conversationContext(history,input,()=>f.now));
  }
});

test('decoded duplicate keys, malformed bounded stream, CSRF change and timeout never retry the read',async()=>{
  const f=await setup();
  for(const value of ['{"v":1,"v":1}','{"v":1,"\\u0076":1}','{"__proto__":{}}',' '.repeat(192*1024+1)]) {
    f.body=()=>value;const {c,history}=await f.make(),before=f.calls.length;await assert.rejects(c.conversationContext(history,f.input,()=>f.now));assert.equal(f.calls.length,before+1);
  }
  const timeout=new Client({origin:f.origin,accountId:text(f.account),userId:text(f.user),ownerSessionId:text(f.session),currentCsrf:()=>csrf,
    signal:new AbortController().signal,timeoutMs:10,fetchImpl:async()=>new Promise(()=>{})});
  const {history}=await f.make();await assert.rejects(timeout.conversationContext(history,f.input,()=>f.now));
  let current=csrf;f.body=r=>{current='ztc_'+b64(new Uint8Array(32).fill(2));return r;};
  const actual=await f.make({currentCsrf:()=>current});await assert.rejects(actual.c.conversationContext(actual.history,f.input,()=>f.now));
});

test('expiry or local clock regression during the last genuine disclosure hash cannot release a context',async()=>{
  for(const mode of ['expiry','regression']) {
    const f=await setup(),{c,history}=await f.make(),original=crypto.subtle.digest;let disclosures=0;
    crypto.subtle.digest=async(...args)=>{
      const result=await Reflect.apply(original,crypto.subtle,args),bytes=new Uint8Array(args[1]);
      if(Buffer.from(bytes).equals(Buffer.from(enc.encode(conversationDisclosure03)))&&++disclosures===2)
        f.now=mode==='expiry'?BigInt(f.outer.permission_expires_ms):f.initialNow-1n;
      return result;
    };
    try{await assert.rejects(c.conversationContext(history,f.input,()=>f.now));assert.equal(disclosures,2);}finally{crypto.subtle.digest=original;}
  }
});

test('public originals and independent selection are owned before awaiting the service',async()=>{
  const f=await setup(true),{c,history}=await f.make(),input=structuredClone(f.input);
  let release,entered;const waiting=new Promise(resolve=>{entered=resolve;});f.body=async r=>{entered();await new Promise(resolve=>{release=resolve;});return r;};
  const read=c.conversationContext(history,input,()=>f.now);await waiting;
  input.statement.fill(0);input.selection.archiveReaderKeyId.fill(0);input.selection.integrationReaders[0].connectorId.fill(0);input.selection.peer.fill(0);
  release();const result=await read;assert.deepEqual(result.statement.peer,f.input.selection.peer);
  await checkConversationStatement03(f.input.statement,result.context,f.now);
});

test('timed-out genuine root verification cannot publish a late clock floor over a newer successful read',async()=>{
  const f=await setup(),{c,history}=await f.make({timeoutMs:200}),base=f.initialNow,verify=crypto.subtle.verify,digest=crypto.subtle.digest;
  let manifests=0,releaseOld,entered,digested,late=false,lateClockCalls=0;
  const blocked=new Promise(resolve=>{entered=resolve;}),returned=new Promise(resolve=>{digested=resolve;});
  crypto.subtle.verify=async(...args)=>{
    const result=await Reflect.apply(verify,crypto.subtle,args);
    if(Buffer.from(args[3]).subarray(0,17).toString()==='ZTSE/manifest/v3\0'&&++manifests===2){
      entered();await new Promise(resolve=>{releaseOld=resolve;});late=true;
    }
    return result;
  };
  crypto.subtle.digest=async(...args)=>{
    const result=await Reflect.apply(digest,crypto.subtle,args);
    if(late&&Buffer.from(args[1]).equals(Buffer.from(f.signed.slice(0,-64))))digested();
    return result;
  };
  let timer;
  try{
    const old=c.conversationContext(history,f.input,()=>{if(late)lateClockCalls++;return f.now;}).then(()=>false,()=>true);
    await Promise.race([blocked,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Actual root verification was not reached')),2000);})]);
    clearTimeout(timer);assert.equal(await old,true);
    f.now=base+100n;f.body=r=>{r.compared_ms=String(base+80n);r.selection.compared_ms=r.compared_ms;return r;};
    const newer=await c.conversationContext(history,f.input,()=>f.now);assert.equal(newer.comparedMs,base+80n);
    releaseOld();await returned;await new Promise(resolve=>setImmediate(resolve));
    assert.equal(lateClockCalls,0,'Abandoned proof must stop before any final clock publication');
    f.body=r=>{r.compared_ms=String(base+40n);r.selection.compared_ms=r.compared_ms;return r;};
    await assert.rejects(c.conversationContext(history,f.input,()=>f.now));
  }finally{clearTimeout(timer);crypto.subtle.verify=verify;crypto.subtle.digest=digest;releaseOld?.();}
});
