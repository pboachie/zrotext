// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { OwnerConversationIntervalClient03 as Client, IntervalTransportError03 } from '../dist/owner-conversation-interval03.js';
import { encodeConversationStatement03 } from '../dist/conversation-interval03.js';
import { fixture, uuid, enc, sha, frame, join, sign, present } from './fixtures/profile03-outbound-fixture.mjs';

const text=b=>Buffer.from(b).toString('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5'),b64=b=>Buffer.from(b).toString('base64url');
const digest=n=>new Uint8Array(32).fill(n),csrf='ztc_'+b64(digest(1));
async function setup(){
  const f=await fixture(),a=f.authority,ownerUser=uuid(140),ownerSession=uuid(160),opening=uuid(201),interval=uuid(202),receipt=uuid(203);
  const integration={connectorId:uuid(180),readGrantId:uuid(181),keyId:f.records[2].id};
  const fields={accountId:a.accountId,deviceId:a.deviceId,lineId:a.lineId,bindingId:a.bindingId,intervalId:interval,receiptId:receipt,
    ownerUserId:ownerUser,ownerSessionId:ownerSession,openingId:opening,bindingGeneration:a.bindingGeneration,vaultGeneration:1n,manifestVersion:a.manifestVersion,selectionEpoch:1n,
    issuedMs:present,setupExpiresMs:50000n,intervalFromMs:present,intervalUntilMs:80000n,selectedReaderKeyId:a.selectedReaderKeyId,
    archiveReaderKeyId:f.records[1].id,phoneSignerKeyId:f.records[3].id,browserSignerKeyId:f.records[4].id,rootFingerprint:a.rootFingerprint,
    manifestDigest:a.manifestDigest,electionCommitment:a.electionCommitment,electionBundleSha256:a.electionBundleSha256,
    ownerSessionDigest:await sha(frame('ZTSE/line/payload-profile/owner-session/v1',join(a.accountId,ownerUser,ownerSession))),
    originDigest:await sha(enc.encode('https://example.test')),deviceSessionDigest:digest(3),physicalSelectionDigest:digest(4),nonce:digest(5),peer:enc.encode('+12'),integrationReaders:[integration]};
  const statement=await encodeConversationStatement03(fields),ownerSignature=await sign(f.records[4].k,'zrotext/conversation/request03/v1',statement);
  const command={v:1,opening_id:text(opening),line_id:text(a.lineId),peer:'+12',archive_reader_key_id:b64(fields.archiveReaderKeyId),
    phone_signer_key_id:b64(fields.phoneSignerKeyId),browser_signer_key_id:b64(fields.browserSignerKeyId),interval_expires_ms:'80000',
    integration_readers:[{connector_id:text(integration.connectorId),read_grant_id:text(integration.readGrantId),key_id:b64(integration.keyId)}]};
  const original={v:1,opening_id:text(opening),interval_id:text(interval),statement:b64(statement),owner_signature:b64(ownerSignature)};
  const candidate={v:1,opening_id:text(opening),interval_id:text(interval),receipt_id:text(receipt),statement:b64(statement),
    owner_signature:null,phone_signature:null,installed_signature:null,requested_ms:null,approved_ms:null,installed_ms:null,phase:'reserved'};
  f.calls=[];f.saved=[];f.events=[];f.candidate=candidate;f.response=r=>Response.json(r);f.cookie=csrf;
  f.make=(extra={})=>new Client({origin:'https://example.test',accountId:text(a.accountId),userId:text(ownerUser),ownerSessionId:text(ownerSession),
    deviceId:text(a.deviceId),lineId:text(a.lineId),rootFingerprint:a.rootFingerprint,currentCsrf:()=>f.cookie,signal:new AbortController().signal,
    saveRecovery:async r=>{f.events.push('saved');f.saved.push(structuredClone(r));},fetchImpl:async(url,options)=>{
      const body=JSON.parse(options.body);f.events.push('http');f.calls.push({url,options,body});
      if(url.endsWith('/requests')){
        assert.equal(body.statement,original.statement);assert.equal(body.owner_signature,original.owner_signature);
        f.candidate={...f.candidate,owner_signature:body.owner_signature,requested_ms:'31000',phase:'requested'};
      }
      if(url.endsWith('/stop')){f.candidate={...f.candidate,phase:'stopped'};return f.response(null,true);}
      return f.response(structuredClone(f.candidate));
    },...extra});
  f.credentials={password:'<synthetic-password>',factor:'<synthetic-factor>'};
  return Object.assign(f,{command,original,fields});
}

test('fixed reservation and original request save only public exact records before each explicit mutation',async()=>{
  const f=await setup(),c=f.make();const reserve=await c.reserve(f.command);assert.equal(reserve.phase,'reserved');
  const request=await c.request(f.original,f.credentials);assert.equal(request.phase,'requested');assert.equal(f.calls.length,2);
  assert.deepEqual(f.events,['saved','http','saved','http']);assert.deepEqual(f.saved[0].packet,f.command);assert.deepEqual(f.saved[1].packet,f.original);
  for(const saved of f.saved){const raw=JSON.stringify(saved);assert.equal(raw.includes(f.credentials.password),false);assert.equal(raw.includes(f.credentials.factor),false);}
  assert.equal(f.calls[0].url,'https://example.test/v1/owner/conversation/interval03/challenges');
  assert.equal(f.calls[1].options.credentials,'same-origin');assert.equal(f.calls[1].options.redirect,'error');assert.equal(f.calls[1].options.headers['x-zrotext-csrf'],csrf);
  assert.deepEqual(f.calls[1].body,{...f.original,...f.credentials});
});

test('lost reservation response resumes by its saved opening with passive fresh-same-user lookup only',async()=>{
  const f=await setup();f.response=()=>{throw Error('Synthetic response lost');};
  await assert.rejects(f.make().reserve(f.command),e=>e instanceof IntervalTransportError03&&e.outcome==='unknown');
  assert.equal(f.saved.length,1);assert.equal(f.calls.length,1);
  f.response=r=>Response.json(r);const fresh=f.make({ownerSessionId:text(uuid(210))}),before=f.saved.length;
  const retained=await fresh.openingStatus(f.command.opening_id);assert.equal(retained.interval_id,f.original.interval_id);
  assert.deepEqual(f.calls[1].body,{v:1,opening_id:f.command.opening_id});assert.equal(f.saved.length,before);
  await assert.rejects(fresh.request(f.original,f.credentials));assert.equal(f.calls.length,2);
  const exact=await fresh.status(f.original.opening_id,f.original.interval_id);assert.equal(exact.statement,f.original.statement);assert.equal(f.calls.length,3);
});

test('UNKNOWN request, uncertain commit503 and malformed successful replies retain the original without retry',async()=>{
  for(const mode of ['lost','503','duplicate','wrong-proof']){
    const f=await setup();f.response=r=>{
      if(mode==='lost')throw Error('Synthetic committed response lost');
      if(mode==='503')return Response.json({error:'temporarily_unavailable'},{status:503});
      if(mode==='duplicate')return new Response(JSON.stringify(r).replace('"v":1','"v":1,"\\u0076":1'),{headers:{'content-type':'application/json'}});
      return Response.json({...r,owner_signature:(f.original.owner_signature[0]==='A'?'B':'A')+f.original.owner_signature.slice(1)});
    };
    await assert.rejects(f.make().request(f.original,f.credentials),e=>e.outcome==='unknown');
    assert.equal(f.calls.length,1);assert.equal(f.saved.length,1);assert.deepEqual(f.saved[0].packet,f.original);assert.equal(f.candidate.phase,'requested');
    f.response=r=>Response.json(r);const receipt=await f.make().status(f.original.opening_id,f.original.interval_id);assert.equal(receipt.phase,'requested');assert.equal(f.saved.length,1);
  }
});

test('only a closed typed4xx error is a definite refusal and even it never erases saved originals',async()=>{
  const f=await setup();
  for(const [body,type,outcome] of [[{error:'origin_or_csrf_refused'},'application/json','refused'],[{error:'other'},'application/json','unknown'],
    [{error:'origin_or_csrf_refused',extra:true},'application/json','unknown'],['<html>unavailable</html>','text/html','unknown']]){
    f.response=()=>new Response(typeof body==='string'?body:JSON.stringify(body),{status:403,headers:{'content-type':type}});
    const before=f.calls.length;await assert.rejects(f.make().reserve(f.command),e=>e.outcome===outcome);assert.equal(f.calls.length,before+1);
    assert.deepEqual(f.saved.at(-1).packet,f.command);
  }
});

test('failed or timed-out recovery commits prevent HTTP even after a late callback completes',async()=>{
  const f=await setup();await assert.rejects(f.make({saveRecovery:async()=>{throw Error('Synthetic IDB failure');}}).reserve(f.command));assert.equal(f.calls.length,0);
  let release;const c=f.make({timeoutMs:10,saveRecovery:async()=>new Promise(resolve=>{release=resolve;})});
  await assert.rejects(c.reserve(f.command),e=>e.outcome==='unknown');assert.equal(f.calls.length,0);release();await new Promise(resolve=>setTimeout(resolve,0));assert.equal(f.calls.length,0);
});

test('caller mutations cannot rewrite committed nested selections and parallel operations never send twice',async()=>{
  const f=await setup();let release,entered;const waiting=new Promise(resolve=>{entered=resolve;});
  const c=f.make({saveRecovery:async r=>{assert.equal(Object.isFrozen(r.packet.integration_readers),true);f.saved.push(structuredClone(r));entered();await new Promise(resolve=>{release=resolve;});}});
  const command=structuredClone(f.command),pending=c.reserve(command);await waiting;
  command.peer='+13';command.integration_readers[0].connector_id=text(uuid(211));command.integration_readers.push(command.integration_readers[0]);
  await assert.rejects(c.reserve(f.command));assert.equal(f.calls.length,0);release();await pending;
  assert.deepEqual(f.calls[0].body,f.command);assert.deepEqual(f.saved[0].packet,f.command);assert.equal(f.calls.length,1);
});

test('post-admission CSRF withdrawal and contradictory reserved ownership are UNKNOWN',async()=>{
  for(const mode of ['csrf','session']){
    const f=await setup();f.response=r=>{if(mode==='csrf')f.cookie='ztc_'+b64(digest(9));
      else{const raw=Uint8Array.from(Buffer.from(r.statement,'base64url'));raw[8+7*16]^=1;r.statement=b64(raw);}return Response.json(r);};
    await assert.rejects(f.make().reserve(f.command),e=>e.outcome==='unknown');assert.equal(f.calls.length,1);assert.equal(f.saved.length,1);
  }
});

test('explicit Stop persists the same revocation identity and passive status never renews or signs',async()=>{
  const f=await setup();f.response=(r,stopped)=>stopped?new Response(null,{status:204}):Response.json(r);const c=f.make();
  await c.stop(f.original.interval_id);assert.equal(f.saved[0].kind,'stop');assert.deepEqual(f.saved[0].packet,{v:1,interval_id:f.original.interval_id});
  assert.deepEqual(f.calls[0].body,f.saved[0].packet);const retained=await c.status(f.original.opening_id,f.original.interval_id);
  assert.equal(retained.phase,'stopped');assert.equal(f.saved.length,1);assert.equal(f.calls.length,2);assert.equal(retained.owner_signature,null);
});

test('closed inputs and noncanonical signatures are rejected before recovery or network admission',async()=>{
  const f=await setup(),c=f.make();
  for(const mutate of [x=>x.extra=true,x=>delete x.peer,x=>x.integration_readers.push(x.integration_readers[0]),x=>x.interval_expires_ms='080000',
    x=>x.peer='+01',x=>Object.defineProperty(x,'peer',{get(){throw Error('getter invoked');}})]){
    const command=structuredClone(f.command);mutate(command);await assert.rejects(c.reserve(command));
  }
  await assert.rejects(c.request({...f.original,owner_signature:b64(new Uint8Array(64))},f.credentials));
  await assert.rejects(c.request(f.original,{...f.credentials,extra:true}));assert.equal(f.saved.length,0);assert.equal(f.calls.length,0);
});
