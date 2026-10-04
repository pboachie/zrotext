// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {createHash,createECDH} from 'node:crypto';
import {test} from 'node:test';
import {setTimeout as delay} from 'node:timers/promises';
import {refreshFixture,signFixtureSuccessor02} from './conversation-refresh-fixture.mjs';
import {verifyManifest02,verifiedManifestTrust02} from '../dist/draft02-manifest.js';
import {sealWorkflowContext,sealIntegrationWorkflowContext} from '../dist/workflow-context.js';
import {keyId} from '../dist/draft01.js';
import {OwnerWorkflowContextClient} from '../dist/owner-workflow-context-client.js';
const hash=b=>createHash('sha256').update(b).digest('hex'),enc=new TextEncoder();
const request='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const json=n=>new Response(JSON.stringify({revision:n}),{headers:{'content-type':'application/json'}});
const binary=b=>new Response(Uint8Array.from(b),{headers:{'content-type':'application/vnd.zrotext.workflow-context.v1'}});
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
async function fixture(overrides={}){
  const f=await refreshFixture(),binding=f.review.binding,controller=new AbortController();
  const scope={kind:1,accountId:Uint8Array.from(binding.account),deviceId:Uint8Array.from(binding.device),lineId:Uint8Array.from(binding.line),intervalId:Uint8Array.from(binding.interval),contextId:new Uint8Array(16).fill(6),bindingGeneration:binding.generation,revision:1n,expiresMs:f.nowMs+300000n,trustGeneration:f.predecessor.generation,manifestVersion:f.predecessor.version,peerDigest:new Uint8Array(createHash('sha256').update(binding.peer).digest()),readerId:Uint8Array.from(binding.archiveReader),manifestDigest:Uint8Array.from(f.predecessor.digest)};
  const state={current:{binding,manifest:f.predecessor,nowMs:f.nowMs,ownerSessionLive:true,consentLive:true,phase:'active',validForMs:60000},csrf:'synthetic-csrf',calls:[],reviews:[],head:null};
  const envelope=await sealWorkflowContext(f.predecessor,scope,f.nowMs,enc.encode('Synthetic owner context private canary'));
  const options={enabled:true,origin:f.origin,selection:{binding,contextId:scope.contextId,kind:1},readCurrent:async()=>state.current,currentCsrf:()=>state.csrf,consumeWriteReview:async r=>{state.reviews.push(r);},signal:controller.signal,fetchImpl:async(url,init)=>{state.calls.push({url,init});if(init.method==='POST'){state.head=new Uint8Array(init.body).slice();return json(Number(new DataView(state.head.buffer).getBigUint64(94)));}return binary(state.head);},...overrides};
  return {f,state,scope,envelope,controller,options,client:new OwnerWorkflowContextClient(options),input:{requestId:request,expectedRevision:0,scope,envelope},async revision(n,manifest=state.current.manifest){const s={...scope,revision:BigInt(n),manifestVersion:manifest.version,manifestDigest:Uint8Array.from(manifest.digest)};return {scope:s,envelope:await sealWorkflowContext(manifest,s,f.nowMs,enc.encode('Synthetic revised local facts'))};}};
}
const rejects=(p,code,state)=>assert.rejects(p,e=>e.code===code&&(!state||e.state===state));
test('owner-only initial authoring and compatible revision use exact browser headers and latest read',async()=>{
  const f=await fixture();try{
    const t=await f.client.prepare(f.input),receipt=await f.client.commit(t);
    assert.equal(receipt.state,'verified_current_snapshot');assert.equal(receipt.requestAcknowledged,true);assert.equal(receipt.envelopeDigest,hash(f.envelope));assert.equal(f.client.pending(),null);
    const call=f.state.calls[0];assert.equal(call.url,'https://owner.invalid/v1/owner/workflow/contexts');
    assert.equal(call.init.credentials,'same-origin');assert.equal(call.init.mode,'same-origin');assert.equal(call.init.redirect,'error');assert.equal(call.init.cache,'no-store');
    assert.equal(call.init.headers['idempotency-key'],request);assert.equal(call.init.headers['x-zrotext-context-revision'],'0');assert.equal(call.init.headers['x-zrotext-csrf'],'synthetic-csrf');
    assert.equal(call.init.headers.Cookie,undefined);assert.equal(call.init.headers.Authorization,undefined);assert.equal(call.init.headers.Origin,undefined);
    assert.equal(Buffer.from(call.init.body).includes(Buffer.from('Synthetic owner context private canary')),false);
    assert.equal(f.state.calls[1].url.endsWith(receipt.contextId),true);assert.equal(f.state.calls[1].url.includes('?'),false);
    const next=await f.revision(2);const t2=await f.client.prepare({...next,requestId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',expectedRevision:1});
    assert.equal((await f.client.commit(t2)).revision,2);assert.equal(f.state.calls[2].init.headers['x-zrotext-context-revision'],'1');
    await rejects(f.client.commit(t),'invalid_ticket');
  }finally{f.client.close();}
});
test('real verified successor supports compatible refresh while stale current header refuses',async()=>{
  const f=await fixture();try{
    await f.client.commit(await f.client.prepare(f.input));
    const successor=await verifyManifest02(await signFixtureSuccessor02(f.f),verifiedManifestTrust02(f.f.predecessor,f.f.nowMs),f.f.nowMs);
    f.state.current={...f.state.current,manifest:successor};const next=await f.revision(2,successor);
    assert.equal((await f.client.commit(await f.client.prepare({...next,requestId:request.replaceAll('a','b'),expectedRevision:1}))).revision,2);
    const stale=await fixture();stale.state.current={...stale.state.current,manifest:successor};
    await assert.rejects(stale.client.prepare(stale.input));assert.equal(stale.state.calls.length,0);stale.client.close();
  }finally{f.client.close();}
});
test('copies ciphertext and scope before awaits and owner review cannot mutate internal data',async()=>{
  const pause=deferred(),f=await fixture({consumeWriteReview:async review=>{review.scope.contextId.fill(9);review.scope.manifestDigest.fill(8);await pause.promise;}});
  try{
    const original=Uint8Array.from(f.envelope),operation=f.client.prepare(f.input);f.input.envelope.fill(7);f.input.scope.contextId.fill(8);pause.resolve();
    const t=await operation;await f.client.commit(t);assert.deepEqual(f.state.head,original);
  }finally{f.client.close();}
});
test('bare conflict is a known refusal while unavailable and malformed success preserve unknown',async()=>{
  for(const [status,body,code,state] of [[409,'','conflict','refused'],[503,'','response_unknown','unknown'],[200,'{"revision":1,"revision":1}','response_unknown','unknown'],[200,'{"revision":"1"}','response_unknown','unknown'],[200,'{"revision":1,"extra":0}','response_unknown','unknown']]){
    const f=await fixture({fetchImpl:async()=>new Response(body,{status,headers:{'content-type':'application/json'}})});
    try{await rejects(f.client.commit(await f.client.prepare(f.input)),code,state);assert.equal(f.client.pending()!==null,state==='unknown');}finally{f.client.close();}
  }
});
test('explicit unknown retry keeps identical request CAS and ciphertext despite transport mutation',async()=>{
  const calls=[];let f;
  f=await fixture({fetchImpl:async(url,init)=>{calls.push({url,init,body:init.body?new Uint8Array(init.body).slice():null});if(init.method==='POST'&&calls.length===1){new Uint8Array(init.body).fill(7);throw Error('Synthetic disconnect');}if(init.method==='POST'){f.state.head=new Uint8Array(init.body).slice();return json(1);}return binary(f.state.head);}});
  try{
    const t=await f.client.prepare(f.input);await rejects(f.client.commit(t),'response_unknown','unknown');assert.ok(f.client.pending());
    await rejects(f.client.prepare(f.input),'pending_write');const receipt=await f.client.retryUnknown(t);assert.equal(receipt.requestAcknowledged,true);
    assert.deepEqual(calls[0].body,calls[1].body);assert.deepEqual(calls[0].init.headers,calls[1].init.headers);assert.equal(calls.length,3);
  }finally{f.client.close();}
});
test('matching latest content does not claim an unknown request acknowledgment',async()=>{
  let f;f=await fixture({fetchImpl:async(_url,init)=>{if(init.method==='POST')throw Error('Synthetic unknown');return binary(f.envelope);}});
  try{const t=await f.client.prepare(f.input);await assert.rejects(f.client.commit(t));const r=await f.client.verifyUnknown(t);assert.equal(r.requestAcknowledged,false);assert.ok(f.client.pending());await rejects(f.client.prepare(f.input),'pending_write');}finally{f.client.close();assert.ok(f.client.pending());}
});
test('later bare refusals and closed deadline cannot erase prior unknown identity',async()=>{
  for(const status of [403,404,409]){
    let count=0;const f=await fixture({fetchImpl:async()=>{if(count++===0)throw Error('Synthetic lost response');return new Response(null,{status});}});
    const t=await f.client.prepare(f.input);await assert.rejects(f.client.commit(t));const before=f.client.pending();await rejects(f.client.retryUnknown(t),'response_unknown','unknown');assert.deepEqual(f.client.pending(),before);f.client.close();assert.deepEqual(f.client.pending(),before);await rejects(f.client.retryUnknown(t),'closed','unknown');
  }
});
test('historical write acknowledgment with a valid newer latest head is never current',async()=>{
  let f,next;f=await fixture({fetchImpl:async(_url,init)=>init.method==='POST'?json(1):binary(next.envelope)});next=await f.revision(2);
  try{await rejects(f.client.commit(await f.client.prepare(f.input)),'head_changed','not_current');assert.equal(f.client.pending(),null);}finally{f.client.close();}
});
test('same-revision altered bytes and newer foreign/malformed heads remain unknown',async()=>{
  for(const edit of ['same_revision','foreign','malformed','wrong_manifest']){
    let f,next;f=await fixture({fetchImpl:async(_url,init)=>init.method==='POST'?json(1):binary(next)});
    next=edit==='same_revision'?Uint8Array.from(f.envelope):(await f.revision(2)).envelope;
    if(edit==='same_revision')next[next.length-1]^=1;if(edit==='foreign')next[70]^=1;if(edit==='malformed')next[287]^=1;if(edit==='wrong_manifest')next[190]^=1;
    try{await rejects(f.client.commit(await f.client.prepare(f.input)),'response_unknown','unknown');assert.ok(f.client.pending());}finally{f.client.close();}
  }
});
test('unverified manifest, foreign reader and immutable scope refuse before HTTP',async()=>{
  for(const field of ['reader','scope','manifest','boolean']){
    const f=await fixture();if(field==='reader')f.input.scope.readerId=new Uint8Array(32).fill(9);
    if(field==='scope')f.input.scope.intervalId=new Uint8Array(16).fill(9);if(field==='manifest')f.state.current={...f.state.current,manifest:{...f.state.current.manifest}};
    if(field==='boolean')f.state.current={...f.state.current,manifest:null};
    try{await assert.rejects(f.client.prepare(f.input));assert.equal(f.state.calls.length,0);}finally{f.client.close();}
  }
});

test('a valid signed role3 envelope cannot alias owner archive authority',async()=>{
  const f=await fixture(),key=createECDH('prime256v1'),scalar=new Uint8Array(32);scalar[31]=7;key.setPrivateKey(scalar);scalar.fill(0);
  const point=new Uint8Array(key.getPublicKey(undefined,'uncompressed')),reader=await keyId(0x10,point);
  const unsigned=f.f.review.unsigned,record=Uint8Array.from(unsigned.slice(300,449));record[0]=3;record.set(reader,1);record.set(point,33);record[131]=8;
  const extended=new Uint8Array(unsigned.length+149);extended.set(unsigned.slice(0,449));extended.set(record,449);extended.set(unsigned.slice(449),598);extended[150]++;
  const manifest=await verifyManifest02(await signFixtureSuccessor02(f.f,extended),verifiedManifestTrust02(f.f.predecessor,f.f.nowMs),f.f.nowMs);
  const binding={...f.state.current.binding,archiveReader:reader},scope={...f.scope,readerId:reader,manifestVersion:manifest.version,manifestDigest:manifest.digest};
  const envelope=await sealIntegrationWorkflowContext(manifest,scope,f.f.nowMs,enc.encode('Synthetic independently encrypted integration context'));
  const client=new OwnerWorkflowContextClient({...f.options,selection:{binding,contextId:scope.contextId,kind:1},readCurrent:async()=>({...f.state.current,binding,manifest})});
  try{await assert.rejects(client.prepare({...f.input,scope,envelope}));assert.equal(f.state.calls.length,0);assert.equal(f.state.reviews.length,0);}finally{client.close();f.client.close();}
});

test('throwing or held owner callbacks close authority before HTTP',async()=>{
  const failure=await fixture({readCurrent:async()=>{throw Error('Synthetic custody unavailable');}});
  await rejects(failure.client.prepare(failure.input),'owner_changed');await rejects(failure.client.prepare(failure.input),'closed');assert.equal(failure.state.calls.length,0);
  const csrf=await fixture({currentCsrf:()=>{throw Error('Synthetic session unavailable');}});
  await rejects(csrf.client.prepare(csrf.input),'owner_changed');await rejects(csrf.client.prepare(csrf.input),'closed');assert.equal(csrf.state.calls.length,0);
  const pause=deferred(),held=await fixture({timeoutMs:20,readCurrent:async()=>pause.promise});
  await rejects(held.client.prepare(held.input),'expired');pause.resolve(held.state.current);assert.equal(held.state.calls.length,0);held.client.close();
});

test('unknown verification has a finite ceiling and redirect responses never confer authority',async()=>{
  let f;f=await fixture({fetchImpl:async(_url,init)=>init.method==='POST'?new Response(null,{status:503}):binary(f.envelope)});
  const ticket=await f.client.prepare(f.input);await rejects(f.client.commit(ticket),'response_unknown','unknown');
  for(let n=0;n<3;n++)assert.equal((await f.client.verifyUnknown(ticket)).requestAcknowledged,false);
  await rejects(f.client.verifyUnknown(ticket),'attempts_exhausted','unknown');assert.ok(f.client.pending());f.client.close();
  const redirected=await fixture({fetchImpl:async()=>{const response=json(1);Object.defineProperty(response,'redirected',{value:true});return response;}});
  try{await rejects(redirected.client.commit(await redirected.client.prepare(redirected.input)),'response_unknown','unknown');assert.ok(redirected.client.pending());}finally{redirected.client.close();}
});
test('strict closed request and wire bounds refuse before owner review and network',async()=>{
  for(const edit of [v=>v.extra=true,v=>v.expectedRevision=128,v=>v.expectedRevision=1,v=>v.requestId='not-a-uuid',v=>v.envelope=new Uint8Array(33076),v=>v.envelope[0]=0,v=>v.envelope[222]=0,v=>v.envelope[287]^=1,v=>Object.defineProperty(v,'requestId',{get(){throw Error('Getter must not run');}})]){
    const f=await fixture();edit(f.input);try{await assert.rejects(f.client.prepare(f.input));assert.equal(f.state.calls.length,0);assert.equal(f.state.reviews.length,0);}finally{f.client.close();}
  }
});
test('close and supplied visibility-linked abort prevent late review or response publication',async()=>{
  for(const phase of ['review','post']){
    const pause=deferred(),entered=deferred();let f;
    f=await fixture(phase==='review'?{consumeWriteReview:async()=>{entered.resolve();await pause.promise;}}:{fetchImpl:async(_url,init)=>{entered.resolve();await pause.promise;return init.method==='POST'?json(1):binary(f.envelope);}});
    const operation=phase==='review'?f.client.prepare(f.input):f.client.commit(await f.client.prepare(f.input));const rejected=assert.rejects(operation);await entered.promise;f.controller.abort();pause.resolve();await rejected;assert.equal(f.client.pending()!==null,phase==='post');
  }
});
test('finite original deadline and identical retry ceiling cannot be renewed',async()=>{
  const pause=deferred(),short=await fixture({timeoutMs:20,consumeWriteReview:async()=>pause.promise});const rejected=rejects(short.client.prepare(short.input),'expired');await rejected;pause.resolve();assert.equal(short.state.calls.length,0);short.client.close();
  const f=await fixture({fetchImpl:async()=>{throw Error('Synthetic unknown');}});
  try{const t=await f.client.prepare(f.input);await assert.rejects(f.client.commit(t));await assert.rejects(f.client.retryUnknown(t));await assert.rejects(f.client.retryUnknown(t));await rejects(f.client.retryUnknown(t),'attempts_exhausted','unknown');assert.ok(f.client.pending());}finally{f.client.close();}
});

test('idle prepared ciphertext expires without a later operation',async()=>{
  const f=await fixture({timeoutMs:1000}),nativeClose=f.client.close.bind(f.client);let closes=0;
  f.client.close=()=>{closes++;nativeClose();};
  const ticket=await f.client.prepare(f.input);
  await delay(1100);assert.equal(closes,1);assert.equal(f.state.calls.length,0);assert.equal(f.client.pending(),null);
  await rejects(f.client.commit(ticket),'invalid_ticket');await rejects(f.client.prepare(f.input),'expired');
});

test('idle unknown expiry aborts transport without renewing on retry or erasing identity',async()=>{
  let signal,calls=0;const f=await fixture({timeoutMs:1000,fetchImpl:async(_url,init)=>{signal=init.signal;calls++;throw Error('Synthetic unknown');}});
  const ticket=await f.client.prepare(f.input);await rejects(f.client.commit(ticket),'response_unknown','unknown');const pending=f.client.pending();
  await delay(350);await rejects(f.client.retryUnknown(ticket),'response_unknown','unknown');assert.equal(signal.aborted,false);
  await delay(800);assert.equal(signal.aborted,true);assert.equal(calls,2);assert.deepEqual(f.client.pending(),pending);
  await rejects(f.client.retryUnknown(ticket),'expired','unknown');await rejects(f.client.prepare(f.input),'pending_write');
});

test('authentic active line signer expiry caps idle lifetime even with cached authenticated time',async()=>{
  let signal;const f=await fixture({fetchImpl:async(_url,init)=>{signal=init.signal;throw Error('Synthetic unknown');}});
  const unsigned=Uint8Array.from(f.f.review.unsigned);
  // Role4 is the third ordered record; its signed untilMs is the shortest authority.
  new DataView(unsigned.buffer).setBigUint64(449+140,f.f.nowMs+1500n);
  const manifest=await verifyManifest02(await signFixtureSuccessor02(f.f,unsigned),verifiedManifestTrust02(f.f.predecessor,f.f.nowMs),f.f.nowMs);
  f.state.current={...f.state.current,manifest};const input=await f.revision(1,manifest),ticket=await f.client.prepare({...input,requestId:request,expectedRevision:0});
  await rejects(f.client.commit(ticket),'response_unknown','unknown');const pending=f.client.pending();
  await delay(1600);assert.equal(f.state.current.nowMs,f.f.nowMs);assert.equal(signal.aborted,true);assert.deepEqual(f.client.pending(),pending);
  await rejects(f.client.retryUnknown(ticket),'expired','unknown');
});
test('single operation, opaque client-owned ticket and bounded latest stream refuse unsafe publication',async()=>{
  const pause=deferred(),f=await fixture({consumeWriteReview:async()=>pause.promise});const pending=f.client.prepare(f.input);await rejects(f.client.prepare(f.input),'pending_write');pause.resolve();const t=await pending;
  const foreign=await fixture();await rejects(foreign.client.commit(t),'invalid_ticket');foreign.client.close();f.client.close();
  for(const response of [()=>new Response(new Uint8Array(33076),{headers:{'content-type':'application/vnd.zrotext.workflow-context.v1'}}),()=>new Response(new Uint8Array(308),{headers:{'content-type':'application/json'}})]){
    const g=await fixture({fetchImpl:async(_url,init)=>init.method==='POST'?json(1):response()});try{await rejects(g.client.commit(await g.client.prepare(g.input)),'response_unknown','unknown');assert.ok(g.client.pending());}finally{g.client.close();}
  }
});
test('CSRF or current owner changes during review prevent HTTP and cannot substitute a boolean grant',async()=>{
  for(const mutation of [f=>f.state.csrf='changed',f=>f.state.current={...f.state.current,ownerSessionLive:false},f=>f.state.current={...f.state.current,phase:'history'},f=>f.state.current={...f.state.current,binding:{...f.state.current.binding,session:new Uint8Array(16).fill(9)}}]){
    let f;f=await fixture({consumeWriteReview:async()=>mutation(f)});try{await assert.rejects(f.client.prepare(f.input));assert.equal(f.state.calls.length,0);}finally{f.client.close();}
  }
});
