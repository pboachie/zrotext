// SPDX-License-Identifier: AGPL-3.0-only
// ORDINARY CONTROLLED FIXTURES ONLY: actual new consumer, unchanged author,
// actual SDK signature verification/HPKE/archive recovery; synthetic signed
// manifest, DOM/current/auth/HTTP and deterministic archive fixture material.
// These cannot prove server admission, a mounted pair, PG or deployed UI.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {archiveFixture} from './conversation-archive-fixture.mjs';
import {unlockExistingArchive02} from '../dist/conversation-archive-custody.js';
import {createAcknowledgedOpeningConsumer} from '../dist/owner-acknowledged-opening-consumer.js';

const canary='Synthetic consumer facts <literal> Ω',media='application/vnd.zrotext.workflow-context.v1';
const requestId='0a0a0a0a-0a0a-0a0a-0a0a-0a0a0a0a0a0a',openingId='0b0b0b0b-0b0b-0b0b-0b0b-0b0b0b0b0b0b';
const uuid=b=>Buffer.from(b).toString('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
const digest=b=>new Uint8Array(createHash('sha256').update(b).digest());
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};

// Minimal controlled DOM dispatches actual capture/target/bubble listeners.
// It supplies no author receipt, private author state or authority factory.
class Target {
  listeners=[];
  addEventListener(name,fn,options=false){this.listeners.push({name,fn,capture:options===true||options?.capture===true});}
  removeEventListener(name,fn,options=false){const capture=options===true||options?.capture===true;this.listeners=this.listeners.filter(v=>v.name!==name||v.fn!==fn||v.capture!==capture);}
  dispatchEvent(event){return this.emit(event.type);}
  emit(type){
    const path=[];for(let p=this;p;p=p.parent)path.push(p);
    let stopped=false,prevented=false;const event={type,target:this,preventDefault(){prevented=true;},stopImmediatePropagation(){stopped=true;}};
    for(const node of [...path].reverse())for(const l of [...node.listeners])if(l.name===type&&l.capture&&!stopped)l.fn(event);
    for(const node of path)for(const l of [...node.listeners])if(l.name===type&&!l.capture&&!stopped)l.fn(event);
    return !prevented;
  }
}
class Element extends Target {
  constructor(document,tag){super();this.ownerDocument=document;this.tagName=tag;this.nodeType=1;this.children=[];this.value='';this.hidden=false;this.disabled=false;this.attributes={};this._text='';}
  append(...children){for(const child of children){child.parent=this;this.children.push(child);}}
  replaceChildren(...children){this.children=[];this._text='';this.append(...children);}
  setAttribute(name,value){this.attributes[name]=value;}
  getAttribute(name){return this.attributes[name]??null;}
  set textContent(value){this._text=value;this.children=[];}
  get textContent(){return this._text+this.children.map(c=>c.textContent).join('');}
  get lastElementChild(){return this.children.at(-1)??null;}
  querySelectorAll(tag){return this.children.flatMap(c=>[...(c.tagName===tag?[c]:[]),...c.querySelectorAll(tag)]);}
  querySelector(tag){return this.querySelectorAll(tag)[0]??null;}
}
const all=e=>[e,...e.children.flatMap(all)];
async function until(check,deadline){
  while(performance.now()<deadline){if(check())return;await delay(Math.min(5,Math.max(0,deadline-performance.now())));}
  assert.ok(check(),'Expected condition inside its original fixed deadline');
}
function json(value){return new Response(JSON.stringify(value),{headers:{'content-type':'application/json'}});}
function receipt(){return {opening:{opening_id:openingId,definition_version:'9007199254740993',state_version:'1'},offer:null,allocation_id:null,allocation_version:null,phase:'open',pending:'0',confirmed:'0'};}
function contextResponse(bytes,url,options={}){
  const response=new Response(bytes,{headers:{'content-type':media},...options});
  // Synthetic response endpoint metadata; never counted as mounted HTTP proof.
  Object.defineProperty(response,'url',{value:url});return response;
}
async function fixture({construct=true,budget=10000,observation=10000,leaseMode='normal'}={}){
  // All fixture crypto/recovery and independent Expected computation precede B.
  const af=await archiveFixture(),lease=await unlockExistingArchive02(af.options);
  const window=new Target(),document=new Target();window.location={origin:af.origin};document.defaultView=window;document.hidden=false;
  document.createElement=tag=>new Element(document,tag);const host=new Element(document,'main');
  const listeners={setup:[],custody:[]},subscribe=name=>listener=>{listeners[name].push(listener);return()=>{listeners[name]=listeners[name].filter(v=>v!==listener);};};
  const state={currentReads:0,keyCalls:0,head:null,sourcePosts:0,gets:0,openingCalls:[],reviews:[],csrf:'synthetic-csrf',authorUnknown:false,transport:null,consumerGet:null,forbidCurrent:false,forbidKey:false};
  const binding=Object.fromEntries(Object.entries(af.review.binding).map(([k,v])=>[k,v instanceof Uint8Array?Uint8Array.from(v):v]));
  const contextId=new Uint8Array(16).fill(6),expires=af.nowMs+300000n;
  const readCurrent=async()=>{state.currentReads++;assert.equal(state.forbidCurrent,false,'Unexpected authority reread');return af.state.current;};
  const wrappedLease=Object.freeze({onClose:listener=>lease.onClose(listener),close:()=>lease.close(),async withKey(selected,run){
    state.keyCalls++;assert.equal(state.forbidKey,false,'Unexpected key reread');
    if(leaseMode==='skip')return new TextEncoder().encode(canary);
    if(leaseMode==='held')return lease.withKey(selected,async key=>{state.keyEntered.resolve();await state.keyRelease.promise;return run(key);});
    const actual=await lease.withKey(selected,run);
    if(leaseMode==='twice')try{await lease.withKey(selected,run);}catch{}
    // Arbitrary lease returns cannot replace actual callback plaintext.
    return leaseMode==='substituted_return'?new Uint8Array([9]):actual;
  }});
  const scope={kind:1,accountId:Uint8Array.from(binding.account),deviceId:Uint8Array.from(binding.device),lineId:Uint8Array.from(binding.line),intervalId:Uint8Array.from(binding.interval),contextId:Uint8Array.from(contextId),bindingGeneration:binding.generation,revision:1n,expiresMs:expires,trustGeneration:af.predecessor.generation,manifestVersion:af.predecessor.version,peerDigest:digest(Buffer.from(binding.peer)),readerId:Uint8Array.from(binding.archiveReader),manifestDigest:Uint8Array.from(af.predecessor.digest)};
  const fetchImpl=async(url,init)=>{
    if(url.endsWith('/workflow/contexts')&&init.method==='POST'){
      state.sourcePosts++;state.head=new Uint8Array(init.body).slice();return state.authorUnknown?new Response(null,{status:503}):json({revision:1});
    }
    if(url.includes('/workflow/contexts/')&&init.method==='GET'){
      state.gets++;if(state.consumerGet)return state.consumerGet(url,init);
      return contextResponse(Uint8Array.from(state.head),url);
    }
    state.openingCalls.push({url,init,body:init.body});
    if(state.transport)return state.transport(url,init);
    if(url.endsWith('/status'))return json({account_id:uuid(af.review.binding.account),receipt:receipt()});
    return json({account_id:uuid(af.review.binding.account),request_id:requestId,outcome:{receipt:receipt(),applied:true,recorded:true}});
  };
  const options={authorOptions:{enabled:true,origin:af.origin,host,binding,contextId,expiresMs:expires,readCurrent,currentCsrf:()=>state.csrf,archiveLease:wrappedLease,onSetupClose:subscribe('setup'),onCustodyClose:subscribe('custody'),signal:af.controller.signal,timeoutMs:10000,observationMs:observation,fetchImpl},expectedScope:scope,expectedContentDigest:digest(Buffer.from(canary)),sourceWindowMs:budget,totalTimeoutMs:budget,observationTimeoutMs:10000,attemptTimeoutMs:10000,maxAttempts:3,consumeCreateReview:async review=>state.reviews.push(review)};
  const f={af,lease,host,document,window,listeners,state,options,consumer:null,constructedAt:null,cutoff:null};
  f.construct=()=>{f.constructedAt=performance.now();f.cutoff=f.constructedAt+budget;f.consumer=createAcknowledgedOpeningConsumer(options);Object.defineProperty(f,'constructorReturnedAt',{value:performance.now(),enumerable:true});return f.consumer;};
  f.button=text=>all(host).find(e=>e.tagName==='button'&&e.textContent===text);
  f.status=()=>all(host).find(e=>e.attributes?.role==='status')?.textContent??'';
  f.input=()=>({requestId,openingId,capacity:3,decisionDeadlineMs:af.nowMs+5000n});
  f.save=async()=>{
    await f.consumer.initialize();host.querySelector('textarea').value=canary;f.button('Review facts').emit('click');
    await until(()=>f.status()==='Review these facts before saving.',f.cutoff);f.button('Save encrypted facts').emit('click');
    await until(()=>f.status().startsWith('Encrypted facts saved')||f.status().startsWith('Save outcome unknown'),f.cutoff);
  };
  f.prepare=()=>f.consumer.prepareCreate(f.input());
  f.close=()=>{f.consumer?.close();lease.close();af.controller.abort();};
  if(construct)f.construct();return f;
}

test('controlled actual consumer gates Review and constructs the unchanged author without automatic I/O',async()=>{
  const f=await fixture();try{
    assert.equal(f.state.currentReads+f.state.keyCalls+f.state.sourcePosts,0);assert.deepEqual(Object.keys(f.consumer).sort(),['close','create','initialize','prepareCreate','retry','state','status']);
    f.host.querySelector('textarea').value=canary;f.button('Review facts').emit('click');await delay(0);
    assert.equal(f.status(),'Enter facts for your selected conversation.');assert.equal(f.state.currentReads+f.state.sourcePosts,0);
    await f.save();assert.equal(f.state.sourcePosts,1);assert.equal(f.state.keyCalls,0);
  }finally{f.close();}
});

test('closed constructor refuses injected authors, accessors and mismatched joint budgets before mounting or callbacks',async()=>{
  for(const change of [o=>o.author={},o=>o.sourceWindowMs=10001,o=>o.authorOptions.observationMs=500,o=>delete o.authorOptions.timeoutMs,o=>o.expectedScope.intervalId=new Uint8Array(16).fill(9),o=>o.expectedScope.kind=2,o=>Object.defineProperty(o,'expectedContentDigest',{get(){throw Error('Accessor must not run');}})]){
    const f=await fixture({construct:false});try{change(f.options);assert.throws(f.construct);assert.equal(f.host.children.length,0);assert.equal(f.state.currentReads+f.state.keyCalls+f.state.sourcePosts,0);}finally{f.close();}
  }
});

test('controlled true author ACK GET and real recovered-key HPKE precede one shorter opening and metadata status',async()=>{
  const f=await fixture();try{
    await f.save();const ticket=await f.prepare();assert.ok(Object.isFrozen(ticket));assert.equal(f.state.keyCalls,1);assert.equal(f.state.openingCalls.length,0);assert.equal(f.state.reviews.length,1);
    assert.equal(Buffer.from(f.state.head).includes(Buffer.from(canary)),false);
    const result=await f.consumer.create(ticket);assert.equal(result.state,'acknowledged');assert.equal(result.applied,true);assert.equal(result.receipt.opening.definition_version,9007199254740993n);
    const call=f.state.openingCalls[0],body=JSON.parse(call.body);assert.equal(body.decision_deadline_ms,(f.af.nowMs+5000n).toString());assert.ok(BigInt(body.decision_deadline_ms)<f.options.authorOptions.expiresMs);
    assert.equal(body.description.context_id,uuid(new Uint8Array(16).fill(6)));assert.equal(body.description.digest,Buffer.from(digest(f.state.head)).toString('hex'));
    assert.equal(call.init.headers['x-zrotext-opening-account'],uuid(f.af.review.binding.account));assert.equal(call.init.headers.Authorization,undefined);assert.equal(call.init.credentials,'same-origin');assert.equal(call.init.redirect,'error');assert.equal(call.init.cache,'no-store');
    assert.equal((await f.consumer.status(openingId)).state,'metadata_snapshot');assert.equal(JSON.stringify(result,(_k,v)=>typeof v==='bigint'?v.toString():v).includes(canary),false);
    assert.equal((await f.consumer.create(ticket)).state,'refused');await assert.rejects(f.prepare());assert.equal(f.state.openingCalls.length,2);
  }finally{f.close();}
});

test('constructor copies caller Expected and binding bytes before initialize awaits',async()=>{
  const f=await fixture();try{
    f.options.authorOptions.binding.account.fill(9);f.options.authorOptions.contextId.fill(9);f.options.expectedScope.accountId.fill(9);f.options.expectedScope.manifestDigest.fill(9);f.options.expectedContentDigest.fill(9);
    await f.save();assert.equal((await f.consumer.create(await f.prepare())).state,'acknowledged');assert.equal(JSON.parse(f.state.openingCalls[0].body).description.context_id,uuid(new Uint8Array(16).fill(6)));
  }finally{f.close();}
});

test('actual author UNKNOWN never supplies a prepared opening or invokes the key callback',async()=>{
  const f=await fixture();try{f.state.authorUnknown=true;await f.save();const reads=f.state.currentReads;await assert.rejects(f.prepare());assert.equal(f.state.currentReads,reads);assert.equal(f.state.keyCalls+f.state.openingCalls.length,0);}finally{f.close();}
});

test('independent wrong content digest fails after actual HPKE without opening POST',async()=>{
  const f=await fixture({construct:false});try{f.options.expectedContentDigest=digest(Buffer.from('Different independent intended facts'));f.construct();await f.save();await assert.rejects(f.prepare());assert.equal(f.state.keyCalls,1);assert.equal(f.state.openingCalls.length,0);}finally{f.close();}
});

test('final explicit opening review changes cannot dispatch a prepared operation',async()=>{
  for(const cause of ['csrf','close','clock']){const f=await fixture({construct:false});try{
    f.options.consumeCreateReview=async()=>{if(cause==='csrf')f.state.csrf='changed-review-csrf';if(cause==='close')f.consumer.close();if(cause==='clock')f.af.state.current={...f.af.state.current,nowMs:f.af.nowMs+6000n};};
    f.construct();await f.save();await assert.rejects(f.prepare());assert.equal(f.state.openingCalls.length,0);assert.equal(f.state.keyCalls,1);
  }finally{f.close();}}
});

test('held late consumer GET and cancellation retain ownership through actual settlement',async()=>{
  const f=await fixture(),arrival=deferred(),cancelRelease=deferred();let streamController,cancelled=0;try{
    await f.save();f.state.consumerGet=async url=>contextResponse(new ReadableStream({start(c){streamController=c;},pull(){arrival.resolve();},async cancel(){cancelled++;await cancelRelease.promise;}},{highWaterMark:0}),url);
    const prepare=f.prepare(),rejected=assert.rejects(prepare);await arrival.promise;f.consumer.close();await rejected;
    assert.equal(f.consumer.state().busy,true);assert.equal(f.state.keyCalls+f.state.openingCalls.length,0);
    streamController.enqueue(Uint8Array.from(f.state.head));await delay(0);assert.equal(cancelled,1);assert.equal(f.consumer.state().busy,true);
    cancelRelease.resolve();await until(()=>!f.consumer.state().busy,f.cutoff+1000);assert.equal(f.consumer.state().closed,true);assert.equal(f.state.keyCalls+f.state.openingCalls.length,0);
  }finally{cancelRelease.resolve();f.close();}
});

test('private reverified signed bytes control ceilings despite mutable public manifest fields',async()=>{
  const f=await fixture();try{
    f.af.state.current.manifest.expiresMs=f.af.nowMs+1n;for(const k of f.af.state.current.manifest.keys)k.untilMs=f.af.nowMs+1n;
    await f.save();assert.equal((await f.consumer.create(await f.prepare())).state,'acknowledged');
  }finally{f.close();}
  const g=await fixture();try{g.af.state.current.manifest.bytes.fill(0);await assert.rejects(g.consumer.initialize());assert.equal(g.state.sourcePosts+g.state.keyCalls+g.state.openingCalls.length,0);}finally{g.close();}
});

test('skipped and repeated key callbacks cannot manufacture HPKE success from a lease return',async()=>{
  for(const leaseMode of ['skip','twice']){const f=await fixture({leaseMode});try{await f.save();await assert.rejects(f.prepare());assert.equal(f.state.openingCalls.length,0);}finally{f.close();}}
  const f=await fixture({leaseMode:'substituted_return'});try{await f.save();assert.ok(await f.prepare());assert.equal(f.state.keyCalls,1);assert.equal(f.state.openingCalls.length,0);}finally{f.close();}
});

test('a substituted private key reaches actual HPKE authentication and cannot produce an opening',async()=>{
  const f=await fixture({construct:false});let callbacks=0;try{
    // Deliberately structural NEGATIVE lease, not a claimed recovery positive.
    const wrong=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
    const real=f.options.authorOptions.archiveLease;
    f.options.authorOptions.archiveLease=Object.freeze({onClose:real.onClose,close:real.close,withKey:async(_selected,run)=>{callbacks++;return run(wrong.privateKey);}});
    f.construct();await f.save();await assert.rejects(f.prepare());assert.equal(callbacks,1);assert.equal(f.state.openingCalls.length,0);
  }finally{f.close();}
});

test('new preparation refuses changed authenticated scope before consuming context ciphertext',async()=>{
  for(const cause of ['account','session','owner','consent']){const f=await fixture();try{
    await f.save();const before=f.state.gets;
    if(cause==='account'||cause==='session')f.af.state.current={...f.af.state.current,binding:{...f.af.state.current.binding,[cause]:new Uint8Array(16).fill(9)}};
    if(cause==='owner')f.af.state.current={...f.af.state.current,ownerSessionLive:false};if(cause==='consent')f.af.state.current={...f.af.state.current,consentLive:false};
    await assert.rejects(f.prepare());assert.equal(f.state.gets,before);assert.equal(f.state.keyCalls+f.state.openingCalls.length,0);
  }finally{f.close();}}
});

test('consumer GET refuses cap plus one and wrong endpoint or media before key use',async()=>{
  for(const cause of ['oversize','endpoint','media','ciphertext']){const f=await fixture();let cancelled=0;try{
    await f.save();f.state.consumerGet=async url=>{
      if(cause==='oversize')return contextResponse(new ReadableStream({start(c){c.enqueue(new Uint8Array(33076));},cancel(){cancelled++;}}),url);
      if(cause==='endpoint')return contextResponse(f.state.head,url+'?other=1');
      if(cause==='media')return contextResponse(f.state.head,url,{headers:{'content-type':'application/octet-stream'}});
      const bytes=Uint8Array.from(f.state.head);bytes[bytes.length-1]^=1;return contextResponse(bytes,url);
    };
    await assert.rejects(f.prepare());assert.equal(f.state.keyCalls+f.state.openingCalls.length,0);if(cause==='oversize')assert.equal(cancelled,1);
  }finally{f.close();}}
});

test('control UNKNOWN replay keeps exact original body and performs zero current or key reads',async()=>{
  const f=await fixture();try{
    await f.save();const ticket=await f.prepare();f.state.transport=async()=>f.state.openingCalls.length===1?new Response(null,{status:503}):json({account_id:uuid(f.af.review.binding.account),request_id:requestId,outcome:{receipt:receipt(),applied:false,recorded:true}});
    assert.equal((await f.consumer.create(ticket)).state,'unknown');const before={current:f.state.currentReads,key:f.state.keyCalls,gets:f.state.gets};f.state.forbidCurrent=f.state.forbidKey=true;
    const result=await f.consumer.retry(ticket);assert.equal(result.state,'acknowledged');assert.equal(result.applied,false);assert.deepEqual({current:f.state.currentReads,key:f.state.keyCalls,gets:f.state.gets},before);
    assert.equal(f.state.openingCalls[0].body,f.state.openingCalls[1].body);assert.deepEqual(f.state.openingCalls[0].init.headers,f.state.openingCalls[1].init.headers);
  }finally{f.close();}
});

test('UNKNOWN changed CSRF refuses replay POST while separate status uses current CSRF',async()=>{
  const f=await fixture();try{
    await f.save();const ticket=await f.prepare();f.state.transport=async(url)=>url.endsWith('/status')?json({account_id:uuid(f.af.review.binding.account),receipt:receipt()}):new Response(null,{status:503});
    assert.equal((await f.consumer.create(ticket)).state,'unknown');f.state.csrf='changed-synthetic-csrf';const before=f.state.openingCalls.length;
    assert.equal((await f.consumer.retry(ticket)).state,'unknown');assert.equal(f.state.openingCalls.length,before);
    assert.equal((await f.consumer.status(openingId)).state,'metadata_snapshot');assert.equal(f.state.openingCalls.at(-1).init.headers['x-zrotext-csrf'],'changed-synthetic-csrf');
  }finally{f.close();}
});

test('create retry and status consume one inherited three-dispatch budget',async()=>{
  const f=await fixture();try{
    await f.save();const ticket=await f.prepare();f.state.transport=async(url)=>url.endsWith('/status')?json({account_id:uuid(f.af.review.binding.account),receipt:receipt()}):new Response(null,{status:503});
    assert.equal((await f.consumer.create(ticket)).state,'unknown');assert.equal((await f.consumer.retry(ticket)).state,'unknown');await f.consumer.status(openingId);
    const before=f.state.openingCalls.length;assert.equal(before,3);assert.equal((await f.consumer.retry(ticket)).state,'unknown');assert.equal(f.state.openingCalls.length,before);
  }finally{f.close();}
});

test('fake and other-consumer tickets cannot dispatch or replace an acknowledged identity',async()=>{
  const f=await fixture(),g=await fixture();try{
    await f.save();await g.save();const ticket=await f.prepare();await g.prepare();
    assert.equal((await g.consumer.create(ticket)).state,'refused');assert.equal((await f.consumer.create(Object.freeze({kind:'acknowledged_opening'}))).state,'refused');
    assert.equal(f.state.openingCalls.length+g.state.openingCalls.length,0);assert.equal((await f.consumer.create(ticket)).state,'acknowledged');
    assert.equal((await f.consumer.create(ticket)).state,'refused');assert.equal(f.state.openingCalls.length,1);
  }finally{f.close();g.close();}
});

test('actual Clear and setup custody page lifecycle closes both owned objects without ticket revival',async()=>{
  for(const cause of ['clear','setup','custody','pagehide','hidden','input']){const f=await fixture();try{
    await f.save();const ticket=await f.prepare();
    if(cause==='clear')f.button('Clear').emit('click');if(cause==='setup'||cause==='custody')for(const listener of [...f.listeners[cause]])listener();
    if(cause==='pagehide')f.window.emit('pagehide');if(cause==='hidden'){f.document.hidden=true;f.document.emit('visibilitychange');}if(cause==='input')f.host.querySelector('textarea').emit('input');
    assert.equal(f.consumer.state().closed,true);assert.ok(f.status().includes('Facts editor closed'));assert.equal((await f.consumer.create(ticket)).state,'refused');assert.equal(f.state.openingCalls.length,0);
  }finally{f.close();}}
});

test('held actual lease callback stays charged through close and cannot publish a late ticket',async()=>{
  const f=await fixture({leaseMode:'held'});try{
    f.state.keyEntered=deferred();f.state.keyRelease=deferred();await f.save();const prepare=f.prepare();const rejected=assert.rejects(prepare);
    await f.state.keyEntered.promise;f.consumer.close();await rejected;assert.equal(f.consumer.state().busy,true);assert.equal(f.state.openingCalls.length,0);
    f.state.keyRelease.resolve();await until(()=>!f.consumer.state().busy,f.cutoff+1000);assert.equal(f.consumer.state().closed,true);assert.equal(f.state.openingCalls.length,0);await assert.rejects(f.prepare());
  }finally{f.state.keyRelease?.resolve();f.close();}
});

test('original 500ms configured horizon closes independently while uncertain transport remains held',async()=>{
  const f=await fixture({budget:500,observation:500}),gate=deferred();try{
    await f.save();const ticket=await f.prepare();f.state.transport=async()=>f.state.openingCalls.length===1?new Response(null,{status:503}):gate.promise;
    assert.equal((await f.consumer.create(ticket)).state,'unknown');const reads={current:f.state.currentReads,key:f.state.keyCalls,gets:f.state.gets};f.state.forbidCurrent=f.state.forbidKey=true;
    const replay=f.consumer.retry(ticket);await until(()=>f.state.openingCalls.length===2,f.cutoff);
    // Constructor-return upper bound plus the same original 500ms and one turn.
    await delay(Math.max(0,f.constructorReturnedAt+500-performance.now()));await delay(0);
    assert.equal(f.consumer.state().closed,true);assert.equal(f.consumer.state().busy,true);assert.deepEqual({current:f.state.currentReads,key:f.state.keyCalls,gets:f.state.gets},reads);
    assert.equal((await replay).state,'unknown');assert.equal(f.consumer.state().pending.requestId,requestId);
    gate.resolve(json({account_id:uuid(f.af.review.binding.account),request_id:requestId,outcome:{receipt:receipt(),applied:false,recorded:true}}));
    await until(()=>!f.consumer.state().busy,f.cutoff+1000);assert.equal((await f.consumer.retry(ticket)).state,'unknown');assert.equal(f.state.openingCalls.length,2);
  }finally{gate.resolve(new Response(null,{status:503}));f.close();}
});

test('typing and delayed Review consume the original constructor window rather than starting a new one',async()=>{
  const f=await fixture({budget:50,observation:50});try{
    await delay(Math.max(0,f.constructorReturnedAt+50-performance.now()));await delay(0);assert.equal(f.consumer.state().closed,true);
    f.button('Review facts').emit('click');assert.equal(f.state.sourcePosts+f.state.currentReads+f.state.keyCalls,0);await assert.rejects(f.consumer.initialize());
  }finally{f.close();}
});
