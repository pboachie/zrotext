// SPDX-License-Identifier: AGPL-3.0-only
// Real SDK manifests/HPKE/author/client; controlled responses are synthetic HTTP, not server/PG.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {setTimeout as delay} from 'node:timers/promises';
import {createHash} from 'node:crypto';
import {refreshFixture,signFixtureSuccessor02} from './conversation-refresh-fixture.mjs';
import {verifyManifest02,verifiedManifestTrust02} from '../dist/draft02-manifest.js';
import {createOwnerContextAuthoring} from '../dist/owner-context-authoring.js';
import {createOwnerOpeningCapacityClient} from '../dist/owner-opening-capacity-client.js';
const uuid=b=>Buffer.from(b).toString('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
const requestId=uuid(new Uint8Array(16).fill(10)),openingId=uuid(new Uint8Array(16).fill(11));
const max=((1n<<63n)-1n).toString();
class Element extends EventTarget {
  constructor(document,tag){super();this.ownerDocument=document;this.tagName=tag;this.nodeType=1;this.children=[];this.value='';this.textContent='';this.hidden=false;this.disabled=false;this.attributes={};}
  append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.textContent='';this.children=nodes;}setAttribute(k,v){this.attributes[k]=v;}
  set textContent(value){this._text=value;this.children=[];}get textContent(){return this._text+this.children.map(v=>v.textContent).join('');}
}
const nodes=e=>[e,...e.children.flatMap(nodes)];
async function until(check){for(let n=0;n<300;n++){if(check())return;await delay(5);}assert.fail('Expected maintained source phase did not arrive');}
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
function publicReceipt(id=openingId){return {opening:{opening_id:id,definition_version:'1',state_version:'1'},offer:null,allocation_id:null,allocation_version:null,phase:'open',pending:'0',confirmed:'0'};}
function ack(f,applied=true){return {account_id:f.accountId,request_id:requestId,outcome:{receipt:publicReceipt(),applied,recorded:true}};}
const response=value=>new Response(typeof value==='string'?value:JSON.stringify(value),{headers:{'content-type':'application/json'}});
async function fixture({save=true,authorUnknown=false,clientEdit={}}={}){
  const base=await refreshFixture(),window=new EventTarget(),document=new EventTarget();window.location={origin:base.origin};document.defaultView=window;document.hidden=false;document.createElement=tag=>new Element(document,tag);const host=new Element(document,'main');
  const controller=new AbortController(),listeners={setup:[],custody:[],archive:[]};
  const subscribe=name=>run=>{listeners[name].push(run);return()=>{listeners[name]=listeners[name].filter(v=>v!==run);};};
  const binding=Object.fromEntries(Object.entries(base.review.binding).map(([k,v])=>[k,v instanceof Uint8Array?Uint8Array.from(v):v]));
  const contextId=new Uint8Array(16).fill(6),expires=base.nowMs+300000n;
  const state={csrf:'synthetic-csrf',current:{binding:base.review.binding,manifest:base.predecessor,nowMs:base.nowMs,ownerSessionLive:true,consentLive:true},sourceReads:0,currentReads:0,reviews:[],sourceCalls:[],calls:[],head:null,transport:null};
  const author=createOwnerContextAuthoring({enabled:true,origin:base.origin,host,binding,contextId,expiresMs:expires,readCurrent:async()=>state.current,currentCsrf:()=>state.csrf,
    archiveLease:{onClose:subscribe('archive'),withKey:()=>{throw Error('No private key read in this flow');},close:()=>listeners.archive.slice().forEach(f=>f())},onSetupClose:subscribe('setup'),onCustodyClose:subscribe('custody'),signal:controller.signal,timeoutMs:10000,observationMs:10000,
    fetchImpl:async(url,init)=>{state.sourceCalls.push({url,init,body:init.body?new Uint8Array(init.body).slice():null});if(init.method==='POST'){state.head=new Uint8Array(init.body).slice();return authorUnknown?new Response(null,{status:503}):response({revision:1});}return new Response(state.head,{headers:{'content-type':'application/vnd.zrotext.workflow-context.v1'}});}});
  const all=nodes(host),click=text=>all.find(e=>e.tagName==='button'&&e.textContent===text).dispatchEvent(new Event('click'));
  if(save){all.find(e=>e.tagName==='textarea').value='Synthetic local facts';click('Review facts');await until(()=>author.state().phase==='review');click('Save encrypted facts');await until(()=>['saved','unknown','refused','closed'].includes(author.state().phase));assert.equal(author.state().phase,authorUnknown?'unknown':'saved');}
  const f={base,binding,accountId:uuid(base.review.binding.account),contextId,expires,controller,listeners,state,author,clients:[]};
  const options={enabled:true,origin:base.origin,binding,contextId,sourceExpiresMs:expires,readSavedSource:()=>{state.sourceReads++;return author.savedSource();},readCurrent:async()=>{state.currentReads++;return state.current;},currentCsrf:()=>state.csrf,consumeCreateReview:async review=>state.reviews.push(review),signal:controller.signal,onSetupClose:subscribe('setup'),onCustodyClose:subscribe('custody'),totalTimeoutMs:5000,attemptTimeoutMs:1000,observationTimeoutMs:5000,maxAttempts:3,
    fetchImpl:async(url,init)=>{state.calls.push({url,init,body:init.body});return state.transport?state.transport(url,init):response(ack(f));},...clientEdit};
  f.options=options;f.client=createOwnerOpeningCapacityClient(options);f.clients.push(f.client);
  f.input=()=>({requestId,openingId,capacity:3,decisionDeadlineMs:base.nowMs+5000n});f.prepare=()=>f.client.prepareCreate(f.input());
  f.close=()=>{for(const c of f.clients)c.close();author.close();controller.abort();};return f;
}

test('actual author ACK and HPKE snapshot prepare a shorter independently bound opening',async()=>{
  const f=await fixture();try{
    const source=f.author.savedSource(),post=f.state.sourceCalls.find(v=>v.init.method==='POST');assert.ok(source);assert.equal(source.receipt.envelopeDigest,createHash('sha256').update(post.body).digest('hex'));assert.equal(Buffer.from(post.body).includes(Buffer.from('Synthetic local facts')),false);
    const ticket=await f.prepare();assert.ok(Object.isFrozen(ticket));assert.equal(f.state.calls.length,0);assert.equal(f.state.reviews.length,1);assert.equal(f.state.reviews[0].decisionDeadlineMs,f.base.nowMs+5000n);assert.ok(f.state.reviews[0].decisionDeadlineMs<f.expires);
    const result=await f.client.create(ticket);assert.equal(result.state,'acknowledged');assert.equal(result.applied,true);assert.equal(result.receipt.opening.definition_version,1n);
    const call=f.state.calls[0],body=JSON.parse(call.body);assert.equal(call.url,f.base.origin+'/v1/owner/workflow/openings');assert.deepEqual(body,{request_id:requestId,opening_id:openingId,capacity:3,description:{context_id:source.receipt.contextId,revision:1,digest:source.receipt.envelopeDigest},decision_deadline_ms:(f.base.nowMs+5000n).toString()});
    assert.equal(call.init.headers['x-zrotext-opening-account'],uuid(f.binding.account));assert.equal(call.init.headers['x-zrotext-csrf'],'synthetic-csrf');for(const key of ['Cookie','Authorization'])assert.equal(call.init.headers[key],undefined);
    for(const [k,v] of [['credentials','same-origin'],['mode','same-origin'],['redirect','error'],['cache','no-store']])assert.equal(call.init[k],v);assert.equal(f.client.state().pending,null);
  }finally{f.close();}
});

test('unknown source and unacknowledged matching ciphertext cannot start opening preparation',async()=>{
  for(const cause of ['unsaved','unknown','closed']){const f=await fixture({save:cause!=='unsaved',authorUnknown:cause==='unknown'});try{if(cause==='closed')f.author.close();assert.equal(f.author.savedSource(),null);await assert.rejects(f.prepare());assert.equal(f.state.calls.length+f.state.currentReads+f.state.reviews.length,0);}finally{f.close();}}
});

test('closed options refuse accessors coercion and invalid origins before application callbacks',async()=>{
  const f=await fixture();try{let invoked=0;for(const change of [o=>o.extra=true,o=>o.origin={toString(){invoked++;return f.base.origin;}},o=>o.origin='not a URL',o=>o.origin=f.base.origin+'/',o=>o.contextId=new Uint8Array(16),o=>o.maxAttempts=4,o=>o.sourceExpiresMs=0n,o=>Object.defineProperty(o,'readCurrent',{get(){invoked++;return f.options.readCurrent;}})]){const o={...f.options};change(o);assert.throws(()=>createOwnerOpeningCapacityClient(o));}assert.equal(invoked,0);assert.equal(f.state.currentReads+f.state.sourceReads+f.state.calls.length,0);}finally{f.close();}
});

test('independent account context and nonzero digest reject altered public receipt copies',async()=>{
  const f=await fixture();try{for(const change of [s=>s.accountId=uuid(new Uint8Array(16).fill(9)),s=>s.receipt.contextId=openingId,s=>s.receipt.revision=2,s=>s.receipt.envelopeDigest='0'.repeat(64),s=>s.receipt.state='pending',s=>s.receipt.requestAcknowledged=false,s=>s.receipt.extra=true]){
    const c=createOwnerOpeningCapacityClient({...f.options,readSavedSource:()=>{const real=f.author.savedSource(),copy={...real,receipt:{...real.receipt}};change(copy);return copy;}});f.clients.push(c);await assert.rejects(c.prepareCreate(f.input()));
  }assert.equal(f.state.calls.length,0);}finally{f.close();}
});

test('binding and context aliases are copied before any asynchronous preparation',async()=>{
  const f=await fixture();try{const expected=uuid(f.binding.account);f.binding.account.fill(9);f.contextId.fill(9);const ticket=await f.prepare();assert.equal((await f.client.create(ticket)).state,'acknowledged');assert.equal(f.state.calls[0].init.headers['x-zrotext-opening-account'],expected);assert.equal(JSON.parse(f.state.calls[0].body).description.context_id,uuid(new Uint8Array(16).fill(6)));}finally{f.close();}
});

test('genuine branded current observation refuses independent binding and owner loss',async()=>{
  for(const cause of ['account','session','peer','owner','consent','branding']){const f=await fixture();try{
    if(cause==='account'||cause==='session')f.state.current={...f.state.current,binding:{...f.state.current.binding,[cause]:new Uint8Array(16).fill(9)}};
    if(cause==='peer')f.state.current={...f.state.current,binding:{...f.state.current.binding,peer:'+13'}};
    if(cause==='owner')f.state.current={...f.state.current,ownerSessionLive:false};if(cause==='consent')f.state.current={...f.state.current,consentLive:false};if(cause==='branding')f.state.current={...f.state.current,manifest:{...f.state.current.manifest}};
    await assert.rejects(f.prepare());assert.equal(f.state.calls.length+f.state.reviews.length,0);
  }finally{f.close();}}
});

test('mutating the original public manifest cannot create a new signed lifetime ceiling',async()=>{
  const f=await fixture();try{
    const unsigned=Uint8Array.from(f.base.review.unsigned);new DataView(unsigned.buffer).setBigUint64(151+140,f.base.nowMs+5000n);
    const m=await verifyManifest02(await signFixtureSuccessor02(f.base,unsigned),verifiedManifestTrust02(f.base.predecessor,f.base.nowMs),f.base.nowMs);f.state.current={...f.state.current,manifest:m};
    m.expiresMs=(1n<<63n)-1n;for(const k of m.keys)k.untilMs=(1n<<63n)-1n;
    await assert.rejects(f.client.prepareCreate({...f.input(),decisionDeadlineMs:f.base.nowMs+6000n}));assert.equal(f.state.calls.length,0);
  }finally{f.close();}
  const g=await fixture();try{const m=g.state.current.manifest;m.expiresMs=g.base.nowMs+1n;for(const k of m.keys)k.untilMs=g.base.nowMs+1n;assert.ok(await g.prepare());assert.equal(g.state.calls.length,0);}finally{g.close();}
});

test('final getter and CSRF checks reject changes after explicit review without dispatch',async()=>{
  for(const cause of ['source','csrf','close','clock']){const f=await fixture();try{
    const c=createOwnerOpeningCapacityClient({...f.options,consumeCreateReview:async()=>{if(cause==='source')f.author.close();if(cause==='csrf')f.state.csrf='changed';if(cause==='close')f.controller.abort();if(cause==='clock')f.state.current={...f.state.current,nowMs:f.base.nowMs+6000n};}});f.clients.push(c);await assert.rejects(c.prepareCreate(f.input()));assert.equal(f.state.calls.length,0);
  }finally{f.close();}}
});

test('expanded or expired decision ends refuse instead of changing the reviewed body',async()=>{
  const f=await fixture();try{for(const end of [f.expires+1n,f.base.nowMs,0n,1n<<63n]){const c=createOwnerOpeningCapacityClient(f.options);f.clients.push(c);await assert.rejects(c.prepareCreate({...f.input(),decisionDeadlineMs:end}));}assert.equal(f.state.calls.length,0);}finally{f.close();}
});

test('fake and cross-client tickets cannot dispatch or recreate a consumed identity',async()=>{
  const f=await fixture();try{const ticket=await f.prepare(),other=createOwnerOpeningCapacityClient(f.options);f.clients.push(other);assert.equal((await other.create(ticket)).state,'refused');assert.equal((await f.client.create(Object.freeze({kind:'opening_create'}))).state,'refused');assert.equal(f.state.calls.length,0);assert.equal((await f.client.create(ticket)).state,'acknowledged');assert.equal((await f.client.create(ticket)).state,'refused');await assert.rejects(f.prepare());assert.equal(f.state.calls.length,1);}finally{f.close();}
});

test('explicit UNKNOWN replay is byte identical and invokes no source current or key callback',async()=>{
  const f=await fixture();try{f.state.transport=async()=>f.state.calls.length===1?new Response(null,{status:503}):response(ack(f,false));const ticket=await f.prepare();assert.equal((await f.client.create(ticket)).state,'unknown');const sourceReads=f.state.sourceReads,currentReads=f.state.currentReads;
    f.author.close();f.state.current={...f.state.current,ownerSessionLive:false};const result=await f.client.retry(ticket);assert.equal(result.state,'acknowledged');assert.equal(result.applied,false);assert.equal(f.state.sourceReads,sourceReads);assert.equal(f.state.currentReads,currentReads);assert.equal(f.state.calls[0].body,f.state.calls[1].body);assert.deepEqual(f.state.calls[0].init.headers,f.state.calls[1].init.headers);
  }finally{f.close();}
});

test('first definitive refusal differs from every later refusal after possible dispatch',async()=>{
  for(const previous of [false,true]){const f=await fixture();try{f.state.transport=async()=>new Response(null,{status:previous&&f.state.calls.length===1?503:403});const ticket=await f.prepare();const first=await f.client.create(ticket);assert.equal(first.state,previous?'unknown':'refused');if(previous){const pending=f.client.state().pending;assert.equal((await f.client.retry(ticket)).state,'unknown');assert.deepEqual(f.client.state().pending,pending);}else assert.equal(f.client.state().pending,null);}finally{f.close();}}
});

test('strict success identity acknowledgement and receipt mismatches retain UNKNOWN',async()=>{
  for(const change of [a=>a.account_id=openingId,a=>a.request_id=openingId,a=>a.outcome.recorded=false,a=>a.outcome.applied='true',a=>a.outcome.receipt.opening.opening_id=requestId,a=>a.outcome.receipt.offer={},a=>a.outcome.receipt.phase='approved',a=>a.extra=true]){const f=await fixture();try{f.state.transport=async()=>{const a=ack(f);change(a);return response(a);};const ticket=await f.prepare();assert.equal((await f.client.create(ticket)).state,'unknown');assert.equal(f.client.state().pending.requestId,requestId);}finally{f.close();}}
});

test('decimal string MAX survives exactly while numeric aliases and count overflow refuse',async()=>{
  const f=await fixture();try{f.state.transport=async()=>{const a=ack(f);a.outcome.receipt.opening.state_version=max;return response(a);};assert.equal((await f.client.create(await f.prepare())).receipt.opening.state_version,(1n<<63n)-1n);}finally{f.close();}
  for(const bad of ['01','1\n','+1','1e0','9223372036854775808',1]){const g=await fixture();try{g.state.transport=async()=>{const a=ack(g);a.outcome.receipt.opening.state_version=bad;return response(a);};assert.equal((await g.client.create(await g.prepare())).state,'unknown');}finally{g.close();}}
  const g=await fixture();try{g.state.transport=async()=>{const a=ack(g);a.outcome.receipt.pending='100';a.outcome.receipt.confirmed='1';return response(a);};assert.equal((await g.client.create(await g.prepare())).state,'unknown');}finally{g.close();}
});

test('duplicate keys invalid UTF8 oversized streams and redirects cannot acknowledge',async()=>{
  for(const cause of ['duplicate','utf8','oversize','redirect','trailing']){const f=await fixture();try{f.state.transport=async()=>{
    if(cause==='duplicate')return response(JSON.stringify(ack(f)).replace('"recorded":true','"recorded":true,"recorded":true'));
    if(cause==='utf8')return new Response(Uint8Array.of(255),{headers:{'content-type':'application/json'}});
    if(cause==='oversize')return response(' '.repeat(8193));if(cause==='trailing')return response(JSON.stringify(ack(f))+' null');
    const r=response(ack(f));Object.defineProperty(r,'redirected',{value:true});return r;
  };assert.equal((await f.client.create(await f.prepare())).state,'unknown');}finally{f.close();}}
});

test('three explicit dispatches are one fixed budget and do not reset UNKNOWN identity',async()=>{
  const f=await fixture();try{f.state.transport=async()=>new Response(null,{status:503});const ticket=await f.prepare();const first=await f.client.create(ticket);assert.equal(first.state,'unknown');for(let n=0;n<2;n++)assert.equal((await f.client.retry(ticket)).state,'unknown');assert.equal(f.state.calls.length,3);assert.equal((await f.client.retry(ticket)).state,'unknown');await assert.rejects(f.client.status(openingId));assert.equal(f.state.calls.length,3);assert.deepEqual(f.client.state().pending,first.pending);}finally{f.close();}
});

test('status is a separate current owner metadata snapshot and never clears UNKNOWN',async()=>{
  const f=await fixture();try{f.state.transport=async(url)=>url.endsWith('/status')?response({account_id:uuid(f.binding.account),receipt:publicReceipt()}):new Response(null,{status:503});const ticket=await f.prepare();const unknown=await f.client.create(ticket),reads=f.state.currentReads,sources=f.state.sourceReads;
    f.author.close();f.state.csrf='new-current-owner-csrf';const status=await f.client.status(openingId);assert.equal(status.state,'metadata_snapshot');assert.deepEqual(f.client.state().pending,unknown.pending);assert.equal(f.state.currentReads,reads);assert.equal(f.state.sourceReads,sources);assert.equal(f.state.calls[1].body,'{}');assert.equal(f.state.calls[1].init.headers['x-zrotext-csrf'],'new-current-owner-csrf');assert.equal((await f.client.retry(ticket)).state,'unknown');assert.equal(f.state.calls.length,2);
  }finally{f.close();}
});

test('outward timeout keeps the actual unsettled transport charged and ignores late ACK',async()=>{
  const f=await fixture({clientEdit:{attemptTimeoutMs:20}}),held=deferred();try{f.state.transport=()=>held.promise;const ticket=await f.prepare();assert.equal((await f.client.create(ticket)).state,'unknown');assert.equal(f.client.state().busy,true);assert.equal((await f.client.retry(ticket)).state,'unknown');await assert.rejects(f.client.status(openingId));assert.equal(f.state.calls.length,1);held.resolve(response(ack(f)));await until(()=>!f.client.state().busy);assert.ok(f.client.state().pending);assert.equal(f.state.calls.length,1);}finally{held.resolve(response(ack(f)));f.close();}
});

test('held current observation refusal cannot free an unsettled callback slot',async()=>{
  const f=await fixture(),held=deferred();try{const c=createOwnerOpeningCapacityClient({...f.options,observationTimeoutMs:20,readCurrent:()=>held.promise});f.clients.push(c);await assert.rejects(c.prepareCreate(f.input()));assert.equal(c.state().busy,true);await assert.rejects(c.status(openingId));assert.equal(f.state.calls.length,0);held.resolve(f.state.current);await until(()=>!c.state().busy);}finally{held.resolve(f.state.current);f.close();}
});

test('original operation deadline cannot be renewed by retry or a late review',async()=>{
  const f=await fixture(),held=deferred();let entered=false;try{const c=createOwnerOpeningCapacityClient({...f.options,totalTimeoutMs:1000,consumeCreateReview:()=>{entered=true;return held.promise;}});const originalLatestCutoff=performance.now()+1000;f.clients.push(c);const work=c.prepareCreate(f.input());void work.catch(()=>{});await until(()=>entered);await assert.rejects(work);assert.equal(c.state().busy,true);while(performance.now()<originalLatestCutoff)await delay(Math.max(1,Math.ceil(originalLatestCutoff-performance.now())));await delay(0);assert.equal(c.state().closed,true);assert.equal(c.state().busy,true);held.resolve();await until(()=>!c.state().busy);assert.equal(c.state().closed,true);await assert.rejects(c.prepareCreate(f.input()));assert.equal(f.state.calls.length,0);}finally{held.resolve();f.close();}
});

test('setup custody parent abort and full close preserve only ambiguous content-free identity',async()=>{
  for(const cause of ['setup','custody','abort','close']){const f=await fixture();try{f.state.transport=async()=>new Response(null,{status:503});const ticket=await f.prepare(),result=await f.client.create(ticket);if(cause==='abort')f.controller.abort();else if(cause==='close')f.client.close();else f.listeners[cause].slice().forEach(run=>run());assert.equal(f.client.state().closed,true);assert.deepEqual(f.client.state().pending,result.pending);assert.deepEqual(Object.keys(f.client.state().pending).sort(),['accountId','openingId','requestId']);assert.equal((await f.client.retry(ticket)).state,'unknown');await assert.rejects(f.client.status(openingId));assert.equal(f.state.calls.length,1);}finally{f.close();}}
});

test('immediate reentrant subscriptions and cleanup throws cannot leave a usable client',async()=>{
  const f=await fixture();try{let cleanup=0;const c=createOwnerOpeningCapacityClient({...f.options,onSetupClose:run=>{run();return()=>{cleanup++;};},onCustodyClose:()=>{assert.fail('Already closed before next subscription');}});f.clients.push(c);assert.equal(c.state().closed,true);assert.equal(cleanup,1);await assert.rejects(c.prepareCreate(f.input()));
    const d=createOwnerOpeningCapacityClient({...f.options,onSetupClose:()=>()=>{throw Error('Synthetic removal failure');},onCustodyClose:()=>()=>{cleanup++;}});f.clients.push(d);d.close();assert.equal(cleanup,2);assert.equal(d.state().closed,true);assert.equal(f.state.calls.length,0);
    const e=createOwnerOpeningCapacityClient({...f.options,onSetupClose:()=>undefined,onCustodyClose:()=>undefined});f.clients.push(e);assert.equal(e.state().closed,false);e.close();
    let closing;closing=createOwnerOpeningCapacityClient({...f.options,readSavedSource:()=>{closing.close();return f.author.savedSource();}});f.clients.push(closing);await assert.rejects(closing.prepareCreate(f.input()));assert.equal(closing.state().closed,true);assert.equal(f.state.calls.length,0);
  }finally{f.close();}
});

test('CSRF rotation or close during a held response suppresses all late success',async()=>{
  for(const cause of ['csrf','close']){const f=await fixture(),held=deferred();try{f.state.transport=()=>held.promise;const ticket=await f.prepare(),work=f.client.create(ticket);await until(()=>f.state.calls.length===1);if(cause==='csrf')f.state.csrf='rotated';else f.client.close();held.resolve(response(ack(f)));assert.equal((await work).state,'unknown');assert.ok(f.client.state().pending);assert.equal(f.state.calls.length,1);}finally{held.resolve(response(ack(f)));f.close();}}
});
