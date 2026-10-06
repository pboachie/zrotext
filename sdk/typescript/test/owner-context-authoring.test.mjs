// SPDX-License-Identifier: AGPL-3.0-only
// Presentation fixture only; manifests and encryption use maintained SDK code.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {setTimeout as delay} from 'node:timers/promises';
import {createHash} from 'node:crypto';
import {refreshFixture,signFixtureSuccessor02} from './conversation-refresh-fixture.mjs';
import {verifyManifest02,verifiedManifestTrust02} from '../dist/draft02-manifest.js';
import {createOwnerContextAuthoring} from '../dist/owner-context-authoring.js';
import {OwnerWorkflowContextClient} from '../dist/owner-workflow-context-client.js';
const canary='Synthetic local private facts <not markup>';
const accountId=b=>Buffer.from(b).toString('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
function assertSaved(f,pending=null){
  const calls=f.state.calls.length,reads=f.state.reads,source=f.author.savedSource(),again=f.author.savedSource(),post=f.state.calls.find(v=>v.init.method==='POST');
  assert.ok(source);assert.deepEqual(Object.keys(source).sort(),['accountId','receipt']);
  assert.deepEqual(Object.keys(source.receipt).sort(),['contextId','envelopeDigest','requestAcknowledged','requestId','revision','state']);
  assert.equal(source.accountId,accountId(f.f.review.binding.account));
  assert.deepEqual(source.receipt,{requestId:post.init.headers['idempotency-key'],contextId:accountId(f.options.contextId),revision:1,envelopeDigest:createHash('sha256').update(post.body).digest('hex'),state:'verified_current_snapshot',requestAcknowledged:true});
  if(pending)for(const key of Object.keys(pending))assert.equal(source.receipt[key],pending[key]);
  assert.ok(Object.isFrozen(source)&&Object.isFrozen(source.receipt));assert.notEqual(source,again);assert.notEqual(source.receipt,again.receipt);assert.deepEqual(source,again);
  assert.throws(()=>source.receipt.revision=2,TypeError);assert.throws(()=>source.accountId='changed',TypeError);
  assert.equal(f.state.calls.length,calls);assert.equal(f.state.reads,reads);assert.deepEqual(f.author.state(),{phase:'saved',pending:null});return source;
}
class Element extends EventTarget{
  constructor(document,tag){super();this.ownerDocument=document;this.tagName=tag;this.nodeType=1;this.children=[];this.value='';this.textContent='';this.hidden=false;this.disabled=false;this.attributes={};}
  append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.textContent='';this.children=nodes;}setAttribute(k,v){this.attributes[k]=v;}
  set textContent(value){this._text=value;this.children=[];}get textContent(){return this._text+this.children.map(v=>v.textContent).join('');}
}
function presentation(origin){const window=new EventTarget();window.location={origin};const document=new EventTarget();document.defaultView=window;document.hidden=false;document.createElement=tag=>new Element(document,tag);return {window,document,host:new Element(document,'main')};}
function nodes(element){return [element,...element.children.flatMap(nodes)];}
async function until(run){for(let n=0;n<300;n++){if(run())return;await delay(5);}assert.fail('Expected authoring phase did not arrive');}
async function fixture(edit={}){
  const f=await refreshFixture(),ui=presentation(f.origin),controller=new AbortController(),listeners={setup:[],custody:[],archive:[]};
  const state={calls:[],reads:0,head:null,csrf:'synthetic-csrf',current:{binding:f.review.binding,manifest:f.predecessor,nowMs:f.nowMs,ownerSessionLive:true,consentLive:true}};
  const subscribe=key=>listener=>{listeners[key].push(listener);return()=>{listeners[key]=listeners[key].filter(v=>v!==listener);};};
  const binding=Object.fromEntries(Object.entries(f.review.binding).map(([key,value])=>[key,value instanceof Uint8Array?Uint8Array.from(value):value]));
  const options={enabled:true,origin:f.origin,host:ui.host,binding,contextId:new Uint8Array(16).fill(6),expiresMs:f.nowMs+300000n,
    readCurrent:async()=>{state.reads++;return state.current;},currentCsrf:()=>state.csrf,archiveLease:{onClose:subscribe('archive'),withKey:()=>{throw Error('Key access must not occur');},close:()=>listeners.archive.slice().forEach(run=>run())},
    onSetupClose:subscribe('setup'),onCustodyClose:subscribe('custody'),signal:controller.signal,timeoutMs:2000,observationMs:2000,
    fetchImpl:async(url,init)=>{state.calls.push({url,init,body:init.body?new Uint8Array(init.body).slice():null});if(init.method==='POST'){state.head=new Uint8Array(init.body).slice();return new Response('{"revision":1}',{headers:{'content-type':'application/json'}});}return new Response(state.head,{headers:{'content-type':'application/vnd.zrotext.workflow-context.v1'}});},...edit};
  const author=createOwnerContextAuthoring(options),all=nodes(ui.host),editor=all.find(v=>v.tagName==='textarea'),review=all.find(v=>v.attributes['aria-label']==='Review facts'),status=all.find(v=>v.attributes.role==='status');
  const click=text=>all.find(v=>v.tagName==='button'&&v.textContent===text).dispatchEvent(new Event('click'));
  return {f,ui,controller,listeners,state,options,author,editor,review,status,click,async prepare(){editor.value=canary;click('Review facts');await until(()=>author.state().phase==='review');},async save(){await this.prepare();click('Save encrypted facts');await until(()=>['saved','unknown','refused','closed'].includes(author.state().phase));}};
}

test('explicit local facts review saves exact initial ciphertext and independently reads latest',async()=>{
  const f=await fixture();try{
    assert.equal(f.state.reads+f.state.calls.length,0);assert.equal(f.author.savedSource(),null);await f.prepare();assert.equal(f.author.savedSource(),null);assert.equal(f.state.calls.length,0);
    assert.equal(f.review.children[1].textContent,canary);assert.ok(f.review.children[0].textContent.includes(f.options.binding.peer));
    f.click('Save encrypted facts');await until(()=>f.author.state().phase==='saved');assert.equal(f.author.state().pending,null);
    assert.equal(f.editor.value,'');assert.equal(f.review.hidden,true);assert.equal(f.review.children.length,0);
    const post=f.state.calls[0];assert.equal(post.init.headers['x-zrotext-context-revision'],'0');assert.equal(new DataView(post.body.buffer).getBigUint64(94),1n);
    assert.equal(new DataView(post.body.buffer).getBigUint64(118),f.state.current.manifest.version);assert.equal(Buffer.from(post.body).includes(Buffer.from(canary)),false);
    assert.equal(post.init.credentials,'same-origin');assert.equal(post.init.headers.Cookie,undefined);assert.equal(post.init.headers.Authorization,undefined);
    assert.equal(f.state.calls.length,2);assert.equal(f.state.calls[1].url.includes('?'),false);assert.match(f.status.textContent,/current at this check/);
    assertSaved(f);
    f.click('Review facts');await delay(5);assert.equal(f.state.calls.length,2);
  }finally{f.author.close();}
});

test('closed options and document origin refuse without invoking getters or authority',async()=>{
  const f=await fixture();f.author.close();
  for(const change of [o=>o.extra=true,o=>o.origin='https://other.invalid',o=>o.timeoutMs=10001,o=>o.observationMs=0,o=>o.contextId=new Uint8Array(16),o=>Object.defineProperty(o,'readCurrent',{get(){throw Error('Getter must not execute');}})]){
    const options={...f.options};change(options);assert.throws(()=>createOwnerContextAuthoring(options),/Owner facts unavailable/);
  }
  assert.equal(f.state.reads+f.state.calls.length,0);
  const disabled=await fixture({enabled:false});assert.equal(disabled.author.state().phase,'closed');disabled.click('Review facts');await delay(5);assert.equal(disabled.state.reads+disabled.state.calls.length,0);disabled.author.close();
});

test('changed or hidden visible review and bounded UTF8 facts cannot publish',async()=>{
  for(const mutate of [f=>f.review.children[1].textContent='Synthetic changed review',f=>f.review.children[0].textContent='Synthetic changed selection',f=>f.review.hidden=true,f=>f.review.replaceChildren()]){
    const f=await fixture();try{await f.prepare();mutate(f);f.click('Save encrypted facts');await until(()=>f.author.state().phase==='refused');assert.equal(f.state.calls.length,0);assert.equal(f.editor.value,'');}finally{f.author.close();}
  }
  for(const text of ['x'.repeat(32769),'\u2603'.repeat(12000)]){const f=await fixture();try{f.editor.value=text;f.click('Review facts');await until(()=>f.author.state().phase==='refused');assert.equal(f.state.reads+f.state.calls.length,0);assert.equal(f.editor.value,'');}finally{f.author.close();}}
});

test('actual signed post-enrollment successor is used and later stale scope cannot publish',async()=>{
  const f=await fixture();try{
    const successor=await verifyManifest02(await signFixtureSuccessor02(f.f),verifiedManifestTrust02(f.f.predecessor,f.f.nowMs),f.f.nowMs);
    f.state.current={...f.state.current,manifest:successor};await f.save();assert.equal(f.author.state().phase,'saved');assert.equal(new DataView(f.state.head.buffer).getBigUint64(118),successor.version);
  }finally{f.author.close();}
  const stale=await fixture();try{await stale.prepare();stale.state.current={...stale.state.current,manifest:await verifyManifest02(await signFixtureSuccessor02(stale.f),verifiedManifestTrust02(stale.f.predecessor,stale.f.nowMs),stale.f.nowMs)};stale.click('Save encrypted facts');await until(()=>stale.author.state().phase==='refused');assert.equal(stale.state.calls.length,0);}finally{stale.author.close();}
});

test('unknown retains one identity and exact retry while matching GET cannot acknowledge',async()=>{
  let f,posts=0;f=await fixture({fetchImpl:async(url,init)=>{f.state.calls.push({url,init,body:init.body?new Uint8Array(init.body).slice():null});if(init.method==='POST'){f.state.head=new Uint8Array(init.body).slice();if(++posts===1)return new Response(null,{status:503});return new Response('{"revision":1}',{headers:{'content-type':'application/json'}});}return new Response(f.state.head,{headers:{'content-type':'application/vnd.zrotext.workflow-context.v1'}});}});
  try{
    await f.save();assert.equal(f.author.state().phase,'unknown');assert.equal(f.author.savedSource(),null);const pending=f.author.state().pending;assert.ok(pending);assert.equal(f.editor.value,'');
    f.click('Review facts');await delay(5);assert.equal(posts,1);
    f.click('Check saved facts');await until(()=>f.author.state().phase==='unknown');assert.equal(f.author.savedSource(),null);assert.deepEqual(f.author.state().pending,pending);assert.equal(posts,1);
    f.click('Retry same save');await until(()=>f.author.state().phase==='saved');const sent=f.state.calls.filter(v=>v.init.method==='POST');assert.deepEqual(sent[0].body,sent[1].body);assert.deepEqual(sent[0].init.headers,sent[1].init.headers);assert.equal(f.author.state().pending,null);
    assertSaved(f,pending);
  }finally{f.author.close();}
});

test('bare conflict is refused and cannot silently reseal or reset identity',async()=>{
  const f=await fixture({fetchImpl:async()=>new Response(null,{status:409})});try{await f.save();assert.equal(f.author.state().phase,'refused');assert.equal(f.author.state().pending,null);assert.equal(f.editor.value,'');f.click('Review facts');await delay(5);assert.equal(f.author.state().phase,'refused');}finally{f.author.close();}
});

test('finite explicit retry and check controls disable without replacing unknown identity',async()=>{
  let f;f=await fixture({fetchImpl:async(url,init)=>{f.state.calls.push({url,init});return new Response(null,{status:503});}});try{
    await f.save();const pending=f.author.state().pending;
    for(let n=0;n<2;n++){f.click('Retry same save');await until(()=>f.author.state().phase==='unknown');}
    for(let n=0;n<3;n++){f.click('Check saved facts');await until(()=>f.author.state().phase==='unknown');}
    assert.equal(f.state.calls.length,6);const buttons=nodes(f.ui.host).filter(v=>v.tagName==='button');assert.ok(buttons.find(v=>v.textContent==='Retry same save').disabled);assert.ok(buttons.find(v=>v.textContent==='Check saved facts').disabled);
    f.click('Retry same save');f.click('Check saved facts');await delay(5);assert.equal(f.state.calls.length,6);assert.deepEqual(f.author.state().pending,pending);
  }finally{f.author.close();}
});

test('actual current owner loss while checking unknown closes unusable actions but preserves identity',async()=>{
  const f=await fixture({fetchImpl:async()=>new Response(null,{status:503})});try{
    await f.save();const pending=f.author.state().pending;assert.ok(pending);f.state.current={...f.state.current,ownerSessionLive:false};f.click('Check saved facts');await until(()=>f.author.state().phase==='closed');
    assert.deepEqual(f.author.state().pending,pending);assert.equal(f.editor.value,'');assert.ok(nodes(f.ui.host).filter(v=>v.tagName==='button').every(v=>v.disabled));
  }finally{f.author.close();}
});

test('changed CSRF or synchronous CSRF abort closes unknown controls before another transport',async()=>{
  for(const cause of ['change','abort']){let f,calls=0;f=await fixture({fetchImpl:async()=>{calls++;return new Response(null,{status:503});},...(cause==='abort'?{currentCsrf:()=>{if(f.state.csrf==='changed')f.controller.abort();return 'synthetic-csrf';}}:{})});try{
    await f.save();const pending=f.author.state().pending;f.state.csrf='changed';f.click('Check saved facts');await until(()=>f.author.state().phase==='closed');assert.deepEqual(f.author.state().pending,pending);assert.ok(nodes(f.ui.host).filter(v=>v.tagName==='button').every(v=>v.disabled));assert.equal(f.editor.value,'');assert.equal(calls,1);
  }finally{f.author.close();}}
});

test('idle pre-seal deadline closes visible review and preserves unknown after expiration',async()=>{
  const prepared=await fixture({timeoutMs:150,observationMs:150});await prepared.prepare();await until(()=>prepared.author.state().phase==='closed');assert.equal(prepared.editor.value,'');assert.equal(prepared.review.hidden,true);assert.equal(prepared.state.calls.length,0);
  const unknown=await fixture({timeoutMs:150,observationMs:150,fetchImpl:async()=>new Response(null,{status:503})});await unknown.save();const pending=unknown.author.state().pending;await until(()=>unknown.author.state().phase==='closed');assert.deepEqual(unknown.author.state().pending,pending);unknown.click('Retry same save');await delay(5);assert.equal(unknown.author.state().phase,'closed');
});

test('setup custody archive pagehide hidden and input changes close all local plaintext',async()=>{
  for(const cause of ['setup','custody','archive','pagehide','hidden','input','signal']){
    const f=await fixture();await f.prepare();
    if(f.listeners[cause])f.listeners[cause].slice().forEach(run=>run());else if(cause==='pagehide')f.ui.window.dispatchEvent(new Event('pagehide'));else if(cause==='hidden'){f.ui.document.hidden=true;f.ui.document.dispatchEvent(new Event('visibilitychange'));}else if(cause==='input'){f.editor.value='Synthetic edit';f.editor.dispatchEvent(new Event('input'));}else f.controller.abort();
    await delay(0);assert.equal(f.author.state().phase,'closed');assert.equal(f.editor.value,'');assert.equal(f.review.hidden,true);assert.equal(f.state.calls.length,0);
  }
});

test('loss during authority or transport observes late rejecting promises without publication',async()=>{
  const unhandled=[],listener=e=>unhandled.push(e);process.on('unhandledRejection',listener);
  try{
    let f;f=await fixture({readCurrent:()=>{f.controller.abort();return Promise.reject(Error('Synthetic closed current'));}});f.editor.value=canary;f.click('Review facts');await until(()=>f.author.state().phase==='closed');await delay(0);assert.deepEqual(unhandled,[]);assert.equal(f.state.calls.length,0);f.author.close();
    let g;g=await fixture({fetchImpl:()=>{g.controller.abort();return Promise.reject(Error('Synthetic closed transport'));}});await g.save();assert.equal(g.author.state().phase,'closed');assert.ok(g.author.state().pending);assert.equal(g.editor.value,'');await delay(0);assert.deepEqual(unhandled,[]);g.author.close();
  }finally{process.removeListener('unhandledRejection',listener);}
});

test('held authority and expired authentic signer are bounded before any publication',async()=>{
  let release;const f=await fixture({timeoutMs:50,observationMs:50,readCurrent:()=>new Promise(resolve=>release=resolve)});f.editor.value=canary;f.click('Review facts');await until(()=>f.author.state().phase==='closed');release(f.state.current);await delay(0);assert.equal(f.state.calls.length,0);assert.equal(f.editor.value,'');
  const signed=await fixture();try{const unsigned=Uint8Array.from(signed.f.review.unsigned);new DataView(unsigned.buffer).setBigUint64(449+140,signed.f.nowMs+300n);const manifest=await verifyManifest02(await signFixtureSuccessor02(signed.f,unsigned),verifiedManifestTrust02(signed.f.predecessor,signed.f.nowMs),signed.f.nowMs);signed.state.current={...signed.state.current,manifest};await signed.prepare();await until(()=>signed.author.state().phase==='closed');assert.equal(signed.state.calls.length,0);assert.equal(signed.editor.value,'');}finally{signed.author.close();}
});

test('subscriber cleanup failure cannot skip remaining cleanup or restore content',async()=>{
  let cleaned=0;const f=await fixture({onSetupClose:()=>()=>{throw Error('Synthetic cleanup');},onCustodyClose:()=>()=>{cleaned++;}});await f.prepare();f.author.close();await delay(0);assert.equal(cleaned,1);assert.equal(f.editor.value,'');assert.equal(f.state.calls.length,0);assert.equal(f.author.state().phase,'closed');
});

test('saved source account is captured before caller binding aliases can change',async()=>{
  const f=await fixture();try{f.options.binding.account.fill(9);await f.save();assertSaved(f);assert.notEqual(accountId(f.options.binding.account),f.author.savedSource().accountId);}finally{f.author.close();}
});

test('saved source is cleared before abort and every cleanup callback',async()=>{
  let f,aborts=0,cleaned=0;const observed=[];
  f=await fixture({onSetupClose:()=>()=>{observed.push(f.author.savedSource());throw Error('Synthetic cleanup');},onCustodyClose:()=>()=>{observed.push(f.author.savedSource());cleaned++;},fetchImpl:async(url,init)=>{
    if(init.method==='POST'){init.signal.addEventListener('abort',()=>{aborts++;observed.push(f.author.savedSource());},{once:true});f.state.head=new Uint8Array(init.body).slice();}
    f.state.calls.push({url,init,body:init.body?new Uint8Array(init.body).slice():null});return init.method==='POST'?new Response('{"revision":1}',{headers:{'content-type':'application/json'}}):new Response(f.state.head,{headers:{'content-type':'application/vnd.zrotext.workflow-context.v1'}});
  }});
  await f.save();const handedOut=assertSaved(f);f.author.close();assert.equal(aborts,1);assert.equal(cleaned,1);assert.deepEqual(observed,[null,null,null]);assert.equal(f.author.savedSource(),null);assert.equal(handedOut.receipt.requestAcknowledged,true);f.author.close();assert.equal(cleaned,1);
});

test('saved source getter enforces original deadline after idle record timer is cleared',async()=>{
  const f=await fixture({timeoutMs:1000,observationMs:1000});try{
    const before=performance.now();await f.save();assertSaved(f);const calls=f.state.calls.length,reads=f.state.reads;
    await delay(Math.max(0,before+1050-performance.now()));assert.equal(f.author.state().phase,'saved');assert.equal(f.author.savedSource(),null);assert.equal(f.author.state().phase,'closed');assert.equal(f.state.calls.length,calls);assert.equal(f.state.reads,reads);
  }finally{f.author.close();}
});

test('saved source cannot survive saved editor lifecycle loss',async()=>{
  for(const cause of ['setup','custody','archive','pagehide','hidden','signal']){
    const f=await fixture();try{await f.save();assertSaved(f);const calls=f.state.calls.length,reads=f.state.reads;
      if(f.listeners[cause])f.listeners[cause].slice().forEach(run=>run());else if(cause==='pagehide')f.ui.window.dispatchEvent(new Event('pagehide'));else if(cause==='hidden'){f.ui.document.hidden=true;f.ui.document.dispatchEvent(new Event('visibilitychange'));}else f.controller.abort();
      assert.equal(f.author.savedSource(),null);assert.equal(f.author.state().phase,'closed');assert.equal(f.state.calls.length,calls);assert.equal(f.state.reads,reads);
    }finally{f.author.close();}
  }
});

test('saving and late latest-read settlement cannot expose acknowledged source after close',async()=>{
  let f,release;f=await fixture({fetchImpl:async(url,init)=>{
    f.state.calls.push({url,init,body:init.body?new Uint8Array(init.body).slice():null});if(init.method==='POST'){f.state.head=new Uint8Array(init.body).slice();return new Response('{"revision":1}',{headers:{'content-type':'application/json'}});}return new Promise(resolve=>release=()=>resolve(new Response(f.state.head,{headers:{'content-type':'application/vnd.zrotext.workflow-context.v1'}})));
  }});
  await f.prepare();f.click('Save encrypted facts');await until(()=>release);assert.equal(f.author.state().phase,'saving');assert.equal(f.author.savedSource(),null);f.author.close();release();await delay(0);assert.equal(f.author.savedSource(),null);assert.equal(f.author.state().phase,'closed');assert.equal(f.state.calls.length,2);
});

test('same-revision changed latest ciphertext stays unknown with exact pending identity on commit or retry',async()=>{
  for(const retry of [false,true]){let f,posts=0;f=await fixture({fetchImpl:async(url,init)=>{
    f.state.calls.push({url,init,body:init.body?new Uint8Array(init.body).slice():null});if(init.method==='POST'){f.state.head=new Uint8Array(init.body).slice();if(retry&&++posts===1)return new Response(null,{status:503});return new Response('{"revision":1}',{headers:{'content-type':'application/json'}});}const changed=Uint8Array.from(f.state.head);changed[changed.length-1]^=1;return new Response(changed,{headers:{'content-type':'application/vnd.zrotext.workflow-context.v1'}});
  }});try{
    await f.save();assert.equal(f.author.state().phase,'unknown');assert.equal(f.author.savedSource(),null);
    const first=f.state.calls.find(v=>v.init.method==='POST'),pending={requestId:first.init.headers['idempotency-key'],contextId:accountId(f.options.contextId),revision:1,envelopeDigest:createHash('sha256').update(first.body).digest('hex')};
    assert.deepEqual(f.author.state().pending,pending);
    if(retry){f.click('Retry same save');assert.equal(f.author.state().phase,'saving');await until(()=>f.author.state().phase==='unknown');const sent=f.state.calls.filter(v=>v.init.method==='POST');assert.equal(sent.length,2);assert.deepEqual(sent[0].body,sent[1].body);assert.deepEqual(sent[0].init.headers,sent[1].init.headers);}
    assert.equal(f.author.state().phase,'unknown');assert.deepEqual(f.author.state().pending,pending);assert.equal(f.author.savedSource(),null);
  }finally{f.author.close();}}
});

test('both acknowledged paths reject altered receipt output after genuine client verification',async()=>{
  // Fault the returned metadata after the real client performs HPKE-scoped write,
  // acknowledgement and latest checks; this does not replace an authority factory.
  for(const method of ['commit','retryUnknown'])for(const change of [r=>({...r,requestId:'09090909-0909-0909-0909-090909090909'}),r=>({...r,contextId:'09090909-0909-0909-0909-090909090909'}),r=>({...r,revision:2}),r=>({...r,envelopeDigest:'9'.repeat(64)}),r=>({...r,state:'changed'}),r=>({...r,requestAcknowledged:false}),r=>({...r,extra:true})]){
    const original=OwnerWorkflowContextClient.prototype[method];let verified=0,f,posts=0;
    OwnerWorkflowContextClient.prototype[method]=async function(...args){const result=await original.apply(this,args);assert.equal(result.requestAcknowledged,true);verified++;return Object.freeze(change(result));};
    try{
      f=await fixture({fetchImpl:async(url,init)=>{f.state.calls.push({url,init,body:init.body?new Uint8Array(init.body).slice():null});if(init.method==='POST'){f.state.head=new Uint8Array(init.body).slice();if(method==='retryUnknown'&&++posts===1)return new Response(null,{status:503});return new Response('{"revision":1}',{headers:{'content-type':'application/json'}});}return new Response(f.state.head,{headers:{'content-type':'application/vnd.zrotext.workflow-context.v1'}});}});
      await f.save();if(method==='retryUnknown'){assert.equal(f.author.state().phase,'unknown');f.click('Retry same save');await until(()=>f.author.state().phase!=='saving');}
      assert.equal(verified,1);assert.equal(f.author.savedSource(),null);assert.notEqual(f.author.state().phase,'saved');assert.ok(f.state.calls.some(v=>v.init.method==='GET'));
    }finally{f?.author.close();OwnerWorkflowContextClient.prototype[method]=original;}
  }
});
