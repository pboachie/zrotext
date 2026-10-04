// SPDX-License-Identifier: AGPL-3.0-only
// Presentation fixture only; manifests and encryption use maintained SDK code.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {setTimeout as delay} from 'node:timers/promises';
import {refreshFixture,signFixtureSuccessor02} from './conversation-refresh-fixture.mjs';
import {verifyManifest02,verifiedManifestTrust02} from '../dist/draft02-manifest.js';
import {createOwnerContextAuthoring} from '../dist/owner-context-authoring.js';
const canary='Synthetic local private facts <not markup>';
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
  const state={calls:[],reads:0,head:null,current:{binding:f.review.binding,manifest:f.predecessor,nowMs:f.nowMs,ownerSessionLive:true,consentLive:true}};
  const subscribe=key=>listener=>{listeners[key].push(listener);return()=>{listeners[key]=listeners[key].filter(v=>v!==listener);};};
  const options={enabled:true,origin:f.origin,host:ui.host,binding:f.review.binding,contextId:new Uint8Array(16).fill(6),expiresMs:f.nowMs+300000n,
    readCurrent:async()=>{state.reads++;return state.current;},currentCsrf:()=> 'synthetic-csrf',archiveLease:{onClose:subscribe('archive'),withKey:()=>{throw Error('Key access must not occur');},close:()=>listeners.archive.slice().forEach(run=>run())},
    onSetupClose:subscribe('setup'),onCustodyClose:subscribe('custody'),signal:controller.signal,timeoutMs:2000,observationMs:2000,
    fetchImpl:async(url,init)=>{state.calls.push({url,init,body:init.body?new Uint8Array(init.body).slice():null});if(init.method==='POST'){state.head=new Uint8Array(init.body).slice();return new Response('{"revision":1}',{headers:{'content-type':'application/json'}});}return new Response(state.head,{headers:{'content-type':'application/vnd.zrotext.workflow-context.v1'}});},...edit};
  const author=createOwnerContextAuthoring(options),all=nodes(ui.host),editor=all.find(v=>v.tagName==='textarea'),review=all.find(v=>v.attributes['aria-label']==='Review facts'),status=all.find(v=>v.attributes.role==='status');
  const click=text=>all.find(v=>v.tagName==='button'&&v.textContent===text).dispatchEvent(new Event('click'));
  return {f,ui,controller,listeners,state,options,author,editor,review,status,click,async prepare(){editor.value=canary;click('Review facts');await until(()=>author.state().phase==='review');},async save(){await this.prepare();click('Save encrypted facts');await until(()=>['saved','unknown','refused','closed'].includes(author.state().phase));}};
}

test('explicit local facts review saves exact initial ciphertext and independently reads latest',async()=>{
  const f=await fixture();try{
    assert.equal(f.state.reads+f.state.calls.length,0);await f.prepare();assert.equal(f.state.calls.length,0);
    assert.equal(f.review.children[1].textContent,canary);assert.ok(f.review.children[0].textContent.includes(f.options.binding.peer));
    f.click('Save encrypted facts');await until(()=>f.author.state().phase==='saved');assert.equal(f.author.state().pending,null);
    assert.equal(f.editor.value,'');assert.equal(f.review.hidden,true);assert.equal(f.review.children.length,0);
    const post=f.state.calls[0];assert.equal(post.init.headers['x-zrotext-context-revision'],'0');assert.equal(new DataView(post.body.buffer).getBigUint64(94),1n);
    assert.equal(new DataView(post.body.buffer).getBigUint64(118),f.state.current.manifest.version);assert.equal(Buffer.from(post.body).includes(Buffer.from(canary)),false);
    assert.equal(post.init.credentials,'same-origin');assert.equal(post.init.headers.Cookie,undefined);assert.equal(post.init.headers.Authorization,undefined);
    assert.equal(f.state.calls.length,2);assert.equal(f.state.calls[1].url.includes('?'),false);assert.match(f.status.textContent,/current at this check/);
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
    await f.save();assert.equal(f.author.state().phase,'unknown');const pending=f.author.state().pending;assert.ok(pending);assert.equal(f.editor.value,'');
    f.click('Review facts');await delay(5);assert.equal(posts,1);
    f.click('Check saved facts');await until(()=>f.author.state().phase==='unknown');assert.deepEqual(f.author.state().pending,pending);assert.equal(posts,1);
    f.click('Retry same save');await until(()=>f.author.state().phase==='saved');const sent=f.state.calls.filter(v=>v.init.method==='POST');assert.deepEqual(sent[0].body,sent[1].body);assert.deepEqual(sent[0].init.headers,sent[1].init.headers);assert.equal(f.author.state().pending,null);
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
