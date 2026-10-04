// SPDX-License-Identifier: AGPL-3.0-only
// DOM presentation is a unit shim. Positive custody and HPKE use actual maintained implementations.
import test from 'node:test';
import assert from 'node:assert/strict';
import {setTimeout as delay} from 'node:timers/promises';
import {archiveFixture} from './conversation-archive-fixture.mjs';
import {unlockExistingArchive02} from '../dist/conversation-archive-custody.js';
import {sealWorkflowContext} from '../dist/workflow-context.js';
import {createOwnerProviderDisclosureReview} from '../dist/owner-provider-disclosure-review.js';
import {verifyManifest02,verifiedManifestTrust02} from '../dist/draft02-manifest.js';
import {signFixtureSuccessor02} from './conversation-refresh-fixture.mjs';
const facts='Synthetic owner facts <plain text>',body='Synthetic exact local message';
const hash=async b=>Buffer.from(await crypto.subtle.digest('SHA-256',b)).toString('hex');
class Element extends EventTarget {
  constructor(document,tag){super();this.ownerDocument=document;this.tagName=tag;this.nodeType=1;this.isConnected=true;this.children=[];this.hidden=false;this.disabled=false;this.attributes={};this.textContent='';}
  append(...nodes){this.children.push(...nodes);}replaceChildren(...nodes){this.textContent='';this.children=nodes;}setAttribute(k,v){this.attributes[k]=v;}
  set textContent(v){this._text=v;this.children=[];}get textContent(){return this._text+this.children.map(v=>v.textContent).join('');}
}
async function fixture(edit={}){
  const f=await archiveFixture(),lease=await unlockExistingArchive02(f.options),b=f.options.binding,controller=new AbortController();
  const window=new EventTarget();window.location={origin:f.origin};window.HTMLElement=Element;
  const document=new EventTarget();document.defaultView=window;document.hidden=false;document.createElement=tag=>new Element(document,tag);const host=new Element(document,'main');
  const scope={kind:1,accountId:b.account,deviceId:b.device,lineId:b.line,intervalId:b.interval,contextId:new Uint8Array(16).fill(6),bindingGeneration:b.generation,revision:1n,expiresMs:f.nowMs+300000n,trustGeneration:f.predecessor.generation,manifestVersion:f.predecessor.version,peerDigest:new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(b.peer))),readerId:b.archiveReader,manifestDigest:f.predecessor.digest};
  const envelope=await sealWorkflowContext(f.predecessor,scope,f.nowMs,new TextEncoder().encode(facts));
  const declaration={adapter:'telnyx-sms-v2',organization_id:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',messaging_profile_id:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',sender:'+15550100001',owner_label:'Example',intended_region:'unverified',retention_policy_ref:null,eligibility_policy_ref:null,cost_policy_ref:null};
  const config={configId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',configVersion:1,recordVersion:1};
  const response={config_id:config.configId,config_version:1,record_version:1,state:'draft',acceptance:'unavailable',declaration,unavailable_reasons:['provider_identity_unverified','sender_eligibility_unverified','policy_unaccepted','cost_bound_unavailable']};
  const state={calls:[],raw:JSON.stringify(response),envelope,csrf:'synthetic-csrf',keyCalls:0,releases:0,listeners:{setup:[],custody:[]}};
  const subscribe=name=>run=>{state.listeners[name].push(run);return()=>{state.releases++;state.listeners[name]=state.listeners[name].filter(v=>v!==run);};};
  const observedLease={onClose:run=>lease.onClose(run),close:()=>lease.close(),withKey:(selected,run)=>lease.withKey(selected,async key=>{state.keyCalls++;return run(key);})};
  const options={enabled:true,origin:f.origin,host,binding:b,source:{scope,envelopeDigest:await hash(envelope)},configuration:config,archiveLease:observedLease,readCurrent:async()=>f.state.current,currentCsrf:()=>state.csrf,onSetupClose:subscribe('setup'),onCustodyClose:subscribe('custody'),signal:controller.signal,timeoutMs:1000,observationMs:1000,
    fetchImpl:async(url,init)=>{state.calls.push({url,init});return url.includes('provider-configurations')?new Response(state.raw,{headers:{'content-type':'application/json'}}):new Response(state.envelope,{headers:{'content-type':'application/vnd.zrotext.workflow-context.v1'}});},...edit};
  const local=createOwnerProviderDisclosureReview(options),click=()=>host.children.find(n=>n.tagName==='button'&&n.textContent==='Review locally').dispatchEvent(new Event('click'));
  return {f,lease,controller,window,document,host,state,options,local,click,async reviewed(){const ticket=await local.prepare(body),promise=local.review(ticket);click();return promise;},close(){local.close();lease.close();}};
}

test('actual existing archive factory and HPKE opening produce only copied local review commitments',async()=>{
  const f=await fixture();try{
    const ticket=await f.local.prepare(body);assert.equal(f.state.keyCalls,1);assert.equal(f.state.calls.length,2);assert.deepEqual(ticket,{});assert.ok(Object.isFrozen(ticket));
    const promise=f.local.review(ticket);assert.equal(f.host.children[1].children[2].textContent,facts);assert.equal(f.host.children[1].children[3].textContent,body);
    assert.match(f.host.children[1].children[0].textContent,/unaccepted.*unavailable/);f.click();const result=await promise;
    assert.equal(result.state,'local_reviewed_unavailable');assert.equal(result.execution,'unavailable');assert.equal(result.rendered_body_digest,await hash(new TextEncoder().encode(body)));assert.equal(result.source_envelope_digest,f.options.source.envelopeDigest);assert.equal(result.review_binding_digest.length,64);
    assert.equal(f.state.calls.length,4);assert.equal(f.local.state().phase,'reviewed');assert.equal(f.host.children[1].children.length,0);assert.ok(!f.host.textContent.includes(facts));
    assert.ok(f.state.calls.every(v=>v.init.method==='GET'&&v.init.credentials==='same-origin'&&v.init.mode==='same-origin'&&v.init.redirect==='error'&&v.init.cache==='no-store'&&v.init.headers.Authorization===undefined&&v.init.headers.Cookie===undefined));
    await assert.rejects(f.local.prepare(body));await assert.rejects(f.local.review(ticket));assert.equal(f.state.keyCalls,1);
  }finally{f.close();}
});
test('closed options reject accessors, foreign origin and unavailable adapters without callbacks',async()=>{
  const f=await fixture();f.local.close();try{
    for(const change of [o=>o.extra=true,o=>o.origin='https://other.invalid',o=>o.configuration={...o.configuration,recordVersion:Number.MAX_SAFE_INTEGER+1},o=>Object.defineProperty(o,'readCurrent',{get(){assert.fail('Getter invoked');}})]){
      const o={...f.options};change(o);assert.throws(()=>createOwnerProviderDisclosureReview(o));
    }
    const off=createOwnerProviderDisclosureReview({...f.options,enabled:false});await assert.rejects(off.prepare(body));assert.equal(f.state.calls.length,0);off.close();
  }finally{f.close();}
});
test('invalid origin scalars refuse before coercion or any application callback',async()=>{
  const f=await fixture();f.local.close();let coercions=0,callbacks=0;
  const called=()=>{callbacks++;assert.fail('Invalid origin invoked an application callback');};
  const options={...f.options,readCurrent:called,currentCsrf:called,onSetupClose:called,onCustodyClose:called,fetchImpl:called,archiveLease:{withKey:called,onClose:called,close:called}};
  try{
    const object={toString(){coercions++;return f.options.origin;}};
    for(const origin of [object,null,1,'','not-a-url','https://[','https://other.invalid','https://other.invalid/path',f.options.origin+'\n','x'.repeat(513)])
      assert.throws(()=>createOwnerProviderDisclosureReview({...options,origin}),/^Error: Local provider review unavailable$/);
    // A malformed matching location is a unit shim only, and exercises parser-error normalization.
    f.window.location.origin='https://[';
    assert.throws(()=>createOwnerProviderDisclosureReview({...options,origin:'https://['}),/^Error: Local provider review unavailable$/);
    assert.equal(coercions,0);assert.equal(callbacks,0);assert.equal(f.state.calls.length,0);assert.equal(f.state.keyCalls,0);
  }finally{f.close();}
});
test('unknown, withdrawn, changed, alias and malformed configuration responses never open plaintext',async()=>{
  for(const mutate of [r=>r.replace('telnyx-sms-v2','telnyx_sms_v2'),r=>r.replace('"state":"draft"','"state":"withdrawn"'),r=>r.replace('"record_version":1','"record_version":2'),r=>r.replace('"config_version":1','"config_version":1e0'),r=>r.replace('{','{"state":"draft",'),r=>r.replace('"sender"','"sen\\u0064er"'),r=>r.replace('"retention_policy_ref":null','"retention_policy_ref":""'),r=>r.replace('"sender":"+15550100001"','"sender":"+15550100001\\n"')]){
    const f=await fixture();try{f.state.raw=mutate(f.state.raw);await assert.rejects(f.local.prepare(body));assert.equal(f.state.keyCalls,0);assert.equal(f.local.state().phase,'closed');assert.equal(f.host.children[1].children.length,0);}finally{f.close();}
  }
});
test('source head, current owner and reader mutations refuse without a commitment',async()=>{
  for(const mutate of [f=>f.state.envelope=Uint8Array.from(f.state.envelope,v=>v^1),f=>f.f.state.current={...f.f.state.current,ownerSessionLive:false},f=>f.f.state.current={...f.f.state.current,binding:{...f.f.state.current.binding,session:new Uint8Array(16).fill(9)}}]){
    const f=await fixture();try{mutate(f);await assert.rejects(f.local.prepare(body));assert.equal(f.local.pending(),null);}finally{f.close();}
  }
  const f=await fixture();try{const ticket=await f.local.prepare(body),p=f.local.review(ticket);f.f.state.current=null;f.click();await assert.rejects(p);assert.ok(f.local.pending());assert.equal(f.local.state().phase,'closed');}finally{f.close();}
});
test('skipped, duplicated and premature key callbacks cannot supply arbitrary plaintext',async()=>{
  for(const mode of ['skip','duplicate','early']){
    const f=await fixture();f.local.close();let later;
    const lease={onClose:run=>f.lease.onClose(run),close:()=>{},withKey:async(b,run)=>{
      if(mode==='skip')return new TextEncoder().encode('Arbitrary substituted plaintext');
      if(mode==='duplicate'){await f.lease.withKey(b,run);return f.lease.withKey(b,run);}
      later=f.lease.withKey(b,async key=>{await delay(30);return run(key);});void later.catch(()=>{});return new Uint8Array(1);
    }};
    const local=createOwnerProviderDisclosureReview({...f.options,archiveLease:lease});try{await assert.rejects(local.prepare(body));assert.equal(local.pending(),null);assert.equal(local.state().phase,'closed');if(later)await assert.rejects(later);}finally{local.close();f.close();}
  }
});
test('arbitrary mutated withKey return is ignored after the actual owned HPKE result',async()=>{
  const f=await fixture();f.local.close();const local=createOwnerProviderDisclosureReview({...f.options,archiveLease:{onClose:run=>f.lease.onClose(run),close:()=>{},withKey:async(b,run)=>{await f.lease.withKey(b,run);return new Uint8Array(32769).fill(99);}}});
  try{const ticket=await local.prepare(body),p=local.review(ticket);assert.equal(f.host.children[1].children[2].textContent,facts);f.click();assert.equal((await p).execution,'unavailable');}finally{local.close();f.close();}
});
test('changed copied review and changed declaration after preparation close and scrub',async()=>{
  for(const mutate of [f=>f.host.children[1].children[3].textContent='Synthetic different message',f=>f.host.children[1].hidden=true,f=>f.state.raw=f.state.raw.replace('"owner_label":"Example"','"owner_label":"Changed"')]){
    const f=await fixture();try{const ticket=await f.local.prepare(body),p=f.local.review(ticket);mutate(f);f.click();await assert.rejects(p);assert.equal(f.host.children[1].children.length,0);assert.equal(f.local.state().phase,'closed');}finally{f.close();}
  }
});
test('idle prepared deadline and all lifecycle closures scrub without another operation',async()=>{
  for(const mode of ['idle','setup','custody','lease','pagehide','hidden']){
    const f=await fixture({timeoutMs:mode==='idle'?150:1000});try{await f.local.prepare(body);const pending=f.local.pending();
      if(mode==='idle')await delay(200);else if(mode==='setup'||mode==='custody')f.state.listeners[mode].slice().forEach(run=>run());else if(mode==='lease')f.lease.close();else if(mode==='pagehide')f.window.dispatchEvent(new Event('pagehide'));else{f.document.hidden=true;f.document.dispatchEvent(new Event('visibilitychange'));}
      assert.equal(f.local.state().phase,'closed');assert.deepEqual(f.local.pending(),pending);assert.equal(f.host.children[1].children.length,0);assert.equal(f.state.calls.length,2);
    }finally{f.close();}
  }
});
test('synchronous CSRF abort and late rejected current callbacks never publish or leak rejections',async()=>{
  const f=await fixture();f.local.close();const errors=[],listener=e=>errors.push(e);process.on('unhandledRejection',listener);
  try{
    let local;local=createOwnerProviderDisclosureReview({...f.options,currentCsrf:()=>{local.close();return 'synthetic-csrf';}});await assert.rejects(local.prepare(body));assert.equal(f.state.calls.length,0);local.close();
    local=createOwnerProviderDisclosureReview({...f.options,readCurrent:()=>{local.close();return Promise.reject(Error('Synthetic late rejection'));}});await assert.rejects(local.prepare(body));await delay(20);assert.deepEqual(errors,[]);local.close();
  }finally{process.removeListener('unhandledRejection',listener);f.close();}
});
test('closed snapshot copies and ticket isolation prevent resets and UTF8 substitution',async()=>{
  const f=await fixture();f.local.close();const input={...f.options,binding:structuredClone(f.options.binding),source:{...f.options.source,scope:structuredClone(f.options.source.scope)},configuration:{...f.options.configuration}},local=createOwnerProviderDisclosureReview(input);
  try{const ticket=await local.prepare(body);input.binding.peer='+13';input.configuration.recordVersion=9;input.source.scope.contextId.fill(0);await assert.rejects(local.review({}));const p=local.review(ticket);f.click();assert.equal((await p).execution,'unavailable');}finally{local.close();f.close();}
  for(const bad of ['', 'x'.repeat(4097), '\u2603'.repeat(1500),'\ud800']){const f=await fixture();try{await assert.rejects(f.local.prepare(bad));assert.equal(f.state.calls.length,0);}finally{f.close();}}
});
test('actual signed short device signer closes an idle ticket despite a cached observation clock',async()=>{
  const f=await fixture();f.local.close();let local;
  try{
    const unsigned=Uint8Array.from(f.f.review.unsigned);for(let at=151;at<unsigned.length;at+=149)if(unsigned[at]===4)new DataView(unsigned.buffer).setBigUint64(at+140,f.f.nowMs+120n);
    const manifest=await verifyManifest02(await signFixtureSuccessor02(f.f,unsigned),verifiedManifestTrust02(f.f.predecessor,f.f.nowMs),f.f.nowMs);
    f.f.state.current={...f.f.state.current,manifest};const selected={...f.options.source.scope,manifestVersion:manifest.version,manifestDigest:manifest.digest};
    f.state.envelope=await sealWorkflowContext(manifest,selected,f.f.nowMs,new TextEncoder().encode(facts));
    local=createOwnerProviderDisclosureReview({...f.options,source:{scope:selected,envelopeDigest:await hash(f.state.envelope)}});
    await local.prepare(body);await delay(170);assert.equal(local.state().phase,'closed');assert.equal(f.state.calls.length,2);assert.equal(f.host.children[1].children.length,0);
  }finally{local?.close();f.close();}
});
test('all teardown subscriptions release even when another cleanup throws',async()=>{
  const f=await fixture();f.local.close();let released=0;const local=createOwnerProviderDisclosureReview({...f.options,onSetupClose:()=>()=>{throw Error('Synthetic release failure');},onCustodyClose:()=>()=>released++});
  try{await local.prepare(body);local.close();assert.equal(released,1);assert.equal(local.state().phase,'closed');assert.equal(f.host.children[1].children.length,0);}finally{local.close();f.close();}
});
test('CSRF teardown at initial, transport and final synchronous boundaries cannot return metadata',async()=>{
  for(const threshold of [1,3,5,10,11]){
    const f=await fixture();f.local.close();let local,calls=0;local=createOwnerProviderDisclosureReview({...f.options,currentCsrf:()=>{if(++calls===threshold)local.close();return 'synthetic-csrf';}});
    try{await assert.rejects((async()=>{const ticket=await local.prepare(body),promise=local.review(ticket);f.click();return promise;})());assert.equal(local.state().phase,'closed');assert.equal(f.host.children[1].children.length,0);}finally{local.close();f.close();}
  }
});
