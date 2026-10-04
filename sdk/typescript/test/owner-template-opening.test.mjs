// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {webcrypto} from 'node:crypto';
import {OwnerTemplateOpening} from '../dist/owner-template-opening.js';
import {OwnerEncryptedTemplateClient} from '../dist/owner-encrypted-template-client.js';
import {templateFixture,templateHost,requestId} from './owner-encrypted-template-client.test.mjs';
globalThis.crypto??=webcrypto;
const latest=f=>new Response(Uint8Array.from(f.envelope),{headers:{'content-type':'application/vnd.zrotext.workflow-template.v1'}});
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
async function selectedKey(f){return f.archive.privateKey;}
function controller(f,extra={},clientExtra={}){
 const host=templateHost(f,clientExtra),client=new OwnerEncryptedTemplateClient({...host,fetchImpl:clientExtra.fetchImpl??(async()=>latest(f))});
 return {client,opening:new OwnerTemplateOpening({enabled:true,client,binding:f.binding,templateId:f.scope.templateId,readCurrent:host.readCurrent,currentCsrf:host.currentCsrf,signal:host.signal,...extra})};
}
test('genuine selected local key opens HPKE ciphertext into bounded preview using GET only',async()=>{
 const f=await templateFixture(),requests=[];const {client,opening}=controller(f,{}, {fetchImpl:async(url,options)=>{requests.push(options);return latest(f);}});
 const result=await opening.openLatest({privateKey:await selectedKey(f)});
 assert.equal(result.preview.text,'Synthetic Example');assert.equal(result.preview.estimate.parts,1);
 assert.equal(result.state,'opened_current_preview');assert.equal(result.requestAcknowledged,false);assert.equal(result.matchesPending,false);
 assert.equal(requests.length,1);assert.equal(requests[0].method,'GET');assert.equal(requests[0].body,undefined);assert.equal(client.pending(),null);opening.close();
});
test('default-off opening performs no network, key inspection or plaintext publication',async()=>{
 const f=await templateFixture();let calls=0,inspections=0;
 const {opening}=controller(f,{enabled:false},{fetchImpl:async()=>{calls++;return latest(f);}});
 await assert.rejects(opening.openLatest(new Proxy({},{getPrototypeOf(){inspections++;return Object.prototype;}})),e=>e.code==='closed');
 assert.equal(calls,0);assert.equal(inspections,0);
});
for(const kind of ['public','wrong-curve','wrong-reader'])test(`opening refuses ${kind} keys without plaintext`,async()=>{
 const f=await templateFixture();let key=f.archive.privateKey;
 if(kind==='public')key=f.archive.publicKey;
 if(kind==='wrong-curve')key=(await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-384'},false,['deriveBits'])).privateKey;
 if(kind==='wrong-reader')key=(await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits'])).privateKey;
 const {opening}=controller(f);await assert.rejects(opening.openLatest({privateKey:key}),e=>e.code==='refused');
});
test('actual AEAD tamper refuses ciphertext that the opaque GET transport can observe',async()=>{
 const f=await templateFixture();f.envelope[f.envelope.length-1]^=1;
 const {opening}=controller(f);await assert.rejects(opening.openLatest({privateKey:await selectedKey(f)}),e=>e.code==='refused');
});
test('maintained selected-reader opening refuses the observed nonextractable key case without publishing',async()=>{
 const f=await templateFixture(),key=await crypto.subtle.importKey('pkcs8',await crypto.subtle.exportKey('pkcs8',f.archive.privateKey),{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const {opening}=controller(f);await assert.rejects(opening.openLatest({privateKey:key}),e=>e.code==='refused');
});
test('a genuine different verified manifest cannot publish an old scope despite the original transport current source',async()=>{
 const f=await templateFixture(),other=await templateFixture(),current=await templateHost(f).readCurrent();let reads=0;
 const {opening}=controller(f,{readCurrent:async()=>({...current,manifest:++reads===1?f.manifest:other.manifest})});
 await assert.rejects(opening.openLatest({privateKey:await selectedKey(f)}));assert.ok(reads>=2);
});
for(const offset of [110,118,158])test(`actual GET with contradictory trust/version/reader header at ${offset} cannot publish`,async()=>{
 const f=await templateFixture();f.envelope[offset]^=1;const {opening}=controller(f);
 await assert.rejects(opening.openLatest({privateKey:await selectedKey(f)}));
});
for(const field of ['account','device','line','interval','session','phoneReader','archiveReader','generation','peer'])test(`independent opening selection refuses changed ${field} despite valid transport host`,async()=>{
 const f=await templateFixture(),current=await templateHost(f).readCurrent(),changed={...f.binding};
 changed[field]=field==='generation'?2n:field==='peer'?'+13':new Uint8Array(changed[field]).fill(99);
 const {opening}=controller(f,{readCurrent:async()=>({...current,binding:changed})});
 await assert.rejects(opening.openLatest({privateKey:await selectedKey(f)}),e=>e.code==='refused');
});
for(const field of ['ownerSessionLive','consentLive','phase','validForMs','nowMs','manifest'])test(`independent opening refuses invalid current ${field}`,async()=>{
 const f=await templateFixture(),current=await templateHost(f).readCurrent();
 const value={ownerSessionLive:false,consentLive:false,phase:'hidden',validForMs:0,nowMs:0n,manifest:{...f.manifest}}[field];
 const {opening}=controller(f,{readCurrent:async()=>({...current,[field]:value})});
 await assert.rejects(opening.openLatest({privateKey:await selectedKey(f)}),e=>e.code==='refused');
});
test('busy is acquired before Proxy inspection and replaced client methods cannot forge snapshots',async()=>{
 const f=await templateFixture(),key=await selectedKey(f);const {client,opening}=controller(f);let nested,replaced=0;
 client.readLatest=async()=>{replaced++;throw Error('Synthetic replaced method');};
 const input=new Proxy({privateKey:key},{getPrototypeOf(target){nested=opening.openLatest({privateKey:key});return Reflect.getPrototypeOf(target);}});
 const outer=opening.openLatest(input),results=await Promise.allSettled([outer,nested]);
 assert.equal(results[0].status,'fulfilled');assert.equal(results[1].status,'rejected');assert.equal(results[1].reason.code,'busy');assert.equal(replaced,0);opening.close();
});
test('accessor key input is refused without invoking the accessor',async()=>{
 const f=await templateFixture();let accessed=0;const {opening}=controller(f);
 await assert.rejects(opening.openLatest({get privateKey(){accessed++;return f.archive.privateKey;}}));assert.equal(accessed,0);
});
test('matching pending GET opens locally without acknowledging or clearing the real unknown POST identity',async()=>{
 const f=await templateFixture();let posts=0,gets=0;
 const {client,opening}=controller(f,{}, {fetchImpl:async(url,options)=>options.method==='GET'?(gets++,latest(f)):(posts++,new Response('',{status:503}))});
 const ticket=await client.prepareSave({requestId,expectedRevision:0,scope:f.scope,envelope:f.envelope});
 await assert.rejects(client.commit(ticket),e=>e.state==='unknown');const pending=client.pending();
 const result=await opening.openLatest({privateKey:await selectedKey(f)});assert.equal(result.matchesPending,true);assert.equal(result.requestAcknowledged,false);
 assert.deepEqual(client.pending(),pending);assert.equal(posts,1);assert.equal(gets,1);opening.close();assert.deepEqual(client.pending(),pending);
});
test('owner revocation after real AES opening refuses late plaintext publication',async()=>{
 const f=await templateFixture(),current=await templateHost(f).readCurrent();let live=true;
 const original=crypto.subtle.decrypt;
 crypto.subtle.decrypt=async function(...args){const plain=await original.apply(this,args);live=false;return plain;};
 try{
  const {opening}=controller(f,{readCurrent:async()=>({...current,ownerSessionLive:live})});
  await assert.rejects(opening.openLatest({privateKey:await selectedKey(f)}),e=>e.code==='refused');
 }finally{crypto.subtle.decrypt=original;}
});
test('CSRF replacement after real AES opening refuses plaintext',async()=>{
 const f=await templateFixture();let csrf='synthetic-csrf';const original=crypto.subtle.decrypt;
 crypto.subtle.decrypt=async function(...args){const plain=await original.apply(this,args);csrf='synthetic-replacement';return plain;};
 try{const {opening}=controller(f,{currentCsrf:()=>csrf});await assert.rejects(opening.openLatest({privateKey:await selectedKey(f)}));}
 finally{crypto.subtle.decrypt=original;}
});
for(const mode of ['close','invalidate','abort','deadline'])test(`${mode} during actual AES wait prevents late plaintext and aborts owned client`,async()=>{
 const f=await templateFixture(),key=await selectedKey(f),entered=deferred(),release=deferred(),signal=new AbortController();
 const original=crypto.subtle.decrypt;crypto.subtle.decrypt=async function(...args){const plain=await original.apply(this,args);entered.resolve();await release.promise;return plain;};
 const {client,opening}=controller(f,{signal:signal.signal,timeoutMs:mode==='deadline'?1000:10000});
 try{
  const pending=opening.openLatest({privateKey:key}),refusal=assert.rejects(pending);
  await Promise.race([entered.promise,pending.then(()=>assert.fail('Opening returned before held AES'),error=>{throw error;})]);
  if(mode==='close')opening.close();if(mode==='invalidate')opening.invalidate();if(mode==='abort')signal.abort();
  await refusal;await assert.rejects(client.readLatest());release.resolve();await new Promise(r=>setImmediate(r));await assert.rejects(opening.openLatest({privateKey:key}));
 }finally{release.resolve();opening.close();crypto.subtle.decrypt=original;}
});
test('one outer deadline includes an uncooperative current source and observes its late rejection',async()=>{
 const f=await templateFixture(),late=deferred();const {client,opening}=controller(f,{timeoutMs:30,readCurrent:()=>late.promise});
 const started=performance.now();await assert.rejects(opening.openLatest({privateKey:await selectedKey(f)}),e=>e.code==='deadline');
 assert.ok(performance.now()-started<1500);late.resolve(null);await assert.rejects(client.readLatest());
});
test('snapshot scope ahead of independent manifest refuses even when transport claims are otherwise genuine',async()=>{
 const f=await templateFixture(),current=await templateHost(f).readCurrent();let calls=0;
 const {opening}=controller(f,{readCurrent:async()=>{calls++;return calls===1?current:{...current,binding:{...f.binding,generation:2n}};}});
 await assert.rejects(opening.openLatest({privateKey:await selectedKey(f)}));assert.ok(calls>=2);
});
