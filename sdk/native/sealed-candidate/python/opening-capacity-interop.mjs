// SPDX-License-Identifier: AGPL-3.0-only
// Actual maintained author/transport under presentation and synthetic HTTP fixtures.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {enrollRootPin02,verifyManifest02} from '../../../typescript/dist/draft02-manifest.js';
import {createOwnerContextAuthoring} from '../../../typescript/dist/owner-context-authoring.js';
import {createOwnerOpeningCapacityClient} from '../../../typescript/dist/owner-opening-capacity-client.js';
globalThis.crypto??=webcrypto;
const b=v=>new Uint8Array(Buffer.from(v,'base64')),b64=v=>Buffer.from(v).toString('base64');
const uuid=v=>Buffer.from(v).toString('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
const request='00000000-0000-0000-0000-000000000021',opening='00000000-0000-0000-0000-000000000022';
const origin='https://owner.example.invalid';
class Element extends EventTarget{
 constructor(document,tag){super();this.ownerDocument=document;this.tagName=tag;this.nodeType=1;this.children=[];this.value='';this.textContent='';this.hidden=false;this.disabled=false;this.attributes={};}
 append(...nodes){this.children.push(...nodes)}replaceChildren(...nodes){this.textContent='';this.children=nodes}setAttribute(k,v){this.attributes[k]=v}
 set textContent(v){this._text=v;this.children=[]}get textContent(){return this._text+this.children.map(v=>v.textContent).join('')}
}
const nodes=e=>[e,...e.children.flatMap(nodes)];
async function until(fn){for(let i=0;i<300;i++){if(fn())return;await delay(5)}throw Error('author deadline')}
async function authority(f){return {binding:Object.fromEntries(Object.entries(f.binding).map(([k,v])=>[k,k==='generation'?BigInt(v):k==='peer'?v:b(v)])),manifest:await verifyManifest02(b(f.manifest),await enrollRootPin02(b(f.rootPin),b(f.fingerprint)),BigInt(f.now)),nowMs:BigInt(f.now),ownerSessionLive:true,consentLive:true};}
function receipt(id=opening){return {opening:{opening_id:id,definition_version:'1',state_version:'1'},offer:null,allocation_id:null,allocation_version:null,phase:'open',pending:'0',confirmed:'0'};}
if(!process.argv[2]){
 const f=JSON.parse(execFileSync(process.execPath,[fileURLToPath(new URL('./context-authoring-interop.mjs',import.meta.url))],{encoding:'utf8'})),current=await authority(f);
 const window=new EventTarget();window.location={origin};const document=new EventTarget();document.defaultView=window;document.hidden=false;document.createElement=tag=>new Element(document,tag);
 const host=new Element(document,'main'),controller=new AbortController();let head;
 const author=createOwnerContextAuthoring({enabled:true,origin,host,binding:current.binding,contextId:b(f.scope.contextId),expiresMs:BigInt(f.scope.expiresMs),readCurrent:async()=>current,currentCsrf:()=> 'synthetic-csrf',archiveLease:{onClose:()=>()=>{},withKey:()=>{throw Error('no private custody')},close:()=>{}},onSetupClose:()=>()=>{},onCustodyClose:()=>()=>{},signal:controller.signal,
  fetchImpl:async(_,init)=>{if(init.method==='POST'){head=new Uint8Array(init.body).slice();return new Response('{"revision":1}',{headers:{'content-type':'application/json'}})}return new Response(head,{headers:{'content-type':'application/vnd.zrotext.workflow-context.v1'}})}});
 try{const all=nodes(host),click=text=>all.find(e=>e.tagName==='button'&&e.textContent===text).dispatchEvent(new Event('click'));
  all.find(e=>e.tagName==='textarea').value='Synthetic acknowledged opening facts';click('Review facts');await until(()=>author.state().phase==='review');click('Save encrypted facts');await until(()=>author.state().phase==='saved');
  f.source=author.savedSource();assert.ok(f.source);f.sourceEnvelope=b64(head);process.stdout.write(JSON.stringify(f));
 }finally{author.close()}
}else if(process.argv[2]==='--cases'){
 const {fixture:f,cases}=JSON.parse(readFileSync(0,'utf8')),current=await authority(f),results=[];
 for(const scenario of cases){
  let csrf='synthetic-csrf',source=structuredClone(f.source),reviews=0,currentReads=0;const calls=[],responses=[...(scenario.responses??[])],controller=new AbortController();
  if(scenario.sourceChange)Object.assign(source.receipt,scenario.sourceChange);
  const client=createOwnerOpeningCapacityClient({enabled:true,origin,binding:current.binding,contextId:b(f.scope.contextId),sourceExpiresMs:BigInt(f.scope.expiresMs),readSavedSource:()=>source,
   readCurrent:async()=>{currentReads++;return current},currentCsrf:()=>csrf,consumeCreateReview:async()=>{reviews++;if(scenario.rejectReview)throw Error('declined');if(scenario.changeOnReview)source={...source,receipt:{...source.receipt,envelopeDigest:'a'.repeat(64)}}},signal:controller.signal,onSetupClose:()=>()=>{},onCustodyClose:()=>()=>{},totalTimeoutMs:5000,attemptTimeoutMs:1000,observationTimeoutMs:5000,maxAttempts:scenario.maxAttempts??3,
   fetchImpl:async(url,init)=>{calls.push({path:new URL(url).pathname,body:init.body});const r=responses.shift()??{};if(r.network)throw Error('synthetic network');if(r.status&&r.status!==200)return new Response(null,{status:r.status});
    const value=url.endsWith('/status')?{account_id:uuid(current.binding.account),receipt:receipt()}:{account_id:uuid(current.binding.account),request_id:request,outcome:{receipt:receipt(),applied:true,recorded:true}};
    return new Response(r.raw??JSON.stringify(value),{headers:{'content-type':r.media??'application/json'}})}});
  let ticket;const rows=[];
  try{for(const op of scenario.ops){let value;
   try{if(op==='prepare'){ticket=await client.prepareCreate({requestId:request,openingId:opening,capacity:scenario.capacity??3,decisionDeadlineMs:BigInt(f.now+4000)});value={prepared:true}}
    else if(op==='create')value=await client.create(ticket);else if(op==='retry')value=await client.retry(ticket);else if(op==='status')value=await client.status(opening);
    else if(op==='wrongStatus')value=await client.status(request);else if(op==='wrongTicket')value=await client.create({});else if(op==='close'){client.close();value={closed:true}}
    else if(op==='rotate'||op==='rotateInvalid'){csrf=op==='rotate'?'changed':'';value={rotated:true}}else if(op==='dropSource'){source=null;value={dropped:true}}else throw Error('operation');
   }catch(error){value={error:error.code??'exception'}}
   rows.push({value,pending:client.state().pending,calls:calls.map(v=>({...v})),reviews,currentReads});
  }results.push(rows)}finally{client.close()}
 }
 process.stdout.write(JSON.stringify(results,(_,v)=>typeof v==='bigint'?v.toString():v));
}else throw Error('mode');
