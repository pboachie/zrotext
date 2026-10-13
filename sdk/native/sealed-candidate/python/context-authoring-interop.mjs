// Maintained cryptography and authoring state machine; presentation fixture only.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';
import {CipherSuite,DhkemP256HkdfSha256,HkdfSha256,Aes128Gcm} from '../../../typescript/node_modules/@hpke/core/esm/mod.js';
import {enrollRootPin02,verifyManifest02} from '../../../typescript/dist/draft02-manifest.js';
import {openWorkflowContext} from '../../../typescript/dist/workflow-context.js';
import {createOwnerContextAuthoring} from '../../../typescript/dist/owner-context-authoring.js';
globalThis.crypto??=webcrypto;
const b=v=>new Uint8Array(Buffer.from(v,'base64')),b64=v=>Buffer.from(v).toString('base64');
const manifestOf=async f=>verifyManifest02(b(f.manifest),await enrollRootPin02(b(f.rootPin),b(f.fingerprint)),BigInt(f.now));
const bindingOf=f=>Object.fromEntries(Object.entries(f.binding).map(([k,v])=>[k,k==='generation'?BigInt(v):k==='peer'?v:b(v)]));
const scopeOf=raw=>{const view=new DataView(raw.buffer,raw.byteOffset,raw.byteLength),scope={kind:raw[5]};
 ['accountId','deviceId','lineId','intervalId','contextId'].forEach((k,i)=>scope[k]=raw.slice(6+16*i,22+16*i));
 ['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'].forEach((k,i)=>scope[k]=view.getBigUint64(86+8*i));
 ['peerDigest','readerId','manifestDigest'].forEach((k,i)=>scope[k]=raw.slice(126+32*i,158+32*i));return scope};
class Element extends EventTarget{
 constructor(document,tag){super();this.ownerDocument=document;this.tagName=tag;this.nodeType=1;this.children=[];this.value='';this.textContent='';this.hidden=false;this.disabled=false;this.attributes={};}
 append(...nodes){this.children.push(...nodes)}replaceChildren(...nodes){this.textContent='';this.children=nodes}setAttribute(k,v){this.attributes[k]=v}
 set textContent(v){this._text=v;this.children=[]}get textContent(){return this._text+this.children.map(v=>v.textContent).join('')}
}
const nodes=e=>[e,...e.children.flatMap(nodes)];
async function until(fn){for(let i=0;i<300;i++){if(fn())return;await delay(5)}throw Error('phase deadline')}
if(!process.argv[2]){
 const f=JSON.parse(execFileSync(process.execPath,[fileURLToPath(new URL('./owner-context-interop.mjs',import.meta.url))],{encoding:'utf8'})),manifest=await manifestOf(f),binding=bindingOf(f);
 const phone=manifest.keys.find(k=>k.role===1&&Buffer.from(k.deviceId).equals(Buffer.from(binding.device))&&Buffer.from(k.lineId).equals(Buffer.from(binding.line)));
 assert.ok(phone);f.binding.phoneReader=b64(phone.keyId);process.stdout.write(JSON.stringify(f));
}else{
 const input=JSON.parse(readFileSync(0,'utf8')),f=input.fixture,manifest=await manifestOf(f);
 if(process.argv[2]==='--consume'){
  const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()}),key=await suite.kem.deserializePrivateKey(b(f.archiveScalar));
  for(const output of input.outputs){const raw=b(output.envelope),scope=scopeOf(raw);assert.equal(scope.kind,1);assert.equal(scope.revision,1n);
   assert.deepEqual(await openWorkflowContext(manifest,scope,BigInt(f.now),key,raw),b(output.plaintext));}
  process.stdout.write(JSON.stringify({verified:true,opened:input.outputs.length}));
 }else if(process.argv[2]==='--cases'){
  const result=[];
  for(const scenario of input.cases){
   const origin='https://owner.example.invalid',window=new EventTarget();window.location={origin};const document=new EventTarget();document.defaultView=window;document.hidden=false;document.createElement=tag=>new Element(document,tag);
   const host=new Element(document,'main'),controller=new AbortController(),binding=bindingOf(f),responses=[...(scenario.responses??[])],calls=[];let head=null,csrf='synthetic-csrf',reviews=0;
   const author=createOwnerContextAuthoring({enabled:true,origin,host,binding,contextId:b(f.scope.contextId),expiresMs:BigInt(f.scope.expiresMs),readCurrent:async()=>({binding,manifest,nowMs:BigInt(f.now),ownerSessionLive:true,consentLive:true}),currentCsrf:()=>csrf,
    archiveLease:{onClose:()=>()=>{},withKey:()=>{throw Error('private key access prohibited')},close:()=>{}},onSetupClose:()=>()=>{},onCustodyClose:()=>()=>{},signal:controller.signal,
    fetchImpl:async(url,init)=>{calls.push({method:init.method,body:init.body?b64(init.body):null,id:init.headers['idempotency-key']});const r=responses.shift()??{};
     if(init.method==='POST')head=new Uint8Array(init.body).slice();if(r.network)throw Error('synthetic unavailable');
     if(r.status&&r.status!==200)return new Response(null,{status:r.status});
     return new Response(init.method==='POST'?(r.body??'{"revision":1}'):head,{headers:{'content-type':init.method==='POST'?'application/json':'application/vnd.zrotext.workflow-context.v1'}});}});
   const all=nodes(host),editor=all.find(e=>e.tagName==='textarea'),review=all.find(e=>e.attributes['aria-label']==='Review facts');
   const click=text=>all.find(e=>e.tagName==='button'&&e.textContent===text).dispatchEvent(new Event('click'));
   const snapshots=[];
   try{
    for(const op of scenario.ops){
     if(op==='author'){
      editor.value=scenario.text??'Synthetic reviewed facts 🌱';click('Review facts');await until(()=>['review','refused','closed'].includes(author.state().phase));
      if(author.state().phase==='review'){reviews++;assert.equal(calls.length,0);if(scenario.reviewReject)review.children[1].textContent='Synthetic changed review';if(scenario.rotate)csrf='rotated';click('Save encrypted facts');await until(()=>['saved','unknown','refused','closed'].includes(author.state().phase));}
     }else if(op==='retry'||op==='verify'){click(op==='retry'?'Retry same save':'Check saved facts');await delay(5);await until(()=>author.state().phase!=='saving');}
     else if(op==='close')author.close();else throw Error('operation');
     const posts=calls.filter(v=>v.method==='POST'),source=author.savedSource();
     snapshots.push({phase:author.state().phase,pending:author.state().pending!==null,source:source!==null,posts:posts.length,gets:calls.length-posts.length,exactRetry:posts.every(v=>v.body===posts[0].body&&v.id===posts[0].id),reviews});
     if(source)assert.equal(source.receipt.requestAcknowledged,true);
    }
    result.push(snapshots);
   }finally{author.close()}
  }
  process.stdout.write(JSON.stringify(result));
 }else throw Error('mode');
}
