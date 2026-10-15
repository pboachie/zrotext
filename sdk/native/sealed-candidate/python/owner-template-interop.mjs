// Genuine maintained owner-template read fixture and differential consumer.
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {webcrypto} from 'node:crypto';
import {enrollRootPin02,verifyManifest02} from '../../../typescript/dist/draft02-manifest.js';
import {sealEncryptedTemplate} from '../../../typescript/dist/encrypted-template.js';
import {OwnerEncryptedTemplateClient} from '../../../typescript/dist/owner-encrypted-template-client.js';
globalThis.crypto??=webcrypto;
const b64=x=>Buffer.from(x).toString('base64'),dec=x=>new Uint8Array(Buffer.from(x,'base64'));
const numeric=['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'];
const scopeOf=f=>Object.fromEntries(Object.entries(f.scope).map(([k,v])=>[k,numeric.includes(k)?BigInt(v):dec(v)]));
async function manifestOf(f){return verifyManifest02(dec(f.manifest),await enrollRootPin02(dec(f.rootPin),dec(f.fingerprint)),BigInt(f.now));}
if(process.argv[2]==='--cases'){
 let input='';for await(const part of process.stdin)input+=part;const {fixture:f,cases}=JSON.parse(input),results=[];
 for(const item of cases){
  const binding=Object.fromEntries(Object.entries(f.binding).map(([k,v])=>[k,k==='generation'?BigInt(v):k==='peer'?v:dec(v)]));
  const manifest=await manifestOf(f);let calls=0,current=0;
  const client=new OwnerEncryptedTemplateClient({enabled:true,origin:'https://owner.example.invalid',binding,templateId:scopeOf(f).templateId,
   readCurrent:async()=>{current++;return {binding,manifest,nowMs:BigInt(f.now),ownerSessionLive:item.ownerLive!==false,consentLive:true,phase:'active',validForMs:10000};},
   currentCsrf:()=> 'synthetic-csrf',consumeCiphertextReview:async()=>{},signal:new AbortController().signal,
   fetchImpl:async()=>{calls++;return new Response(dec(item.envelope??f.envelope),{status:item.status??200,headers:{'content-type':item.contentType??'application/vnd.zrotext.workflow-template.v1'}});}});
  try{const value=await client.readLatest();results.push({accepted:true,calls,digest:value.encryptedDigest,ack:value.requestAcknowledged});}
  catch(e){results.push({accepted:false,calls,code:e.code,state:e.state});}finally{client.close();}
 }
 process.stdout.write(JSON.stringify(results));
}else{
 const f=JSON.parse(execFileSync(process.execPath,[fileURLToPath(new URL('./template-interop.mjs',import.meta.url)),...process.argv.slice(2)],{encoding:'utf8'}));
 const scope=scopeOf(f);scope.peerDigest=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode('+12')));
 const binding={account:scope.accountId,device:scope.deviceId,line:scope.lineId,interval:scope.intervalId,session:new Uint8Array(16).fill(31),generation:1n,peer:'+12',phoneReader:new Uint8Array(32).fill(32),archiveReader:scope.readerId};
 f.scope=Object.fromEntries(Object.entries(scope).map(([k,v])=>[k,typeof v==='bigint'?Number(v):b64(v)]));
 f.binding=Object.fromEntries(Object.entries(binding).map(([k,v])=>[k,typeof v==='bigint'?Number(v):typeof v==='string'?v:b64(v)]));
 f.envelope=b64(await sealEncryptedTemplate(await manifestOf(f),scope,BigInt(f.now),f.content));
 process.stdout.write(JSON.stringify(f));
}
