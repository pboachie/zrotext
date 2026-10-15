// Actual maintained opening lifecycle; software fixture key only, no custody claim.
import {webcrypto} from 'node:crypto';
import {enrollRootPin02,verifyManifest02} from '../../../typescript/dist/draft02-manifest.js';
import {OwnerEncryptedTemplateClient} from '../../../typescript/dist/owner-encrypted-template-client.js';
import {OwnerTemplateOpening} from '../../../typescript/dist/owner-template-opening.js';
import {CipherSuite,DhkemP256HkdfSha256,HkdfSha256,Aes128Gcm} from '../../../typescript/node_modules/@hpke/core/esm/mod.js';
globalThis.crypto??=webcrypto;
let input='';for await(const part of process.stdin)input+=part;const {fixture:f,cases}=JSON.parse(input),results=[];
const dec=x=>new Uint8Array(Buffer.from(x,'base64'));
for(const item of cases){
 const binding=Object.fromEntries(Object.entries(f.binding).map(([k,v])=>[k,k==='generation'?BigInt(v):k==='peer'?v:dec(v)]));
 const manifest=await verifyManifest02(dec(f.manifest),await enrollRootPin02(dec(f.rootPin),dec(f.fingerprint)),BigInt(f.now));
 let calls=0;
 const readCurrent=async()=>({binding,manifest,nowMs:BigInt(f.now),ownerSessionLive:item.ownerLive!==false&&!(item.ownerLostAfterRead&&calls),consentLive:true,phase:'active',validForMs:10000});
 const currentCsrf=()=>item.csrfLostAfterRead&&calls?'rotated':'synthetic-csrf',signal=new AbortController().signal;
 const client=new OwnerEncryptedTemplateClient({enabled:true,origin:'https://owner.example.invalid',binding,templateId:dec(f.scope.templateId),readCurrent,currentCsrf,signal,consumeCiphertextReview:async()=>{},fetchImpl:async()=>{calls++;const raw=dec(f.envelope);if(item.tamper)raw[raw.length-1]^=1;return new Response(raw,{status:item.status??200,headers:{'content-type':'application/vnd.zrotext.workflow-template.v1'}});}});
 const opening=new OwnerTemplateOpening({enabled:true,client,binding,templateId:dec(f.scope.templateId),readCurrent,currentCsrf,signal});
 const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
 const key=await suite.kem.deserializePrivateKey(dec(f.archiveScalar));
 try{const value=await opening.openLatest({privateKey:key});results.push({accepted:true,calls,preview:value.preview});}
 catch(error){results.push({accepted:false,calls});}finally{opening.close();}
}
process.stdout.write(JSON.stringify(results));
