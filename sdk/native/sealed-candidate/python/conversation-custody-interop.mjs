// Independent maintained custody lifecycle and actual signed/encrypted fixtures.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {webcrypto,createECDH} from 'node:crypto';
import {CipherSuite,DhkemP256HkdfSha256,HkdfSha256,Aes128Gcm} from '../../../typescript/node_modules/@hpke/core/esm/mod.js';
import {enrollRootPin02,verifyManifest02,advanceManifestTrust02,canonicalSignature02,authorizeOutbound02} from '../../../typescript/dist/draft02-manifest.js';
import {keyId} from '../../../typescript/dist/draft01.js';
import {prepareInboundEnvelope02} from '../../../typescript/dist/draft02-envelope-prep.js';
import {prepareConversationCustody02,existingConversationRootCustodian02} from '../../../typescript/dist/conversation-custody.js';
globalThis.crypto??=webcrypto;
const b=v=>new Uint8Array(Buffer.from(v,'base64')),b64=v=>Buffer.from(v).toString('base64');
const join=(...v)=>new Uint8Array(Buffer.concat(v.map(x=>Buffer.from(x)))),enc=new TextEncoder(),label=v=>enc.encode(v+'\0');
const num=(v,n=8)=>{const out=Buffer.alloc(n);n===8?out.writeBigUInt64BE(BigInt(v)):out.writeUIntBE(v,0,n);return out};
const sha=async v=>new Uint8Array(await crypto.subtle.digest('SHA-256',v));
const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
async function signing(n){const scalar=Buffer.alloc(32);scalar[31]=n;const dh=createECDH('prime256v1');dh.setPrivateKey(scalar);const point=dh.getPublicKey(),url=v=>v.toString('base64url');return {point:new Uint8Array(point),key:await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:url(point.subarray(1,33)),y:url(point.subarray(33)),d:url(scalar)},{name:'ECDSA',namedCurve:'P-256'},false,['sign'])};}
const binding=f=>({account:b(f.account),device:b(f.device),line:b(f.line),interval:new Uint8Array(16).fill(9),session:new Uint8Array(16).fill(8),generation:3n,peer:'+12',phoneReader:b(f.phoneReader),archiveReader:b(f.reader)});
async function material(f){const pin=await enrollRootPin02(b(f.rootPin),b(f.fingerprint));return{pin,manifest:await verifyManifest02(b(f.manifest),pin,BigInt(f.now))};}
async function complete(f){
 const {manifest}=await material(f),origin=await signing(6);f.phoneReader=b64(manifest.keys.find(k=>k.role===1).keyId);
 const reader=manifest.keys.find(k=>k.role===2),prepared=await prepareInboundEnvelope02({manifest,nowMs:BigInt(f.now),kind:2,messageId:new Uint8Array(16).fill(49),eventId:new Uint8Array(16).fill(49),localSequence:7n,deviceId:b(f.device),lineId:b(f.line),peer:enc.encode('+12'),observedMs:BigInt(f.now),content:f.text,cek:new Uint8Array(32).fill(193),nonce:new Uint8Array(12).fill(165),signer:{privateKey:origin.key,publicPoint:origin.point},recipients:[{role:2,keyId:reader.keyId,point:reader.point,ekm:new Uint8Array(32).fill(82)}]});
 return{...f,inbound:b64(prepared.envelope)};
}
const mode=process.argv[2],input=mode?JSON.parse(readFileSync(0,'utf8')):null;
if(!mode||mode==='--material'){
 const args=input?.archivePoint?['--recipient-point',input.archivePoint]:[],f=JSON.parse(execFileSync(process.execPath,[fileURLToPath(new URL('./produce-fixture.mjs',import.meta.url)),...args],{encoding:'utf8'}));
 if(input?.rootPoint){const point=new Uint8Array(Buffer.from(input.rootPoint,'hex'));await crypto.subtle.importKey('raw',point,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);const pin=b(f.rootPin),unsigned=b(f.manifest).slice(0,-64);pin.set(point,29);unsigned.set(point,85);for(let at=151;at<unsigned.length;at+=149){if(unsigned[at]===6){unsigned.set(await keyId(257,point),at+1);unsigned.set(point,at+33);}}f.rootPin=b64(pin);f.fingerprint=b64(await sha(join(label('ZTSE/root-pin/v2'),pin)));f.unsigned=b64(unsigned);delete f.manifest;delete f.inbound;delete f.outbound;process.stdout.write(JSON.stringify(f));}
 else process.stdout.write(JSON.stringify(await complete(f)));
}else if(mode==='--fixture')process.stdout.write(JSON.stringify(await complete(input)));
else if(mode==='--consume'){
 const f=input.fixture,{pin,manifest:old}=await material(f),m=await verifyManifest02(b(input.manifest),advanceManifestTrust02(pin,old),BigInt(f.now));
 const raw=b(input.envelope),proof=b(input.confirmation),signature=b(input.signature),v=new DataView(raw.buffer),protectedEnd=10+v.getUint16(8),p=raw.slice(10,protectedEnd),bodyEnd=protectedEnd+16+v.getUint32(protectedEnd+12),count=raw[bodyEnd];
 assert.equal(count,2);assert.equal(raw.length,bodyEnd+1+count*146+64);
 const wraps=Array.from({length:count},(_,i)=>{const at=bodyEnd+1+i*146;return{role:raw[at],keyId:raw.slice(at+1,at+33),enc:raw.slice(at+33,at+98),ct:raw.slice(at+98,at+146)}});
 authorizeOutbound02(m,{accountId:p.slice(0,16),deviceId:p.slice(32,48),lineId:p.slice(48,64),manifestDigest:p.slice(72,104),keysetVersion:v.getBigUint64(74),signerKeyId:p.slice(104,136),wraps},BigInt(f.now));
 const signer=m.keys.find(k=>k.role===5&&b64(k.keyId)===b64(p.slice(104,136))),key=await crypto.subtle.importKey('raw',signer.point,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 for(const[domain,data,sig]of[['ZTSE/sign/v2',raw.slice(0,-64),raw.slice(-64)],['zrotext/conversation/confirm-send/v1',proof,signature]]){assert.deepEqual(sig,canonicalSignature02(sig));assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,sig,join(label(domain),num(data.length,4),data)),true);}
 const bind=binding(f),expected=join(enc.encode('ZTCS\x01'),...['account','device','line','interval','session'].map(k=>bind[k]),p.slice(16,32),num(3),num(m.generation),num(m.version),num(BigInt(f.now)+30000n),[3],enc.encode('+12'),signer.keyId,b(f.reader),m.digest,await sha(raw),await sha(enc.encode(input.text)));
 assert.deepEqual(proof,expected);let opened=0;
 for(const w of wraps){const scalar=w.role===1?f.deviceScalar:f.archiveScalar;if(!scalar)continue;const recipient=await suite.createRecipientContext({recipientKey:await suite.kem.deserializePrivateKey(b(scalar)),enc:w.enc,info:join(label('ZTSE/wrap/v2'),raw.slice(0,protectedEnd),[w.role],w.keyId)}),cek=await recipient.open(w.ct,new Uint8Array()),aes=await crypto.subtle.importKey('raw',cek,'AES-GCM',false,['decrypt']);const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:raw.slice(protectedEnd,protectedEnd+12),additionalData:join(label('ZTSE/body/v2'),raw.slice(0,protectedEnd))},aes,raw.slice(protectedEnd+16,bodyEnd));assert.equal(new TextDecoder('utf-8',{fatal:true}).decode(plaintext),input.text);opened++;}
 process.stdout.write(JSON.stringify({verified:true,openedRecipients:opened,confirmation:true}));
}else if(mode==='--cases'){
 const f=input.fixture,results=[];
 for(const row of input.cases){const {manifest}=await material(f),root=await signing(7),events={setup:0,owner:0,install:0,confirmation:0};let client,current={binding:binding(f),manifest,nowMs:BigInt(f.now),ownerSessionLive:true,consentLive:true};
  try{
   const pair=await suite.kem.deserializePrivateKey(b(f.archiveScalar));
   // Reimport as the exact nonextractable ECDH key shape admitted by custody.
   const jwk=await crypto.subtle.exportKey('jwk',pair),archive=await crypto.subtle.importKey('jwk',jwk,{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
   client=await prepareConversationCustody02({binding:current.binding,archivePrivateKey:archive,readCurrent:async()=>current,
    consumeSetupDecision:async()=>{events.setup++;if(row.setupThrow)throw Error('declined')},consumeOwnerDecision:async()=>{events.owner++;if(row.ownerThrow)throw Error('declined')},signWithExistingRoot:existingConversationRootCustodian02(root.key),installVerified:async(_,accepted)=>{events.install++;if(row.installThrow)throw Error('uncertain');if(!row.staleReadback)current={...current,manifest:accepted}},consumeConfirmation:async()=>{events.confirmation++;if(row.confirmThrow)throw Error('declined')}});
   let scope=(await client.authority()).scope;if(row.scopeField)scope={...scope,[row.scopeField]:'different'};
   if(row.currentField)current={...current,[row.currentField]:false};
   const text=row.text??'Scope-bound native 🌱';
   if(row.open){assert.equal(await client.openSealed(b(f.inbound),scope),f.text)}
   else{const ticket=await client.prepare(scope,text);if(row.close)client.close();await client.signReviewed(ticket,scope,row.changedBody?'different':text);if(row.replay)await client.signReviewed(ticket,scope,text);}
   results.push({accepted:true,...events});
  }catch{results.push({accepted:false,...events})}finally{client?.close()}
 }
 process.stdout.write(JSON.stringify(results));
}else throw Error('fixture mode');
