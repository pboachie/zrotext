// Independent maintained TS profile02 authority and HPKE/WebCrypto consumer.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {webcrypto,createECDH} from 'node:crypto';
import {CipherSuite,DhkemP256HkdfSha256,HkdfSha256,Aes128Gcm} from '../../../typescript/node_modules/@hpke/core/esm/mod.js';
import {enrollRootPin02,verifyManifest02,authorizeOutbound02} from '../../../typescript/dist/draft02-manifest.js';
import {composeSealedOutboundEnvelope} from '../../../typescript/dist/sealed-envelope.js';
globalThis.crypto??=webcrypto;
const {fixture:f,envelope:encoded,expectedText,negativeCases}=JSON.parse(readFileSync(0,'utf8'));
const b=s=>new Uint8Array(Buffer.from(s,'base64')),join=(...p)=>new Uint8Array(Buffer.concat(p.map(v=>Buffer.from(v)))),label=s=>new TextEncoder().encode(s+'\0');
const pin=await enrollRootPin02(b(f.rootPin),b(f.fingerprint)),manifest=await verifyManifest02(b(f.manifest),pin,10000n);
if(negativeCases){
  const scalar=Buffer.alloc(32);scalar[31]=5;const dh=createECDH('prime256v1');dh.setPrivateKey(scalar);const point=dh.getPublicKey();
  const key=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url'),d:scalar.toString('base64url'),ext:true,key_ops:['sign']},{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
  const base=()=>({manifest,nowMs:10000n,messageId:new Uint8Array(16).fill(49),deviceId:b(f.device),lineId:b(f.line),peer:new TextEncoder().encode('+12'),observedMs:10000n,expiresMs:20000n,content:'Native composed02 🌱',signer:{privateKey:key,publicPoint:new Uint8Array(point)},recipients:manifest.keys.filter(k=>[1,2].includes(k.role)).map(k=>({role:k.role,keyId:k.keyId,point:k.point}))});
  const cases={identity:i=>{i.messageId=new Uint8Array(15)},peer:i=>{i.peer=new TextEncoder().encode('+01')},time_range:i=>{i.observedMs=-1n},intent_expiry:i=>{i.expiresMs=i.observedMs},content:i=>{i.content='\ufeffbad'},wrap_count:i=>{i.recipients.pop()},recipient:i=>{i.recipients=[i.recipients[0],i.recipients[0]]},recipient_key_id:i=>{i.recipients[0].keyId=new Uint8Array(32)},authorization:i=>{i.lineId=new Uint8Array(16)},key_material:i=>{i.deterministicKeyMaterial={}}};
  const result={};for(const [name,change]of Object.entries(cases)){const input=base();change(input);try{await composeSealedOutboundEnvelope(input);result[name]='accepted'}catch(error){result[name]=error.code??'untyped'}}
  const zero=base();zero.messageId=new Uint8Array(16);zero.observedMs=0n;zero.expiresMs=1n;
  try{await composeSealedOutboundEnvelope(zero);result.zero_candidate='accepted'}catch(error){result.zero_candidate=error.code??'untyped'}
  process.stdout.write(JSON.stringify(result));
}else{
  const raw=b(encoded),v=new DataView(raw.buffer),end=10+v.getUint16(8),prefix=raw.slice(0,end),p=raw.slice(10,end);
  assert.deepEqual(raw.slice(0,8),Uint8Array.of(90,84,83,69,2,1,0,0));assert.equal(end,164+p[153]);assert.equal(p[152],1);
  assert.equal(new TextDecoder().decode(p.slice(154)),'+12');
  const bodyEnd=end+16+v.getUint32(end+12),count=raw[bodyEnd];assert.ok(count>=2&&count<=8);assert.equal(raw.length,bodyEnd+1+146*count+64);
  const wraps=Array.from({length:count},(_,i)=>{const at=bodyEnd+1+i*146;return{role:raw[at],keyId:raw.slice(at+1,at+33),enc:raw.slice(at+33,at+98),ct:raw.slice(at+98,at+146)}});
  authorizeOutbound02(manifest,{accountId:p.slice(0,16),deviceId:p.slice(32,48),lineId:p.slice(48,64),manifestDigest:p.slice(72,104),keysetVersion:v.getBigUint64(74),signerKeyId:p.slice(104,136),wraps},10000n);
  const unsigned=raw.slice(0,-64),length=Buffer.alloc(4);length.writeUInt32BE(unsigned.length);
  const key=await crypto.subtle.importKey('raw',b(f.signerPoint),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,raw.slice(-64),join(label('ZTSE/sign/v2'),length,unsigned)),true);
  const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
  for(const w of wraps){const scalar=b(w.role===1?f.deviceScalar:f.archiveScalar);const recipient=await suite.createRecipientContext({recipientKey:await suite.kem.deserializePrivateKey(scalar),enc:w.enc,info:join(label('ZTSE/wrap/v2'),prefix,[w.role],w.keyId)});
    const cek=await recipient.open(w.ct,new Uint8Array());const aes=await crypto.subtle.importKey('raw',cek,'AES-GCM',false,['decrypt']);
    const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:raw.slice(end,end+12),additionalData:join(label('ZTSE/body/v2'),prefix)},aes,raw.slice(end+16,bodyEnd));assert.equal(new TextDecoder('utf-8',{fatal:true}).decode(plain),expectedText);}
  process.stdout.write(JSON.stringify({verified:true,openedRecipients:count}));
}
