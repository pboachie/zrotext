// Independent maintained TS authority verification and native-crypto opening.
// Input is synthetic test material on stdin, never production key transport.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '../../../typescript/node_modules/@hpke/core/esm/mod.js';
import { enrollRootPin02, verifyManifest02 } from '../../../typescript/dist/draft02-manifest.js';
import { verifyManifest03From02, authorizeOutbound03 } from '../../../typescript/dist/draft03-manifest.js';
import { verifyAcceptedPayloadProfileElection03, requireCurrentElection03 } from '../../../typescript/dist/payload-profile-election03.js';
globalThis.crypto ??= webcrypto;
const {fixture:f,envelope:encoded,expectedText}=JSON.parse(readFileSync(0,'utf8'));
const b=s=>new Uint8Array(Buffer.from(s,'base64')), join=(...p)=>new Uint8Array(Buffer.concat(p.map(v=>Buffer.from(v))));
const label=s=>new TextEncoder().encode(s+'\0');
const record=o=>Object.fromEntries(Object.entries(o).map(([k,v])=>[k,typeof v==='string'?b(v):['profile','manifestProfile'].includes(k)?v:BigInt(v)]));
const accepted=record(f.accepted),authority=record(f.authority),original=b(f.signed02);
const pin=await enrollRootPin02(b(f.rootPin),b(f.fingerprint)),prior=await verifyManifest02(original,pin,10000n);
const manifest=await verifyManifest03From02(b(f.signed03),prior,original,10000n);
const proof=await verifyAcceptedPayloadProfileElection03({bundle:b(f.bundle),expectedCore:b(f.core),acceptedRecord:accepted,
  predecessor02:prior,priorSignedManifest02:original,acceptedSignedManifest03:b(f.signed03),deviceSigningPointAtAcceptance:b(f.deviceSigningPoint),ownerApprovalPointAtAcceptance:b(f.ownerApprovalPoint)});
requireCurrentElection03(proof,manifest,authority,30000n);
const raw=b(encoded),view=new DataView(raw.buffer),end=10+view.getUint16(8),prefix=raw.slice(0,end),p=raw.slice(10,end);
assert.deepEqual(raw.slice(0,8),Uint8Array.of(90,84,83,69,3,1,0,0));
assert.equal(end,164+p[153]); assert.equal(p[152],1); assert.equal(new TextDecoder().decode(p.slice(154)),'+12');
assert.deepEqual(p.slice(16,32),b(f.message));
assert.equal(view.getBigUint64(10+136),30000n); assert.equal(view.getBigUint64(10+144),40000n);
const bodyEnd=end+16+view.getUint32(end+12),count=raw[bodyEnd];
assert.ok(count>=2&&count<=8); assert.equal(raw.length,bodyEnd+1+146*count+64);
const wraps=Array.from({length:count},(_,i)=>{const at=bodyEnd+1+i*146;return{role:raw[at],keyId:raw.slice(at+1,at+33),enc:raw.slice(at+33,at+98),ct:raw.slice(at+98,at+146)};});
const auth=authorizeOutbound03(manifest,{accountId:p.slice(0,16),deviceId:p.slice(32,48),lineId:p.slice(48,64),generation:1n,
  version:view.getBigUint64(74),digest:p.slice(72,104),signerKeyId:p.slice(104,136),wraps},30000n);
assert.deepEqual(auth.signerPoint,b(f.signerPoint));
const unsigned=raw.slice(0,-64),length=Buffer.alloc(4);length.writeUInt32BE(unsigned.length);
const publicKey=await crypto.subtle.importKey('raw',auth.signerPoint,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},publicKey,raw.slice(-64),join(label('ZTSE/sign/v3'),length,unsigned)),true);
const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
for(const w of wraps){
  const scalar=b(w.role===1?f.readerScalar:f.archiveScalar),suffix=join(prefix,[w.role],w.keyId);
  const receiver=await suite.createRecipientContext({recipientKey:await suite.kem.deserializePrivateKey(scalar),enc:w.enc,info:join(label('ZTSE/wrap/v3'),suffix)});
  const cek=await receiver.open(w.ct,join(label('ZTSE/wrap-aad/v3'),suffix));
  const aes=await crypto.subtle.importKey('raw',cek,'AES-GCM',false,['decrypt']);
  const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:raw.slice(end,end+12),additionalData:join(label('ZTSE/body/v3'),prefix)},aes,raw.slice(end+16,bodyEnd));
  assert.equal(new TextDecoder('utf-8',{fatal:true}).decode(plain),expectedText);
}
process.stdout.write(JSON.stringify({verified:true,openedRecipients:wraps.length}));
