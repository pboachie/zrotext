// Synthetic maintained lifecycle oracle and independent native transcript consumer.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {webcrypto,createECDH} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {CipherSuite,DhkemP256HkdfSha256,HkdfSha256,Aes128Gcm} from '../../../typescript/node_modules/@hpke/core/esm/mod.js';
import {enrollRootPin02,verifyManifest02,verifiedManifestTrust02,canonicalSignature02,authorizeOutbound02,browserSignerKeyId02} from '../../../typescript/dist/draft02-manifest.js';
import {prepareConversationSignerSetup02} from '../../../typescript/dist/conversation-signer.js';
globalThis.crypto??=webcrypto;
const b=v=>new Uint8Array(Buffer.from(v,'base64')),b64=v=>Buffer.from(v).toString('base64');
const join=(...v)=>new Uint8Array(Buffer.concat(v.map(x=>Buffer.from(x)))),label=v=>new TextEncoder().encode(v+'\0');
const number=(v,n=8)=>{const out=Buffer.alloc(n);n===8?out.writeBigUInt64BE(BigInt(v)):out.writeUIntBE(v,0,n);return out};
const hash=async v=>new Uint8Array(await crypto.subtle.digest('SHA-256',v));
const base=()=>JSON.parse(execFileSync(process.execPath,[fileURLToPath(new URL('./produce-fixture.mjs',import.meta.url))],{encoding:'utf8'}));
const binding=f=>({account:b(f.account),device:b(f.device),line:b(f.line),interval:new Uint8Array(16).fill(9),session:new Uint8Array(16).fill(8),generation:3n,peer:'+12',phoneReader:b(f.phoneReader),archiveReader:b(f.reader)});
async function initial(f){const pin=await enrollRootPin02(b(f.rootPin),b(f.fingerprint));return await verifyManifest02(b(f.manifest),pin,10000n)}
async function enrolled(f,point){
 const previous=await initial(f),old=b(f.manifest),unsigned=old.slice(0,-64),record=join([5],await browserSignerKeyId02(point),point,new Uint8Array(16),b(f.line),number(1,2),number(9000),number(100000),[1]);
 const keys=Array.from({length:unsigned[150]},(_,i)=>unsigned.slice(151+i*149,300+i*149));keys.push(record);keys.sort((a,c)=>Buffer.compare(Buffer.from(a.slice(0,33)),Buffer.from(c.slice(0,33))));
 const head=unsigned.slice(0,150);head.set(number(2),29);head.set(number(10000),37);head.set(await hash(unsigned),53);
 const next=join(head,[keys.length],...keys),scalar=Buffer.alloc(32);scalar[31]=7;
 const dh=createECDH('prime256v1');dh.setPrivateKey(scalar);const publicPoint=dh.getPublicKey();
 const privateKey=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:publicPoint.subarray(1,33).toString('base64url'),y:publicPoint.subarray(33).toString('base64url'),d:scalar.toString('base64url'),ext:true,key_ops:['sign']},{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
 const signature=canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,join(label('ZTSE/manifest/v2'),number(next.length,4),next))));
 const raw=join(next,signature),manifest=await verifyManifest02(raw,verifiedManifestTrust02(previous,10000n),10000n);
 return{raw,manifest};
}
async function consume(f,proof,raw,signature,expectedText,publicPoint){
 const {manifest}=await enrolled(f,publicPoint),p=raw.slice(10,10+new DataView(raw.buffer,raw.byteOffset).getUint16(8)),end=10+p.length,v=new DataView(raw.buffer,raw.byteOffset,raw.byteLength),bodyEnd=end+16+v.getUint32(end+12),count=raw[bodyEnd];
 assert.equal(count,2);assert.equal(raw.length,bodyEnd+1+146*count+64);
 const wraps=Array.from({length:count},(_,i)=>{const at=bodyEnd+1+i*146;return{role:raw[at],keyId:raw.slice(at+1,at+33),enc:raw.slice(at+33,at+98),ct:raw.slice(at+98,at+146)}});
 authorizeOutbound02(manifest,{accountId:p.slice(0,16),deviceId:p.slice(32,48),lineId:p.slice(48,64),manifestDigest:p.slice(72,104),keysetVersion:v.getBigUint64(74),signerKeyId:p.slice(104,136),wraps},10000n);
 const key=await crypto.subtle.importKey('raw',publicPoint,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 for(const[domain,data,sig]of[['ZTSE/sign/v2',raw.slice(0,-64),raw.slice(-64)],['zrotext/conversation/confirm-send/v1',proof,signature]])assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,sig,join(label(domain),number(data.length,4),data)),true);
 const select=binding(f),expected=join(new TextEncoder().encode('ZTCS\x01'),...['account','device','line','interval','session'].map(k=>select[k]),p.slice(16,32),number(3),number(1),number(2),number(40000),[3],new TextEncoder().encode('+12'),await browserSignerKeyId02(publicPoint),b(f.reader),p.slice(72,104),await hash(raw),await hash(new TextEncoder().encode(expectedText)));
 assert.deepEqual(proof,expected);
 const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
 for(const w of wraps){const scalar=b(w.role===1?f.deviceScalar:f.archiveScalar),recipient=await suite.createRecipientContext({recipientKey:await suite.kem.deserializePrivateKey(scalar),enc:w.enc,info:join(label('ZTSE/wrap/v2'),raw.slice(0,end),[w.role],w.keyId)});
  const cek=await recipient.open(w.ct,new Uint8Array()),aes=await crypto.subtle.importKey('raw',cek,'AES-GCM',false,['decrypt']);
  const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:raw.slice(end,end+12),additionalData:join(label('ZTSE/body/v2'),raw.slice(0,end))},aes,raw.slice(end+16,bodyEnd));assert.equal(new TextDecoder('utf-8',{fatal:true}).decode(plaintext),expectedText);}
 return{verified:true,openedRecipients:2,confirmation:true};
}
const mode=process.argv[2];
if(!mode){const f=base(),m=await initial(f);f.phoneReader=b64(m.keys.find(k=>k.role===1).keyId);process.stdout.write(JSON.stringify(f));}
else{
 const input=JSON.parse(readFileSync(0,'utf8')),f=input.fixture;
 if(mode==='--enroll'){const value=await enrolled(f,b(input.point));process.stdout.write(JSON.stringify({manifest:b64(value.raw)}));}
 else if(mode==='--consume')process.stdout.write(JSON.stringify(await consume(f,b(input.proof),b(input.envelope),b(input.signature),input.text,b(input.point))));
 else if(mode==='--cases'){
  const results=[];
  for(const c of input.cases){let calls=0,confirmation=0,client,current={binding:binding(f),manifest:await initial(f),nowMs:10000n,ownerSessionLive:true,consentLive:true};
   try{
    if(c.setupField)current[c.setupField]=false;
    client=await prepareConversationSignerSetup02(binding(f),async()=>{calls++;if(c.setupThrow)throw Error('declined');return false},async()=>current);
    current={...current,manifest:(await enrolled(f,client.publicPoint)).manifest};
    if(c.reviewField)current[c.reviewField]=false;
    const text=c.text??'Session review 🌱',review=await client.prepareReview(text),proof=Uint8Array.from(review.proof),envelope=Uint8Array.from(review.envelope);
    if(c.proofOffset!==undefined)proof[c.proofOffset]^=1;
    if(c.envelopeOffset!==undefined)envelope[c.envelopeOffset]^=1;
    if(c.confirmNow!==undefined)current.nowMs=BigInt(c.confirmNow);
    const confirm=async()=>{confirmation++;if(c.confirmThrow)throw Error('declined');return false};
    const signature=await client.signReviewed(proof,envelope,c.confirmText??text,confirm);
    if(c.replay)await client.signReviewed(proof,envelope,text,confirm);
    results.push({accepted:true,calls,confirmation});
   }catch{results.push({accepted:false,calls,confirmation});}finally{client?.close()}
  }
  process.stdout.write(JSON.stringify(results));
 }else throw Error('unsupported mode');
}
