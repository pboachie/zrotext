// Independent maintained TS profile02 authority and HPKE/WebCrypto consumer.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {webcrypto,createECDH} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
if(process.argv.length!==3)throw Error('Reviewed producer checkout required');
const source=resolve(process.argv[2],'sdk/typescript');
const {CipherSuite,DhkemP256HkdfSha256,HkdfSha256,Aes128Gcm}=await import(pathToFileURL(resolve(source,'node_modules/@hpke/core/esm/mod.js')));
const {enrollRootPin02,verifyManifest02,authorizeOutbound02,advanceManifestTrust02,verifyRootTransition02}=await import(pathToFileURL(resolve(source,'dist/draft02-manifest.js')));

globalThis.crypto??=webcrypto;
const {fixture:f,envelope:encoded,expectedText}=JSON.parse(readFileSync(0,'utf8'));
const b=s=>new Uint8Array(Buffer.from(s,'base64')),join=(...p)=>new Uint8Array(Buffer.concat(p.map(v=>Buffer.from(v)))),label=s=>new TextEncoder().encode(s+'\0');
const pin=await enrollRootPin02(b(f.rootPin),b(f.fingerprint)),old=await verifyManifest02(b(f.manifest),pin,10000n),next=await verifyRootTransition02(b(f.transition),advanceManifestTrust02(pin,old),33000n,b(f.newPoint)),manifest=await verifyManifest02(b(f.newManifest),next,33000n);

  const raw=b(encoded),v=new DataView(raw.buffer),end=10+v.getUint16(8),prefix=raw.slice(0,end),p=raw.slice(10,end);
  assert.deepEqual(raw.slice(0,8),Uint8Array.of(90,84,83,69,2,1,0,0));assert.equal(end,164+p[153]);assert.equal(p[152],1);
  assert.equal(new TextDecoder().decode(p.slice(154)),'+12');
  const bodyEnd=end+16+v.getUint32(end+12),count=raw[bodyEnd];assert.ok(count>=2&&count<=8);assert.equal(raw.length,bodyEnd+1+146*count+64);
  const wraps=Array.from({length:count},(_,i)=>{const at=bodyEnd+1+i*146;return{role:raw[at],keyId:raw.slice(at+1,at+33),enc:raw.slice(at+33,at+98),ct:raw.slice(at+98,at+146)}});
  authorizeOutbound02(manifest,{accountId:p.slice(0,16),deviceId:p.slice(32,48),lineId:p.slice(48,64),manifestDigest:p.slice(72,104),keysetVersion:v.getBigUint64(74),signerKeyId:p.slice(104,136),wraps},33000n);
  const unsigned=raw.slice(0,-64),length=Buffer.alloc(4);length.writeUInt32BE(unsigned.length);
  const key=await crypto.subtle.importKey('raw',b(f.signerPoint),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  assert.equal(await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,raw.slice(-64),join(label('ZTSE/sign/v2'),length,unsigned)),true);
  const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
  for(const w of wraps){const scalar=b(w.role===1?f.deviceScalar:f.archiveScalar);const recipient=await suite.createRecipientContext({recipientKey:await suite.kem.deserializePrivateKey(scalar),enc:w.enc,info:join(label('ZTSE/wrap/v2'),prefix,[w.role],w.keyId)});
    const cek=await recipient.open(w.ct,new Uint8Array());const aes=await crypto.subtle.importKey('raw',cek,'AES-GCM',false,['decrypt']);
    const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:raw.slice(end,end+12),additionalData:join(label('ZTSE/body/v2'),prefix)},aes,raw.slice(end+16,bodyEnd));assert.equal(new TextDecoder('utf-8',{fatal:true}).decode(plain),expectedText);}
  process.stdout.write(JSON.stringify({verified:true,openedRecipients:count}));
