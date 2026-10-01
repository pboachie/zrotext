// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {createHash,webcrypto} from 'node:crypto';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';
import {Aes128Gcm,CipherSuite,DhkemP256HkdfSha256,HkdfSha256} from '@hpke/core';
import {canonicalSignature02,verifyManifest02} from '../dist/draft02-manifest.js';
import {keyId} from '../dist/draft01.js';
import {sealWorkflowContext,openWorkflowContext,workflowContextAad} from '../dist/workflow-context.js';
globalThis.crypto ??= webcrypto;
const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
const bytes=(v,n)=>new Uint8Array(n).fill(v),enc=new TextEncoder();
const concat=(...parts)=>new Uint8Array(Buffer.concat(parts.map(p=>Buffer.from(p))));
const hash=b=>new Uint8Array(createHash('sha256').update(b).digest());
const u64=n=>{const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n,false);return b;};
const u32=n=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,false);return b;};
const now=1893500000000n;
test('canonical authenticated bytes match the independent public protocol vector',()=>{
  const v=JSON.parse(readFileSync(new URL('../../../protocol/v1/vectors/workflow-context-01.json',import.meta.url),'utf8'));
  const s=v.scope,uuid=b=>new Uint8Array(Buffer.from(b.replaceAll('-',''),'hex')),digest=b=>new Uint8Array(Buffer.from(b,'hex'));
  const scope={kind:s.kind,accountId:uuid(s.account_id),deviceId:uuid(s.device_id),lineId:uuid(s.line_id),intervalId:uuid(s.interval_id),contextId:uuid(s.context_id),
    bindingGeneration:BigInt(s.binding_generation),revision:BigInt(s.revision),expiresMs:BigInt(s.expires_ms),trustGeneration:BigInt(s.trust_generation),manifestVersion:BigInt(s.manifest_version),
    peerDigest:digest(s.peer_digest),readerId:digest(s.reader_id),manifestDigest:digest(s.manifest_digest)};
  assert.equal(Buffer.from(workflowContextAad(scope)).toString('hex'),v.aad_hex);
});
async function fixture(){
  const root=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const signer=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const rootPoint=new Uint8Array(await crypto.subtle.exportKey('raw',root.publicKey));
  const signerPoint=new Uint8Array(await crypto.subtle.exportKey('raw',signer.publicKey));
  const archive=await suite.kem.deriveKeyPair(bytes(0x22,32));
  const archivePoint=new Uint8Array(await suite.kem.serializePublicKey(archive.publicKey));
  const account=bytes(1,16),device=bytes(2,16),line=bytes(3,16),zero16=new Uint8Array(16),zero32=new Uint8Array(32);
  const reader=await keyId(0x0010,archivePoint);
  const record=async(role,point,d,l,scope)=>concat(Uint8Array.of(role),await keyId(role===2?0x0010:0x0101,point),point,d,l,Uint8Array.of(0,scope),u64(now-1000n),u64(now+3600000n),Uint8Array.of(1));
  const unsigned=concat(enc.encode('ZTMA'),Uint8Array.of(2),account,u64(1n),u64(1n),u64(now-1000n),u64(now+3600000n),zero32,rootPoint,Uint8Array.of(3),
    await record(2,archivePoint,zero16,zero16,12),await record(4,signerPoint,device,line,2),await record(6,rootPoint,zero16,zero16,0));
  const signature=canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},root.privateKey,concat(enc.encode('ZTSE/manifest/v2\0'),u32(unsigned.length),unsigned))));
  const manifest=await verifyManifest02(concat(unsigned,signature),{accountId:account,generation:1n,rootPoint,version:0n,digest:zero32,anchorDigest:zero32},now);
  const scope={kind:1,accountId:account,deviceId:device,lineId:line,intervalId:bytes(4,16),contextId:bytes(5,16),bindingGeneration:1n,revision:1n,expiresMs:now+300000n,
    trustGeneration:1n,manifestVersion:1n,peerDigest:hash(enc.encode('+12')),readerId:reader,manifestDigest:Uint8Array.from(manifest.digest)};
  return {manifest,scope,archive,root};
}
test('client HPKE roundtrip hides content and rejects ciphertext or every identity substitution',async()=>{
  const f=await fixture(),plain=enc.encode('synthetic workflow private canary');
  const sealed=await sealWorkflowContext(f.manifest,f.scope,now,plain);
  assert.equal(workflowContextAad(f.scope).length,222);
  assert.equal(sealed.length,291+plain.length+16);
  assert.equal(Buffer.from(sealed).includes(Buffer.from(plain)),false);
  assert.deepEqual(await openWorkflowContext(f.manifest,f.scope,now,f.archive.privateKey,sealed),plain);
  const changed=Uint8Array.from(sealed);changed[changed.length-1]^=1;
  await assert.rejects(openWorkflowContext(f.manifest,f.scope,now,f.archive.privateKey,changed));
  for(const field of ['accountId','deviceId','lineId','intervalId','contextId','peerDigest','readerId','manifestDigest']){
    const value=Uint8Array.from(f.scope[field]);value[0]^=1;
    await assert.rejects(openWorkflowContext(f.manifest,{...f.scope,[field]:value},now,f.archive.privateKey,sealed));
  }
  for(const field of ['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion']){
    await assert.rejects(openWorkflowContext(f.manifest,{...f.scope,[field]:f.scope[field]+1n},now,f.archive.privateKey,sealed));
  }
  await assert.rejects(openWorkflowContext(f.manifest,{...f.scope,kind:2},now,f.archive.privateKey,sealed));
  const wrong=await suite.kem.deriveKeyPair(bytes(0x23,32));
  await assert.rejects(openWorkflowContext(f.manifest,f.scope,now,wrong.privateKey,sealed));
});
test('authority, expiry, bounds and caller snapshots fail closed before encryption',async()=>{
  const f=await fixture(),plain=enc.encode('synthetic context');
  await assert.rejects(sealWorkflowContext({...f.manifest},f.scope,now,plain));
  await assert.rejects(sealWorkflowContext(f.manifest,f.scope,now+3600000n,plain));
  await assert.rejects(sealWorkflowContext(f.manifest,{...f.scope,expiresMs:now},now,plain));
  await assert.rejects(sealWorkflowContext(f.manifest,{...f.scope,readerId:bytes(9,32)},now,plain));
  await assert.rejects(sealWorkflowContext(f.manifest,f.scope,now,new Uint8Array(32769)));
  await assert.rejects(sealWorkflowContext(f.manifest,f.scope,now,new Uint8Array()));
  const expected={...f.scope,contextId:Uint8Array.from(f.scope.contextId)};
  const promise=sealWorkflowContext(f.manifest,f.scope,now,plain);
  f.scope.contextId.fill(9);plain.fill(0);
  const sealed=await promise;
  assert.deepEqual(await openWorkflowContext(f.manifest,expected,now,f.archive.privateKey,sealed),enc.encode('synthetic context'));
});


test('a retired signer before the active line signer does not remove workflow authority',async()=>{
  const f=await fixture();
  const archiveRecord=f.manifest.bytes.slice(151,300),originalSigner=f.manifest.bytes.slice(300,449),ownerRecord=f.manifest.bytes.slice(449,598);
  const pair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const point=new Uint8Array(await crypto.subtle.exportKey('raw',pair.publicKey));
  const extra=concat(Uint8Array.of(4),await keyId(0x0101,point),point,f.scope.deviceId,f.scope.lineId,Uint8Array.of(0,2),u64(now-1000n),u64(now+3600000n),Uint8Array.of(1));
  const signers=[originalSigner,extra].sort((a,b)=>Buffer.compare(Buffer.from(a.slice(1,33)),Buffer.from(b.slice(1,33))));
  signers[0][148]=2;signers[1][148]=1;
  const header=f.manifest.bytes.slice(0,151);header[150]=4;
  const unsigned=concat(header,archiveRecord,...signers,ownerRecord);
  const signature=canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},f.root.privateKey,concat(enc.encode('ZTSE/manifest/v2\0'),u32(unsigned.length),unsigned))));
  const zero32=new Uint8Array(32);
  const manifest=await verifyManifest02(concat(unsigned,signature),{accountId:f.scope.accountId,generation:1n,rootPoint:f.manifest.rootPoint,version:0n,digest:zero32,anchorDigest:zero32},now);
  const scope={...f.scope,manifestDigest:Uint8Array.from(manifest.digest)};
  const plain=enc.encode('synthetic context with rotated signer');
  const ciphertext=await sealWorkflowContext(manifest,scope,now,plain);
  assert.deepEqual(await openWorkflowContext(manifest,scope,now,f.archive.privateKey,ciphertext),plain);
});
