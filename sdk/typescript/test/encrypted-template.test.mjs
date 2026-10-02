// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import {createHash,webcrypto} from 'node:crypto';
import {test} from 'node:test';
import {readFileSync} from 'node:fs';
import {Aes128Gcm,CipherSuite,DhkemP256HkdfSha256,HkdfSha256} from '@hpke/core';
import {canonicalSignature02,verifyManifest02} from '../dist/draft02-manifest.js';
import {keyId} from '../dist/draft01.js';
import {encryptedTemplateAad,sealEncryptedTemplate,openEncryptedTemplate,sealEncryptedTemplateBytes,encryptedTemplateDigest,previewEncryptedTemplate} from '../dist/encrypted-template.js';
import {templateSaveRequest,templateSaveReceipt} from '../dist/template-store-contract.js';
import {openWorkflowContext} from '../dist/workflow-context.js';
globalThis.crypto ??= webcrypto;
const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
const bytes=(v,n)=>new Uint8Array(n).fill(v),enc=new TextEncoder();
const concat=(...parts)=>new Uint8Array(Buffer.concat(parts.map(p=>Buffer.from(p))));
const hash=b=>new Uint8Array(createHash('sha256').update(b).digest());
const u64=n=>{const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n,false);return b;};
const u32=n=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n,false);return b;};
const now=1893500000000n;
async function fixture(integrationScope){
  const root=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const signer=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const rootPoint=new Uint8Array(await crypto.subtle.exportKey('raw',root.publicKey));
  const signerPoint=new Uint8Array(await crypto.subtle.exportKey('raw',signer.publicKey));
  const archive=await suite.kem.deriveKeyPair(bytes(0x22,32));
  const archivePoint=new Uint8Array(await suite.kem.serializePublicKey(archive.publicKey));
  const integration=await suite.kem.deriveKeyPair(bytes(0x24,32));
  const integrationPoint=new Uint8Array(await suite.kem.serializePublicKey(integration.publicKey));
  const account=bytes(1,16),device=bytes(2,16),line=bytes(3,16),zero16=new Uint8Array(16),zero32=new Uint8Array(32);
  const reader=await keyId(0x0010,archivePoint);
  const record=async(role,point,d,l,scope)=>concat(Uint8Array.of(role),await keyId(role<=3?0x0010:0x0101,point),point,d,l,Uint8Array.of(0,scope),u64(now-1000n),u64(now+3600000n),Uint8Array.of(1));
  const unsigned=concat(enc.encode('ZTMA'),Uint8Array.of(2),account,u64(1n),u64(1n),u64(now-1000n),u64(now+3600000n),zero32,rootPoint,Uint8Array.of(integrationScope===undefined?3:4),
    await record(2,archivePoint,zero16,zero16,12),...(integrationScope===undefined?[]:[await record(3,integrationPoint,zero16,zero16,integrationScope)]),await record(4,signerPoint,device,line,2),await record(6,rootPoint,zero16,zero16,0));
  const signature=canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},root.privateKey,concat(enc.encode('ZTSE/manifest/v2\0'),u32(unsigned.length),unsigned))));
  const manifest=await verifyManifest02(concat(unsigned,signature),{accountId:account,generation:1n,rootPoint,version:0n,digest:zero32,anchorDigest:zero32},now);
  const scope={accountId:account,deviceId:device,lineId:line,intervalId:bytes(4,16),templateId:bytes(5,16),bindingGeneration:1n,revision:1n,expiresMs:now+300000n,
    trustGeneration:1n,manifestVersion:1n,peerDigest:hash(enc.encode('+12')),readerId:reader,manifestDigest:Uint8Array.from(manifest.digest)};
  return {manifest,scope,archive,root,integration,integrationId:await keyId(0x0010,integrationPoint)};
}

test('template HPKE hides values and rejects context alias and identity substitution',async()=>{
 const f=await fixture(),content={template:'Hello {{name}} ^',values:{name:'Synthetic'}};
 const sealed=await sealEncryptedTemplate(f.manifest,f.scope,now,content);
 assert.equal(Buffer.from(sealed).includes(Buffer.from('Synthetic')),false);
 assert.deepEqual(await openEncryptedTemplate(f.manifest,f.scope,now,f.archive.privateKey,sealed),content);
 assert.equal(previewEncryptedTemplate(content).text,'Hello Synthetic ^');
 await assert.rejects(openWorkflowContext(f.manifest,{...f.scope,kind:1,contextId:f.scope.templateId},now,f.archive.privateKey,sealed));
 const changed=await sealEncryptedTemplate(f.manifest,{...f.scope,revision:2n},now,{...content,values:{name:'Changed'}});
 assert.notDeepEqual(await encryptedTemplateDigest(sealed),await encryptedTemplateDigest(changed));
 for(const field of ['accountId','deviceId','lineId','intervalId','templateId','peerDigest','readerId','manifestDigest']){const value=Uint8Array.from(f.scope[field]);value[0]^=1;await assert.rejects(openEncryptedTemplate(f.manifest,{...f.scope,[field]:value},now,f.archive.privateKey,sealed));}
 for(const field of ['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'])await assert.rejects(openEncryptedTemplate(f.manifest,{...f.scope,[field]:f.scope[field]+1n},now,f.archive.privateKey,sealed));
 const altered=Uint8Array.from(sealed);altered[altered.length-1]^=1;await assert.rejects(openEncryptedTemplate(f.manifest,f.scope,now,f.archive.privateKey,altered));
 await assert.rejects(openEncryptedTemplate(f.manifest,f.scope,f.scope.expiresMs,f.archive.privateKey,sealed));
 await assert.rejects(sealEncryptedTemplate({...f.manifest},f.scope,now,content));
});
test('personalization stays literal bounded and segment-capped',()=>{
 const emoji=String.fromCodePoint(0x1f642);
 assert.equal(previewEncryptedTemplate({template:'{{value}}',values:{value:'{{other}}'}}).text,'{{other}}');
 assert.equal(previewEncryptedTemplate({template:'{{value}}',values:{value:'^'.repeat(81)}}).estimate.parts,2);
 assert.equal(previewEncryptedTemplate({template:'{{value}}',values:{value:emoji.repeat(36)}}).estimate.parts,2);
 for(const content of [{template:'{{missing}}',values:{}},{template:'{{constructor}}',values:{}},{template:'{{bad-name}}',values:{}},{template:'x',values:{x:String.fromCharCode(0xd800)}},{template:'{{x}}',values:{x:emoji.repeat(300)}}])assert.throws(()=>previewEncryptedTemplate(content));
 assert.throws(()=>previewEncryptedTemplate({template:'{{x}}'.repeat(700),values:{x:'a'.repeat(512)}}));
});
test('decrypted payload must retain exact canonical bounded contract',async()=>{
 const f=await fixture();
 for(const body of ['{"v":1,"template":"x","values":{},"send":true}','{"values":{},"template":"x","v":1}','{"v":1,"template":"{{bad-name}}","values":{}}']){const sealed=await sealEncryptedTemplateBytes(f.manifest,f.scope,now,enc.encode(body));await assert.rejects(openEncryptedTemplate(f.manifest,f.scope,now,f.archive.privateKey,sealed));}
});

test('shared template vector fixes exact authenticated bytes and HPKE info',()=>{
 const v=JSON.parse(readFileSync(new URL('../../../protocol/v1/vectors/encrypted-template-01.json',import.meta.url),'utf8')),s=v.scope;
 const uuid=x=>new Uint8Array(Buffer.from(x.replaceAll('-',''),'hex')),digest=x=>new Uint8Array(Buffer.from(x,'hex'));
 const scope={accountId:uuid(s.account_id),deviceId:uuid(s.device_id),lineId:uuid(s.line_id),intervalId:uuid(s.interval_id),templateId:uuid(s.template_id),bindingGeneration:BigInt(s.binding_generation),revision:BigInt(s.revision),expiresMs:BigInt(s.expires_ms),trustGeneration:BigInt(s.trust_generation),manifestVersion:BigInt(s.manifest_version),peerDigest:digest(s.peer_digest),readerId:digest(s.reader_id),manifestDigest:digest(s.manifest_digest)};
 const aad=encryptedTemplateAad(scope);assert.equal(Buffer.from(aad).toString('hex'),v.aad_hex);assert.equal(Buffer.concat([Buffer.from('ZT/workflow-template/hpke/v1'+String.fromCharCode(0)),Buffer.from(aad)]).toString('hex'),v.hpke_info_hex);
});

test('bounded save messages require exact CAS and acknowledge save without send authority',async()=>{
 const f=await fixture(),envelope=await sealEncryptedTemplate(f.manifest,f.scope,now,{template:'x',values:{}}),requestId='00000000-0000-0000-0000-000000000009';
 const request=await templateSaveRequest(f.scope,requestId,0,envelope);assert.equal(request.path,'/v1/owner/workflow/templates');assert.equal(request.headers['x-zrotext-template-revision'],'0');assert.equal(request.encryptedDigest.length,64);
 envelope[envelope.length-1]^=1;assert.notDeepEqual(request.body,envelope);
 assert.deepEqual(templateSaveReceipt(request,enc.encode('{"revision":1}')),{revision:1});
 for(const receipt of ['{"revision":2}','{"revision":1,"send":true}','null'])assert.throws(()=>templateSaveReceipt(request,enc.encode(receipt)));
 assert.throws(()=>templateSaveReceipt(request,new Uint8Array(257)));
 await assert.rejects(templateSaveRequest(f.scope,requestId,1,request.body));await assert.rejects(templateSaveRequest(f.scope,'00000000-0000-0000-0000-000000000000',0,request.body));
});
