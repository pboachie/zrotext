// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { webcrypto, createHash } from 'node:crypto';
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';
import { canonicalSignature02, verifyManifest02 } from '../dist/draft02-manifest.js';
import { keyId } from '../dist/draft01.js';
import { sealWorkflowContext, sealIntegrationWorkflowContext, openWorkflowContext,openIntegrationWorkflowContext } from '../dist/workflow-context.js';
import { WorkflowToolClient } from '../dist/workflow-tool-client.js';
import { CustomerRoutineService, policy } from '../../assistant/routine-service.mjs';
test('published local-process policy vector is accepted by the actual closed SDK parser',async()=>{
 const vector=JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/customer-routine-policy-01.json',import.meta.url),'utf8'));
 assert.deepEqual(policy(vector),vector);
 assert.throws(()=>policy({...vector,window:{...vector.window,opens_minute:vector.window.closes_minute}}));
 assert.throws(()=>policy({...vector,window:{...vector.window,timezone:'synthetic-\u00e9'}}));
});
import { CustomerRoutineEngine, renderRoutine } from '../../assistant/routine-engine.mjs';
import { CipherArtifactStore, ciphertextDigest } from '../../assistant/artifact-store.mjs';
import { customerReaderKey } from '../../assistant/customer-routines.mjs';
globalThis.crypto ??= webcrypto;
const id=n=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const rawId=n=>new Uint8Array(Buffer.from(id(n).replaceAll('-',''),'hex'));
const encode=new TextEncoder(), credential='ztw_'+Buffer.alloc(32,7).toString('base64url');
const response=value=>new Response(JSON.stringify(value),{headers:{'content-type':'application/json'}});
const p={request_id:id(1),policy_id:id(2),context_id:id(3),routine_id:id(4),generation:1,kind:'faq',executor:'deterministic_local',period:'utc_day',expires_ms:1893500300000,
  call_limit:2,unit_limit:100,units_per_call:10,turn_limit:1,timeout_ms:10000,window:{timezone:'UTC',first_local_date:'2030-01-01',opens_minute:1,closes_minute:2,repeat_every_days:null,max_occurrences:1,pacing_seconds:60}};
const c={call_id:id(5),assigned_output_context_id:id(5),execute_once:true,policy_id:id(2),phase:'unknown',output_context_id:null,output_revision:null,action_id:null,binding_digest:null};
const now=1893500000000n;
async function cryptoFixture(parity) {
  const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
  const root=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const signer=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const signerPoint=new Uint8Array(await crypto.subtle.exportKey('raw',signer.publicKey));
  const point=new Uint8Array(await crypto.subtle.exportKey('raw',root.publicKey));
  const archive=await suite.kem.deriveKeyPair(new Uint8Array(32).fill(22));let integration;
  for(let i=24;i<56;i++){integration=await suite.kem.deriveKeyPair(new Uint8Array(32).fill(i));
    const point=new Uint8Array(await suite.kem.serializePublicKey(integration.publicKey));
    if(parity===undefined||(point.at(-1)&1)===parity)break;
  }
  const archivePoint=new Uint8Array(await suite.kem.serializePublicKey(archive.publicKey)), integrationPoint=new Uint8Array(await suite.kem.serializePublicKey(integration.publicKey));
  const concat=(...b)=>new Uint8Array(Buffer.concat(b.map(v=>Buffer.from(v))));
  const u64=n=>{const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n);return b;};
  const u32=n=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n);return b;};
  const zero16=new Uint8Array(16),zero32=new Uint8Array(32);
  const record=async(role,p,scope)=>concat(Uint8Array.of(role),await keyId(role<=3?0x10:0x0101,p),p,role===4?rawId(11):zero16,role===4?rawId(12):zero16,new Uint8Array([0,scope]),u64(now-1000n),u64(now+3600000n),Uint8Array.of(1));
  const unsigned=concat(encode.encode('ZTMA'),Uint8Array.of(2),rawId(10),u64(1n),u64(1n),u64(now-1000n),u64(now+3600000n),zero32,point,Uint8Array.of(4),await record(2,archivePoint,12),await record(3,integrationPoint,8),await record(4,signerPoint,2),await record(6,point,0));
  const sig=canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},root.privateKey,concat(encode.encode('ZTSE/manifest/v2\0'),u32(unsigned.length),unsigned))));
  const manifest=await verifyManifest02(concat(unsigned,sig),{accountId:rawId(10),generation:1n,rootPoint:point,version:0n,digest:zero32,anchorDigest:zero32},now);
  const inputScope={kind:1,accountId:rawId(10),deviceId:rawId(11),lineId:rawId(12),intervalId:rawId(13),contextId:rawId(3),bindingGeneration:1n,revision:1n,
    expiresMs:now+300000n,trustGeneration:1n,manifestVersion:1n,peerDigest:new Uint8Array(createHash('sha256').update('synthetic peer').digest()),readerId:await keyId(0x10,integrationPoint),manifestDigest:Uint8Array.from(manifest.digest)};
  const plain=encode.encode(JSON.stringify({question:'synthetic question',answer:'synthetic confidential answer'}));
  const envelope=await sealIntegrationWorkflowContext(manifest,inputScope,now,plain);plain.fill(0);
  if(parity!==undefined)assert.equal(integrationPoint.at(-1)&1,parity);
  return {manifest,inputScope,inputPrivateKey:integration.privateKey,archiveReaderId:await keyId(0x10,archivePoint),archive,envelope};
}
test('actual CLI software-key import opens reviewed HPKE for both public-key parities',async()=>{
  for(const parity of [0,1]){const f=await cryptoFixture(parity),jwk=await crypto.subtle.exportKey('jwk',f.inputPrivateKey),key=await customerReaderKey(jwk);
    assert.equal(key.extractable,true);const bytes=await openIntegrationWorkflowContext(f.manifest,f.inputScope,now,key,f.envelope);
    try{assert.deepEqual(JSON.parse(new TextDecoder().decode(bytes)),{question:'synthetic question',answer:'synthetic confidential answer'});}finally{bytes.fill(0);}
  }
});
test('expired artifact observation survives erase, prune and restart without clock revival',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'zrotext-routine-clock-')),file=join(directory,'artifacts.sqlite');let store;
  try{const f=await cryptoFixture(),envelope=await sealWorkflowContext(f.manifest,{...f.inputScope,contextId:rawId(5),readerId:f.archiveReaderId},now,encode.encode('synthetic private output'));
    store=new CipherArtifactStore(file);store.put({call_id:id(5),input_context:id(3),input_revision:1,input_digest:'ab'.repeat(32),expires_ms:Number(f.inputScope.expiresMs),envelope});
    assert.throws(()=>store.read(id(5),Number(f.inputScope.expiresMs)),{code:'artifact_unavailable'});store.close();
    store=new CipherArtifactStore(file);assert.throws(()=>store.read(id(5),Number(now)),{code:'clock_unavailable'});
    store.erase(id(5));store.prune(Number(f.inputScope.expiresMs));store.close();store=new CipherArtifactStore(file);
    assert.throws(()=>store.observeTime(Number(now)),{code:'clock_unavailable'});
  }finally{store?.close();await rm(directory,{recursive:true,force:true});}
});
test('all five deterministic formats are bounded and refuse caller authority or inbound fields',()=>{
  for(const [kind,value,want] of [['faq',{question:'q',answer:'a'},'a'],['intake',{fields:[{label:'Name',value:'synthetic'}]},'Name: synthetic'],['note',{note:'n'},'n'],['reminder',{reminder:'r'},'r'],['owner_reply',{reply:'o'},'o']]){
    assert.equal(new TextDecoder().decode(renderRoutine(kind,encode.encode(JSON.stringify(value)))),want);
    assert.throws(()=>renderRoutine(kind,encode.encode(JSON.stringify({...value,approved:true}))));
  }
  assert.throws(()=>renderRoutine('note',encode.encode(JSON.stringify({note:'a'.repeat(8193)}))));
  assert.throws(()=>renderRoutine('inbound',encode.encode('{}')));
  assert.throws(()=>policy({...p,period:'subscription'}));
});
test('durable artifact conflict and expiry refuse while only ciphertext survives restart',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'zrotext-customer-artifacts-'));const file=join(directory,'artifacts.sqlite');
  try {
    const f=await cryptoFixture(), store=new CipherArtifactStore(file);
    const artifact=await sealWorkflowContext(f.manifest,{...f.inputScope,contextId:rawId(5),readerId:f.archiveReaderId},now,encode.encode('synthetic private output'));
    const entry={call_id:id(5),input_context:id(3),input_revision:1,input_digest:'ab'.repeat(32),expires_ms:Number(now+300000n),envelope:artifact};
    assert.throws(()=>store.put({...entry,envelope:f.envelope}));
    const hash=store.put(entry); assert.equal(hash,ciphertextDigest(artifact));
    assert.equal(store.put(entry),hash);assert.throws(()=>store.put({...entry,input_digest:'cd'.repeat(32)}));store.close();
    const reopened=new CipherArtifactStore(file);assert.deepEqual(reopened.read(id(5),Number(now)).envelope,artifact);
    assert.throws(()=>reopened.read(id(5),entry.expires_ms));reopened.close();
    assert.equal((await readFile(file)).includes(Buffer.from('synthetic confidential answer')),false);
  }finally{await rm(directory,{recursive:true,force:true});}
});
test('real HPKE output is sealed before checkpoint and replay cannot execute twice',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'zrotext-customer-engine-'));let store;
  try {
    const f=await cryptoFixture();store=new CipherArtifactStore(join(directory,'artifacts.sqlite'));
    let reads=0,produced=0,admissions=0;
    const service=new CustomerRoutineService({origin:'https://gateway.example',inputCredential:credential,fetchImpl:async(_url,init)=>{
      const b=JSON.parse(init.body);
      if(b.operation==='current'){f.inputScope.contextId.fill(9);return response({kind:'policy',result:p});}
      if(b.operation==='admit'){admissions++;return response({kind:'call',result:{...c,execute_once:admissions===1}});}
      if(b.operation==='produced'){produced++;assert.equal(store.read(id(5),Number(now)).archive_digest,b.params.archive_ciphertext_digest);return response({kind:'call',result:{...c,execute_once:false,phase:'produced'}});}
      throw Error('unexpected operation');
    }});
    const tools=new WorkflowToolClient({origin:'https://gateway.example',credential,fetchImpl:async(_url,init)=>{
      const b=JSON.parse(init.body);if(b.method==='workflow.context.metadata')return response({kind:'context_metadata',result:{context_id:id(3),source_content_digest:'ab'.repeat(32),revision:1,kind:1,expires_at_ms:Number(now+300000n),binding_generation:1,trust_generation:1,manifest_version:1}});
      reads++;return response({kind:'context_content',result:{context_id:id(3),revision:1,envelope_base64url:Buffer.from(f.envelope).toString('base64url')}});
    }});
    const engine=new CustomerRoutineEngine({enabled:true,service,tools,store,cryptoContext:f,clock:()=>Number(now)});
    await assert.rejects(engine.execute({request_id:id(5),context_id:id(3),policy_id:id(2),approved:true}),/invalid_request/);
    const result=await engine.execute({request_id:id(5),context_id:id(3),policy_id:id(2)});
    assert.equal(result.state,'awaiting_owner_publication');assert.equal(reads,1);assert.equal(produced,1);
    const artifact=store.read(id(5),Number(now)),outputScope={...f.inputScope,contextId:rawId(5),revision:1n,readerId:f.archiveReaderId};
    const opened=await openWorkflowContext(f.manifest,outputScope,now,f.archive.privateKey,artifact.envelope);
    assert.equal(new TextDecoder().decode(opened),'synthetic confidential answer');opened.fill(0);
    assert.notEqual(artifact.archive_digest,createHash('sha256').update('synthetic confidential answer').digest('hex'));
    await engine.execute({request_id:id(5),context_id:id(3),policy_id:id(2)});assert.equal(reads,1);assert.equal(produced,1);
    engine.withdraw();await assert.rejects(engine.execute({request_id:id(7),context_id:id(3),policy_id:id(2)}),/withdrawn/);
  }finally{store?.close();await rm(directory,{recursive:true,force:true});}
});
test('admission response identity and fresh-state substitution are unknown without retry',async()=>{
  for(const edited of [{...c,call_id:id(7),assigned_output_context_id:id(7)}, {...c,phase:'produced'}, {...c,output_revision:1}]) {
    let count=0;const service=new CustomerRoutineService({origin:'https://gateway.example',inputCredential:credential,fetchImpl:async()=>{count++;return response({kind:'call',result:edited});}});
    await assert.rejects(service.admit({request_id:id(5),policy_id:id(2),context_id:id(3),input_revision:1,input_source_digest:'ab'.repeat(32),direction:'owner_declared'}),e=>e.code==='response_unknown'&&e.state==='unknown');assert.equal(count,1);
  }
});
test('unknown admission is never retried and private transport errors are redacted',async()=>{
  let count=0;const service=new CustomerRoutineService({origin:'https://gateway.example',inputCredential:credential,fetchImpl:async()=>{count++;throw Error(credential);}});
  await assert.rejects(service.admit({request_id:id(1),policy_id:id(2),context_id:id(3),input_revision:1,input_source_digest:'ab'.repeat(32),direction:'owner_declared'}),e=>e.code==='response_unknown'&&e.state==='unknown'&&!e.message.includes(credential));
  assert.equal(count,1);
  await assert.rejects(service.admit({request_id:id(1),policy_id:id(2),context_id:id(3),input_revision:1,input_source_digest:'ab'.repeat(32),direction:'inbound'}));assert.equal(count,1);
});

test('resume binds complete phase-dependent output and proposal identity without retry',async()=>{
  const proposed={...c,execute_once:false,phase:'proposed',output_context_id:c.call_id,output_revision:1,
    action_id:c.call_id,binding_digest:'ab'.repeat(32)};
  for(const result of [proposed,{...proposed,phase:'published',action_id:null,binding_digest:null}]){
    const service=new CustomerRoutineService({origin:'https://gateway.example',inputCredential:credential,outputCredential:credential,
      fetchImpl:async()=>response({kind:'call',result})});
    assert.deepEqual(await service.resume(c.call_id),result);
  }
  for(const edited of [
    {...proposed,action_id:null},{...proposed,binding_digest:null},{...proposed,action_id:id(99)},
    {...proposed,output_context_id:null},{...proposed,output_revision:2},
    {...proposed,phase:'published'},{...proposed,phase:'produced'},
    {...c,execute_once:false,binding_digest:'ab'.repeat(32)},
  ]){
    let requests=0;
    const service=new CustomerRoutineService({origin:'https://gateway.example',inputCredential:credential,outputCredential:credential,
      fetchImpl:async()=>{requests++;return response({kind:'call',result:edited});}});
    await assert.rejects(service.resume(c.call_id),error=>error.code==='response_unknown'&&error.state==='unknown');
    assert.equal(requests,1);
  }
});

async function ownerArtifactFixture(run) {
  const directory=await mkdtemp(join(tmpdir(),'zrotext-customer-owner-review-'));let store;
  try {
    const f=await cryptoFixture();store=new CipherArtifactStore(join(directory,'artifact.sqlite'));
    const archive=await sealWorkflowContext(f.manifest,{...f.inputScope,contextId:rawId(5),readerId:f.archiveReaderId},now,encode.encode('synthetic owner review'));
    store.put({call_id:id(5),input_context:id(3),input_revision:1,input_digest:'ab'.repeat(32),expires_ms:Number(now+300000n),envelope:archive});
    const service=new CustomerRoutineService({origin:'https://gateway.example',inputCredential:credential,
      fetchImpl:async()=>{throw Error('unexpected service request');}});
    const tools=new WorkflowToolClient({origin:'https://gateway.example',credential,
      fetchImpl:async()=>{throw Error('unexpected tool request');}});
    let time=Number(now);
    const engine=new CustomerRoutineEngine({enabled:true,service,tools,store,cryptoContext:f,clock:()=>time});
    await run({f,engine,store,time:value=>{time=value;}});
  }finally{store?.close();await rm(directory,{recursive:true,force:true});}
}

// Gate a genuine completed WebCrypto operation before its promise returns to
// the SDK. The original HPKE algorithm and all manifest checks still execute.
async function delayCrypto(method,run) {
  const subtle=crypto.subtle,originals={decrypt:subtle.decrypt,encrypt:subtle.encrypt};
  let enter,release,seen=false;
  const entered=new Promise(resolve=>{enter=resolve;}),gate=new Promise(resolve=>{release=resolve;});
  const plaintext=[];
  for(const name of ['decrypt','encrypt'])subtle[name]=async function(...args){
    const result=await originals[name].apply(this,args);
    if(name==='decrypt')plaintext.push(new Uint8Array(result));
    if(name===method&&args[0]?.name==='AES-GCM'&&!seen){seen=true;enter();await gate;}
    return result;
  };
  try{await run({entered,release,plaintext});}
  finally{release();for(const name of ['decrypt','encrypt'])subtle[name]=originals[name];}
}

test('owner review refuses withdrawal, expiry, rollback and erasure during real HPKE and clears newly opened plaintext',async()=>{
  await ownerArtifactFixture(async({f,engine})=>{
    const plain=await engine.review(id(5),f.archive.privateKey);
    assert.equal(new TextDecoder().decode(plain),'synthetic owner review');plain.fill(0);
  });
  for(const reason of ['withdrawal','expiry','rollback','erasure'])await ownerArtifactFixture(async({f,engine,store,time})=>{
    await delayCrypto('decrypt',async({entered,release,plaintext})=>{
      const pending=engine.review(id(5),f.archive.privateKey);
      const rejected=assert.rejects(pending,error=>error.code===(reason==='withdrawal'?'withdrawn':reason==='rollback'?'clock_unavailable':'artifact_unavailable'));
      await entered;
      if(reason==='withdrawal')engine.withdraw();else if(reason==='expiry')time(Number(now+300000n));else if(reason==='rollback')time(Number(now)-1);else store.erase(id(5));
      release();await rejected;
      assert.equal(plaintext.length,1);assert.equal(plaintext[0].every(value=>value===0),true);
    });
  });
});

test('owner projection refuses withdrawal, expiry, rollback and erasure during real HPKE without exposing a sealed result',async()=>{
  await ownerArtifactFixture(async({f,engine})=>{
    const projection=await engine.projection(id(5),f.archive.privateKey,f.inputScope.readerId);
    assert.ok(projection.length>308);projection.fill(0);
  });
  for(const reason of ['withdrawal','expiry','rollback','erasure'])await ownerArtifactFixture(async({f,engine,store,time})=>{
    await delayCrypto('encrypt',async({entered,release,plaintext})=>{
      const pending=engine.projection(id(5),f.archive.privateKey,f.inputScope.readerId);
      const rejected=assert.rejects(pending,error=>error.code===(reason==='withdrawal'?'withdrawn':reason==='rollback'?'clock_unavailable':'artifact_unavailable'));
      await entered;
      if(reason==='withdrawal')engine.withdraw();else if(reason==='expiry')time(Number(now+300000n));else if(reason==='rollback')time(Number(now)-1);else store.erase(id(5));
      release();await rejected;
      assert.equal(plaintext.length,1);assert.equal(plaintext[0].every(value=>value===0),true);
    });
  });
});
test('sealing refusal wipes its owned plaintext copy without mutating caller bytes',async()=>{
  const f=await cryptoFixture(),plain=encode.encode('synthetic owned-copy zeroization canary');
  const original=Uint8Array.from;let held;
  Uint8Array.from=function(value,...args){const result=original.call(this,value,...args);if(value===plain)held=result;return result;};
  let pending;
  try{pending=sealWorkflowContext({...f.manifest},f.inputScope,now,plain);}finally{Uint8Array.from=original;}
  await assert.rejects(pending);
  assert.ok(held);assert.equal(held.every(b=>b===0),true);assert.equal(new TextDecoder().decode(plain),'synthetic owned-copy zeroization canary');
  plain.fill(0);
});
test('live service revocation after decryption prevents artifact and produced checkpoint',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'zrotext-customer-revocation-'));let store;
  try {
    const f=await cryptoFixture();store=new CipherArtifactStore(join(directory,'artifact.sqlite'));let checks=0,produced=0;
    const service=new CustomerRoutineService({origin:'https://gateway.example',inputCredential:credential,fetchImpl:async(_url,init)=>{
      const b=JSON.parse(init.body);if(b.operation==='current'){
        if(++checks===1)return response({kind:'policy',result:p});
        return new Response(JSON.stringify({error:{code:'forbidden'}}),{status:403,headers:{'content-type':'application/json'}});
      }
      if(b.operation==='admit')return response({kind:'call',result:c});produced++;throw Error();
    }});
    const tools=new WorkflowToolClient({origin:'https://gateway.example',credential,fetchImpl:async(_url,init)=>{
      const b=JSON.parse(init.body);return b.method==='workflow.context.metadata'?response({kind:'context_metadata',result:{context_id:id(3),source_content_digest:'ab'.repeat(32),revision:1,kind:1,expires_at_ms:Number(now+300000n),binding_generation:1,trust_generation:1,manifest_version:1}}):
        response({kind:'context_content',result:{context_id:id(3),revision:1,envelope_base64url:Buffer.from(f.envelope).toString('base64url')}});
    }});
    const engine=new CustomerRoutineEngine({enabled:true,service,tools,store,cryptoContext:f,clock:()=>Number(now)});
    await assert.rejects(engine.execute({request_id:id(5),context_id:id(3),policy_id:id(2)}),/forbidden/);
    assert.equal(checks,2);assert.equal(produced,0);assert.throws(()=>store.read(id(5),Number(now)),/artifact_unavailable/);
  }finally{store?.close();await rm(directory,{recursive:true,force:true});}
});
