// SPDX-License-Identifier: AGPL-3.0-only
// Fixture-only customer-controlled reader/adapter. No credential input or live transport.
import {createHash,webcrypto} from 'node:crypto';
import {readFile,rename,mkdir,open,unlink,lstat} from 'node:fs/promises';
import {createServer} from 'node:http';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {CipherSuite,DhkemP256HkdfSha256,HkdfSha256,Aes128Gcm} from '@hpke/core';
import {AgentRecipe,newRecipeCheckpoint} from '../dist/agent-recipe.js';
import {openDraftEnvelope,keyId,parseDraftEnvelope} from '../dist/draft01.js';
globalThis.crypto??=webcrypto;
const fixture=JSON.parse(await readFile(new URL('../../../protocol/v1/vectors/ztse-draft-01.json',import.meta.url),'utf8'));
const bytes=hex=>Uint8Array.from(Buffer.from(hex,'hex'));
const digest=value=>createHash('sha256').update(value).digest('hex');
const inbound=bytes(fixture.inbound.envelopeHex);
const baseTime=Number(parseDraftEnvelope(inbound).observedMs)+1;
export const recipeScope=Object.freeze({accountId:fixture.accountIdHex,lineId:fixture.lineIdHex,recipientId:'owner_fixture',readerId:'local_archive_fixture',expiresAt:baseTime+60000,maxTurns:1,budget:2});

export class FileRecipeStore {
  constructor(directory,scope=recipeScope){this.directory=directory;this.scope=scope;}
  async transact(run){
    await mkdir(this.directory,{recursive:true});
    if((await lstat(this.directory)).isSymbolicLink())throw new Error('checkpoint_unavailable');
    const lock=join(this.directory,'checkpoint.lock');let handle;
    try{handle=await open(lock,'wx',0o600);}catch{throw new Error('checkpoint_busy');}
    try{
      const file=join(this.directory,'checkpoint.json');let state;
      try{
        const info=await lstat(file);if(!info.isFile()||info.isSymbolicLink()||info.size>32768)throw new Error('checkpoint_unavailable');
        state=JSON.parse(await readFile(file,'utf8'));
      }catch(error){if(error.code!=='ENOENT')throw new Error('checkpoint_unavailable');state=newRecipeCheckpoint(this.scope);}
      if(!validCheckpoint(state,this.scope))throw new Error('checkpoint_unavailable');
      const result=await run(state);const serialized=JSON.stringify(state);
      if(Buffer.byteLength(serialized)>32768)throw new Error('checkpoint_unavailable');
      const pending=join(this.directory,'checkpoint.pending');const output=await open(pending,'wx',0o600);
      try{await output.writeFile(serialized);await output.sync();}finally{await output.close();}
      await rename(pending,file);return result;
    }finally{await handle.close();await unlink(lock);}
  }
}

function validCheckpoint(state,scope){
  const record=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
  const id=value=>/^[a-z0-9][a-z0-9_-]{0,63}$/.test(value)&&!['constructor','prototype','__proto__'].includes(value);
  if(!record(state)||state.synthetic!==true||state.version!==1||state.accountId!==scope.accountId||state.lineId!==scope.lineId||!['revoked','takeover','stopped'].every(key=>typeof state[key]==='boolean')||!record(state.events)||!record(state.notifications)||Object.keys(state.events).length>128||Object.keys(state.notifications).length>32||!Number.isSafeInteger(state.turns)||state.turns<0||state.turns>scope.maxTurns||!Number.isSafeInteger(state.used)||state.used<0||state.used>scope.budget)return false;
  if(!Object.entries(state.events).every(([key,row])=>id(key)&&record(row)&&/^[a-f0-9]{64}$/.test(row.digest)&&id(row.actionId)&&['metadata_only_stop','owner_review','content_unavailable','reply_routed_for_review'].includes(row.result)))return false;
  return Object.entries(state.notifications).every(([key,row])=>id(key)&&record(row)&&/^[a-f0-9]{64}$/.test(row.digest)&&record(row.result)&&row.result.synthetic===true&&['accepted','refused','unknown'].includes(row.result.state)&&Number.isSafeInteger(row.result.attempts)&&row.result.attempts>=0&&row.result.attempts<=1);
}

/** Exact independently pinned public test-vector trust, not production manifest trust. */
export async function verifyFixtureReply(envelope=inbound){
  const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
  const pair=await suite.kem.deriveKeyPair(bytes(fixture.archiveIkmHex));
  const point=new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  const plaintext=await openDraftEnvelope(envelope,{accountId:bytes(fixture.accountIdHex),deviceId:bytes(fixture.deviceIdHex),lineId:bytes(fixture.lineIdHex),peer:fixture.peer,manifestDigest:bytes(fixture.manifestDigestHex),signerPublicPoint:bytes(fixture.signerPublicPointHex),recipientRole:2,recipientKeyId:await keyId(0x0010,point),recipientPrivateKey:pair.privateKey});
  const parsed=parseDraftEnvelope(envelope);if(parsed.kind!==2)throw new Error('invalid_reply');
  return {eventId:Buffer.from(parsed.eventId).toString('hex'),actionId:'owner_followup_fixture',accountId:recipeScope.accountId,lineId:recipeScope.lineId,recipientId:recipeScope.recipientId,observedAt:baseTime-1,expiresAt:baseTime+30000,digest:digest(envelope),verified:true,kind:'reply',contentAvailable:plaintext.length>0,activeRequest:true};
}

export async function callableRecipe(operation,store,scenario='normal'){
  if(!['task_completion','owner_proposal','verified_reply','journey'].includes(operation)||!['normal','unknown','offline','stop','takeover','revoked','missing_grant'].includes(scenario))throw new Error('invalid_request');
  if(scenario==='missing_grant')return {synthetic:true,available:false,state:'missing_grant',content:'unavailable',modelProviderAccess:'none'};
  if(['stop','takeover','revoked'].includes(scenario))await store.transact(async state=>{state[scenario==='stop'?'stopped':scenario=== 'takeover'?'takeover':'revoked']=true;});
  const recipe=new AgentRecipe(recipeScope,store,()=>scenario==='offline'?recipeScope.expiresAt:baseTime);
  const output={synthetic:true,available:false,reader:recipeScope.readerId,modelProviderAccess:'none',readiness:recipe.readiness(),results:[]};
  if(operation==='task_completion'||operation==='journey')output.results.push(await recipe.taskCompletion('job_completion_fixture',bytes(fixture.outbound.envelopeHex),scenario==='unknown'));
  if(operation==='owner_proposal'||operation==='journey')output.results.push(await recipe.ownerProposal('owner_followup_fixture'));
  if(operation==='verified_reply'||operation==='journey')output.results.push(await recipe.verifiedReply(await verifyFixtureReply()));
  return output;
}

export function previewServer(store){
  return createServer(async(request,response)=>{
    response.setHeader('cache-control','no-store');response.setHeader('content-type','application/json');
    try{
      if(request.method!=='POST'||request.url!=='/preview')throw new Error('invalid_request');
      let size=0;const chunks=[];for await(const chunk of request){size+=chunk.length;if(size>1024)throw new Error('invalid_request');chunks.push(chunk);}
      const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if(input===null||typeof input!=='object'||Array.isArray(input)||input.synthetic!==true||Object.keys(input).some(key=>!['synthetic','operation','scenario'].includes(key)))throw new Error('invalid_request');
      const result=await callableRecipe(input.operation,store,input.scenario??'normal');response.end(JSON.stringify(result));
    }catch(error){response.statusCode=error.message==='invalid_request'?400:503;response.end(JSON.stringify({code:response.statusCode===400?'invalid_request':'preview_unavailable',synthetic:true,available:false}));}
  });
}

if(import.meta.url===pathToFileURL(process.argv[1]??'').href){
  const store=new FileRecipeStore(join(tmpdir(),'zrotext-synthetic-recipe-preview'));
  if(process.argv[2]==='serve'){
    const server=previewServer(store);server.requestTimeout=5000;server.headersTimeout=5000;server.listen(37620,'localhost',()=>console.log('Synthetic recipe preview ready; production unavailable.'));
    for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>server.close(()=>process.exit(0)));
  }else if(process.argv[2]==='setup'){
    console.log(JSON.stringify({synthetic:true,installedState:'disabled',productionActivation:'unavailable',scope:recipeScope,requiredGrants:['metadata','draft','read:selected_owner_reply','send:owner_self_notification'],ownerActionRequired:true,controlledRecipient:'owner_fixture',reader:recipeScope.readerId,modelProviderAccess:'none'}));
  }else if(process.argv[2]==='preview')console.log(JSON.stringify(await callableRecipe(process.argv[3]??'journey',store,process.argv[4]??'normal')));
  else{console.error('Use setup, preview [operation] [scenario], or serve. Synthetic fixtures only.');process.exitCode=2;}
}
