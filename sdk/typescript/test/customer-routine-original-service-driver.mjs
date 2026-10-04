// SPDX-License-Identifier: AGPL-3.0-only
// Real HTTPS/router fixture. All keys and credentials arrive through private stdin.
import assert from 'node:assert/strict';
import {webcrypto,createHash} from 'node:crypto';
import {request} from 'node:https';
import {join,parse,sep} from 'node:path';
import {realpathSync,writeFileSync,readFileSync,existsSync,openSync,fstatSync,readSync,closeSync,constants} from 'node:fs';
import {enrollRootPin02,verifyManifest02,verifiedManifestTrust02} from '../dist/draft02-manifest.js';
import {OriginalReplyClient} from '../dist/original-reply-client.js';
import {WorkflowToolClient} from '../dist/workflow-tool-client.js';
import {sealWorkflowContext,sealIntegrationWorkflowContext} from '../dist/workflow-context.js';
import {CustomerRoutineEngine} from '../../assistant/routine-engine.mjs';
import {CustomerRoutineService} from '../../assistant/routine-service.mjs';
import {customerReaderKey,customerOriginalReaderKey} from '../../assistant/customer-routines.mjs';
import {CipherArtifactStore} from '../../assistant/artifact-store.mjs';
import {LocalProvider} from '../../assistant/local-provider.mjs';
import {originalRoutineDiagnostic,runWithProviderDiagnostic} from './original-service-diagnostics.mjs';
import {RequestHistogram} from './original-request-histogram.mjs';
const requestHistogram=new RequestHistogram();
globalThis.crypto??=webcrypto;
const bytes=value=>Uint8Array.from(Buffer.from(value,'base64'));
const hex=value=>{assert.match(value,/^[0-9a-f]+$/);return Uint8Array.from(Buffer.from(value,'hex'));};
const uuid=value=>{assert.match(value,/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);return hex(value.replaceAll('-',''));};
const hash=value=>createHash('sha256').update(value).digest('hex');
async function history(f){
  let trust=await enrollRootPin02(bytes(f.root_anchor.pin_b64),hex(f.root_anchor.fingerprint_hex));
  if(f.root_anchor.highwater_version!==undefined)trust={...trust,version:BigInt(f.root_anchor.highwater_version),digest:hex(f.root_anchor.highwater_digest)};
  assert.ok(Array.isArray(f.accepted_manifests)&&f.accepted_manifests.length>0&&f.accepted_manifests.length<=32);
  const accepted=[];
  for(const entry of f.accepted_manifests){const at=BigInt(entry.accepted_at_ms),manifest=await verifyManifest02(bytes(entry.manifest_b64),trust,at);
    accepted.push(manifest);trust=verifiedManifestTrust02(manifest,at);}
  return accepted;
}
function workflowScope(f){const s=f.routine_scope;
  return {kind:s.kind,accountId:uuid(s.account_id),deviceId:uuid(s.device_id),lineId:uuid(s.line_id),intervalId:uuid(s.interval_id),
    contextId:uuid(s.context_id),bindingGeneration:BigInt(s.binding_generation),revision:BigInt(s.revision),expiresMs:BigInt(s.expires_ms),
    trustGeneration:BigInt(s.trust_generation),manifestVersion:BigInt(s.manifest_version),peerDigest:hex(s.peer_digest),
    readerId:hex(s.reader_id),manifestDigest:hex(s.manifest_digest)};
}
function install(directory,seed){
  const script=join(directory,'original-routine-executor.mjs');
  if(seed)writeFileSync(script,`import fs from 'node:fs';let wire='';for await(const bytes of process.stdin){wire+=bytes;if(Buffer.byteLength(wire)>65536)process.exit(2);}
    const frame=JSON.parse(wire),input=JSON.parse(Buffer.from(frame.input_base64url,'base64url').toString('utf8'));
    if(input.original_message!=='synthetic original reply'||input.configuration.question!=='synthetic owner configured question')process.exit(2);
    fs.appendFileSync(new URL('./original-routine-invocations',import.meta.url),'x');
    process.stdout.write(JSON.stringify({v:1,call_id:frame.call_id,output_base64url:Buffer.from('synthetic proposed original answer').toString('base64url')})+'\\n');`,{flag:'wx'});
  const executable=realpathSync(process.execPath);
  return new LocalProvider({approvedArtifact:{adapter_id:'customer_faq',executable,executable_digest:hash(readFileSync(executable)),args:[script],
    cwd:directory,artifact_files:[{path:script,digest:hash(readFileSync(script))}]}});
}
function transport(f){
  const origin=new URL(f.origin);assert.equal(origin.protocol,'https:');assert.equal(origin.hostname,'localhost');
  assert.equal(origin.pathname,'/');assert.equal(origin.username,'');assert.equal(origin.password,'');assert.equal(origin.search,'');assert.equal(origin.hash,'');
  const port=Number(origin.port);assert.ok(Number.isInteger(port)&&port>0&&port<=65535);assert.ok(typeof f.ca_pem==='string'&&f.ca_pem.length<8192);
  const paths=new Set(['/v1/reply-events','/v1/workflow/routines','/v1/workflow/tools']);
  const fetch=(url,init)=>new Promise((resolve,reject)=>{
    const endpoint=new URL(url);if(endpoint.origin!==origin.origin||!paths.has(endpoint.pathname)||endpoint.search||endpoint.hash||init.method!=='POST'){
      reject(Error());return;}
    let operation;try{operation=JSON.parse(init.body);}catch{operation={};}
    const labels=endpoint.pathname==='/v1/reply-events'?{current:'original_current',read:'original_read',page:'original_page'}:endpoint.pathname==='/v1/workflow/tools'?{'workflow.context.metadata':'context_metadata','workflow.context.content':'context_content'}:{current:'routine_current',admit_original:'original_admit',current_original:'call_current',produced:'produced'};
    const started=performance.now();
    const label=labels[operation.operation??operation.method]??'transport';
    stage=label;settlement='pending';requestStarted=started;
    let counted=false;const record=()=>{if(!counted){counted=true;requestHistogram.record(label,performance.now()-started);}};
    const elapsed=()=>{if(requestStarted===started)lastRequestMs=clippedElapsed(started);};
    const aborted=()=>{record();elapsed();settlement='aborted';};init.signal?.addEventListener('abort',aborted,{once:true});
    const failed=error=>{record();elapsed();init.signal?.removeEventListener('abort',aborted);if(settlement==='pending')settlement='transport_failed';reject(error);};
    const req=request({hostname:origin.hostname,port,path:endpoint.pathname,method:'POST',ca:f.ca_pem,headers:init.headers,
      signal:init.signal,rejectUnauthorized:true},response=>{
      settlement=[200,400,401,403,409,429,503].includes(response.statusCode)?`http_${response.statusCode}`:'other_status';
      const chunks=[];let size=0;response.on('error',failed);
      response.on('data',chunk=>{size+=chunk.length;if(size>524288){req.destroy();failed(Error());}else chunks.push(chunk);});
      response.on('end',()=>{record();elapsed();init.signal?.removeEventListener('abort',aborted);resolve(new Response(Buffer.concat(chunks),{status:response.statusCode,headers:response.headers}));});
    });req.on('error',failed);req.end(init.body);
  });return {origin:origin.origin,fetch};
}
let providerRefusal=null,invocationMarker=null,requestStarted=null,engineStarted=null,lastRequestMs=0;
const clippedElapsed=start=>start===null?0:Math.min(60000,Math.max(0,Math.floor(performance.now()-start)));
let stage='input',settlement='pending',wire='',engine,provider,store;
try{
  for await(const chunk of process.stdin){wire+=chunk;if(Buffer.byteLength(wire)>262144)throw Error();}
  const f=JSON.parse(wire);wire='';assert.ok(['seed_context','exercise_original','recover_original','publish_original'].includes(f.phase));
  const directory=realpathSync(process.cwd()),sourceRoot=realpathSync(new URL('../../../',import.meta.url));
  assert.notEqual(directory,parse(directory).root);assert.notEqual(directory,sourceRoot);assert.ok(!directory.startsWith(sourceRoot+sep));
  stage='history';const accepted=await history(f),manifest=accepted.at(-1);stage='scope';const scope=workflowScope(f);
  stage='installation';provider=install(directory,f.phase==='seed_context');
  const actualProviderRun=provider.run.bind(provider);
  provider.run=options=>runWithProviderDiagnostic({run:actualProviderRun},options,line=>{providerRefusal=line;});
  invocationMarker=join(directory,'original-routine-invocations');
  if(f.phase==='seed_context'){
    const plain=new TextEncoder().encode(JSON.stringify({question:'synthetic owner configured question',answer:'synthetic owner configured answer'}));
    try{
      const now=BigInt(Date.now());
      stage='seed_prepare';const archive=await sealWorkflowContext(manifest,{...scope,readerId:hex(f.archive_reader_id)},now,plain);
      const projection=await sealIntegrationWorkflowContext(manifest,scope,now,plain);
      process.stdout.write(JSON.stringify({archive_b64:Buffer.from(archive).toString('base64'),projection_b64:Buffer.from(projection).toString('base64'),
        adapter_id:provider.identity.adapter_id,artifact_digest:provider.identity.artifact_digest}));
    }finally{plain.fill(0);}
  }else{
    assert.equal(f.routine_policy.adapter_id,provider.identity.adapter_id);assert.equal(f.routine_policy.artifact_digest,provider.identity.artifact_digest);
    stage='client';const {origin,fetch}=transport(f),s=f.scope,privateKey=await customerReaderKey(f.role3_private_jwk);
    const originalClient=new OriginalReplyClient({origin,credential:f.read_credential,scope:{account:uuid(s.account_id),device:uuid(s.device_id),line:uuid(s.line_id),
      interval:uuid(s.interval_id),connector:uuid(s.connector_id),readGrant:uuid(s.read_grant_id),reader:hex(s.reader_id),peer:s.peer},
      privateKey:await customerOriginalReaderKey(f.role3_private_jwk),acceptedHistory:accepted,clock:()=>BigInt(Date.now()),fetch});
    const service=new CustomerRoutineService({origin,inputCredential:f.input_credential,originalCredential:f.read_credential,fetchImpl:fetch});
    store=new CipherArtifactStore(join(directory,'original-routine-artifacts.sqlite'));
    engine=new CustomerRoutineEngine({enabled:true,service,tools:new WorkflowToolClient({origin,credential:f.input_credential,fetchImpl:fetch}),
      store,provider,originalClient,cryptoContext:{manifest,inputScope:scope,inputPrivateKey:privateKey,archiveReaderId:hex(f.archive_reader_id)}});
    if(f.phase==='publish_original'){
      // Explicit owner-local review: no execute/admit/provider call in this phase.
      const archiveKey=await customerReaderKey(f.archive_private_jwk);
      const plain=await engine.review(f.request_id,archiveKey);
      try{assert.equal(new TextDecoder('utf-8',{fatal:true}).decode(plain),'synthetic proposed original answer');}
      finally{plain.fill(0);}
      const artifact=store.read(f.request_id,Date.now());
      const projection=await engine.projection(f.request_id,archiveKey,scope.readerId);
      try{
        const markerBytes=readFileSync(join(directory,'original-routine-invocations'));
        assert.ok(markerBytes.length<=2&&markerBytes.every(byte=>byte===120));
        process.stdout.write(JSON.stringify({archive_b64:Buffer.from(artifact.envelope).toString('base64'),
          projection_b64:Buffer.from(projection).toString('base64'),invocations:markerBytes.length}));
      }finally{artifact.envelope.fill(0);projection.fill(0);}
    }else{
    const marker=join(directory,'original-routine-invocations');
    const before=existsSync(marker)?readFileSync(marker,'utf8'):'';
    stage='engine_execute';engineStarted=performance.now();const result=await engine.executeOriginal({request_id:f.request_id,context_id:f.routine_policy.context_id,policy_id:f.routine_policy.policy_id,event_id:f.event_id});
    stage='result_assert';const after=existsSync(marker)?readFileSync(marker,'utf8'):'';
    if(f.phase==='exercise_original'){assert.equal(result.state,'awaiting_owner_publication');assert.equal(after,before+'x');}
    else{assert.equal(result.call.execute_once,false);assert.equal(after,before);}
    process.stdout.write(JSON.stringify(result));
    }
  }
}catch(error){
  const outer=originalRoutineDiagnostic(stage,error,settlement);
  process.stderr.write(outer);
  process.stderr.write(requestHistogram.failureLines());
  if(providerRefusal!==null)process.stderr.write(providerRefusal);
  // Fixture marker contains only bounded literal x bytes from the owned child.
  let invocations='unavailable';
  let fd,marker;
  try{if(invocationMarker!==null){
    try{fd=openSync(invocationMarker,constants.O_RDONLY|(constants.O_NOFOLLOW??0)|(constants.O_NONBLOCK??0));}catch(error){if(error?.code==='ENOENT')invocations='0';else throw error;}
    if(fd!==undefined){const info=fstatSync(fd);if(info.isFile()&&info.nlink===1&&info.size>=0&&info.size<=2){marker=Buffer.alloc(3);const size=readSync(fd,marker,0,3,0);if(size===info.size&&size<=2&&marker.subarray(0,size).every(byte=>byte===120))invocations=String(size);}}
  }}catch{}finally{marker?.fill(0);if(fd!==undefined)try{closeSync(fd);}catch{}}
  process.stderr.write(`original routine invocations=${invocations}\n`);
  const totalMs=clippedElapsed(engineStarted),requestMs=requestStarted===null?0:(settlement==='pending'?clippedElapsed(requestStarted):lastRequestMs);
  // This is only the known synthetic fixture budget, never an authority claim.
  const remainingMs=Math.max(0,10000-totalMs);
  process.stderr.write(`original routine timing request_ms=${requestMs} total_ms=${totalMs} remaining_ms=${remainingMs}\n`);process.exitCode=1;
}finally{engine?.withdraw();provider?.close();store?.close();}
