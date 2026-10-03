// SPDX-License-Identifier: AGPL-3.0-only
// CI fixture driver for an actual Rust router/disposable database. Private
// configuration arrives on stdin; stdout contains ciphertext and metadata only.
import assert from 'node:assert/strict';
import { createServer as httpsServer, request as httpsRequest } from 'node:https';
import { request as httpRequest, createServer as httpServer } from 'node:http';
import { execFileSync,execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { readFile, writeFile,mkdir } from 'node:fs/promises';
import { join, isAbsolute,dirname } from 'node:path';
import { ownedScratch,fixtureLocalPath } from './fixture-scratch.mjs';
import { webcrypto,createHash } from 'node:crypto';
import { verifyManifest02 } from '../typescript/dist/draft02-manifest.js';
import { sealIntegrationWorkflowContext, sealWorkflowContext, openIntegrationWorkflowContext } from '../typescript/dist/workflow-context.js';
import { WorkflowToolClient } from '../typescript/dist/workflow-tool-client.js';
import { CustomerRoutineService } from './routine-service.mjs';
import { CustomerRoutineEngine, renderRoutine } from './routine-engine.mjs';
import { CipherArtifactStore } from './artifact-store.mjs';
import { LocalProvider } from './local-provider.mjs';
import { customerRoutineDiagnostic } from './customer-routines.mjs';
globalThis.crypto ??= webcrypto;
const decode=value=>new Uint8Array(Buffer.from(value,'base64url'));
const encode=value=>Buffer.from(value).toString('base64url');
const bytes=['accountId','deviceId','lineId','intervalId','contextId','peerDigest','readerId','manifestDigest'];
const numbers=['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'];
async function configuration() {
  let buffer='';for await(const chunk of process.stdin){buffer+=chunk;if(Buffer.byteLength(buffer)>196608)throw Error('bounded fixture configuration');}
  return JSON.parse(buffer);
}
const inputs={faq:{question:'synthetic owner question',answer:'synthetic confidential answer'},intake:{fields:[{label:'Selected',value:'synthetic value'}]},note:{note:'synthetic owner note'},reminder:{reminder:'synthetic owner reminder'},owner_reply:{reply:'synthetic owner reply'}};
async function main() {
  const config=await configuration();
  config.artifact_path=fixtureLocalPath(config.artifact_path);
  assert.ok(['seed','execute','replay','publish','withdraw'].includes(config.phase));
  console.error(`routine fixture phase=${config.phase}`);
  assert.ok(Number.isInteger(config.proxy_port)&&config.proxy_port>1024&&config.proxy_port<65536);
  assert.ok(isAbsolute(config.artifact_path));
  const upstream=new URL(config.upstream);
  assert.equal(upstream.protocol,'http:');assert.equal(upstream.pathname,'/');assert.equal(upstream.search,'');assert.equal(upstream.hash,'');
  assert.ok(upstream.hostname==='localhost'||/^127\./.test(upstream.hostname));
  const scope={...config.input_scope};for(const field of bytes)scope[field]=decode(scope[field]);for(const field of numbers)scope[field]=BigInt(scope[field]);
  const anchor={...config.root_anchor};for(const field of ['accountId','rootPoint','digest','anchorDigest'])anchor[field]=decode(anchor[field]);for(const field of ['generation','version'])anchor[field]=BigInt(anchor[field]);
  const now=BigInt(Date.now());
  const manifest=await verifyManifest02(decode(config.manifest_base64url),anchor,now);
  const inputPrivateKey=await crypto.subtle.importKey('jwk',config.role3_private_jwk,{name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const cryptoContext={manifest,inputScope:scope,inputPrivateKey,archiveReaderId:decode(config.archive_reader_id)};
  const selectedInput=new TextEncoder().encode(JSON.stringify(inputs[config.policy.kind]));
  if(config.phase==='seed') {
    try {
      const archive=await sealWorkflowContext(manifest,{...scope,readerId:decode(config.archive_reader_id)},now,selectedInput);
      const envelope=await sealIntegrationWorkflowContext(manifest,scope,now,selectedInput);
      const opened=await openIntegrationWorkflowContext(manifest,scope,BigInt(Date.now()),inputPrivateKey,envelope);
      try { assert.deepEqual(opened,selectedInput); } finally { opened.fill(0); }
      return {archive_base64url:encode(archive),projection_base64url:encode(envelope)};
    }
    finally{selectedInput.fill(0);}
  }
  selectedInput.fill(0);
  const scratch=await ownedScratch();
  const directory=scratch.path;
  let proxy,store;const sockets=new Set();
  try {
    const run=args=>execFileSync('openssl',args,{cwd:directory,timeout:15000,stdio:'pipe'});
    run(['req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Synthetic Routine Fixture CA','-keyout','ca.key','-out','ca.pem']);
    run(['req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout','leaf.key','-out','leaf.csr']);
    await writeFile(join(directory,'leaf.ext'),'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
    run(['x509','-req','-in','leaf.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-days','1','-extfile','leaf.ext','-out','leaf.pem']);
    proxy=httpsServer({key:await readFile(join(directory,'leaf.key')),cert:await readFile(join(directory,'leaf.pem'))},(incoming,outgoing)=>{
      const routes=new Map([
        ['POST /v1/workflow/routines','/v1/workflow/routines'],
        ['POST /v1/workflow/tools','/v1/workflow/tools'],
        ['POST /v1/owner/workflow/routines/policy','/v1/owner/workflow/routines/policy'],
        ['POST /v1/owner/workflow/routines/output','/v1/owner/workflow/routines/output'],
        ['POST /v1/owner/workflow/routines/withdraw','/v1/owner/workflow/routines/withdraw'],
        ['POST /v1/owner/workflow/contexts','/v1/owner/workflow/contexts'],
        ['POST /v1/auth/workflow-grants','/v1/auth/workflow-grants'],
      ]);
      const path=routes.get(`${incoming.method} ${incoming.url}`);
      if(!path){outgoing.writeHead(400);outgoing.end();return;}
      const port=Number(upstream.port);
      assert.ok(Number.isInteger(port)&&port>1024&&port<65536);
      const forwarded=httpRequest({hostname:'127.0.0.1',port,path,method:'POST',headers:incoming.headers},reply=>{outgoing.writeHead(reply.statusCode,reply.headers);reply.pipe(outgoing);});
      forwarded.on('error',()=>{outgoing.writeHead(503,{'content-type':'application/json'});outgoing.end(JSON.stringify({error:{code:'unavailable'}}));});
      incoming.on('aborted',()=>forwarded.destroy());incoming.pipe(forwarded);
    });
    proxy.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
    await new Promise((resolve,reject)=>{proxy.once('error',reject);proxy.listen(config.proxy_port,'localhost',resolve);});
    const origin=`https://localhost:${config.proxy_port}`,ca=await readFile(join(directory,'ca.pem'));
    // A second actual listener must never receive an absolute request target.
    let diverted=0;
    const other=httpServer((_request,response)=>{diverted++;response.writeHead(200);response.end();});
    await new Promise(resolve=>other.listen(0,'127.0.0.1',resolve));
    try {
      const status=await new Promise((resolve,reject)=>{
        const request=httpsRequest({hostname:'localhost',port:config.proxy_port,ca,method:'POST',path:`http://127.0.0.1:${other.address().port}/v1/workflow/tools`},reply=>{reply.resume();reply.on('end',()=>resolve(reply.statusCode));});
        request.setTimeout(5000,()=>request.destroy(Error('fixture request timeout')));
        request.on('error',reject);request.end();
      });
      assert.equal(status,400);assert.equal(diverted,0);
    } finally { await new Promise(resolve=>other.close(resolve)); }
    const fetchImpl=(url,init)=>new Promise((resolve,reject)=>{
      const request=httpsRequest(url,{method:init.method,headers:init.headers,signal:init.signal,ca},reply=>{
        if(reply.statusCode>=400){
          const requested=new URL(url).pathname==='/v1/workflow/routines'?JSON.parse(init.body).operation:'owner';
          const operation=['current','admit','produced','resume','owner'].includes(requested)?requested:'refused';
          console.error(`routine fixture phase=${config.phase} operation=${operation} method=${init.method} path=${new URL(url).pathname} status=${reply.statusCode} policy_remaining_ms=${config.policy.expires_ms-Date.now()} context_remaining_ms=${Number(scope.expiresMs)-Date.now()}`);
        }
        const chunks=[];let size=0;reply.on('data',b=>{size+=b.length;if(size>131072){request.destroy();reject(Error('bounded fixture response'));}else chunks.push(b);});
        reply.on('error',reject);reply.on('end',()=>resolve(new Response(Buffer.concat(chunks),{status:reply.statusCode,headers:reply.headers})));
      });request.on('error',reject);request.end(init.body);
    });
    const service=new CustomerRoutineService({origin,inputCredential:config.input_credential,owner:config.owner,fetchImpl});
    let currentFinished,firstPolicy,policyChanged=false;
    const actualCurrent=service.current.bind(service);
    service.current=async(...args)=>{
      const result=await actualCurrent(...args);
      if(currentFinished===undefined){currentFinished=performance.now();firstPolicy=JSON.stringify(result);}
      else policyChanged ||= JSON.stringify(result)!==firstPolicy;
      return result;
    };
    const tools=new WorkflowToolClient({origin,credential:config.input_credential,fetchImpl});
    store=new CipherArtifactStore(config.artifact_path);
    let provider=null,approvedArtifact;
    if(config.local_process===true){
      // Installation and marker belong to the native fixture's private parent,
      // not this short-lived proxy directory; identities survive process restart.
      const installation=join(dirname(config.artifact_path),'provider-installation');
      try{await mkdir(installation,{mode:0o700});}catch(error){if(error.code!=='EEXIST')throw error;}
      const script=join(installation,'synthetic-provider.mjs'),marker=join(installation,'provider-invocations');
      // Synthetic child chosen by trusted fixture configuration. It receives
      // no owner/integration credential or key; actual owner HTTP pins identity.
      const code=`import fs from 'node:fs';let bytes='';process.stdin.on('data',b=>bytes+=b);process.stdin.on('end',()=>{const q=JSON.parse(bytes),v=JSON.parse(Buffer.from(q.input_base64url,'base64url').toString('utf8'));const output={faq:()=>v.answer,intake:()=>v.fields.map(f=>f.label+': '+f.value).join('\\n'),note:()=>v.note,reminder:()=>v.reminder,owner_reply:()=>v.reply}[q.kind]();fs.appendFileSync(new URL('./provider-invocations',import.meta.url),'x');process.stdout.write(JSON.stringify({v:1,call_id:q.call_id,output_base64url:Buffer.from(output).toString('base64url')}));});`;
      try{await writeFile(script,code,{mode:0o600,flag:'wx'});}catch(error){if(error.code!=='EEXIST')throw error;assert.equal(await readFile(script,'utf8'),code);}
      const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
      approvedArtifact={adapter_id:'synthetic_local',executable:process.execPath,executable_digest:digest(await readFile(process.execPath)),args:[script],cwd:installation,artifact_files:[{path:script,digest:digest(await readFile(script))}]};
      provider=new LocalProvider({approvedArtifact});
      config.policy={...config.policy,executor:'local_process',adapter_id:provider.identity.adapter_id,artifact_digest:provider.identity.artifact_digest};
    }
    const engine=new CustomerRoutineEngine({enabled:true,service,tools,store,cryptoContext,provider});
    const invocation={request_id:config.request_id,context_id:config.policy.context_id,policy_id:config.policy.policy_id};
    if(config.phase==='execute'||config.phase==='replay') {
      if(config.phase==='execute')await service.configure(config.policy);
      let result;
      try {
        if(config.local_process===true){
          const cliConfig=join(dirname(config.artifact_path),'customer-routine-config.json');
          await writeFile(cliConfig,JSON.stringify({origin,input_credential:config.input_credential,policy:config.policy,manifest_base64url:config.manifest_base64url,
            root_anchor:config.root_anchor,input_scope:config.input_scope,role3_private_jwk:config.role3_private_jwk,archive_reader_id:config.archive_reader_id,artifact_path:config.artifact_path,provider:approvedArtifact}),{mode:0o600});
          // Actual production CLI in a fresh process; owner auth stays in this
          // explicit publication driver, not the persisted executor config.
          const executed=await promisify(execFile)(process.execPath,[fileURLToPath(new URL('./customer-routines.mjs',import.meta.url)),'--config',cliConfig,'--execute',config.request_id],
            {cwd:dirname(config.artifact_path),env:{...process.env,NODE_EXTRA_CA_CERTS:join(directory,'ca.pem')},timeout:30000,maxBuffer:65536}).catch(error=>{
              const bounded=typeof error.stderr==='string'&&error.stderr.length<=65536?error.stderr:'';
              const marker=bounded.match(/(?:^|\n)customer_routine_unavailable code=([a-z_]+)\r?\n$/);
              const code=customerRoutineDiagnostic({code:marker?.[1]});
              console.error('routine fixture cli_code='+code);
              throw Object.assign(Error('customer routine unavailable'),{code});
            });
          result=JSON.parse(executed.stdout);
        }else result=await engine.execute(invocation);
      }
      catch(error){
        console.error(`routine fixture phase=${config.phase} elapsed_ms=${Math.round(performance.now()-currentFinished)} timeout_ms=${config.policy.timeout_ms} policy_remaining_ms=${config.policy.expires_ms-Date.now()} policy_changed=${policyChanged}`);
        throw error;
      }
      if(config.phase==='execute'){assert.equal(result.state,'awaiting_owner_publication');
        if(config.local_process===true)assert.equal(await readFile(join(dirname(config.artifact_path),'provider-installation','provider-invocations'),'utf8'),'x');}
      else assert.equal(result.call.execute_once,false);
      if(config.local_process===true)assert.equal(await readFile(join(dirname(config.artifact_path),'provider-installation','provider-invocations'),'utf8'),'x');
      const artifact=store.read(result.call.call_id,Date.now());
      return {result,archive_base64url:encode(artifact.envelope),archive_ciphertext_digest:artifact.archive_digest};
    }
    if(config.phase==='publish') {
      const archivePrivateKey=await crypto.subtle.importKey('jwk',config.archive_private_jwk,{name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
      const reviewed=await engine.review(config.request_id,archivePrivateKey);
      const expected=renderRoutine(config.policy.kind,new TextEncoder().encode(JSON.stringify(inputs[config.policy.kind])));
      try{assert.deepEqual(reviewed,expected);}finally{reviewed.fill(0);expected.fill(0);}
      await engine.publishArchive(config.request_id,config.publication_request_id);
      const projection=await engine.projection(config.request_id,archivePrivateKey,scope.readerId);
      const issued=await service.issueOutputGrant({...config.owner_grant,context_id:config.request_id,
        permissions:['context_metadata','context_content','propose'],content_envelope_base64url:encode(projection)});
      const outputService=new CustomerRoutineService({origin,inputCredential:config.input_credential,outputCredential:issued.token,owner:config.owner,fetchImpl});
      const result=await engine.bindAndResume(config.request_id,config.binding_request_id,outputService);
      assert.equal(result.phase,'proposed');
      const replay=await outputService.resume(config.request_id);assert.deepEqual(replay,result);
      return {result,replay,grant_id:issued.grant_id};
    }
    const response=await fetchImpl(origin+'/v1/owner/workflow/routines/withdraw',{method:'POST',headers:{Cookie:config.owner.cookie,Origin:origin,'x-zrotext-csrf':config.owner.csrf,'content-type':'application/json'},body:JSON.stringify({policy_id:config.policy.policy_id})});
    assert.equal(response.status,200);assert.deepEqual(await response.json(),{withdrawn:true});
    let refusal;
    try{await engine.execute(invocation);}catch(error){refusal=error.code;}
    assert.equal(refusal,'forbidden');return {withdrawn:true,refused:true,code:refusal};
  }finally{store?.close();for(const socket of sockets)socket.destroy();if(proxy)await new Promise(resolve=>proxy.close(resolve));await scratch.remove();}
}
try{console.log(JSON.stringify(await main()));}
catch(error){
  console.error('routine fixture cli_code='+customerRoutineDiagnostic(error));
  const code=['forbidden','conflict','authority_unavailable','unknown','timeout','invalid_response'].includes(error?.code)?error.code:'refused';
  const name=['Error','AssertionError','OpenError','AbortError'].includes(error?.name)?error.name:'Error';
  console.error(`routine integration fixture ${name}: ${code}`);process.exitCode=1;
}
