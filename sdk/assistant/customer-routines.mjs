// SPDX-License-Identifier: AGPL-3.0-only
// Customer-local entrypoint. Explicit configuration is not model input.
import { pathToFileURL } from 'node:url';
import { webcrypto } from 'node:crypto';
import { readPrivateConfiguration } from './private-store.mjs';
import { LocalProvider } from './local-provider.mjs';
import { CustomerRoutineService,closed,id,policy,fail } from './routine-service.mjs';
import { CustomerRoutineEngine } from './routine-engine.mjs';
import { CipherArtifactStore } from './artifact-store.mjs';
import { WorkflowToolClient } from '../typescript/dist/workflow-tool-client.js';
import { verifyManifest02 } from '../typescript/dist/draft02-manifest.js';
import { OriginalReplyClient } from '../typescript/dist/original-reply-client.js';
globalThis.crypto ??=webcrypto;
const decode=value=>{if(typeof value!=='string'||!/^[A-Za-z0-9_-]+$/.test(value))fail('invalid_configuration');
  const bytes=Uint8Array.from(Buffer.from(value,'base64url'));if(Buffer.from(bytes).toString('base64url')!==value)fail('invalid_configuration');return bytes;};
/** Trusted startup document; never supplied by a provider, webhook or model. */
export function configuration(path){
  const bytes=readPrivateConfiguration(path);
  try{
    const value=JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(bytes));
    const fields=['origin','input_credential','policy','manifest_base64url','root_anchor','input_scope','role3_private_jwk','archive_reader_id','artifact_path','provider'];
    return Object.hasOwn(value,'original_reader')?closed(value,[...fields,'original_reader']):{...closed(value,fields),original_reader:null};
  }
  catch{fail('invalid_configuration');}finally{bytes.fill(0);}
}
export function customerRoutineDiagnostic(error){
  const known=['invalid_configuration','invalid_request','storage_unavailable','forbidden','conflict','authority_unavailable','unknown','timeout','invalid_response','executor_unavailable','artifact_changed','invalid_invocation','replay_conflict','unknown_no_retry','not_executable','withdrawn','provider_unknown','invalid_output'];
  return known.includes(error?.code)?error.code:'unavailable';
}
export function customerReaderKey(jwk){
  // Software JWK already contains exportable secret material in customer
  // custody. Explicit exportability supports the maintained HPKE public-key path.
  return crypto.subtle.importKey('jwk',jwk,{name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
}
export async function runCustomerRoutine(config,{operation,requestId,eventId,owner=null}){
  let store,engine,provider;
  try{
    const p=policy(config.policy);provider=config.provider===null?null:new LocalProvider({approvedArtifact:config.provider});
    const original=config.original_reader==null?null:closed(config.original_reader,['credential','scope']);
    if((p.original_input!=null)!==(original!==null))fail('invalid_configuration');
    const service=new CustomerRoutineService({origin:config.origin,inputCredential:config.input_credential,
      originalCredential:original?.credential??null,owner});
    if(operation==='identity'){if(!provider)fail('executor_unavailable');return provider.identity;}
    if(operation==='configure'){
      if(p.executor==='local_process'&&(!provider||provider.identity.adapter_id!==p.adapter_id||provider.identity.artifact_digest!==p.artifact_digest))fail('invalid_configuration');
      return service.configure(p); // Explicit owner-authenticated policy ceremony.
    }
    if(!['execute','execute_original'].includes(operation)||!id(requestId)||(operation==='execute_original'&&!id(eventId)))fail('invalid_request');
    const scope=closed(config.input_scope,['kind','accountId','deviceId','lineId','intervalId','contextId','bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion','peerDigest','readerId','manifestDigest']);
    for(const field of ['accountId','deviceId','lineId','intervalId','contextId','peerDigest','readerId','manifestDigest'])scope[field]=decode(scope[field]);
    for(const field of ['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'])scope[field]=BigInt(scope[field]);
    const anchor=closed(config.root_anchor,['accountId','generation','rootPoint','version','digest','anchorDigest']);
    for(const field of ['accountId','rootPoint','digest','anchorDigest'])anchor[field]=decode(anchor[field]);
    for(const field of ['generation','version'])anchor[field]=BigInt(anchor[field]);
    // The root pin is independent trusted startup state, never service response.
    const manifest=await verifyManifest02(decode(config.manifest_base64url),anchor,BigInt(Date.now()));
    // Serialized software JWK custody; this is not a hardware/nonexportable key
    // claim. The reviewed HPKE implementation requires public-key availability.
    const privateKey=await customerReaderKey(config.role3_private_jwk);
    let originalClient=null;
    if(original){
      const selected=closed(original.scope,['account','device','line','interval','connector','readGrant','reader','peer']);
      for(const field of ['account','device','line','interval','connector','readGrant','reader'])selected[field]=decode(selected[field]);
      if(typeof selected.peer!=='string')fail('invalid_configuration');
      originalClient=new OriginalReplyClient({origin:config.origin,credential:original.credential,scope:selected,
        privateKey,acceptedHistory:[manifest],clock:()=>BigInt(Date.now())});
    }
    store=new CipherArtifactStore(config.artifact_path);
    engine=new CustomerRoutineEngine({enabled:true,service,tools:new WorkflowToolClient({origin:config.origin,credential:config.input_credential}),store,provider,originalClient,
      cryptoContext:{manifest,inputScope:scope,inputPrivateKey:privateKey,archiveReaderId:decode(config.archive_reader_id)}});
    return operation==='execute_original'?await engine.executeOriginal({request_id:requestId,context_id:p.context_id,policy_id:p.policy_id,event_id:eventId}):
      await engine.execute({request_id:requestId,context_id:p.context_id,policy_id:p.policy_id});
  }finally{engine?.withdraw();provider?.close();store?.close();}
}
async function main(){
  const args=process.argv.slice(2);if(args.length<4||args[0]!=='--config'||!['--identity','--configure','--execute','--execute-original'].includes(args[2])||
    (args[2]==='--execute-original'?args.length!==5:args[2]==='--execute'?args.length!==4:args.length!==4||args[3]!=='explicit'))fail('invalid_request');
  let owner=null;
  if(args[2]==='--configure'){
    // Explicit owner session is ephemeral private stdin, never agent config.
    const chunks=[];let size=0;try{
      for await(const chunk of process.stdin){size+=chunk.length;if(size>8192)fail('invalid_configuration');chunks.push(chunk);}
      const bytes=Buffer.concat(chunks,size);try{owner=closed(JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(bytes)),['cookie','csrf']);}finally{bytes.fill(0);}
    }finally{for(const bytes of chunks)bytes.fill(0);}
  }
  const value=await runCustomerRoutine(configuration(args[1]),{operation:args[2].slice(2).replaceAll('-','_'),requestId:args[3],eventId:args[4],owner});
  process.stdout.write(JSON.stringify(value)+'\n'); // Metadata/digests only.
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{process.stderr.write('customer_routine_unavailable code='+customerRoutineDiagnostic(error)+'\n');process.exitCode=1;});
