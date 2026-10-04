// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {originalRoutineDiagnostic,runWithProviderDiagnostic} from './original-service-diagnostics.mjs';
import {LocalProvider,ProviderError} from '../../assistant/local-provider.mjs';
import {mkdtempSync,writeFileSync,readFileSync,realpathSync,chmodSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,sep} from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
const canary='synthetic-private-canary';
test('actual pinned child refusal retains its closed provider code before engine masking',async t=>{
 const anchor=realpathSync(tmpdir()),directory=mkdtempSync(join(anchor,'zt-provider-diagnostic-'));chmodSync(directory,0o700);
 const canonical=realpathSync(directory);let provider;
 t.after(()=>{provider?.close();assert.equal(realpathSync(directory),canonical);assert.ok(canonical.startsWith(anchor+sep));rmSync(canonical,{recursive:true});});
 const script=join(directory,'child.mjs'),marker=join(directory,'invocations');
 writeFileSync(script,"import fs from 'node:fs';for await(const bytes of process.stdin){};fs.appendFileSync(new URL('./invocations',import.meta.url),'x');process.stdout.write('synthetic-private-canary-not-json');",{mode:0o600});
 const hash=bytes=>createHash('sha256').update(bytes).digest('hex'),executable=realpathSync(process.execPath);
 provider=new LocalProvider({approvedArtifact:{adapter_id:'diagnostic_child',executable,executable_digest:hash(readFileSync(executable)),args:[script],cwd:directory,artifact_files:[{path:script,digest:hash(readFileSync(script))}]}});
 const id=randomUUID(),options={call:{call_id:id,assigned_output_context_id:id,execute_once:true,phase:'unknown',output_context_id:null,output_revision:null,action_id:null,binding_digest:null},adapter_id:provider.identity.adapter_id,kind:'faq',policyArtifactDigest:provider.identity.artifact_digest,input:new TextEncoder().encode('synthetic input'),timeoutMs:10000,preInvoke:async()=>{},postReturn:async()=>{}};
 let captured,original;
 await assert.rejects(runWithProviderDiagnostic(provider,options,line=>{captured=line;}),error=>{original=error;assert.ok(error instanceof ProviderError);assert.equal(error.code,'invalid_output');return true;});
 assert.equal(captured,'original reply fixture phase=engine_execute;code=invalid_output\n');assert.equal(captured.includes(canary),false);
 assert.equal(readFileSync(marker,'utf8'),'x');
 // The real engine maps this same refusal to unknown. The fixture keeps only
 // the closed diagnostic and does not change the original thrown object.
 const selected={run:async()=>{throw original;}};
 await assert.rejects(runWithProviderDiagnostic(selected,options,()=>{}),error=>error===original);
 await assert.rejects(provider.run(options),{code:'unknown_no_retry'});assert.equal(readFileSync(marker,'utf8'),'x');
});
test('driver diagnostic maps only exact stages and closed error codes',()=>{
 assert.equal(originalRoutineDiagnostic('produced',{code:'forbidden',message:canary,stack:canary,cause:canary}),'original reply fixture phase=produced;code=forbidden\n');
 assert.equal(originalRoutineDiagnostic('history',Error('ZTSE draft-02 manifest: rollback, fork, or chain gap')),'original reply fixture phase=history;code=manifest_chain\n');
 assert.equal(originalRoutineDiagnostic('transport',null),'original reply fixture phase=transport;code=unavailable\n');
});
test('child-controlled code message relative path and injected stage cannot reach driver stderr text',()=>{
 const values=[canary,'synthetic-directory/'+canary,'synthetic-directory\\'+canary,'invalid_output;'+canary,'invalid_output\n'+canary];
 for(const value of values){
  const line=originalRoutineDiagnostic(value,{code:value,message:value,path:value,stack:value});
  assert.equal(line,'original reply fixture phase=unavailable;code=unavailable\n');assert.equal(line.includes(canary),false);
 }
 for(const stage of [null,{},[],42])assert.equal(originalRoutineDiagnostic(stage,{message:canary}),'original reply fixture phase=unavailable;code=unavailable\n');
});
test('raw crypto message suffixes and hostile property getters stay unavailable',()=>{
 assert.equal(originalRoutineDiagnostic('history',Error('ZTSE draft-02 manifest: rollback, fork, or chain gap '+canary)),'original reply fixture phase=history;code=unavailable\n');
 const hostile={get code(){throw Error(canary);}};
 assert.equal(originalRoutineDiagnostic('engine_execute',hostile),'original reply fixture phase=engine_execute;code=unavailable\n');
});
test('changing getters are sampled once and non-string values never enter stderr',()=>{
 let codeReads=0,messageReads=0;
 const changingCode={get code(){return ++codeReads===1?'invalid_output':canary;},get message(){messageReads++;return canary;}};
 assert.equal(originalRoutineDiagnostic('engine_execute',changingCode),'original reply fixture phase=engine_execute;code=invalid_output\n');
 assert.equal(codeReads,1);assert.equal(messageReads,0);
 const changingMessage={get code(){return undefined;},get message(){return ++messageReads===1?'ZTSE draft-02 manifest: inbound reader authority':canary;}};
 assert.equal(originalRoutineDiagnostic('history',changingMessage),'original reply fixture phase=history;code=reader_authority\n');
 assert.equal(messageReads,1);
 for(const value of [Symbol(canary),{toString(){throw Error(canary);}},[canary]]){
  assert.equal(originalRoutineDiagnostic(value,{code:value,message:value}),'original reply fixture phase=unavailable;code=unavailable\n');
 }
});

test('unknown response exposes only fixed settlement states and never spoofed transport data',()=>{
 for(const state of ['pending','aborted','transport_failed','http_200','http_400','http_401','http_403','http_409','http_429','http_503','other_status']){
  assert.equal(originalRoutineDiagnostic('call_current',{code:'response_unknown',message:canary},state),`original reply fixture phase=call_current;code=${state}\n`);
 }
 for(const state of [canary,'http_200;'+canary,{},[],Symbol(canary)])assert.equal(originalRoutineDiagnostic('call_current',{code:'response_unknown'},state),'original reply fixture phase=call_current;code=unavailable\n');
 assert.equal(originalRoutineDiagnostic('call_current',{code:'forbidden'},'http_403'),'original reply fixture phase=call_current;code=forbidden\n');
});
