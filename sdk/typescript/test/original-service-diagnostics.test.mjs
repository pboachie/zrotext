// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {originalRoutineDiagnostic} from './original-service-diagnostics.mjs';
const canary='synthetic-private-canary';
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
