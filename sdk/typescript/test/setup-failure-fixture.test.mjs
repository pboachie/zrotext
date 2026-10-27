// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import {CleanupFailure} from './owned-process-fixture.mjs';
import {setupStep,markSetupFailure,setupFailureObservation,finishSetupCleanup} from './setup-failure-fixture.mjs';
import {setupConsumerFailureDiagnostic,joinOwnedAcceptance} from '../../../scripts/sealed_setup_ci_driver.mjs';
const detail=(substage,cleanup_substages=[])=>({substage,cleanup_substages});
async function rejected(operation){try{await operation();}catch(error){return error;}assert.fail('Expected fixture failure');}
test('fixed setup substages retain the innermost failure without reading exception properties',async()=>{
  const error=new Proxy({},{get(){assert.fail('Private exception property inspected');}});
  let caught;try{await setupStep('browser-acceptance',()=>setupStep('line-challenge',()=>{throw error;}));}catch(value){caught=value;}
  assert.equal(caught,error);
  assert.deepEqual(setupFailureObservation(error),detail('line-challenge'));
  assert.equal(setupConsumerFailureDiagnostic('compiled-browser-native-consumption',error),'SETUP_CONSUMER_FAILURE_DETAIL '+JSON.stringify(detail('line-challenge')));
});
test('only branded errors and fixed substages can produce a setup diagnostic',async()=>{
  const canary='synthetic-private-canary',foreign=[null,undefined,7,canary,Error(canary),{substage:'browser-launch'},new Proxy({},{get(){assert.fail('Foreign error inspected');}})];
  for(const error of foreign){assert.equal(setupFailureObservation(error),null);assert.equal(setupConsumerFailureDiagnostic('compiled-browser-native-consumption',error),null);}
  for(const stage of [canary,null,new Proxy({},{get(){assert.fail('Foreign stage inspected');}})]){
    let called=false;await assert.rejects(setupStep(stage,()=>{called=true;}));assert.equal(called,false);
    const error=Error(canary);assert.equal(markSetupFailure(error,stage),error);assert.equal(setupFailureObservation(error),null);
  }
  const error=markSetupFailure(Error(canary),'browser-launch');error.stack=canary;error.substage=canary;error.cleanup_substages=[canary];
  for(const stage of ['phone-consumer-build',canary,null,new Proxy({},{get(){assert.fail('Foreign stage inspected');}})])assert.equal(setupConsumerFailureDiagnostic(stage,error),null);
  for(const stage of ['compiled-browser-native-consumption','phone-consumer-admission'])assert.equal(setupConsumerFailureDiagnostic(stage,error),'SETUP_CONSUMER_FAILURE_DETAIL '+JSON.stringify(detail('browser-launch')));
  assert.ok(Object.isFrozen(setupFailureObservation(error)));assert.ok(Object.isFrozen(setupFailureObservation(error).cleanup_substages));
});
test('cleanup retains primary failures and preserves stronger owned-process safety priority',async()=>{
  for(const primaryUnsafe of [false,true])for(const cleanupUnsafe of [false,true]){
    const primary=markSetupFailure(primaryUnsafe?new CleanupFailure('synthetic private primary'):Error('synthetic private primary'),'native-root-prepare');
    const cleanup=markSetupFailure(cleanupUnsafe?new CleanupFailure('synthetic private cleanup'):Error('synthetic private cleanup'),'fixture-finish');
    const selected=await rejected(()=>finishSetupCleanup(true,primary,()=>{throw cleanup;}));
    assert.equal(selected,primaryUnsafe||!cleanupUnsafe?primary:cleanup);
    assert.deepEqual(setupFailureObservation(selected),detail('native-root-prepare',['fixture-finish']));
    assert.equal(setupConsumerFailureDiagnostic('compiled-browser-native-consumption',selected),'SETUP_CONSUMER_FAILURE_DETAIL '+JSON.stringify(detail('native-root-prepare',['fixture-finish'])));
  }
});
test('multiple cleanup failures retain both contexts and cannot mutate earlier snapshots',async()=>{
  const primary=markSetupFailure(Error('synthetic primary'),'root-challenge'),close=markSetupFailure(Error('synthetic close'),'frontend-close'),finish=markSetupFailure(Error('synthetic finish'),'fixture-finish');
  const before=setupFailureObservation(primary),secondary=await rejected(()=>finishSetupCleanup(true,close,()=>{throw finish;}));
  assert.equal(await rejected(()=>finishSetupCleanup(true,primary,()=>{throw secondary;})),primary);
  assert.deepEqual(setupFailureObservation(primary),detail('root-challenge',['frontend-close','fixture-finish']));assert.deepEqual(before,detail('root-challenge'));
});
test('cleanup-only failure still rejects and unmarked primary gets its enclosing substage',async()=>{
  const cleanup=markSetupFailure(Error('synthetic cleanup'),'browser-context-close');
  assert.equal(await rejected(()=>finishSetupCleanup(false,undefined,()=>{throw cleanup;})),cleanup);
  const primary=Error('synthetic primary');
  assert.equal(await rejected(()=>setupStep('browser-acceptance',()=>finishSetupCleanup(true,primary,()=>{throw cleanup;}))),primary);
  assert.deepEqual(setupFailureObservation(primary),detail('browser-acceptance',['browser-context-close']));
  assert.equal(await rejected(()=>finishSetupCleanup(true,'synthetic primitive',()=>{throw cleanup;})),'synthetic primitive');
});
test('only an elapsed aggregate deadline receives the fixed deadline substage',async()=>{
  let settled=false;
  const acceptance=new Promise((_,reject)=>setTimeout(()=>{settled=true;reject(Error('synthetic late failure'));},30));
  const error=await rejected(()=>joinOwnedAcceptance(acceptance,{timeoutMs:5,joinMs:100,cancel:()=>{}}));
  assert.equal(settled,true);assert.deepEqual(setupFailureObservation(error),detail('acceptance-deadline'));
  const foreign=Error('Fixture deadline exceeded');
  assert.equal(await rejected(()=>joinOwnedAcceptance(Promise.reject(foreign),{cancel:()=>{}})),foreign);assert.equal(setupFailureObservation(foreign),null);
});
