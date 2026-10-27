// SPDX-License-Identifier: AGPL-3.0-only
// Private exception identity carries only fixed public fixture substages.
import {CleanupFailure} from './owned-process-fixture.mjs';
const observations=new WeakMap();
const substages=new Set([
  'browser-launch','browser-context','browser-navigation','browser-acceptance',
  'native-root-prepare','prepared-artifacts','frontend-start','root-challenge',
  'root-signing','line-challenge','line-signing','phone-root-admission',
  'acceptance-deadline','browser-context-close','frontend-close','fixture-finish',
  'browser-close','unknown',
]);
const key=value=>value!==null&&(typeof value==='object'||typeof value==='function');
export function setupFailureObservation(error){
  return key(error)?observations.get(error)||null:null;
}
export function markSetupFailure(error,substage){
  // Do not inspect exception properties, messages, stacks or foreign stages.
  if(key(error)&&typeof substage==='string'&&substages.has(substage)){
    const prior=observations.get(error);
    if(!prior||prior.substage==='unknown')observations.set(error,Object.freeze({substage,cleanup_substages:prior?.cleanup_substages||Object.freeze([])}));
  }
  return error;
}
export async function setupStep(substage,operation){
  if(typeof substage!=='string'||!substages.has(substage))throw Error('Unknown setup fixture substage');
  try{return await operation();}catch(error){throw markSetupFailure(error,substage);}
}
function cleanupFailure(error){try{return error instanceof CleanupFailure;}catch{return false;}}
export async function finishSetupCleanup(failed,primary,cleanup){
  try{await cleanup();}catch(error){
    if(!failed)throw error;
    // Keep the original failure unless cleanup establishes the stronger owned
    // process safety failure. Record BOTH fixed contexts; neither becomes a pass.
    const first=setupFailureObservation(primary),second=setupFailureObservation(error);
    const selected=cleanupFailure(primary)?primary:cleanupFailure(error)?error:primary;
    if(key(selected))observations.set(selected,Object.freeze({
      substage:first?.substage||'unknown',
      cleanup_substages:Object.freeze([...new Set([...(first?.cleanup_substages||[]),second?.substage||'unknown',...(second?.cleanup_substages||[])])]),
    }));
    throw selected;
  }
}
