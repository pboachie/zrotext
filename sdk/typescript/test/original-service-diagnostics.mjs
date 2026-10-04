// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic fixture diagnostics only. Never serialize exception objects.
import {ProviderError} from '../../assistant/local-provider.mjs';
const stages=new Set(['input','history','scope','installation','seed_prepare','client','engine_execute','result_assert','transport','original_current','original_read','original_page','context_metadata','context_content','routine_current','original_admit','call_current','produced']);
const codes=new Set(['forbidden','response_unknown','authority_unavailable','scope_denied','invalid_scope','invalid_content','invalid_configuration','executor_unavailable','provider_unknown','invalid_output','artifact_changed','storage_unavailable','artifact_unavailable','unknown_no_retry','invalid_invocation','not_executable','clock_unavailable']);
const known=new Map([
 ['ZTSE draft-02 manifest: rollback, fork, or chain gap','manifest_chain'],
 ['ZTSE draft-02 manifest: stale or future signed object','manifest_time'],
 ['ZTSE draft-02 manifest: inbound reader authority','reader_authority'],
 ['ZTSE draft-02 manifest: inbound signer authority','signer_authority'],
 ['ZTSE draft-02 envelope prep: recipient key id','recipient_identity'],
 ['ZTSE draft-02 envelope prep: wrap order/duplicate','recipient_order'],
]);
const settlements=new Set(['pending','aborted','transport_failed','http_200','http_400','http_401','http_403','http_409','http_429','http_503','other_status']);
export function originalRoutineDiagnostic(stage,error,settlement){
 const selected=typeof stage==='string'&&stages.has(stage)?stage:'unavailable';
 let code='unavailable';
 try{const candidateCode=error?.code;
 if(typeof candidateCode==='string'&&codes.has(candidateCode))code=candidateCode;
 else{const candidateMessage=error?.message;if(typeof candidateMessage==='string')code=known.get(candidateMessage)??code;}}catch{/* Untrusted getters cannot escape fixed diagnostics. */}
 if(code==='response_unknown'&&settlement!==undefined)code=typeof settlement==='string'&&settlements.has(settlement)?settlement:'unavailable';
 return `original reply fixture phase=${selected};code=${code}\n`;
}
export async function runWithProviderDiagnostic(provider,options,record){
 try{return await provider.run(options);}catch(error){
  if(error instanceof ProviderError)record(originalRoutineDiagnostic('engine_execute',error));
  throw error;
 }
}
