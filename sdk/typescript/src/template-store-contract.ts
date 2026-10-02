// SPDX-License-Identifier: AGPL-3.0-only
//! Client-neutral bounded persistence messages, with no credential or send grant.
import {encryptedTemplateAad,encryptedTemplateDigest,type EncryptedTemplateScope} from "./encrypted-template.js";
export type TemplateSaveRequest=Readonly<{path:string;headers:Readonly<Record<string,string>>;body:Uint8Array;revision:number;encryptedDigest:string}>;
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Transport adapters supply independently checked real owner authentication and
 * CSRF. This builder accepts no actor, grants, queue IDs or dispatch permission. */
export async function templateSaveRequest(scope:EncryptedTemplateScope,requestId:string,expectedRevision:number,envelope:Uint8Array):Promise<TemplateSaveRequest>{
 if(!uuid.test(requestId)||requestId==='00000000-0000-0000-0000-000000000000'||!Number.isSafeInteger(expectedRevision)||expectedRevision<0||expectedRevision>127||BigInt(expectedRevision+1)!==scope.revision)throw new Error("Invalid template compare-and-swap.");
 const body=Uint8Array.from(envelope),aad=encryptedTemplateAad(scope);
 if(body.length<308||body.length>33075||!aad.every((v,i)=>body[i]===v)||new DataView(body.buffer).getUint32(287,false)!==body.length-291)throw new Error("Invalid template envelope.");
 const encryptedDigest=Array.from(await encryptedTemplateDigest(body),b=>b.toString(16).padStart(2,'0')).join('');
 return Object.freeze({path:'/v1/owner/workflow/templates',headers:Object.freeze({'content-type':'application/vnd.zrotext.workflow-template.v1','idempotency-key':requestId,'x-zrotext-template-revision':String(expectedRevision)}),body,revision:expectedRevision+1,encryptedDigest});
}
/** Only a bounded exact receipt can acknowledge saving; never sending. */
export function templateSaveReceipt(request:TemplateSaveRequest,body:Uint8Array):Readonly<{revision:number}>{
 if(body.length>256)throw new Error("Invalid template receipt.");
 const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(body));
 if(!value||Object.keys(value).join()!=='revision'||value.revision!==request.revision)throw new Error("Invalid template receipt.");
 return Object.freeze({revision:value.revision});
}
