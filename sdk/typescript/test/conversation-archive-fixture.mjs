// SPDX-License-Identifier: AGPL-3.0-only
// SYNTHETIC existing archive scalar3 + separate recovery8; no production producer override.
import {refreshFixture,join} from "./conversation-refresh-fixture.mjs";
const enc=new TextEncoder(),label=s=>enc.encode(s+"\0"),u64=n=>{const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n);return b;};
export async function encryptArchiveFixture02({account,fingerprint,reader,point,scalar,origin="https://owner.invalid",generation=1n}){
 const encoded=enc.encode(origin),n=new Uint8Array(2);new DataView(n.buffer).setUint16(0,encoded.length);
 const header=join(enc.encode("ZTAB"),Uint8Array.of(1,1),new Uint8Array(16).fill(7),account,u64(generation),fingerprint,reader,point,n,encoded),salt=crypto.getRandomValues(new Uint8Array(32)),wrapNonce=crypto.getRandomValues(new Uint8Array(12)),bodyNonce=crypto.getRandomValues(new Uint8Array(12)),vault=crypto.getRandomValues(new Uint8Array(32)),recovery=new Uint8Array(32).fill(8);
 const material=await crypto.subtle.importKey("raw",recovery,"HKDF",false,["deriveKey"]),wrapping=await crypto.subtle.deriveKey({name:"HKDF",hash:"SHA-256",salt,info:join(label("ZTSE/archive-vault-wrap/v1"),account,u64(generation),reader)},material,{name:"AES-GCM",length:256},false,["encrypt"]),prefix=join(header,salt,wrapNonce),wrapped=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:wrapNonce,additionalData:join(label("ZTSE/archive-vault-key-wrap/v1"),prefix)},wrapping,vault)),bodyPrefix=join(prefix,wrapped,bodyNonce,Uint8Array.of(0,0,0,48)),bodyKey=await crypto.subtle.importKey("raw",vault,"AES-GCM",false,["encrypt"]),body=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:bodyNonce,additionalData:join(label("ZTSE/archive-backup/v1"),bodyPrefix)},bodyKey,scalar));vault.fill(0);
 return {encrypted:join(bodyPrefix,body),recovery};
}
export async function archiveFixture({scalar=3,nowMs=2000n}={}){
 const f=await refreshFixture(nowMs),reader=f.predecessor.keys.find(k=>k.role===2),d=new Uint8Array(32);d[31]=scalar;
 const backup=await encryptArchiveFixture02({account:f.review.binding.account,fingerprint:f.comparedRootFingerprint,reader:reader.keyId,point:reader.point,scalar:d});d.fill(0);
 const controller=new AbortController(),state={current:{binding:f.review.binding,manifest:f.predecessor,nowMs,ownerSessionLive:true,consentLive:true},decisions:0};
 const options={...backup,binding:f.review.binding,origin:f.origin,comparedRootFingerprint:f.comparedRootFingerprint,untilMs:nowMs+300000n,signal:controller.signal,readCurrent:async()=>state.current,consumeUnlockDecision:async review=>{if(review.capability!=="account-wide archive decryption")throw Error("Missing archive capability disclosure");state.decisions++;}};
 return {...f,options,state,controller};
}
