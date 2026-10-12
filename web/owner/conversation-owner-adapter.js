// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function(root) {
  const fields=["account","session","interval","device","line","generation","peer","reader","manifest"];
  const same=(a,b)=>fields.every(k=>a?.[k]===b?.[k]);
  // Read identity from the already signed proof, never from a new client-generated retry.
  function messageIdentity(packet) {
    const encoded=packet?.confirmation;
    if(typeof encoded!=="string" || encoded.length>416 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))throw Error("Confirmation identity unavailable");
    const decoded=atob(encoded),bytes=Uint8Array.from(decoded,c=>c.charCodeAt(0));
    if(btoa(decoded)!==encoded || bytes.length<297 || bytes.length>310 || decoded.slice(0,4)!=="ZTCS" || bytes[4]!==1)throw Error("Confirmation identity unavailable");
    const hex=Array.from(bytes.slice(85,101),n=>n.toString(16).padStart(2,"0")).join("");
    if(/^0+$/.test(hex))throw Error("Confirmation identity unavailable");
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
  }
  // The server acknowledges admission of this exact signed message, not delivery.
  function queuedAcknowledgement(value,messageId) {
    return value!==null && typeof value==="object" && !Array.isArray(value) &&
      Object.keys(value).length===3 && value.message_id===messageId &&
      value.state==="queued" && typeof value.created==="boolean";
  }
  /** Explicit owner-session transport. Custody verifies/decrypts/signs locally; no key or bearer is accepted here.
   * Endpoint paths are supplied by the dormant integration owner. No endpoint/default adapter is mounted.
   */
  function create({enabled=false,fetch:request,readAuthority,currentCsrf,custody,endpoints,initialEvent}) {
    let closed=!enabled,custodyClosed=false;
    const closeListeners=new Set();
    function close(){
      if(custodyClosed)return;closed=true;custodyClosed=true;
      try{custody?.close();}
      finally{for(const listener of closeListeners){try{listener();}catch{ /* Closure cannot depend on presentation delivery. */ }}closeListeners.clear();}
    }
    async function useCustody(run){try{return await run();}catch(error){close();throw error;}}
    if(enabled && (typeof request!=="function" || typeof readAuthority!=="function" || typeof currentCsrf!=="function" ||
       !custody || ["openSealed","prepare","signReviewed","close"].some(k=>typeof custody[k]!=="function") ||
       typeof endpoints?.read!=="function" || typeof endpoints?.submit!=="string")) throw Error("Owner integration unavailable");
    if(enabled&&typeof custody.onClose==="function")custody.onClose(close);
    if(initialEvent!==undefined && (typeof initialEvent!=="string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(initialEvent) || initialEvent==="00000000-0000-0000-0000-000000000000"))throw Error("Owner event discovery unavailable");
    const path=value=>{if(typeof value!=="string" || !/^\/v1\/owner\/[A-Za-z0-9/_-]+$/.test(value))throw Error("Owner endpoint refused");return value;};
    const csrf=()=>{let value;try{value=currentCsrf?.();}catch(error){close();throw error;}if(typeof value!=="string" || !value || value.length>256){close();throw Error("Owner CSRF unavailable");}return value;};
    const sameCsrf=value=>{if(csrf()!==value){close();throw Error("Owner session changed");}};
    async function live(scope) {
      if(closed)throw Error("Owner conversation disabled");
      let value;try{value=await readAuthority();}catch(error){close();throw error;}
      if(closed || value?.phase!=="active" || !same(value.scope,scope) ||
         !Number.isFinite(value.validForMs) || value.validForMs<=0 || value.validForMs>60000){close();throw Error("Owner authority changed");}
      return value;
    }
    async function authority() {
      if(closed)throw Error("Owner conversation disabled");
      let value;try{value=await readAuthority();}catch(error){close();throw error;}return live(value?.scope);
    }
    async function read({scope,event}) {
      const protection=csrf();await live(scope);sameCsrf(protection);
      const response=await request(path(endpoints.read(event)),{method:"GET",credentials:"same-origin",mode:"same-origin",redirect:"error",cache:"no-store",
        headers:{Accept:"application/vnd.zrotext.sealed.v1","x-zrotext-csrf":protection}});
      if(!response.ok || response.headers.get("Content-Type")?.split(";")[0]!=="application/vnd.zrotext.sealed.v1")throw Error("Sealed read refused");
      const bytes=new Uint8Array(await response.arrayBuffer());if(bytes.length<426 || bytes.length>34213)throw Error("Sealed size refused");
      await live(scope);sameCsrf(protection);const text=await useCustody(()=>custody.openSealed(bytes,Object.freeze({...scope})));await live(scope);sameCsrf(protection);return text;
    }
    async function prepare({scope,body}) {
      const protection=csrf();await live(scope);sameCsrf(protection);const selected=Object.freeze({...scope});
      const review=await useCustody(()=>custody.prepare(selected,body));await live(selected);
      let used=false;
      return Object.freeze({confirm:async guard=>{
        if(used)throw Error("Confirmation consumed");used=true;
        guard();sameCsrf(protection);await live(selected);sameCsrf(protection);guard();
        const packet=await useCustody(()=>custody.signReviewed(review,selected,body));guard();sameCsrf(protection);await live(selected);sameCsrf(protection);guard();
        const messageId=messageIdentity(packet),url=path(endpoints.submit),encoded=JSON.stringify(packet);
        // Once POST is attempted, transport loss, refusal or a malformed acknowledgement cannot prove absence of admission.
        try {
          const response=await request(url,{method:"POST",credentials:"same-origin",mode:"same-origin",redirect:"error",cache:"no-store",
            headers:{"Content-Type":"application/json","x-zrotext-csrf":protection},body:encoded});
          if(!response.ok || response.status!==202)throw Error("Confirmed submission unavailable");
          const result=await response.json();await live(selected);sameCsrf(protection);guard();
          if(!queuedAcknowledgement(result,messageId))throw Error("Submission result unavailable");
        } catch {
          // Teardown listeners may clear presentation while confirmation is still pending.
          try{close();}catch{ /* UNKNOWN must survive cleanup failure. */ }
          throw Object.freeze(Object.assign(Error("Send outcome unknown. Check delivery before sending again."),{outcome:"unknown",messageId}));
        }
        return Object.freeze({status:"queued"});
      }});
    }
    return Object.freeze({authority,read,prepare,initialEvent,close,onClose:listener=>{if(typeof listener!=="function")throw Error("Closure listener unavailable");if(closed)listener();else closeListeners.add(listener);}});
  }
  const api=Object.freeze({create});if(typeof module!=="undefined"&&module.exports)module.exports=api;
  else root.ZtConversationOwnerTransport=api;
})(globalThis);
