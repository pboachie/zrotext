// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function(root) {
  const fields=["account","session","interval","device","line","generation","peer","reader","manifest"];
  const same=(a,b)=>fields.every(k=>a?.[k]===b?.[k]);
  /** Explicit owner-session transport. Custody verifies/decrypts/signs locally; no key or bearer is accepted here.
   * Endpoint paths are supplied by the dormant integration owner. No endpoint/default adapter is mounted.
   */
  function create({enabled=false,fetch:request,readAuthority,currentCsrf,custody,endpoints}) {
    let closed=!enabled;
    if(enabled && (typeof request!=="function" || typeof readAuthority!=="function" || typeof currentCsrf!=="function" ||
       !custody || ["openSealed","prepare","signReviewed","close"].some(k=>typeof custody[k]!=="function") ||
       typeof endpoints?.read!=="function" || typeof endpoints?.submit!=="string")) throw Error("Owner integration unavailable");
    const path=value=>{if(typeof value!=="string" || !/^\/v1\/owner\/[A-Za-z0-9/_-]+$/.test(value))throw Error("Owner endpoint refused");return value;};
    const csrf=()=>{const value=currentCsrf?.();if(typeof value!=="string" || !value || value.length>256)throw Error("Owner CSRF unavailable");return value;};
    const sameCsrf=value=>{if(csrf()!==value)throw Error("Owner session changed");};
    async function live(scope) {
      if(closed)throw Error("Owner conversation disabled");
      const value=await readAuthority();
      if(closed || value?.phase!=="active" || !same(value.scope,scope) ||
         !Number.isFinite(value.validForMs) || value.validForMs<=0 || value.validForMs>60000)throw Error("Owner authority changed");
      return value;
    }
    async function authority() {
      if(closed)throw Error("Owner conversation disabled");
      const value=await readAuthority();return live(value?.scope);
    }
    async function read({scope,event}) {
      const protection=csrf();await live(scope);sameCsrf(protection);
      const response=await request(path(endpoints.read(event)),{method:"GET",credentials:"same-origin",mode:"same-origin",redirect:"error",cache:"no-store",
        headers:{Accept:"application/vnd.zrotext.sealed.v1","x-zrotext-csrf":protection}});
      if(!response.ok || response.headers.get("Content-Type")?.split(";")[0]!=="application/vnd.zrotext.sealed.v1")throw Error("Sealed read refused");
      const bytes=new Uint8Array(await response.arrayBuffer());if(bytes.length<426 || bytes.length>34213)throw Error("Sealed size refused");
      await live(scope);sameCsrf(protection);const text=await custody.openSealed(bytes,Object.freeze({...scope}));await live(scope);sameCsrf(protection);return text;
    }
    async function prepare({scope,body}) {
      const protection=csrf();await live(scope);sameCsrf(protection);const selected=Object.freeze({...scope});
      const review=await custody.prepare(selected,body);await live(selected);
      let used=false;
      return Object.freeze({confirm:async guard=>{
        if(used)throw Error("Confirmation consumed");used=true;
        guard();sameCsrf(protection);await live(selected);sameCsrf(protection);guard();
        const packet=await custody.signReviewed(review,selected,body);guard();sameCsrf(protection);await live(selected);sameCsrf(protection);guard();
        // A signature never authorizes a changed draft. No retry after a lost/ambiguous POST.
        const response=await request(path(endpoints.submit),{method:"POST",credentials:"same-origin",mode:"same-origin",redirect:"error",cache:"no-store",
          headers:{"Content-Type":"application/json","x-zrotext-csrf":protection},body:JSON.stringify(packet)});
        if(!response.ok)throw Error("Confirmed submission unavailable");
        const result=await response.json();await live(selected);sameCsrf(protection);guard();
        if(result?.status!=="queued")throw Error("Submission result unavailable");
        return Object.freeze({status:"queued"});
      }});
    }
    return Object.freeze({authority,read,prepare,close:()=>{closed=true;custody?.close();}});
  }
  const api=Object.freeze({create});if(typeof module!=="undefined"&&module.exports)module.exports=api;
  else root.ZtConversationOwnerTransport=api;
})(globalThis);
