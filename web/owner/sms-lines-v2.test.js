// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const assert = require("node:assert/strict");
const test = require("node:test");
const vm = require("node:vm");
const fs = require("node:fs");
const { webcrypto, createPublicKey, verify } = require("node:crypto");
const signing = require("./sms-line-signing.js");
const ACCOUNT="00000000-0000-4000-8000-000000000001",LINE="00000000-0000-4000-8000-000000000002";
const DEVICE="00000000-0000-4000-8000-000000000003",CHALLENGE="00000000-0000-4000-8000-000000000004";
const USER="00000000-0000-4000-8000-000000000005",SESSION="00000000-0000-4000-8000-000000000006";
const OBS="002100020000000b020000000000004000800000000000001100000000000040008000000000000021000000000000000100000000000040008000000000000040000000000000000100000000000040008000000000000041893205abddcccbe664fcbba578beba84ba4a3354c5df1b39adc67d0dab5cc017";
function raw(value){return "{"+Object.entries(value).map(([k,v])=>JSON.stringify(k)+":"+(typeof v==="bigint"?v.toString():JSON.stringify(v))).join(",")+"}";}
function response(value,status=200){return new Response(status===204?null:raw(value),{status,headers:{"content-type":"application/json"}});}
function concat(...parts){return Uint8Array.from(Buffer.concat(parts.map(p=>Buffer.from(p))));}
function deferred(){let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};}

async function page() {
  const owner=await webcrypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},false,["sign"]);
  const point=new Uint8Array(await webcrypto.subtle.exportKey("raw",owner.publicKey));
  const fingerprint=signing.base64url(await signing.sha256(point));
  const held={privateKey:owner.privateKey,fingerprint};
  const elements=new Map(),listeners={},timers=[];
  function element(id){if(!elements.has(id))elements.set(id,{value:"",hidden:false,disabled:false,textContent:"",children:[],listeners:{},
    replaceChildren(...items){this.children=items;},append(...items){this.children.push(...items);},
    addEventListener(name,fn){this.listeners[name]=fn;}});return elements.get(id);}
  const document={cookie:"__Host-zrotext_csrf=ztc_synthetic",hidden:false,getElementById:element,
    createElement:()=>element("created"+elements.size),addEventListener:(name,fn)=>{listeners[name]=fn;}};
  const state={generation:"9223372036854775807",expires:BigInt(Date.now()+300000),opens:[],approvals:[],views:0,
    session:{account_id:ACCOUNT,user_id:USER,session_id:SESSION,role:"owner"},activeFingerprint:fingerprint,
    phase:"awaiting_owner",loseOpen:false,loseApproval:false,onSession:null,onView:null,onSign:null,mutateView:null,legacyOpening:null};
  const generationBytes=Buffer.alloc(8);generationBytes.writeBigInt64BE(BigInt(state.generation));
  const statement=concat(Buffer.from("ZTSMS/line/device-confirm/v2\0"),[2,1],signing.uuidBytes(ACCOUNT),
    signing.uuidBytes(LINE),signing.uuidBytes(DEVICE),generationBytes,signing.uuidBytes(CHALLENGE),new Uint8Array(32).fill(9),Buffer.from(OBS,"hex"));
  const phone=await webcrypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},false,["sign"]);
  const der=signing.p1363ToDer(new Uint8Array(await webcrypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},phone.privateKey,statement)));
  const ownerStatement=concat(Buffer.from("ZTSMS/line/owner-approve/v2\0"),statement,await signing.sha256(der));
  const crypto={randomUUID:()=>webcrypto.randomUUID(),subtle:{
    sign:async(...args)=>{await state.onSign?.();return webcrypto.subtle.sign(...args);}
  }};
  const fetch=async(path,options={})=>{
    const method=options.method??"GET",body=options.body?JSON.parse(options.body):null;
    if(path==="/v1/auth/session"){await state.onSession?.();return response(state.session);}
    assert.equal(options.headers["x-zrotext-csrf"],"ztc_synthetic");
    if(path==="/v1/auth/sms-line-owner-keys")return Response.json([{active:true,fingerprint:state.activeFingerprint}]);
    if(path==="/v1/enrollment/devices")return Response.json({devices:[{device_id:DEVICE,display_name:"Synthetic phone",revoked:false,active_socket_lease:true}]});
    if(path==="/v1/auth/sms-lines")return Response.json({lines:[],next_cursor:null});
    if(state.legacyOpening && method==="POST" && path.endsWith("/activations"))return state.legacyOpening.promise;
    assert.ok(path.includes("/activations-v2"),"v2 must never fall back to legacy routes");
    if(method==="POST"&&!path.endsWith("/approve")){
      state.opens.push({path,body});
      if(state.loseOpen){state.loseOpen=false;throw new TypeError("lost response after commit");}
      return response({challenge_id:CHALLENGE,account_id:ACCOUNT,line_id:LINE,device_id:DEVICE,generation:state.generation,expires_at_ms:state.expires},201);
    }
    if(path.endsWith("/approve")){
      state.approvals.push(body);
      const publicKey=createPublicKey({key:{kty:"EC",crv:"P-256",x:Buffer.from(point.slice(1,33)).toString("base64url"),y:Buffer.from(point.slice(33)).toString("base64url")},format:"jwk"});
      assert.equal(verify("sha256",ownerStatement,{key:publicKey,dsaEncoding:"der"},signing.fromBase64url(body.owner_signature_der_b64url)),true);
      state.phase="activated";
      if(state.loseApproval){state.loseApproval=false;throw new TypeError("lost approval after commit");}
      return response(null,204);
    }
    state.views+=1;await state.onView?.();
    let view={challenge_id:CHALLENGE,device_id:DEVICE,generation:state.generation,expires_at_ms:state.expires,status:state.phase,
      observation_b64url:signing.base64url(Buffer.from(OBS,"hex")),device_statement_b64url:state.phase==="awaiting_owner"?signing.base64url(statement):null,
      device_signature_der_b64url:signing.base64url(der),owner_statement_b64url:state.phase==="awaiting_owner"?signing.base64url(ownerStatement):null};
    view=state.mutateView?.(view)??view;
    return typeof view==="string"?new Response(view,{headers:{"content-type":"application/json"}}):response(view);
  };
  const context={document,fetch,crypto,Uint8Array,DataView,TextEncoder,AbortSignal,URL,Response,console,
    ZtSmsLineSigning:signing,ZtSmsKeyStore:{get:async()=>held},
    ZtSmsLinesSchedule:(fn,ms)=>{timers.push({fn,ms});return timers.length;}};
  vm.createContext(context);vm.runInContext(fs.readFileSync(__dirname+"/sms-lines.js","utf8"),context);
  await context.ZtSmsLinesReady;
  element("activation-mode").value="v2";element("activation-device").value=DEVICE;element("activation-line").value=LINE;
  const click=id=>element(id).listeners.click({preventDefault(){}});
  const start=()=>element("activation-form").listeners.submit({preventDefault(){}});
  return {state,element,document,listeners,context,click,start,timers,
    runTimers:async()=>{for(const {fn} of timers.splice(0))await fn();}};
}

test("real page approves a two-subscription eSIM with exact i64 generation and nonexportable key",async()=>{
  const f=await page();await f.start();
  assert.equal(f.element("activation-review").hidden,false);
  assert.equal(f.element("review-count").textContent,"2");assert.match(f.element("review-kind").textContent,/eSIM/);
  assert.equal(f.element("activation-approve").disabled,false);
  await f.click("activation-approve");
  assert.equal(f.state.opens.length,1);assert.equal(f.state.approvals.length,1);
  assert.match(f.element("activation-status").textContent,/server approved.*confirm local installation/);
});

test("lost opening holds and only deliberate retry uses the exact same opening identity",async()=>{
  const f=await page();f.state.loseOpen=true;await f.start();await f.runTimers();await f.start();
  assert.equal(f.state.opens.length,1);assert.equal(f.element("activation-start").disabled,true);
  await f.click("activation-recheck");assert.equal(f.state.opens.length,2);
  assert.deepEqual(f.state.opens[0],f.state.opens[1]);assert.equal(f.element("activation-review").hidden,false);
});

test("lost approval allows status checking but no repeated signature mutation",async()=>{
  const f=await page();await f.start();f.state.loseApproval=true;await f.click("activation-approve");
  assert.equal(f.state.approvals.length,1);assert.match(f.element("activation-status").textContent,/Outcome unknown/);
  await f.click("activation-approve");await f.start();await f.runTimers();assert.equal(f.state.approvals.length,1);
  await f.click("activation-recheck");assert.equal(f.state.approvals.length,1);
  assert.match(f.element("activation-status").textContent,/server approved/);
});

for(const [name,mutate] of [
  ["other challenge",v=>({...v,challenge_id:USER})], ["other device",v=>({...v,device_id:USER})],
  ["other generation",v=>({...v,generation:"1"})], ["other observation",v=>({...v,observation_b64url:signing.base64url(new Uint8Array(121))})],
  ["owner transcript mismatch",v=>({...v,owner_statement_b64url:signing.base64url(new Uint8Array(8))})],
  ["decoded duplicate key",v=>raw(v).replace('"status":','"status":"awaiting_owner","status":')],
  ["escaped field alias",v=>raw(v).replace('"status":','"\\u0073tatus":')],
  ["extra field",v=>({...v,unexpected:"value"})],
])test(`page refuses ${name} before approval`,async()=>{
  const f=await page();f.state.mutateView=mutate;await f.start();await f.click("activation-approve");
  assert.equal(f.state.approvals.length,0);assert.equal(f.element("activation-review").hidden,true);
});

test("hidden page while signing retires cached approval before submission",async()=>{
  const f=await page();await f.start();f.state.onSign=async()=>{f.document.hidden=true;f.listeners.visibilitychange();};
  await f.click("activation-approve");assert.equal(f.state.approvals.length,0);assert.equal(f.element("activation-review").hidden,true);
});

test("changed session after signing and changed active owner key both refuse before mutation",async()=>{
  for(const mode of ["session","key"]){const f=await page();await f.start();
    f.state.onSign=async()=>{if(mode==="session")f.state.session={...f.state.session,session_id:USER};else f.state.activeFingerprint="different-key";};
    await f.click("activation-approve");assert.equal(f.state.approvals.length,0,mode);
  }
});

test("selection change while view awaits cannot publish approval",async()=>{
  const f=await page(),entered=deferred(),release=deferred();
  f.state.onView=async()=>{entered.resolve();await release.promise;};const work=f.start();await entered.promise;
  f.element("activation-device").value=USER;f.element("activation-device").listeners.change();release.resolve();await work;
  assert.equal(f.element("activation-review").hidden,true);assert.equal(f.state.approvals.length,0);
});

test("hidden page forbids starting a mutation",async()=>{
  const f=await page();f.document.hidden=true;await f.start();assert.equal(f.state.opens.length,0);
});

for(const lost of [false,true])test(`late legacy opening ${lost?"failure":"success"} cannot replace a newer selected SIM review`,async()=>{
  const f=await page(),pending=deferred();
  f.state.legacyOpening=pending;f.element("activation-mode").value="v1";
  const old=f.start();
  await Promise.resolve();
  f.element("activation-mode").value="v2";await f.start();
  assert.equal(vm.runInContext("activation.v2",f.context),true);
  const status=f.element("activation-status").textContent;
  if(lost)pending.resolve(Promise.reject(new TypeError("old opening response lost")));
  else pending.resolve(response({challenge_id:CHALLENGE,generation:1},201));
  await old;
  assert.equal(vm.runInContext("activation.v2",f.context),true);
  assert.equal(f.element("activation-status").textContent,status);
  assert.equal(f.element("activation-review").hidden,false);
  await f.click("activation-approve");
  assert.equal(f.state.approvals.length,1);
});
