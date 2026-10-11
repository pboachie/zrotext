// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {create}=require("./conversation-owner-adapter.js");
const scope={account:"a",session:"s",interval:"i",device:"d",line:"l",generation:"1",peer:"+12",reader:"r",manifest:"m"};
const messageId="12345678-1234-1234-1234-123456789abc";
function packet(){const bytes=Buffer.alloc(297);bytes.write("ZTCS");bytes[4]=1;Buffer.from(messageId.replaceAll("-",""),"hex").copy(bytes,85);return {confirmation:bytes.toString("base64"),envelope:"synthetic",signature:"synthetic"};}
function acknowledgement(created=true){return {message_id:messageId,state:"queued",created};}
function queuedResponse(value=acknowledgement(),status=202){return new Response(JSON.stringify(value),{status,headers:{"Content-Type":"application/json"}});}
function fixture({ack=acknowledgement(),httpStatus=202,response}={}) {
 let current={phase:"active",scope:{...scope},validForMs:1000},calls=[],signed=0;
 let duringSign=()=>{},duringPost=()=>{},csrf="fixture-csrf";
 const custody={openSealed:async()=>"synthetic incoming",prepare:async(s,body)=>({s,body}),signReviewed:async(review,s,body)=>{
   assert.deepEqual(review,{s,body});signed++;await duringSign();return packet();},close:()=>{current=null;}};
 const adapter=create({enabled:true,currentCsrf:()=>csrf,readAuthority:async()=>current,custody,endpoints:{read:event=>"/v1/owner/conversation/events/"+event,submit:"/v1/owner/conversation/send"},
 fetch:async(url,options)=>{calls.push({url,options});if(options.method==="POST"){await duringPost();return response??queuedResponse(ack,httpStatus);}return {ok:true,headers:new Headers({"Content-Type":"application/vnd.zrotext.sealed.v1"}),arrayBuffer:async()=>new Uint8Array(500).buffer};}});
 return {adapter,calls,custody,csrf:v=>{csrf=v;},get signed(){return signed;},replace:v=>{current=v;},duringSign:fn=>{duringSign=fn;},duringPost:fn=>{duringPost=fn;}};
}
test("owner adapter defaults disabled and never fetches",async()=>{await assert.rejects(create({}).authority());});
test("custody failure closes transport and notifies presentation without retry",async()=>{const f=fixture();let notifications=0;f.adapter.onClose(()=>{notifications++;});f.custody.openSealed=async()=>{throw Error("Reader revoked");};await assert.rejects(f.adapter.read({scope,event:"synthetic"}));assert.equal(notifications,1);await assert.rejects(f.adapter.authority());f.adapter.close();assert.equal(notifications,1);});
test("sampled owner authority loss closes custody even without a logout notification",async()=>{const f=fixture();let notifications=0;f.adapter.onClose(()=>{notifications++;});f.replace({phase:"closed",scope,validForMs:1000});await assert.rejects(f.adapter.prepare({scope,body:"Synthetic"}));assert.equal(notifications,1);assert.equal(f.calls.length,0);await assert.rejects(f.adapter.authority());});
test("presentation listener failure cannot prevent other closure notifications",async()=>{const f=fixture();let notifications=0;f.adapter.onClose(()=>{throw Error("Presentation unavailable");});f.adapter.onClose(()=>{notifications++;});f.adapter.close();assert.equal(notifications,1);await assert.rejects(f.adapter.authority());});
test("throwing custody close still delivers every closure notification and disables transport",async()=>{const f=fixture();let notifications=0;f.custody.close=()=>{throw Error("Synthetic custody close failure");};f.adapter.onClose(()=>{throw Error("Presentation unavailable");});f.adapter.onClose(()=>{notifications++;});f.adapter.onClose(()=>{notifications++;});assert.throws(()=>f.adapter.close(),/Synthetic custody close failure/);assert.equal(notifications,2);f.adapter.close();assert.equal(notifications,2);await assert.rejects(f.adapter.authority());assert.equal(f.calls.length,0);});
test("explicit close releases supplied custody even on a disabled transport",()=>{let closes=0;const adapter=create({custody:{close:()=>{closes++;}}});adapter.close();adapter.close();assert.equal(closes,1);});
test("initial discovery is a canonical nonzero event hint and never grants authority",async()=>{const event="12345678-1234-1234-1234-123456789abc",adapter=create({initialEvent:event});assert.equal(adapter.initialEvent,event);await assert.rejects(adapter.authority());for(const invalid of ["../event",event.toUpperCase(),"00000000-0000-0000-0000-000000000000",null])assert.throws(()=>create({initialEvent:invalid}),/discovery/);});
test("cancelled review makes no signature or request",async()=>{const f=fixture();await f.adapter.prepare({scope,body:"exact synthetic"});assert.equal(f.signed,0);assert.equal(f.calls.length,0);});
test("server-shaped 202 confirmation uses owner cookie and cannot replay",async()=>{const f=fixture(),candidate=await f.adapter.prepare({scope,body:"exact synthetic"});assert.deepEqual(await candidate.confirm(()=>{}),{status:"queued"});assert.equal(f.signed,1);assert.equal(f.calls.length,1);assert.equal(f.calls[0].options.credentials,"same-origin");assert.equal(f.calls[0].options.headers["x-zrotext-csrf"],"fixture-csrf");assert.equal(f.calls[0].options.redirect,"error");assert.deepEqual(JSON.parse(f.calls[0].options.body),packet());await assert.rejects(candidate.confirm(()=>{}));assert.equal(f.calls.length,1);});
test("exact existing admission acknowledgement preserves the core queued status without another POST",async()=>{const f=fixture({ack:acknowledgement(false)}),core=require("./conversation-core.js"),c=core.create(f.adapter);await c.authorize();c.edit("Synthetic private reply");await c.prepare();assert.deepEqual(await c.confirm(),{status:"queued"});assert.equal(c.state().uncertain,null);assert.deepEqual(c.state().messages,[{direction:"outbound",body:"Synthetic private reply",status:"queued"}]);assert.equal(f.signed,1);assert.equal(f.calls.length,1);await assert.rejects(c.confirm());assert.equal(f.calls.length,1);});
test("edit during signing creates no submission",async()=>{const f=fixture();let changed=false;f.duringSign(()=>{changed=true;});const candidate=await f.adapter.prepare({scope,body:"exact synthetic"});await assert.rejects(candidate.confirm(()=>{if(changed)throw Error("revision changed");}));assert.equal(f.calls.length,0);});
test("account or session change and close reject stale confirmation",async()=>{const f=fixture(),candidate=await f.adapter.prepare({scope,body:"synthetic"});f.replace({phase:"active",scope:{...scope,session:"other"},validForMs:1000});await assert.rejects(candidate.confirm(()=>{}));assert.equal(f.signed,0);f.adapter.close();await assert.rejects(f.adapter.authority());});
test("only verified bounded sealed content can become browser text",async()=>{const f=fixture();assert.equal(await f.adapter.read({scope,event:"synthetic"}),"synthetic incoming");await assert.rejects(f.adapter.read({scope,event:"../escape"}));assert.equal(f.calls.length,1);});

test("missing CSRF prevents custody preparation and all network",async()=>{const f=fixture();f.csrf(null);await assert.rejects(f.adapter.prepare({scope,body:"synthetic"}));await assert.rejects(f.adapter.read({scope,event:"synthetic"}));assert.equal(f.signed,0);assert.equal(f.calls.length,0);});
test("CSRF rotation during signing prevents submission",async()=>{const f=fixture();f.duringSign(()=>f.csrf("rotated-fixture-csrf"));const c=await f.adapter.prepare({scope,body:"synthetic"});await assert.rejects(c.confirm(()=>{}));assert.equal(f.calls.length,0);});

test("custody close event immediately clears presentation and denies transport",async()=>{const f=fixture();let notify,plaintext="synthetic",closures=0;const custody={...f.custody,onClose:listener=>{notify=listener;},close:()=>{closures++;}};const adapter=create({enabled:true,custody,currentCsrf:()=>"synthetic",readAuthority:async()=>({phase:"active",scope,validForMs:1000}),fetch:async()=>{throw Error("No network expected");},endpoints:{read:()=>"/v1/owner/conversation/events/synthetic",submit:"/v1/owner/conversation/send"}});adapter.onClose(()=>{plaintext="";});notify();assert.equal(plaintext,"");assert.equal(closures,1);await assert.rejects(adapter.authority());adapter.close();assert.equal(closures,1);});

test("accepted POST with lost acknowledgement closes custody and latches identity without another send",async()=>{
 const core=require("./conversation-core.js");let posts=0,closes=0;
 const custody={prepare:async()=>({}),signReviewed:async()=>packet(),openSealed:async()=>"Synthetic",close:()=>{closes++;}};
 const adapter=create({enabled:true,custody,currentCsrf:()=>"synthetic",readAuthority:async()=>({phase:"active",scope,validForMs:1000}),endpoints:{read:()=>"/v1/owner/conversation/events/synthetic",submit:"/v1/owner/conversation/send"},fetch:async()=>{posts++;throw Error("Synthetic accepted response lost");}});
 const c=core.create(adapter);adapter.onClose(()=>c.clear());await c.authorize();c.edit("Synthetic private reply");await c.prepare();
 await assert.rejects(c.confirm(),error=>error.outcome==="unknown"&&error.messageId===messageId);
 assert.deepEqual(c.state().uncertain,{messageId});assert.equal(c.state().draft,"");assert.equal(c.state().scope,null);assert.equal(closes,1);
 c.clear();await assert.rejects(c.authorize());await assert.rejects(c.prepare());await assert.rejects(c.confirm());assert.equal(posts,1);assert.deepEqual(c.state().uncertain,{messageId});
});

for(const result of ["malformed", "refused", "lost-after-ack"])test(result+" post-attempt acknowledgement retains UNKNOWN identity",async()=>{
 let posts=0,closes=0;
 const adapter=create({enabled:true,custody:{prepare:async()=>({}),signReviewed:async()=>packet(),openSealed:async()=>"Synthetic",close:()=>closes++},currentCsrf:()=>"synthetic",readAuthority:async()=>({phase:"active",scope,validForMs:1000}),endpoints:{read:()=>"/v1/owner/conversation/events/synthetic",submit:"/v1/owner/conversation/send"},fetch:async()=>{posts++;return {ok:result!=="refused",status:result==="refused"?403:202,json:async()=>{if(result==="lost-after-ack")throw Error("Synthetic response lost");return {...acknowledgement(),state:"unexpected"};}};}});
 const candidate=await adapter.prepare({scope,body:"Synthetic"});await assert.rejects(candidate.confirm(()=>{}),error=>error.outcome==="unknown"&&error.messageId===messageId);assert.equal(posts,1);assert.equal(closes,1);await assert.rejects(candidate.confirm(()=>{}));assert.equal(posts,1);
});
test("definite validation failure before POST never claims an unknown send",async()=>{const f=fixture();f.custody.signReviewed=async()=>({confirmation:"invalid"});const c=await f.adapter.prepare({scope,body:"Synthetic"});await assert.rejects(c.confirm(()=>{}),error=>error.outcome===undefined);assert.equal(f.calls.length,0);});

for(const [name,ack] of [
 ["legacy status without canonical fields",{status:"queued"}],
 ["wrong message identity",{...acknowledgement(),message_id:"12345678-1234-1234-1234-123456789abd"}],
 ["noncanonical message identity",{...acknowledgement(),message_id:messageId.toUpperCase()}],
 ["missing message identity",{state:"queued",created:true}],
 ["wrong state",{...acknowledgement(),state:"submitted"}],
 ["missing created receipt",{message_id:messageId,state:"queued"}],
 ["nonboolean created receipt",{...acknowledgement(),created:"true"}],
 ["extra response field",{...acknowledgement(),status:"queued"}],
 ["null response",null],
 ["array response",[acknowledgement()]]
])test(name+" after POST retains the original UNKNOWN identity and closes without retry",async()=>{
 const f=fixture({ack});let closes=0;f.adapter.onClose(()=>closes++);const candidate=await f.adapter.prepare({scope,body:"Synthetic"});
 await assert.rejects(candidate.confirm(()=>{}),error=>error.outcome==="unknown"&&error.messageId===messageId);
 assert.equal(f.signed,1);assert.equal(f.calls.length,1);assert.equal(closes,1);await assert.rejects(f.adapter.authority());await assert.rejects(candidate.confirm(()=>{}));assert.equal(f.calls.length,1);
});
test("canonical queued body with an unexpected success status remains UNKNOWN after one POST",async()=>{const f=fixture({httpStatus:200}),candidate=await f.adapter.prepare({scope,body:"Synthetic"});await assert.rejects(candidate.confirm(()=>{}),error=>error.outcome==="unknown"&&error.messageId===messageId);await assert.rejects(candidate.confirm(()=>{}));assert.equal(f.calls.length,1);});
test("mismatched acknowledgement latches the signed identity in presentation rather than the response identity",async()=>{
 const f=fixture({ack:{...acknowledgement(),message_id:"12345678-1234-1234-1234-123456789abd"}}),core=require("./conversation-core.js"),c=core.create(f.adapter);f.adapter.onClose(()=>c.clear());
 await c.authorize();c.edit("Synthetic private reply");await c.prepare();await assert.rejects(c.confirm(),error=>error.outcome==="unknown"&&error.messageId===messageId);
 assert.deepEqual(c.state().uncertain,{messageId});assert.equal(c.state().draft,"");assert.equal(c.state().scope,null);c.clear();await assert.rejects(c.authorize());await assert.rejects(c.prepare());await assert.rejects(c.confirm());assert.equal(f.calls.length,1);assert.deepEqual(c.state().uncertain,{messageId});
});

for(const [name,value] of [["pending",{phase:"pending",validForMs:1000}],["expired",{phase:"active",validForMs:0}],["negative lifetime",{phase:"active",validForMs:-1}],["oversized lifetime",{phase:"active",validForMs:60001}],["invalid lifetime",{phase:"active",validForMs:NaN}]])test(name+" owner lease refuses preparation before signing or POST",async()=>{
 const f=fixture();f.replace({...value,scope});await assert.rejects(f.adapter.prepare({scope,body:"Synthetic"}));assert.equal(f.signed,0);assert.equal(f.calls.length,0);await assert.rejects(f.adapter.authority());
});
for(const status of [401,403,409,410,500])test("HTTP "+status+" after POST retains UNKNOWN even with a canonical queued body",async()=>{
 const f=fixture({httpStatus:status}),candidate=await f.adapter.prepare({scope,body:"Synthetic"});await assert.rejects(candidate.confirm(()=>{}),error=>error.outcome==="unknown"&&error.messageId===messageId);await assert.rejects(candidate.confirm(()=>{}));assert.equal(f.signed,1);assert.equal(f.calls.length,1);await assert.rejects(f.adapter.authority());
});
for(const field of ["account","session","manifest","generation"])test(field+" change after POST refuses a canonical acknowledgement without another send",async()=>{
 const f=fixture();f.duringPost(()=>f.replace({phase:"active",scope:{...scope,[field]:"changed"},validForMs:1000}));const candidate=await f.adapter.prepare({scope,body:"Synthetic"});await assert.rejects(candidate.confirm(()=>{}),error=>error.outcome==="unknown"&&error.messageId===messageId);await assert.rejects(candidate.confirm(()=>{}));assert.equal(f.calls.length,1);await assert.rejects(f.adapter.authority());
});
test("lease expiry after POST keeps the original UNKNOWN identity",async()=>{const f=fixture();f.duringPost(()=>f.replace({phase:"active",scope,validForMs:0}));const candidate=await f.adapter.prepare({scope,body:"Synthetic"});await assert.rejects(candidate.confirm(()=>{}),error=>error.outcome==="unknown"&&error.messageId===messageId);assert.equal(f.calls.length,1);await assert.rejects(candidate.confirm(()=>{}));});
test("CSRF rotation after POST keeps the original UNKNOWN identity",async()=>{const f=fixture();f.duringPost(()=>f.csrf("rotated-fixture-csrf"));const candidate=await f.adapter.prepare({scope,body:"Synthetic"});await assert.rejects(candidate.confirm(()=>{}),error=>error.outcome==="unknown"&&error.messageId===messageId);assert.equal(f.calls.length,1);await assert.rejects(candidate.confirm(()=>{}));});
test("invalid JSON in an actual HTTP 202 response remains UNKNOWN after one POST",async()=>{const f=fixture({response:new Response("{",{status:202,headers:{"Content-Type":"application/json"}})}),candidate=await f.adapter.prepare({scope,body:"Synthetic"});await assert.rejects(candidate.confirm(()=>{}),error=>error.outcome==="unknown"&&error.messageId===messageId);await assert.rejects(candidate.confirm(()=>{}));assert.equal(f.calls.length,1);});
function deferred(){let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};}
test("concurrent confirmation of one signed identity issues one POST",async()=>{
 const f=fixture(),entered=deferred(),release=deferred();f.duringPost(()=>{entered.resolve();return release.promise;});const candidate=await f.adapter.prepare({scope,body:"Synthetic"}),first=candidate.confirm(()=>{});await entered.promise;await assert.rejects(candidate.confirm(()=>{}),/consumed/);assert.equal(f.calls.length,1);release.resolve();assert.deepEqual(await first,{status:"queued"});assert.equal(f.signed,1);assert.equal(f.calls.length,1);
});

// Exercise the unchanged page renderer with the actual transport/core; no browser or owner credentials.
function presentation(adapter){
 const nodes=new Map(),events=new Map(),element=()=>({value:"",textContent:"",disabled:false,hidden:false,children:[],listeners:new Map(),addEventListener(name,listener){this.listeners.set(name,listener);},replaceChildren(){this.children=[];},append(child){this.children.push(child);},focus(){}});
 const node=id=>{if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
 const document={hidden:false,getElementById:node,createElement:element,addEventListener(name,listener){events.set(name,listener);}},window={addEventListener(name,listener){events.set(name,listener);}};
 const storage=new Proxy({}, {get(){throw Error("Conversation content must not use browser storage");}});
 require("node:vm").runInNewContext(require("node:fs").readFileSync(require("node:path").join(__dirname,"conversation.js"),"utf8"),{document,window,ZtConversationSimulatorAdapter:adapter,ZtConversation:require("./conversation-core.js"),localStorage:storage,sessionStorage:storage,setInterval(){return 1;}},{filename:"conversation.js"});
 return {node,click:id=>node(id).listeners.get("click")(),edit:text=>{node("body").value=text;node("body").listeners.get("input")();},hide:()=>{document.hidden=true;events.get("visibilitychange")();}};
}
test("rendered canonical acknowledgement shows queued admission and consumes confirmation",async()=>{
 const f=fixture(),ui=presentation(f.adapter);await ui.click("connect");ui.edit("Synthetic <script>literal</script> reply");await ui.click("review");assert.equal(f.calls.length,0);assert.equal(ui.node("review-body").textContent,"Synthetic <script>literal</script> reply");await ui.click("confirm");assert.equal(ui.node("status").textContent,"Confirmed message queued. Delivery is pending.");assert.equal(ui.node("messages").children[0].textContent,"Queued for delivery: Synthetic <script>literal</script> reply");assert.equal(ui.node("body").value,"");assert.equal(ui.node("confirm").disabled,true);await ui.click("confirm");assert.equal(f.calls.length,1);
});
test("rendered lost acknowledgement survives clear and reconnect without another POST",async()=>{
 const f=fixture();f.duringPost(()=>{throw Error("Synthetic accepted response lost");});const ui=presentation(f.adapter);await ui.click("connect");ui.edit("Synthetic private reply");await ui.click("review");await ui.click("confirm");assert.ok(ui.node("status").textContent.includes(messageId));assert.equal(ui.node("messages").children.length,0);assert.equal(ui.node("body").value,"");assert.equal(ui.node("review-body").textContent,"");assert.equal(ui.node("composer").disabled,true);await ui.click("clear");await ui.click("connect");await ui.click("confirm");assert.ok(ui.node("status").textContent.includes(messageId));assert.equal(f.calls.length,1);
});
test("page hiding during an attempted POST renders UNKNOWN and prevents a repeat",async()=>{
 const f=fixture(),ui=presentation(f.adapter);f.duringPost(()=>ui.hide());await ui.click("connect");ui.edit("Synthetic private reply");await ui.click("review");await ui.click("confirm");assert.ok(ui.node("status").textContent.includes(messageId));assert.equal(ui.node("composer").disabled,true);assert.equal(ui.node("messages").children.length,0);await ui.click("connect");await ui.click("confirm");assert.equal(f.calls.length,1);
});
