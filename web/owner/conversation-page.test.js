// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const core = require("./conversation-core.js");
async function page({ expireReview = false, adapterAvailable = true, ownerSetup, resultStatus = "simulator_accepted", closeError } = {}) {
  const previous = new Map(), elements = new Map(), events = {}, writes = [];
  let time = 0, accepted = 0;
  const scope = {account:randomUUID(),session:randomUUID(),interval:randomUUID(),device:randomUUID(),line:randomUUID(),generation:"1",peer:"+12",reader:"fixture",manifest:"fixture"};
  const literal = "Synthetic <img src=x onerror=fail()> Ω";
  function element(id) {
    if (!elements.has(id)) {
      let text = "";
      elements.set(id,{value:"",hidden:true,disabled:true,listeners:{},children:[],
        get textContent(){return text;}, set textContent(value){text=value;writes.push([id,value,time]);},
        addEventListener(event, fn){this.listeners[event]=fn;},replaceChildren(){this.children=[];},append(p){this.children.push(p);},
        focus(){assert.ok(id!=="review-body" || !this.hidden && element("confirmation").hidden===false);},
        set innerHTML(_){throw Error("HTML injection forbidden");},
      });
    } return elements.get(id);
  }
  const adapter = { initialEvent:randomUUID(),authority:async()=>({phase:"active",validForMs:60000,scope}),read:async()=>literal,
    prepare:async()=>({confirm:async(guard)=>{guard();accepted++;return {status:resultStatus};}}),onClose(fn){events.close=fn;},close(){if(closeError)throw Error(closeError);} };
  const values = { document:{hidden:false,getElementById:element,createElement:()=>({textContent:""}),addEventListener(event,fn){events[event]=fn;}},
    window:{addEventListener(event,fn){events[event]=fn;}},setInterval(fn){events.timer=fn;return 1;},
    ZtConversation:{create(a){const c=core.create(a,()=>time);return {...c,prepare:async()=>{const review=await c.prepare();if(expireReview)time=60000;return review;}};}},
    ZtConversationSimulatorAdapter:adapterAvailable?adapter:undefined,
    ZtConversationOwnerSetup:ownerSetup };
  for (const [name,value] of Object.entries(values)) {previous.set(name,Object.getOwnPropertyDescriptor(globalThis,name));Object.defineProperty(globalThis,name,{value,writable:true,configurable:true});}
  delete require.cache[require.resolve("./conversation.js")];require("./conversation.js");
  return {element,events,writes,literal,accepted:()=>accepted,async click(id){await element(id).listeners.click();},input(value){element("body").value=value;element("body").listeners.input();},
    cleanup(){for(const [name,value]of previous){if(value)Object.defineProperty(globalThis,name,value);else delete globalThis[name];}} };
}
test("page renders literal content, requires review and clears on visibility loss", async()=>{
  const p=await page();try {
    await p.click("connect");assert.equal(p.element("messages").children[0].textContent,`Phone received: ${p.literal}`);
    p.input(p.literal);await p.click("review");assert.equal(p.accepted(),0);assert.equal(p.element("review-body").textContent,p.literal);
    await p.click("confirm");assert.equal(p.accepted(),1);assert.equal(p.element("body").value,"");
    globalThis.document.hidden=true;p.events.visibilitychange();assert.equal(p.element("messages").children.length,0);
    assert.equal(p.element("review-body").textContent,"");assert.equal(p.element("composer").disabled,true);
  }finally{p.cleanup();}
});
test("expiry between prepare and DOM render never repopulates private review text",async()=>{
  const p=await page({expireReview:true});try {
    await p.click("connect");p.input(p.literal);await p.click("review");
    assert.equal(p.element("confirmation").hidden,true);assert.equal(p.element("review-body").textContent,"");
    assert.equal(p.writes.filter(([id,value,time])=>id==="review-body"&&value&&time>=60000).length,0);
    assert.equal(p.accepted(),0);
  }finally{p.cleanup();}
});
test("page has no implicit transport when the fixture adapter is absent",async()=>{
  const p=await page({adapterAvailable:false});try {assert.deepEqual(p.element("connect").listeners,{});assert.equal(p.accepted(),0);}finally{p.cleanup();}
});
test("owner configuration requires an affirmative session decision before SDK or custody access",async()=>{
 let accesses=0;
 const p=await page({adapterAvailable:false,ownerSetup:{custodyOptions:async()=>{accesses++;throw Error("No implicit custody");}}});
 try{assert.equal(accesses,0);assert.equal(p.element("connect").disabled,false);await p.click("connect");assert.equal(accesses,0);assert.equal(p.element("composer").disabled,true);p.events.pagehide();assert.equal(accesses,0);}finally{p.cleanup();}
});
test("queued acceptance renders pending delivery distinctly from fixture acceptance",async()=>{
 const p=await page({resultStatus:"queued"});try{await p.click("connect");p.input("Synthetic queued reply");await p.click("review");await p.click("confirm");assert.equal(p.element("messages").children[1].textContent,"Queued for delivery: Synthetic queued reply");assert.equal(p.element("status").textContent,"Confirmed message queued. Delivery is pending.");}finally{p.cleanup();}
});
for(const trigger of ["clear","pagehide","visibilitychange"])test(trigger+" clears plaintext and review even when custody teardown throws",async()=>{
 const p=await page({closeError:"Synthetic custody close failure"});try{await p.click("connect");p.input(p.literal);await p.click("review");assert.equal(p.element("review-body").textContent,p.literal);if(trigger==="clear")await assert.rejects(p.click("clear"),/Synthetic custody close failure/);else{if(trigger==="visibilitychange")globalThis.document.hidden=true;assert.throws(()=>p.events[trigger](),/Synthetic custody close failure/);}assert.equal(p.element("messages").children.length,0);assert.equal(p.element("body").value,"");assert.equal(p.element("review-body").textContent,"");assert.equal(p.element("selection").textContent,"");assert.equal(p.element("confirmation").hidden,true);assert.equal(p.element("composer").disabled,true);assert.equal(p.accepted(),0);}finally{p.cleanup();}
});
