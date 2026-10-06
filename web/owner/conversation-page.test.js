// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const core = require("./conversation-core.js");
async function page({ expireReview = false, adapterAvailable = true, ownerSetup, ownerFactory, rootFactory, lineFactory, resultStatus = "simulator_accepted", closeError, acceptedError } = {}) {
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
    prepare:async()=>({confirm:async(guard)=>{guard();accepted++;if(acceptedError)throw acceptedError;return {status:resultStatus};}}),onClose(fn){events.close=fn;},close(){if(closeError)throw Error(closeError);} };
  const values = { document:{hidden:false,getElementById:element,createElement:()=>({textContent:""}),addEventListener(event,fn){events[event]=fn;}},
    window:{addEventListener(event,fn){events[event]=fn;}},setInterval(fn){events.timer=fn;return 1;},
    ZtConversation:{create(a){const c=core.create(a,()=>time);return {...c,prepare:async()=>{const review=await c.prepare();if(expireReview)time=60000;return review;}};}},
    ZtConversationSimulatorAdapter:adapterAvailable?adapter:undefined,
    ZtConversationOwnerSetup:ownerSetup,ZtConversationOwnerSetupFactory:ownerFactory,ZtConversationRootEnrollment:rootFactory,ZtConversationLineSetup:lineFactory };
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

test("facts never mount through simulator or without genuine completed owner custody",async()=>{
 for(const options of [{},{adapterAvailable:false,ownerFactory:{create:()=>({close(){}})}}]){
  const p=await page(options);try{assert.equal(p.element("facts-open").disabled,true);await p.click("facts-open");assert.equal(p.element("facts-editor").children.length,0);assert.equal(p.accepted(),0);}finally{p.cleanup();}
 }
});

test("facts intent controls are independent of owner setup and promise only live reconciliation",()=>{
 const html=require("node:fs").readFileSync(require("node:path").join(__dirname,"conversation.html"),"utf8");
 assert.ok(html.indexOf('id="facts-setup"')>html.indexOf('id="session-custody"'));
 for(const id of ["facts-context","facts-expires","facts-open","facts-editor","facts-status"])assert.ok(html.includes(`id="${id}"`));
 assert.ok(html.includes("Reload recovery is unavailable"));assert.ok(html.includes("does not approve messages"));
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

test("ordinary page constructs real owner setup without injected owner global and leaves opt-ins unchecked",async()=>{const factory=require("./conversation-owner-setup.js");let constructed=0;const p=await page({adapterAvailable:false,ownerFactory:{create:options=>{constructed++;return factory.create(options);}}});try{assert.equal(constructed,1);assert.equal(globalThis.ZtConversationOwnerSetup,undefined);assert.equal(p.element("owner-enabled").checked,undefined);assert.equal(p.element("content-consent").checked,undefined);assert.equal(p.element("composer").disabled,true);await p.click("connect");assert.match(p.element("status").textContent,/Action unavailable/);assert.equal(p.accepted(),0);assert.ok(p.element("activate-conversation").listeners.click);const html=require("node:fs").readFileSync(require("node:path").join(__dirname,"conversation.html"),"utf8");assert.ok(html.indexOf('src="conversation-bootstrap.js"')<html.indexOf('src="conversation-owner-setup.js"'));assert.ok(html.indexOf('src="conversation-owner-setup.js"')<html.indexOf('src="conversation.js"'));}finally{p.cleanup();}});
test("ordinary page clear fences a late activation result and aborts its explicit lifetime",async()=>{let release,signal,closed=0;const p=await page({adapterAvailable:false,ownerFactory:{create:()=>({close(){closed++;},activate:async(_file,options)=>{signal=options.signal;await new Promise(resolve=>release=resolve);}})}});try{p.element("activation-file").files=[{}];const pending=p.click("activate-conversation");await Promise.resolve();await p.click("clear");assert.equal(signal.aborted,true);assert.equal(closed,1);release();await pending;assert.ok(!p.element("status").textContent.startsWith("Activation submitted"));assert.equal(p.element("composer").disabled,true);}finally{p.cleanup();}});

test("lost accepted response clears plaintext and displays identity with no new send",async()=>{
 const messageId="12345678-1234-1234-1234-123456789abc";
 const p=await page({acceptedError:Object.assign(Error("Fixed unknown outcome"),{outcome:"unknown",messageId})});
 try{await p.click("connect");p.input(p.literal);await p.click("review");await p.click("confirm");
 assert.equal(p.accepted(),1);assert.equal(p.element("body").value,"");assert.equal(p.element("review-body").textContent,"");assert.equal(p.element("messages").children.length,0);assert.equal(p.element("composer").disabled,true);
 assert.match(p.element("status").textContent,/Send outcome unknown/);assert.ok(p.element("status").textContent.includes(messageId));
 await p.click("clear");assert.ok(p.element("status").textContent.includes(messageId));await p.click("connect");await p.click("confirm");assert.equal(p.accepted(),1);
 }finally{p.cleanup();}
});

test("ordinary page includes concrete root enrollment controls and no recovery input",()=>{const html=require("node:fs").readFileSync(require("node:path").join(__dirname,"conversation.html"),"utf8");assert.ok(html.includes('src="conversation-root-enrollment.js"'));for(const id of ["root-begin","root-complete","root-backup-file","root-card-file","root-signatures-file","root-mfa"])assert.ok(html.includes(`id="${id}"`),id);assert.ok(!html.includes('id="root-recovery"'));});
test("ordinary page passes a separately unchecked reader decision and closes a held activation when its readers change",async()=>{
 let read,release,signal,closed=0;const p=await page({adapterAvailable:false,ownerFactory:{create:options=>{read=options.readSelection;return {close(){closed++;},activate:async(_file,options)=>{signal=options.signal;await new Promise(resolve=>release=resolve);}};}}});
 try{assert.equal(read().integrationReadersText,"");assert.equal(read().integrationTransferConsent,undefined);
 p.element("integration-readers").value="synthetic reader selection";p.element("integration-transfer-consent").checked=true;assert.equal(read().integrationReadersText,"synthetic reader selection");assert.equal(read().integrationTransferConsent,true);
 const pending=p.click("prepare-activation");await Promise.resolve();p.element("owner-setup").listeners.input({target:{id:"integration-readers",closest:()=>null}});assert.equal(signal.aborted,true);assert.equal(closed,1);release();await pending;assert.ok(!p.element("status").textContent.startsWith("Activation submitted"));
 const html=require("node:fs").readFileSync(require("node:path").join(__dirname,"conversation.html"),"utf8");assert.ok(html.includes('id="integration-readers"'));assert.ok(html.includes('id="integration-transfer-consent" type="checkbox">'));assert.ok(html.includes("Separate phone approval of the exact reader list"));
 }finally{p.cleanup();}
});

for(const phase of ["begin","complete"])test("root page Clear fences held "+phase+" and clears local factor",async()=>{
 let release,closed=0,signal;
 const root={close(){closed++;},begin:async(_b,_c,options)=>{signal=options.signal;if(phase==="begin")await new Promise(r=>release=r);},complete:async()=>{await new Promise(r=>release=r);}};
 const p=await page({adapterAvailable:false,ownerFactory:{create:()=>({close(){}})},rootFactory:{create:()=>root}});
 try{p.element("root-backup-file").files=[{}];p.element("root-card-file").files=[{}];p.element("root-signatures-file").files=[{}];
 if(phase==="complete")await p.click("root-begin");p.element("root-mfa").value="fixture-factor";
 const pending=p.click(phase==="begin"?"root-begin":"root-complete");await Promise.resolve();await p.click("clear");assert.equal(signal.aborted,true);assert.equal(p.element("root-mfa").value,"");assert.ok(closed>=1);release();await pending;assert.ok(!p.element("status").textContent.startsWith("Existing root custody enrolled"));assert.ok(!p.element("status").textContent.startsWith("Public root challenge prepared"));assert.equal(p.element("composer").disabled,true);
 }finally{p.cleanup();}
});
test("root completion reports only custody and clears MFA without changing manifest checkpoint",async()=>{const p=await page({adapterAvailable:false,ownerFactory:{create:()=>({close(){}})},rootFactory:{create:()=>({begin:async()=>{},complete:async()=>({rootEnrolled:true}),close(){}})}});try{p.element("root-backup-file").files=[{}];p.element("root-card-file").files=[{}];await p.click("root-begin");p.element("root-signatures-file").files=[{}];p.element("root-mfa").value="fixture-factor";p.element("owner-version").value="independent";await p.click("root-complete");assert.match(p.element("status").textContent,/content consent remain separate/);assert.equal(p.element("owner-version").value,"independent");assert.equal(p.element("root-mfa").value,"");assert.equal(p.element("composer").disabled,true);}finally{p.cleanup();}});

for(const field of ["owner-account","owner-fingerprint"])test("prepared root identity edit closes candidate and clears factor: "+field,async()=>{let closed=0;const p=await page({adapterAvailable:false,ownerFactory:{create:()=>({close(){}})},rootFactory:{create:()=>({begin:async()=>{},close(){closed++;}})}});try{p.element("root-backup-file").files=[{}];p.element("root-card-file").files=[{}];await p.click("root-begin");p.element("root-mfa").value="fixture-factor";p.element("owner-setup").listeners.input({target:{id:field,closest:()=>false}});assert.ok(closed>0);assert.equal(p.element("root-mfa").value,"");}finally{p.cleanup();}});
test("competing public setup fences a held root begin and closes its candidate",async()=>{let release,closed=0;const p=await page({adapterAvailable:false,ownerFactory:{create:()=>({close(){},provisionInitial:async()=>({manifestVersion:"1",manifestDigest:"fixture"})})},rootFactory:{create:()=>({begin:async()=>new Promise(r=>release=r),close(){closed++;}})}});try{p.element("root-backup-file").files=[{}];p.element("root-card-file").files=[{}];const pending=p.click("root-begin");await Promise.resolve();p.element("genesis-phone-file").files=[{}];p.element("genesis-archive-file").files=[{}];await p.click("provision-initial");release();await pending;assert.ok(closed>0);assert.ok(!p.element("status").textContent.startsWith("Public root challenge prepared"));}finally{p.cleanup();}});

test("ordinary line page is concrete, separate opt-in and waits for phone ACK",async()=>{let phase="unprepared",completion=0,approval=0,closed=0,onClose;const setup={state:()=>({phase}),onClose:fn=>onClose=fn,close(){closed++;phase="closed";onClose?.();},begin:async()=>({phase:phase="awaiting_root"}),complete:async()=>{completion++;return {phase:phase="registered"};},open:async()=>({phase:phase="awaiting_device"}),view:async()=>({phase:phase==="activation_committed"?"phone_acknowledged":phase="awaiting_owner",androidApi:31,subscription:4}),approve:async()=>{approval++;return {phase:phase="activation_committed"};}};const p=await page({adapterAvailable:false,ownerFactory:{create:()=>({close(){}})},lineFactory:{create:()=>setup}});try{assert.equal(p.element("line-session-consent").checked,undefined);assert.equal(p.element("line-approve").disabled,true);p.element("line-phone-point-file").files=[{}];await p.click("line-begin");assert.equal(p.element("line-complete").disabled,false);p.element("line-root-signature-file").files=[{}];p.element("line-mfa").value="fixture-factor";await p.click("line-complete");assert.equal(p.element("line-mfa").value,"");await p.click("line-open");await p.click("line-check");assert.equal(p.element("line-approve").disabled,false);await p.click("line-approve");assert.match(p.element("line-status").textContent,/acknowledgment is still required/);await p.click("line-check");assert.match(p.element("line-status").textContent,/installation acknowledged/);assert.equal(completion,1);assert.equal(approval,1);assert.equal(p.element("composer").disabled,true);await p.click("clear");assert.ok(closed>0);assert.equal(p.element("line-approve").disabled,true);const html=require("node:fs").readFileSync(require("node:path").join(__dirname,"conversation.html"),"utf8");assert.ok(html.includes('src="conversation-line-setup.js"'));assert.ok(html.includes('id="line-session-consent"'));}finally{p.cleanup();}});
for(const method of ["begin","complete","approve"])test("page Clear fences held line "+method+" and clears factor/files",async()=>{let release,onClose,closed=0,phase="unprepared";const setup={state:()=>({phase}),onClose:fn=>onClose=fn,close(){closed++;phase="closed";onClose?.();},begin:async()=>{if(method==="begin")await new Promise(r=>release=r);return {phase:phase="awaiting_root"};},complete:async()=>{if(method==="complete")await new Promise(r=>release=r);return {phase:phase="registered"};},approve:async()=>{await new Promise(r=>release=r);return {phase:phase="activation_committed"};}};const p=await page({adapterAvailable:false,ownerFactory:{create:()=>({close(){}})},lineFactory:{create:()=>setup}});try{p.element("line-phone-point-file").files=[{}];p.element("line-root-signature-file").files=[{}];if(method!=="begin")await p.click("line-begin");if(method==="approve")await p.click("line-complete");p.element("line-mfa").value="fixture-factor";const pending=p.click("line-"+method);await Promise.resolve();await p.click("clear");assert.ok(closed>0);assert.equal(p.element("line-mfa").value,"");assert.equal(p.element("line-root-signature-file").value,"");release();await pending;assert.ok(!p.element("line-status").textContent.includes("Activation committed"));assert.equal(p.element("composer").disabled,true);}finally{p.cleanup();}});

test("competing public setup closes held line candidate that lost page ownership",async()=>{let release,closed=0,phase="unprepared",listener;const setup={state:()=>({phase}),onClose:fn=>listener=fn,close(){closed++;phase="closed";listener?.();},begin:async()=>{await new Promise(r=>release=r);return {phase:"awaiting_root"};}};const p=await page({adapterAvailable:false,ownerFactory:{create:()=>({close(){},provisionInitial:async()=>({manifestVersion:"1",manifestDigest:"fixture"})})},lineFactory:{create:()=>setup}});try{p.element("line-phone-point-file").files=[{}];const pending=p.click("line-begin");await Promise.resolve();p.element("genesis-phone-file").files=[{}];p.element("genesis-archive-file").files=[{}];await p.click("provision-initial");release();await pending;assert.ok(closed>0);assert.equal(p.element("line-complete").disabled,true);assert.match(p.element("line-status").textContent,/closed/);assert.equal(p.element("composer").disabled,true);}finally{p.cleanup();}});

test("automatic line expiry clears factor and both public files despite throwing UI disable",async()=>{let listener;const setup={state:()=>({phase:"closed"}),onClose:fn=>listener=fn,close(){listener?.();},begin:async()=>({phase:"awaiting_root"})};const p=await page({adapterAvailable:false,ownerFactory:{create:()=>({close(){}})},lineFactory:{create:()=>setup}});try{p.element("line-phone-point-file").files=[{}];await p.click("line-begin");for(const id of ["line-mfa","line-phone-point-file","line-root-signature-file"])p.element(id).value="fixture-selected";Object.defineProperty(p.element("line-complete"),"disabled",{configurable:true,set(){throw Error("Fixture UI failure");}});assert.doesNotThrow(()=>listener());for(const id of ["line-mfa","line-phone-point-file","line-root-signature-file"])assert.equal(p.element(id).value,"");}finally{p.cleanup();}});
