// SPDX-License-Identifier: AGPL-3.0-only
// Actual Chromium UI against the ephemeral fixture server. Host fixture custody only.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { webcrypto, randomBytes } from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { prepareConfirmedFixture, openConfirmedFixture, signFixtureConfirmation } from "./conversation-simulator-send.mjs";
const require=createRequire(import.meta.url);
const { chromium }=require(process.env.ZT_CONVERSATION_BROWSER_TOOLS
    ? path.join(process.env.ZT_CONVERSATION_BROWSER_TOOLS,"node_modules/playwright") : "playwright");
globalThis.crypto??=webcrypto;
let input="";
for await(const chunk of process.stdin){input+=chunk;if(input.length>100000)throw Error("Fixture input bound");}
const {ready,event,inbound}=JSON.parse(input);
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"../../../web/owner");
const files=new Set(["conversation.html","conversation-core.js","conversation-owner-adapter.js","conversation.js","conversation.css","devices.css"]);
const mime={".html":"text/html",".js":"text/javascript",".css":"text/css"};
const bridgeChallenge=randomBytes(32).toString("hex");
let signed=0,submitted=0,packet;
let releaseSign, signalSign;
const signStarted=new Promise(resolve=>{signalSign=resolve;});
const signRelease=new Promise(resolve=>{releaseSign=resolve;});
let heldSign=true;
async function command(op,values={}){
    const response=await fetch(`http://localhost:${ready.port}/fixture`,{method:"POST",headers:{"Content-Type":"application/json"},
        body:JSON.stringify({token:ready.token,op,...values}),signal:AbortSignal.timeout(10000)});
    return response.json();
}
async function authority(){const value=await command("browser_authority");assert.equal(value.ok,true);return value;}
const server=http.createServer(async(request,response)=>{
    try{
        const filename=new URL(request.url,"http://localhost").pathname.slice(1);
        if(request.method==="GET" && files.has(filename)){
            response.writeHead(200,{"Content-Type":mime[path.extname(filename)],"Cache-Control":"no-store"});
            response.end(await fs.readFile(path.join(root,filename)));return;
        }
        assert.equal(request.method,"POST");assert.equal(filename,"rpc");
        let body="";for await(const chunk of request){body+=chunk;if(body.length>100000)throw Error("Fixture RPC bound");}
        const value=JSON.parse(body);assert.equal(value.token,bridgeChallenge);
        const current=await authority();
        let result;
        if(value.op==="authority")result=current;
        else{
            assert.deepEqual(value.scope,current.scope);
            if(value.op==="read"){
                assert.equal(value.event,event);
                const history=await command("history",{event});assert.equal(history.ok,true);
                const opened=spawnSync("node",[ready.sdkTool],{input:JSON.stringify({op:"open",ready,envelope:history.envelope,
                    device:current.scope.device,line:current.scope.line,peer:current.scope.peer}),encoding:"utf8",timeout:20000,maxBuffer:150000});
                assert.equal(opened.status,0);result={body:JSON.parse(opened.stdout).opened};
            }else if(value.op==="prepare"){
                const candidate=await prepareConfirmedFixture({ready,scope:current.scope,body:value.body,current:current.manifest});
                result={envelope:candidate.envelope,confirmation:candidate.confirmation,message:candidate.message};
            }else if(value.op==="sign"){
                if(heldSign){heldSign=false;signalSign();await signRelease;}
                const candidate=value.candidate;
                const signature=await signFixtureConfirmation(ready,candidate.confirmation);signed++;
                result={...candidate,signature};
                await openConfirmedFixture({ready,scope:current.scope,current:current.manifest,packet:result});
            }else if(value.op==="dispatch"){
                packet=value.packet;
                await openConfirmedFixture({ready,scope:current.scope,current:current.manifest,packet});
                const accepted=await command("send",{data:packet.envelope,confirmation:packet.confirmation,signature:packet.signature});
                assert.equal(accepted.ok,true);assert.equal(accepted.created,true);submitted++;
                result={status:"simulator_accepted"};
            }else throw Error("Unsupported fixture RPC");
        }
        response.writeHead(200,{"Content-Type":"application/json","Cache-Control":"no-store"});response.end(JSON.stringify(result));
    }catch{
        response.writeHead(400,{"Content-Type":"application/json","Cache-Control":"no-store"});response.end('{"error":"Synthetic adapter refused"}');
    }
});
await new Promise(resolve=>server.listen(0,"localhost",resolve));
const origin=`http://localhost:${server.address().port}`;
const browser=await chromium.launch({headless:true,executablePath:process.env.ZT_CONVERSATION_BROWSER_EXECUTABLE});
try{
    const context=await browser.newContext({viewport:{width:1100,height:900}});
    await context.route("**/*",route=>route.request().url().startsWith(origin+"/")?route.continue():route.abort());
    await context.addInitScript(({bridgeChallenge,event})=>{
        const rpc=async(op,values={})=>{const response=await fetch("/rpc",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:bridgeChallenge,op,...values})});if(!response.ok)throw Error("Synthetic adapter refused");return response.json();};
        window.ZtConversationSimulatorAdapter={initialEvent:event,
            authority:()=>rpc("authority"),read:async({scope,event})=>(await rpc("read",{scope,event})).body,
            prepare:async({scope,body})=>{const candidate=await rpc("prepare",{scope,body});return{confirm:async(guard)=>{guard();const packet=await rpc("sign",{scope,candidate});guard();const result=await rpc("dispatch",{scope,packet});guard();return result;}};},
        };
    },{bridgeChallenge,event});
    const page=await context.newPage();const errors=[];page.on("pageerror",error=>errors.push(error.message));
    await page.goto(origin+"/conversation.html");
    await page.getByRole("button",{name:"Check conversation authorization"}).click();
    await page.waitForFunction(()=>!document.querySelector("#body").matches(":disabled"));
    assert.equal(await page.locator("#messages").textContent(),"Phone received: "+inbound);
    const body="Synthetic browser reply \u03A9\nExact trailing spaces  ";
    await page.locator("#body").fill(body);
    await page.getByRole("button",{name:"Review message",exact:true}).click();await page.locator("#confirmation").waitFor({state:"visible"});
    assert.equal(await page.locator("#review-body").textContent(),body);assert.equal(signed,0);assert.equal(submitted,0);
    await page.getByRole("button",{name:"Cancel review"}).click();assert.equal(signed,0);assert.equal(submitted,0);
    await page.getByRole("button",{name:"Review message",exact:true}).click();await page.locator("#confirmation").waitFor({state:"visible"});
    assert.equal(await page.locator("#review-body").textContent(),body);
    await page.getByRole("button",{name:"Confirm this send",exact:true}).click();
    await signStarted;
    await page.locator("#body").evaluate(el=>{el.value="Changed during fixture signing";el.dispatchEvent(new Event("input",{bubbles:true}));});
    releaseSign();
    await page.waitForFunction(()=>document.querySelector("#status").textContent.startsWith("Action unavailable"));
    assert.equal(submitted,0);const midFlightSubmissions=submitted;
    await page.locator("#body").fill(body);await page.getByRole("button",{name:"Review message",exact:true}).click();await page.locator("#confirmation").waitFor({state:"visible"});
    assert.equal(await page.locator("#review-body").textContent(),body);
    await page.getByRole("button",{name:"Confirm this send",exact:true}).click();
    await page.waitForFunction(()=>document.querySelector("#body").value==="");
    assert.equal(signed,2);assert.equal(submitted,1);assert.ok((await page.locator("#messages").textContent()).includes(body));
    assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);assert.deepEqual(errors,[]);
    await context.close();
    process.stdout.write(JSON.stringify({signed,verified:submitted,closedDuringDecrypt:false,packet,chromium:true,cancelSubmissions:0,midFlightSubmissions}));
}finally{releaseSign();await browser.close();await new Promise(resolve=>server.close(resolve));}
