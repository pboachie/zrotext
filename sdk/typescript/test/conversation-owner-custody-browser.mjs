// SPDX-License-Identifier: AGPL-3.0-only
// Explicit Chromium integration: packaged product SDK/page/owner transport, ephemeral fixture custody.
// The HTTP queue and authority are synthetic. No live bootstrap, activation or radio calls occur.
import assert from "node:assert/strict";
import { webcrypto, randomUUID, createHash } from "node:crypto";
import { createRequire } from "node:module";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import http from "node:http";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { canonicalSignature02, enrollRootPin02, verifyManifest02, advanceManifestTrust02, authorizeOutbound02 } from "../dist/draft02-manifest.js";
import { prepareInboundEnvelope02 } from "../dist/draft02-envelope-prep.js";
import { parseDraftEnvelope, decodeBodyText, keyId } from "../dist/draft01.js";
import {encryptArchiveFixture02} from "./conversation-archive-fixture.mjs";
import { openFixtureWrap } from "./conversation-simulator-wrap.mjs";

globalThis.crypto ??= webcrypto;
const require=createRequire(import.meta.url),tools=process.env.ZT_CONVERSATION_BROWSER_TOOLS;
const {chromium}=require(tools?path.join(tools,"node_modules/playwright"):"playwright");
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"../../.."),enc=new TextEncoder();
const b64=b=>Buffer.from(b).toString("base64"),un64=s=>new Uint8Array(Buffer.from(s,"base64"));
const join=(...parts)=>new Uint8Array(Buffer.concat(parts.map(p=>Buffer.from(p))));
const uuid=b=>Buffer.from(b).toString("hex").replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,"$1-$2-$3-$4-$5");
const id=()=>new Uint8Array(Buffer.from(randomUUID().replaceAll("-",""),"hex"));
const u64=n=>{const b=new Uint8Array(8);new DataView(b.buffer).setBigUint64(0,n);return b;};
const u32=n=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n);return b;};
const hash=b=>new Uint8Array(createHash("sha256").update(b).digest());
const transcript=(label,b)=>join(enc.encode(label+"\0"),u32(b.length),b);
const equal=(a,b)=>Buffer.from(a).equals(Buffer.from(b));
async function pair(name){const p=await crypto.subtle.generateKey({name,namedCurve:"P-256"},true,name==="ECDH"?["deriveBits"]:["sign","verify"]);return {...p,point:new Uint8Array(await crypto.subtle.exportKey("raw",p.publicKey))};}
const account=id(),device=id(),line=id(),interval=id(),session=id(),event=id(),zero16=new Uint8Array(16),zero32=new Uint8Array(32);
const root=await pair("ECDSA"),phone=await pair("ECDH"),archive=await pair("ECDH"),inboundSigner=await pair("ECDSA");
const issued=BigInt(Date.now())-1000n,expires=issued+3600000n;
const records=[{role:1,key:phone,device,line,scope:4},{role:2,key:archive,device:zero16,line:zero16,scope:12},{role:4,key:inboundSigner,device,line,scope:2},{role:6,key:root,device:zero16,line:zero16,scope:0}];
for(const r of records)r.keyId=await keyId(r.role<=3?0x10:0x101,r.key.point);
const rootPin=join(enc.encode("ZTRP"),Uint8Array.of(2),account,u64(1n),root.point),fingerprint=hash(join(enc.encode("ZTSE/root-pin/v2\0"),rootPin));
const archiveJwk=await crypto.subtle.exportKey("jwk",archive.privateKey),archiveScalar=new Uint8Array(Buffer.from(archiveJwk.d,"base64url")),archiveBackup=await encryptArchiveFixture02({account,fingerprint,reader:records[1].keyId,point:archive.point,scalar:archiveScalar});archiveScalar.fill(0);delete archiveJwk.d;
let trust=await enrollRootPin02(rootPin,fingerprint);
const unsigned=join(enc.encode("ZTMA"),Uint8Array.of(2),account,u64(1n),u64(1n),u64(issued),u64(expires),zero32,root.point,Uint8Array.of(records.length),...records.map(r=>join(Uint8Array.of(r.role),r.keyId,r.key.point,r.device,r.line,Uint8Array.of(0,r.scope),u64(issued),u64(expires),Uint8Array.of(1))));
const genesisBytes=join(unsigned,canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},root.privateKey,transcript("ZTSE/manifest/v2",unsigned)))));
let manifest=await verifyManifest02(genesisBytes,trust,BigInt(Date.now()));trust=advanceManifestTrust02(trust,manifest);
const binding={account:Array.from(account),device:Array.from(device),line:Array.from(line),interval:Array.from(interval),session:Array.from(session),generation:"1",peer:"+12",phoneReader:Array.from(records[0].keyId),archiveReader:Array.from(records[1].keyId)};
const inboundBody="Synthetic browser incoming <script>literal</script> \u03a9\nTrailing spaces  ";
const incoming=(await prepareInboundEnvelope02({kind:2,manifest,nowMs:BigInt(Date.now()),messageId:event,eventId:event,deviceId:device,lineId:line,peer:enc.encode(binding.peer),observedMs:BigInt(Date.now()),localSequence:1n,content:inboundBody,cek:crypto.getRandomValues(new Uint8Array(32)),nonce:crypto.getRandomValues(new Uint8Array(12)),signer:{privateKey:inboundSigner.privateKey,publicPoint:inboundSigner.point},recipients:[{role:2,keyId:records[1].keyId,point:archive.point,ekm:crypto.getRandomValues(new Uint8Array(32))}]})).envelope;
let alive=true,tamperRead=false,reads=0,queued=0,installs=0,lastTime=0n;
const scope=()=>({account:uuid(account),device:uuid(device),line:uuid(line),interval:uuid(interval),session:uuid(session),generation:"1",peer:binding.peer,reader:b64(records[1].keyId),manifest:b64(manifest.digest)});
const time=()=>{const now=BigInt(Date.now());lastTime=now>lastTime?now:lastTime;return lastTime;};
const snapshot=()=>({binding,manifest:b64(manifest.bytes),nowMs:time().toString(),ownerSessionLive:alive,consentLive:alive,scope:scope(),phase:alive?"active":"closed",validForMs:60000});
const submissions=[];
async function verifyPacket(packet){
 const bytes=un64(packet.envelope),grammar=Uint8Array.from(bytes);assert.equal(grammar[4],2);grammar[4]=1;
 const p=parseDraftEnvelope(grammar),proof=un64(packet.confirmation),signature=un64(packet.signature),now=time();
 assert.equal(p.kind,1);assert.ok(p.observedMs<=now&&now<p.expiresMs&&p.expiresMs-p.observedMs<=30000n);
 const signer=manifest.keys.find(k=>k.role===5&&equal(k.keyId,p.signerKeyId));assert.ok(signer);
 authorizeOutbound02(manifest,{accountId:account,deviceId:device,lineId:line,manifestDigest:p.manifestDigest,keysetVersion:p.keysetVersion,signerKeyId:p.signerKeyId,wraps:p.wraps},now);
 assert.ok(equal(p.accountId,account)&&equal(p.deviceId,device)&&equal(p.lineId,line));assert.equal(p.peer,binding.peer);
 const key=await crypto.subtle.importKey("raw",signer.point,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
 assert.ok(equal(p.signature,canonicalSignature02(p.signature))&&equal(signature,canonicalSignature02(signature)));
 assert.ok(await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},key,p.signature,transcript("ZTSE/sign/v2",bytes.subarray(0,p.unsigned.length))));
 assert.ok(await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},key,signature,transcript("zrotext/conversation/confirm-send/v1",proof)));
 const wrap=p.wraps.find(w=>w.role===1&&equal(w.keyId,records[0].keyId));assert.ok(wrap);
 const cek=await openFixtureWrap(phone.privateKey,phone.point,wrap.enc,join(enc.encode("ZTSE/wrap/v2\0"),bytes.subarray(0,10),p.protected,Uint8Array.of(1),wrap.keyId),wrap.ct);
 let plain;
 try{const content=await crypto.subtle.importKey("raw",cek,"AES-GCM",false,["decrypt"]);plain=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:p.nonce,additionalData:join(enc.encode("ZTSE/body/v2\0"),bytes.subarray(0,10),p.protected),tagLength:128},content,p.bodyCt));const expected=join(enc.encode("ZTCS"),Uint8Array.of(1),account,device,line,interval,session,p.messageId,u64(1n),u64(manifest.generation),u64(manifest.version),u64(p.expiresMs),Uint8Array.of(enc.encode(binding.peer).length),enc.encode(binding.peer),p.signerKeyId,records[1].keyId,manifest.digest,hash(bytes),hash(plain));assert.ok(equal(proof,expected));return decodeBodyText(plain);}finally{cek.fill(0);plain?.fill(0);}
}

// Runs inside Chromium. Fixture keys are already owned by this explicit test; only their public
// trust ledger is persistent. Bootstrap/authority/root approval remain synthetic integration seams.
function browserSetup(config){
 window.fixtureDatabase=config.database;
 const counters=window.fixtureCounters={options:0,setup:0,root:0,confirmation:0},controls=window.fixtureControls={hold:false,release:null,held:false,holdAuthority:false,authorityHeld:false,releaseAuthority:null,throwClose:false};
 // Preserve the actual transport and SDK; inject only a teardown fault after real key closure.
 let transport;
 Object.defineProperty(window,"ZtConversationOwnerTransport",{configurable:true,get:()=>transport,set:api=>{transport={...api,create:options=>{const actual=options.custody;actual.onClose?.(()=>{counters.custodyCloseEvents=(counters.custodyCloseEvents||0)+1;});return api.create({...options,custody:{...actual,close:()=>{actual.close();if(controls.throwClose){controls.throwClose=false;counters.throwingCloseCalls=(counters.throwingCloseCalls||0)+1;throw Error("Synthetic custody close failure");}}}});}};}});
 const decode=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0)),owned=b=>({...b,generation:BigInt(b.generation),account:Uint8Array.from(b.account),device:Uint8Array.from(b.device),line:Uint8Array.from(b.line),interval:Uint8Array.from(b.interval),session:Uint8Array.from(b.session),phoneReader:Uint8Array.from(b.phoneReader),archiveReader:Uint8Array.from(b.archiveReader)});
 const same=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]),exact=selected=>selected.peer===config.binding.peer&&selected.generation.toString()===config.binding.generation&&["account","device","line","interval","session","phoneReader","archiveReader"].every(key=>same(selected[key],config.binding[key]));
 let optionsPromise,closeHook,custodyOptions,unlockArchive;
 window.fixtureLogout=()=>closeHook?.();
 window.ZtConversationOwnerSetup={
  transportOptions:{fetch:window.fetch.bind(window),readAuthority:async()=>{if(controls.holdAuthority){controls.holdAuthority=false;controls.authorityHeld=true;await new Promise(resolve=>{controls.releaseAuthority=()=>{controls.authorityHeld=false;resolve();};});}return window.fixtureAuthority();},currentCsrf:()=>config.csrf,initialEvent:config.event,endpoints:{read:event=>"/v1/owner/conversation/events/"+event,submit:"/v1/owner/conversation/send"}},
  onClose:fn=>{closeHook=fn;},
  custodyOptions:async()=>{
   counters.options++;
   optionsPromise??=(async()=>{
    const base="/v1/owner/conversation-sdk/sdk/",{Draft02TrustStore}=await import(base+"draft02-trust-store.js");
    const store=await Draft02TrustStore.open(config.database);
    if(!await store.read())await store.enroll(decode(config.pin),decode(config.fingerprint),BigInt(Date.now()));
    const readCurrent=async()=>{const value=await window.fixtureAuthority();return {binding:owned(value.binding),manifest:await store.acceptManifest(decode(value.manifest),BigInt(value.nowMs)),nowMs:BigInt(value.nowMs),ownerSessionLive:value.ownerSessionLive,consentLive:value.consentLive};};
    unlockArchive=async()=>{const initial=await readCurrent(),host=document.createElement("div");document.body.append(host);const flow=ZtConversationBootstrap.requestArchiveUnlock({enabled:true,host,signal:new AbortController().signal,context:{binding:owned(config.binding),origin:"https://owner.invalid",comparedRootFingerprint:decode(config.fingerprint),untilMs:initial.nowMs+BigInt(controls.archiveLifetimeMs||300000),readCurrent}});const inputs=host.querySelectorAll('input[type="file"]');for(const [index,data]of [config.archiveBackup,config.archiveRecovery].entries()){const transfer=new DataTransfer();transfer.items.add(new File([decode(data)],"synthetic-archive-file.bin",{type:"application/octet-stream"}));inputs[index].files=transfer.files;}host.querySelector('input[type="checkbox"]').checked=true;host.querySelector("button").click();try{const lease=await flow.result;lease.onClose(()=>{counters.archiveCloseEvents=(counters.archiveCloseEvents||0)+1;});window.fixtureCloseArchive=()=>lease.close();return lease;}finally{host.remove();}};
    custodyOptions={binding:owned(config.binding),history:{trustStore:store},readCurrent,
     consumeSetupDecision:async selected=>{if(!document.querySelector("#session-custody").checked||!exact(selected)||!window.confirm("Use session-only custody for account "+Array.from(selected.account)+", line "+Array.from(selected.line)+", session "+Array.from(selected.session)+", peer "+selected.peer+"?"))throw Error("Fixture setup declined");counters.setup++;},
     consumeOwnerDecision:async review=>{const value=await readCurrent();if(!exact(review.binding)||!same(review.predecessorDigest,value.manifest.digest)||review.successorVersion!==value.manifest.version+1n||!window.confirm("Approve exact root-signed successor "+review.successorVersion+", predecessor "+Array.from(review.predecessorDigest)+", signer "+Array.from(review.keyId)+", account "+Array.from(review.binding.account)+", line "+Array.from(review.binding.line)+", peer "+review.binding.peer+"?"))throw Error("Fixture root approval declined");counters.root++;},
     signWithExistingRoot:async review=>{const value=await readCurrent(),{encodeConversationRefreshProposal02}=await import(base+"conversation-refresh-proposal.js"),typedProposal=await encodeConversationRefreshProposal02({review,predecessor:value.manifest,origin:"https://owner.invalid",comparedRootFingerprint:decode(config.fingerprint),nowMs:value.nowMs});if(typedProposal[4]!==1)throw Error("Typed offline proposal missing");const host=document.createElement("div");document.body.append(host);const approval=ZtConversationBootstrap.requestFileSignature({host,review,typedProposal});const downloaded=new Uint8Array(await(await fetch(host.querySelector("a").href)).arrayBuffer());if(!same(downloaded,typedProposal)||host.querySelector("a").download!=="conversation-role5-proposal.bin")throw Error("Typed public download differs");const signed=Uint8Array.from(await window.fixtureOfflineSignedFile(Array.from(review.unsigned))),input=host.querySelector("input"),transfer=new DataTransfer();transfer.items.add(new File([signed],"synthetic-signed-manifest.bin",{type:"application/octet-stream"}));input.files=transfer.files;input.dispatchEvent(new Event("change"));try{return await approval.result;}finally{approval.close();host.remove();}},
     installVerified:async(expected,accepted,highWater,selected)=>{const signer=accepted.keys.find(k=>k.role===5&&k.fromMs===accepted.issuedMs);await ZtConversationBootstrap.createHttp({enabled:true}).enroll({device_id:config.deviceId,line_id:config.lineId,binding_generation:Number(selected.generation),peer:selected.peer,phone_reader:selected.phoneReader,archive_reader:selected.archiveReader,signer:signer.keyId,public_point:signer.point,predecessor:expected,signed_successor:accepted.bytes});const installed=await store.acceptManifest(accepted.bytes,BigInt((await window.fixtureAuthority()).nowMs));if(installed.version!==highWater.version)throw Error("Fixture install mismatch");},
     consumeConfirmation:async(_proofDigest,bodyDigest)=>{const text=document.querySelector("#review-body").textContent,hash=new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(text)));if(hash.some((v,i)=>v!==bodyDigest[i]))throw Error("Fixture reviewed body mismatch");counters.confirmation++;if(controls.hold){controls.hold=false;controls.held=true;await new Promise(resolve=>{controls.release=()=>{controls.held=false;resolve();};});}}
    };
    window.fixtureReadOld=async()=>{const sdk=await import(base+"conversation-custody.js"),custody=await sdk.prepareConversationCustody02({...custodyOptions,archiveLease:await unlockArchive()});try{const authority=await custody.authority();return await custody.openSealed(decode(config.incoming),authority.scope);}finally{custody.close();}};
    return custodyOptions;
   })();
   return {...await optionsPromise,archiveLease:await unlockArchive()};
  }
 };
}

const assets=await mkdtemp(path.join(tmpdir(),"zrotext-owner-custody-assets-"));
const packaged=spawnSync(process.execPath,[path.join(repo,"scripts/package_conversation_browser.mjs"),assets],{encoding:"utf8",timeout:20000});assert.equal(packaged.status,0,packaged.stderr);
const allowed=new Map();
async function inventory(directory,prefix){for(const entry of await readdir(directory,{withFileTypes:true})){const source=path.join(directory,entry.name),url=prefix+"/"+entry.name;if(entry.isDirectory())await inventory(source,url);else if(entry.name.endsWith(".js"))allowed.set(url,source);}}
await inventory(assets,"/v1/owner/conversation-sdk");
for(const name of ["conversation.html","conversation-core.js","conversation-owner-adapter.js","conversation-bootstrap.js","conversation.js","conversation.css","devices.css"])allowed.set("/"+name,path.join(repo,"web/owner",name));
const csrf="synthetic-csrf",cookie="synthetic-owner-session";
const server=http.createServer(async(req,res)=>{try{
 const url=new URL(req.url,"http://localhost").pathname,source=allowed.get(url);
 if(req.method==="GET"&&source){res.writeHead(200,{"Content-Type":source.endsWith(".html")?"text/html":source.endsWith(".css")?"text/css":"text/javascript","Cache-Control":"no-store"});res.end(await readFile(source));return;}
 assert.ok(alive&&req.headers.cookie?.includes("fixture-owner="+cookie));assert.equal(req.headers["x-zrotext-csrf"],csrf);
 if(req.method==="GET"&&url==="/v1/owner/conversation/events/"+uuid(event)){reads++;const bytes=Uint8Array.from(incoming);if(tamperRead)bytes[bytes.length-1]^=1;res.writeHead(200,{"Content-Type":"application/vnd.zrotext.sealed.v1","Cache-Control":"no-store"});res.end(bytes);return;}
 assert.equal(req.method,"POST");let text="";for await(const part of req){text+=part;if(text.length>60000)throw Error("Fixture packet bound");}
 const packet=JSON.parse(text);if(url==="/v1/owner/conversation/enrollment"){assert.equal(packet.device_id,uuid(device));assert.equal(packet.line_id,uuid(line));assert.equal(packet.binding_generation,1);assert.equal(packet.peer,binding.peer);assert.ok(equal(un64(packet.predecessor),manifest.digest));assert.ok(equal(un64(packet.phone_reader),records[0].keyId)&&equal(un64(packet.archive_reader),records[1].keyId));const accepted=await verifyManifest02(un64(packet.signed_successor),trust,time());assert.equal(accepted.version,manifest.version+1n);assert.equal(accepted.keys.length,manifest.keys.length+1);for(const old of manifest.keys)assert.deepEqual(accepted.keys.find(k=>equal(k.keyId,old.keyId)),old);const signer=accepted.keys.find(k=>equal(k.keyId,un64(packet.signer)));assert.equal(signer.role,5);assert.ok(equal(signer.point,un64(packet.public_point)));assert.ok(alive);manifest=accepted;trust=advanceManifestTrust02(trust,accepted);installs++;res.writeHead(204);res.end();return;}assert.equal(url,"/v1/owner/conversation/send");const body=await verifyPacket(packet);assert.ok(alive);submissions.push(body);queued++;res.writeHead(200,{"Content-Type":"application/json"});res.end('{"status":"queued"}');
 }catch{res.writeHead(403,{"Content-Type":"application/json"});res.end('{"error":"Fixture owner refused"}');}});
await new Promise(resolve=>server.listen(0,"localhost",resolve));const origin="http://localhost:"+server.address().port;
const browser=await chromium.launch({headless:true,executablePath:process.env.ZT_CONVERSATION_BROWSER_EXECUTABLE});
let context;
try{
 context=await browser.newContext({viewport:{width:1100,height:900}});await context.addCookies([{name:"fixture-owner",value:cookie,url:origin},{name:"__Host-zrotext_csrf",value:csrf,domain:"localhost",path:"/",secure:true}]);
 await context.route("**/*",route=>route.request().url().startsWith(origin+"/")?route.continue():route.abort());
 await context.exposeBinding("fixtureAuthority",()=>snapshot());
 await context.exposeBinding("fixtureOfflineSignedFile",async(_source,value)=>{const proposal=Uint8Array.from(value);return Array.from(join(proposal,canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},root.privateKey,transcript("ZTSE/manifest/v2",proposal))))));});
 await context.addInitScript(()=>{document.addEventListener("DOMContentLoaded",()=>{const script=document.createElement("script");script.src="/conversation-bootstrap.js";document.head.append(script);});});

 await context.addInitScript(browserSetup,{binding,deviceId:uuid(device),lineId:uuid(line),pin:b64(rootPin),fingerprint:b64(fingerprint),archiveBackup:b64(archiveBackup.encrypted),archiveRecovery:b64(archiveBackup.recovery),csrf,event:uuid(event),incoming:b64(incoming),database:"synthetic-owner-custody-"+randomUUID()});
 const page=await context.newPage(),errors=[];page.on("pageerror",e=>errors.push(e.message));page.on("dialog",dialog=>dialog.accept());
 await page.goto(origin+"/conversation.html");assert.equal(await page.evaluate(()=>typeof ZtConversationSimulatorAdapter),"undefined");assert.equal(reads+queued+installs,0);assert.equal(await page.evaluate(()=>fixtureCounters.options),0);
 await page.locator("#connect").click();await page.waitForFunction(()=>document.querySelector("#status").textContent.startsWith("Action unavailable"));assert.equal(await page.evaluate(()=>fixtureCounters.options),0);
 await page.waitForFunction(()=>typeof ZtConversationBootstrap!=="undefined");await page.locator("#session-custody").check();await page.locator("#connect").click();await page.waitForFunction(()=>document.querySelector("#messages").textContent.includes("Synthetic browser incoming"));
 assert.equal(await page.locator("#messages").textContent(),"Phone received: "+inboundBody);assert.equal(installs,1);assert.deepEqual(await page.evaluate(()=>fixtureCounters),{options:1,setup:1,root:1,confirmation:0});
 const body="Synthetic exact owner reply \u03a9\nTrailing spaces  ";await page.locator("#body").fill(body);await page.locator("#review").click();await page.locator("#confirmation").waitFor({state:"visible"});assert.equal(await page.locator("#review-body").textContent(),body);await page.locator("#cancel").click();assert.equal(queued,0);assert.equal(await page.evaluate(()=>fixtureCounters.confirmation),0);
 await page.locator("#review").click();await page.locator("#confirmation").waitFor({state:"visible"});await page.evaluate(()=>{fixtureControls.hold=true;});await page.locator("#confirm").click();await page.waitForFunction(()=>fixtureControls.held);await page.locator("#body").evaluate(el=>{el.value="Changed during exact confirmation";el.dispatchEvent(new Event("input",{bubbles:true}));});await page.evaluate(()=>fixtureControls.release());await page.waitForFunction(()=>document.querySelector("#status").textContent.startsWith("Action unavailable"));assert.equal(queued,0);
 await page.locator("#body").fill(body);await page.locator("#review").click();await page.locator("#confirmation").waitFor({state:"visible"});await page.locator("#confirm").click();await page.waitForFunction(()=>document.querySelector("#status").textContent.startsWith("Confirmed message queued"));assert.deepEqual(submissions,[body]);assert.ok((await page.locator("#messages").textContent()).includes("Queued for delivery: "+body));assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
 await page.locator("#body").fill("Synthetic private review before teardown");await page.locator("#review").click();await page.locator("#confirmation").waitFor({state:"visible"});
 await page.evaluate(()=>{fixtureControls.throwClose=true;window.dispatchEvent(new Event("pagehide"));});assert.equal(await page.locator("#messages").textContent(),"");assert.equal(await page.locator("#body").inputValue(),"");assert.equal(await page.locator("#review-body").textContent(),"");assert.equal(await page.locator("#body").isDisabled(),true);assert.equal(await page.evaluate(()=>fixtureCounters.throwingCloseCalls),1);
 await page.evaluate(()=>{fixtureControls.holdAuthority=true;});await page.locator("#connect").click();await page.waitForFunction(()=>fixtureControls.authorityHeld);await page.waitForTimeout(1100);assert.equal(await page.locator("#body").isDisabled(),true);await page.evaluate(()=>fixtureControls.releaseAuthority());await page.waitForFunction(()=>document.querySelector("#messages").textContent.includes("Synthetic browser incoming"));assert.equal(installs,2);
 alive=false;await page.evaluate(()=>fixtureLogout());assert.equal(await page.locator("#messages").textContent(),"");assert.equal(await page.locator("#body").isDisabled(),true);const before=queued;await page.locator("#confirm").evaluate(el=>el.click());assert.equal(queued,before);alive=true;
 await page.reload();await page.waitForFunction(()=>typeof ZtConversationBootstrap!=="undefined");await page.locator("#session-custody").check();await page.locator("#connect").click();await page.waitForFunction(()=>document.querySelector("#messages").textContent.includes("Synthetic browser incoming"));assert.equal(installs,3);assert.equal(await page.evaluate(()=>fixtureCounters.root),1);
 alive=false;await page.locator("#body").fill("Synthetic authority-loss draft");await page.locator("#review").click();await page.waitForFunction(()=>document.querySelector("#status").textContent.startsWith("Action unavailable"));assert.equal(await page.locator("#messages").textContent(),"");assert.equal(await page.locator("#body").isDisabled(),true);alive=true;
 tamperRead=true;await page.locator("#connect").click();await page.waitForFunction(()=>document.querySelector("#status").textContent.startsWith("Action unavailable"));assert.equal(await page.locator("#messages").textContent(),"");assert.equal(await page.locator("#body").isDisabled(),true);assert.equal(installs,4);tamperRead=false;
 await page.locator("#connect").click();await page.waitForFunction(()=>document.querySelector("#messages").textContent.includes("Synthetic browser incoming"));assert.equal(installs,5);
 await page.evaluate(()=>{window.dispatchEvent(new Event("pagehide"));fixtureControls.archiveLifetimeMs=1500;});await page.locator("#connect").click();await page.waitForFunction(()=>document.querySelector("#messages").textContent.includes("Synthetic browser incoming"));assert.equal(installs,6);await page.locator("#body").fill("Synthetic archive-expiry private draft");await page.locator("#review").click();await page.locator("#confirmation").waitFor({state:"visible"});try{await page.waitForFunction(()=>document.querySelector("#messages").textContent===""&&document.querySelector("#composer").disabled,{},{timeout:5000});}catch(error){process.stdout.write(JSON.stringify(await page.evaluate(()=>({counters:fixtureCounters,bodyDisabled:document.querySelector("#body").disabled,messageLength:document.querySelector("#messages").textContent.length})))+"\n");throw error;}assert.equal(await page.locator("#review-body").textContent(),"");assert.equal(await page.locator("#body").inputValue(),"");assert.equal(await page.locator("#body").isDisabled(),true);
 await page.evaluate(()=>{fixtureControls.archiveLifetimeMs=0;});await page.locator("#connect").click();await page.waitForFunction(()=>document.querySelector("#messages").textContent.includes("Synthetic browser incoming"));assert.equal(installs,7);await page.evaluate(()=>fixtureCloseArchive());assert.equal(await page.locator("#messages").textContent(),"");assert.equal(await page.locator("#body").isDisabled(),true);
 await page.evaluate(async()=>{window.dispatchEvent(new Event("pagehide"));const db=await new Promise((resolve,reject)=>{const request=indexedDB.open(fixtureDatabase,1);request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);});try{await new Promise((resolve,reject)=>{const tx=db.transaction("owner-root-high-water","readwrite"),cursor=tx.objectStore("owner-root-high-water").openCursor();cursor.onsuccess=()=>{const row=cursor.result;if(!row)return;if(typeof row.key==="string"&&row.key.startsWith("accepted-manifest:")&&row.key.endsWith(":0000000000000000001"))row.delete();row.continue();};tx.oncomplete=()=>resolve();tx.onabort=()=>reject(tx.error);});}finally{db.close();}});
 await page.reload();await page.waitForFunction(()=>typeof ZtConversationBootstrap!=="undefined");await page.locator("#session-custody").check();await page.locator("#connect").click();await page.waitForFunction(()=>document.querySelector("#status").textContent.startsWith("Action unavailable"));assert.equal(await page.locator("#messages").textContent(),"");assert.equal(await page.locator("#body").isDisabled(),true);assert.equal(installs,8);assert.equal(await page.evaluate(()=>fixtureCounters.root),1);assert.equal(queued,1);
 assert.deepEqual(errors,[]);
 process.stdout.write(JSON.stringify({chromium:true,ownerSetup:true,simulatorAdapter:false,inboundVerified:true,tamperedSignatureRefused:true,exactQueued:queued,cancelQueued:0,editedQueued:0,pagehideClosed:true,throwingCustodyCloseClearsPlaintext:true,pendingAuthorizationTimerSafe:true,logoutClosed:true,sampledAuthorityLossClosed:true,sameBrowserReload:true,missingObservedHistoryRefused:true,freshApprovalRequired:true,rootApprovals:installs,offlinePublicFileExchange:true,typedPublicProposalDownload:true,explicitEncryptedArchiveUnlock:true,archiveExpiryImmediatelyClearsPlaintext:true,archiveCloseImmediatelyClearsPlaintext:true,archivePrivateJwkProvided:false,actualOwnerEnrollmentHttp:true,browserRootImported:false,bootstrap:"ephemeral fixture authority/root/archive only; no production access"})+"\n");
}finally{await context?.close();await browser.close();await new Promise(resolve=>server.close(resolve));await rm(assets,{recursive:true,force:true});}
