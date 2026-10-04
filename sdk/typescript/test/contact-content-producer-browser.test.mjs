// SPDX-License-Identifier: AGPL-3.0-only
// Actual packaged Chromium with synthetic keys; no production caller or key custody claim.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createRequire} from 'node:module';
import {mkdtemp,readFile,rm,realpath} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..'),require=createRequire(import.meta.url);
test('packaged Chromium produces matched historical commitments and refuses wrong scope and unresolved work',async t=>{
 const tooling=path.join(repo,'web/owner/node_modules/playwright');if(!existsSync(path.join(tooling,'package.json'))){t.skip('Owner Playwright dependency required; owner-browser CI installs it');return;}
 const vector=JSON.parse(await readFile(path.join(repo,'protocol/v1/contact-content-contract-vectors.json'),'utf8')),assets=await mkdtemp(path.join(tmpdir(),'contact-content-producer-browser-'));let browser;
 try{const built=spawnSync(process.execPath,[path.join(repo,'scripts/package_conversation_browser.mjs'),assets],{encoding:'utf8',timeout:20000});assert.equal(built.status,0,built.stderr);assert.ok((await readFile(path.join(assets,'sdk/contact-content-producer.js'),'utf8')).includes('produceContactFieldCommitment01'));
  browser=await require(tooling).chromium.launch({headless:true});for(const scenario of ['matched','wrong-key','scope','abort']){const context=await browser.newContext();try{
   await context.route(vector.reader_statement.origin+'/**',async route=>{const u=new URL(route.request().url());if(u.pathname.startsWith('/assets/')){const p=path.resolve(assets,u.pathname.slice(8));assert.ok(p.startsWith(assets+path.sep));await route.fulfill({contentType:'text/javascript',body:await readFile(p)});}else{assert.equal(u.pathname,'/');assert.equal(route.request().method(),'GET');await route.fulfill({contentType:'text/html',body:'<!doctype html><title>Historical contact commitment fixture</title>'});}});
   const page=await context.newPage();await page.goto(vector.reader_statement.origin);const out=await page.evaluate(async({v,scenario})=>{
    const {enrollRootPin02,verifyManifest02}=await import('/assets/sdk/draft02-manifest.js'),{verifyContactReaderStatement01,verifiedContactReaderStatementIdentity01}=await import('/assets/sdk/contact-reader-statement.js'),c=await import('/assets/sdk/contact-content-contract.js'),p=await import('/assets/sdk/contact-content-producer.js');
    const hex=s=>Uint8Array.from(s.match(/../g),b=>parseInt(b,16)),must=v=>{if(!v)throw Error('browser assertion');},r=v.reader_statement;
    const trust=await enrollRootPin02(hex(r.root_pin_hex),hex(r.expected_root_fingerprint_hex)),manifest=await verifyManifest02(hex(r.accepted_manifest_hex),{...trust,version:6n,digest:hex(r.accepted_previous_digest_hex)},2000n);
    const statement=await verifyContactReaderStatement01({bytes:hex(r.statement_hex),acceptedManifest:manifest,expectedAccountId:hex(r.account_hex),expectedOrigin:r.origin,expectedRootFingerprint:hex(r.expected_root_fingerprint_hex),comparison:'declared_issued_ms'}),s=verifiedContactReaderStatementIdentity01(statement);
    const b64=b=>btoa(Array.from(b,v=>String.fromCharCode(v)).join('')).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');const scalar=new Uint8Array(32);scalar[31]=1;
    const rootPrivateKey=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:b64(s.rootPoint.slice(1,33)),y:b64(s.rootPoint.slice(33)),d:b64(scalar)},{name:'ECDSA',namedCurve:'P-256'},false,['sign']);scalar.fill(0);
    const expected={accountId:s.accountId,origin:s.origin,rootFingerprint:s.rootFingerprint,contactId:hex(v.contact_hex),routingDigest:hex(v.routing_digest_hex)},parsed=await c.parseContactField01(hex(v.name_hex)),field={kind:parsed.kind,sealRevision:parsed.sealRevision,requestId:parsed.requestId,encapsulation:parsed.encapsulation,ciphertext:parsed.ciphertext},base={rootPrivateKey,statement,expected,field,signal:new AbortController().signal};
    const refused=async i=>{let no=false;try{await p.produceContactFieldCommitment01(i);}catch{no=true;}must(no);};
    if(scenario==='wrong-key'){const other=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);await refused({...base,rootPrivateKey:other.privateKey});return {scenario,refused:true};}
    if(scenario==='scope'){const sign=crypto.subtle.sign;let calls=0;crypto.subtle.sign=function(...args){calls++;return sign.apply(this,args);};try{await refused({...base,expected:{...expected,origin:'https://elsewhere.example'}});await refused({...base,statement:{kind:'historical_integrity'}});must(calls===0);}finally{crypto.subtle.sign=sign;}return {scenario,refusedBeforeSign:true};}
    if(scenario==='abort'){const sign=crypto.subtle.sign,releases=[];crypto.subtle.sign=function(...args){const real=sign.apply(this,args);return new Promise((resolve,reject)=>real.then(value=>releases.push(()=>resolve(value)),error=>releases.push(()=>reject(error))));};
     try{const controls=Array.from({length:4},()=>new AbortController()),jobs=controls.map(a=>p.produceContactFieldCommitment01({...base,signal:a.signal}));const wait=performance.now()+5000;while(releases.length!==4){must(performance.now()<wait);await new Promise(r=>setTimeout(r,2));}
      controls.forEach(a=>a.abort());const states=await Promise.all(jobs.map(job=>job.then(()=>false,()=>true)));must(states.every(Boolean));await refused(base);releases.forEach(r=>r());await new Promise(r=>setTimeout(r,10));
     }finally{crypto.subtle.sign=sign;}must((await p.produceContactFieldCommitment01(base)).kind==='produced_historical_integrity');return {scenario,heldFour:true,lateRefused:true};}
    const made=await p.produceContactFieldCommitment01(base);must(c.verifiedContactFieldIdentity01(made.verified).kind===1);const notes=await c.verifyContactField01({bytes:hex(v.notes_hex),statement,expectedContactId:expected.contactId,expectedRoutingDigest:expected.routingDigest}),m=c.parseContactMutation01(hex(v.create_hex));
    const keys=['operation','accountId','contactId','expectedRevision','revision','requestId','previousDigest','trustGeneration','manifestVersion','manifestDigest','statementDigest','routingDigest','legacyGeneration','name','notes'],mutation=Object.fromEntries(keys.map(k=>[k,k==='name'||k==='notes'?{...m[k]}:m[k]]));mutation.name.digest=c.verifiedContactFieldIdentity01(made.verified).digest;
    const produced=await p.produceContactMutationTransition01({rootPrivateKey,statement,expected:{...expected,legacyGeneration:0n},mutation,previous:null,previousStatement:null,replacementFields:[made.verified,notes],signal:new AbortController().signal});must(c.verifiedContactTransitionIdentity01(produced.verified).revision===1n);return {scenario,historicalOnly:produced.kind==='produced_historical_integrity'};
   },{v:vector,scenario});assert.equal(out.scenario,scenario);if(scenario==='matched')assert.equal(out.historicalOnly,true);
  }finally{await context.close();}}
 }finally{await browser?.close();const absolute=path.resolve(assets);assert.equal(path.dirname(absolute),path.resolve(tmpdir()));assert.ok(path.basename(absolute).startsWith('contact-content-producer-browser-'));assert.equal(await realpath(absolute),absolute);await rm(absolute,{recursive:true,force:true});}
});
