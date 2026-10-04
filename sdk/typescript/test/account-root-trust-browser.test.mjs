// SPDX-License-Identifier: AGPL-3.0-only
// Real packaged Chromium/IDB; session transport is an explicitly synthetic observation.
import {test} from 'node:test';import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';import path from 'node:path';import os from 'node:os';import {createRequire} from 'node:module';import {fileURLToPath} from 'node:url';
import {refreshFixture,signFixtureSuccessor02,join} from './conversation-refresh-fixture.mjs';
import {canonicalSignature02} from '../dist/draft02-manifest.js';
import {encodeContactReaderStatementUnsigned01} from '../dist/contact-reader-statement.js';
import {packageAccountRootTrust,files} from '../../../scripts/package_account_root_trust_browser.mjs';
const repo=fileURLToPath(new URL('../../../',import.meta.url)),require=createRequire(path.join(repo,'web/owner/package.json'));
async function fixture(){
 const f=await refreshFixture(),now=Date.now(),u=f.predecessor.bytes.slice(0,-64),view=new DataView(u.buffer);view.setBigUint64(29,1n);view.setBigUint64(37,BigInt(now-1000));view.setBigUint64(45,BigInt(now+60000));u.fill(0,53,85);
 for(let at=151;at<u.length;at+=149){view.setBigUint64(at+132,BigInt(now-1000));view.setBigUint64(at+140,BigInt(now+60000));}
 const signed=await signFixtureSuccessor02(f,u),pin=new Uint8Array(94);pin.set([90,84,82,80,2]);pin.set(f.review.binding.account,5);new DataView(pin.buffer).setBigUint64(21,1n);pin.set(f.predecessor.rootPoint,29);
 const o=new TextEncoder().encode(f.origin),card=new Uint8Array(133+o.length);card.set([90,84,82,67,1]);new DataView(card.buffer).setUint16(5,o.length);card.set(o,7);card.set(pin,7+o.length);
 const h=b=>Buffer.from(b).toString('hex'),uuid=b=>h(b).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
 const manifestDigest=new Uint8Array(await crypto.subtle.digest('SHA-256',u)),reader=f.predecessor.keys.find(k=>k.role===2),s={authorizationId:new Uint8Array(16).fill(7),accountId:f.review.binding.account,origin:f.origin,trustGeneration:1n,manifestVersion:1n,readerGeneration:1n,rootFingerprint:f.comparedRootFingerprint,manifestDigest,readerId:reader.keyId,readerPoint:reader.point,issuedMs:BigInt(now),untilMs:BigInt(now+30000),capability:3};
 const unsigned=encodeContactReaderStatementUnsigned01(s),length=new Uint8Array(4);new DataView(length.buffer).setUint32(0,unsigned.length);
 const point=f.predecessor.rootPoint,scalar=new Uint8Array(32);scalar[31]=1;const b64=b=>Buffer.from(b).toString('base64url');
 const key=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:b64(point.slice(1,33)),y:b64(point.slice(33)),d:b64(scalar)},{name:'ECDSA',namedCurve:'P-256'},false,['sign']);scalar.fill(0);
 const signature=canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,join(new TextEncoder().encode('ZT/contact-reader/authorization/v1\0'),length,unsigned))));
 const expected=Object.fromEntries(Object.entries(s).map(([k,v])=>[k,v instanceof Uint8Array?(['accountId','authorizationId'].includes(k)?uuid(v):h(v)):typeof v==='bigint'?v.toString():v]));
 expected.statementDigest=h(new Uint8Array(await crypto.subtle.digest('SHA-256',join(unsigned,signature))));
 return {f,account:uuid(f.review.binding.account),fingerprint:h(f.comparedRootFingerprint),card,signed,statement:join(unsigned,signature),expected,u,signNext:async()=>{const next=u.slice();new DataView(next.buffer).setBigUint64(29,2n);next.set(manifestDigest,53);return signFixtureSuccessor02(f,next);}};
}
test('actual fixed package page supports genuine genesis, same/next history and intended reader integrity',async()=>{
 const {chromium}=require('playwright'),out=await mkdtemp(path.join(os.tmpdir(),'account-trust-browser-'));let browser;
 try{
  await packageAccountRootTrust(out);const modules=Object.fromEntries(await Promise.all(files.map(async n=>[n,await readFile(path.join(out,'sdk',n))]))),html=await readFile(path.join(repo,'web/owner/account-root-trust.html')),controller=await readFile(path.join(repo,'web/owner/account-root-trust.js'));
  browser=await chromium.launch({headless:true});const f=await fixture();
  async function context(){const ctx=await browser.newContext({serviceWorkers:'block'});await ctx.addCookies([{name:'__Host-zrotext_csrf',value:'synthetic-review',url:f.f.origin,secure:true,sameSite:'Strict'}]);let session={account_id:f.account,user_id:'22222222-2222-4222-8222-222222222222',session_id:'33333333-3333-4333-8333-333333333333',role:'owner'};const requests=[];
   await ctx.route('**/*',async route=>{const url=new URL(route.request().url());requests.push(url.pathname);if(url.origin!==f.f.origin)return route.abort();let body,type;
    if(url.pathname==='/v1/auth/session'){body=JSON.stringify(session);type='application/json';}else if(url.pathname==='/owner/account/root-trust'){body=html;type='text/html';}else if(url.pathname==='/owner/account/root-trust.js'){body=controller;type='text/javascript';}else{const name=url.pathname.replace('/v1/owner/account-root-trust-sdk/sdk/','');if(!Object.hasOwn(modules,name))return route.abort();body=modules[name];type='text/javascript';}
    return route.fulfill({status:200,body,headers:{'content-type':type,'cache-control':'no-store','content-security-policy':"default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"}});
   });const page=await ctx.newPage();await page.goto(f.f.origin+'/owner/account/root-trust');await page.locator('#review').waitFor({state:'visible'});await page.waitForFunction(()=>!document.getElementById('review').disabled);
   await page.locator('#account').fill(f.account);await page.locator('#origin').fill(f.f.origin);await page.locator('#fingerprint').fill(f.fingerprint);await page.locator('#card').setInputFiles({name:'public-card.bin',mimeType:'application/octet-stream',buffer:Buffer.from(f.card)});await page.locator('#manifest').setInputFiles({name:'manifest.bin',mimeType:'application/octet-stream',buffer:Buffer.from(f.signed)});
   return {ctx,page,requests,setSession:v=>{session=v;}};
  }
  const c=await context();try{
   await c.page.locator('#review').click();await c.page.waitForFunction(()=>!document.getElementById('decision').hidden);assert.match(await c.page.locator('#tuple').textContent(),/manifestDigest/);
   await c.page.locator('#accept').click();await c.page.waitForFunction(()=>document.getElementById('status').textContent.startsWith('Signed local history accepted'));
   await c.page.locator('summary').click();await c.page.locator('#expected').fill(JSON.stringify(f.expected));await c.page.locator('#statement').setInputFiles({name:'statement.bin',mimeType:'application/octet-stream',buffer:Buffer.from(f.statement)});await c.page.locator('#verify-statement').click();await c.page.waitForFunction(()=>document.getElementById('status').textContent.startsWith('Historical reader statement integrity'));
   for(const bytes of [f.signed,await f.signNext()]){await c.page.locator('#manifest').setInputFiles({name:'manifest.bin',mimeType:'application/octet-stream',buffer:Buffer.from(bytes)});await c.page.locator('#review').click();await c.page.waitForFunction(()=>!document.getElementById('decision').hidden);await c.page.locator('#accept').click();await c.page.waitForFunction(()=>document.getElementById('status').textContent.startsWith('Signed local history accepted'));}
   assert.ok(c.requests.every(p=>p==='/v1/auth/session'||p==='/owner/account/root-trust'||p==='/owner/account/root-trust.js'||p.startsWith('/v1/owner/account-root-trust-sdk/sdk/')));
  }finally{await c.ctx.close();}
  for(const mode of ['wrong-fingerprint','decline','session-drift','cold-next']){const c=await context();try{
   if(mode==='wrong-fingerprint')await c.page.locator('#fingerprint').fill('00'.repeat(32));if(mode==='cold-next')await c.page.locator('#manifest').setInputFiles({name:'next.bin',mimeType:'application/octet-stream',buffer:Buffer.from(await f.signNext())});
   await c.page.locator('#review').click();if(mode==='wrong-fingerprint'||mode==='cold-next'){await c.page.waitForFunction(()=>document.getElementById('status').textContent.startsWith('Local review unavailable'));}else{
    await c.page.waitForFunction(()=>!document.getElementById('decision').hidden);if(mode==='decline'){await c.page.locator('#decline').click();assert.equal(await c.page.locator('#decision').isHidden(),true);}else{c.setSession({account_id:f.account,user_id:'22222222-2222-4222-8222-222222222222',session_id:'44444444-4444-4444-8444-444444444444',role:'owner'});await c.page.locator('#accept').click();await c.page.waitForFunction(()=>document.getElementById('status').textContent.startsWith('Local review unavailable'));}
   }
   const stored=await c.page.evaluate(async()=>{const {Draft02TrustStore}=await import('/v1/owner/account-root-trust-sdk/sdk/draft02-trust-store.js'),store=await Draft02TrustStore.open();try{return (await store.read())?.trust.version.toString()??null;}finally{store.close();}});assert.equal(stored,null,mode);
  }finally{await c.ctx.close();}}
  for(const mode of ['wrong-intent','wrong-packet-digest','bad-signature']){const c=await context();try{
   await c.page.locator('#review').click();await c.page.waitForFunction(()=>!document.getElementById('decision').hidden);await c.page.locator('#accept').click();await c.page.waitForFunction(()=>document.getElementById('status').textContent.startsWith('Signed local history accepted'));
   const expected={...f.expected},statement=f.statement.slice();if(mode==='wrong-intent')expected.readerGeneration='2';if(mode==='wrong-packet-digest')expected.statementDigest='00'.repeat(32);if(mode==='bad-signature')statement[statement.length-1]^=1;
   await c.page.locator('summary').click();await c.page.locator('#expected').fill(JSON.stringify(expected));await c.page.locator('#statement').setInputFiles({name:'statement.bin',mimeType:'application/octet-stream',buffer:Buffer.from(statement)});await c.page.locator('#verify-statement').click();await c.page.waitForFunction(()=>document.getElementById('status').textContent.startsWith('Local review unavailable'));assert.equal(await c.page.locator('#decision').isHidden(),true);
   const version=await c.page.evaluate(async()=>{const {Draft02TrustStore}=await import('/v1/owner/account-root-trust-sdk/sdk/draft02-trust-store.js'),store=await Draft02TrustStore.open();try{return (await store.read()).trust.version.toString();}finally{store.close();}});assert.equal(version,'1');
  }finally{await c.ctx.close();}}
 }finally{if(browser)await browser.close();await rm(out,{recursive:true,force:true});}
});
