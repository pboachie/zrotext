// SPDX-License-Identifier: AGPL-3.0-only
// Ordinary packaged page/setup/custody/HPKE. Auth and HTTP persistence are synthetic.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm,realpath} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {archiveFixture} from '../../../sdk/typescript/test/conversation-archive-fixture.mjs';
import {join,signFixtureSuccessor02} from '../../../sdk/typescript/test/conversation-refresh-fixture.mjs';
import {verifyManifest02,verifiedManifestTrust02} from '../../../sdk/typescript/dist/draft02-manifest.js';
import {unlockExistingArchive02} from '../../../sdk/typescript/dist/conversation-archive-custody.js';
import {openWorkflowContext} from '../../../sdk/typescript/dist/workflow-context.js';
const repo=fileURLToPath(new URL('../../../',import.meta.url)),require=createRequire(path.join(repo,'web/owner/package.json'));
const b64=b=>Buffer.from(b).toString('base64'),hex=b=>Buffer.from(b).toString('hex');
const uuid=b=>hex(b).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
const contextId=new Uint8Array(16).fill(6),canary='Synthetic ordinary facts <plain text> Ω';

test('ordinary facts page uses final enrollment, real archive custody and one original encrypted save',async()=>{
 const {chromium}=require('playwright'),assets=await mkdtemp(path.join(os.tmpdir(),'conversation-facts-page-'));let browser;
 try{
  const packaged=spawnSync(process.execPath,[path.join(repo,'scripts/package_conversation_browser.mjs'),assets],{encoding:'utf8',timeout:20000});assert.equal(packaged.status,0,packaged.stderr);
  browser=await chromium.launch({headless:true});
  for(const mode of ['save','unknown','unknown-close','editor-close','conflict','clear-review','pagehide','late','scope','csrf','bad-pin','expiry']){
   const f=await archiveFixture({nowMs:BigInt(Date.now())}),binding=f.review.binding,reader=f.predecessor.keys.find(k=>k.role===2),phone=f.predecessor.keys.find(k=>k.role===1),signer=f.predecessor.keys.find(k=>k.role===4);
   let manifest=f.predecessor,installs=0,posts=0,head=null,heldReply=null;const requests=[],bootstrapVersions=[];
   const context=await browser.newContext({serviceWorkers:'block'});
   try{
    await context.addCookies([{name:'__Host-zrotext_session',value:'synthetic-facts-owner',url:f.origin,httpOnly:true,secure:true,sameSite:'Strict'},{name:'__Host-zrotext_csrf',value:'synthetic-facts-review',url:f.origin,secure:true,sameSite:'Strict'}]);
    await context.route(f.origin+'/**',async route=>{
     const request=route.request(),url=new URL(request.url());
     if(url.pathname.startsWith('/v1/owner/conversation-sdk/')){
      const target=path.resolve(assets,url.pathname.replace('/v1/owner/conversation-sdk/',''));assert.ok(target.startsWith(assets+path.sep));return route.fulfill({contentType:'text/javascript',body:await readFile(target)});
     }
     if(url.pathname.startsWith('/v1/owner/conversation/')||url.pathname.startsWith('/v1/owner/workflow/contexts')){
      const headers=await request.allHeaders(),body=request.postDataBuffer();requests.push({method:request.method(),url:url.pathname,headers,body});
      assert.ok(headers.cookie.includes('__Host-zrotext_session=synthetic-facts-owner'));assert.equal(headers['x-zrotext-csrf'],'synthetic-facts-review');assert.equal(headers.authorization,undefined);
      if(url.pathname==='/v1/owner/conversation/bootstrap'){
       bootstrapVersions.push(manifest.version.toString());
       return route.fulfill({contentType:'application/json',body:JSON.stringify({v:1,trust_candidate:true,owner_session_live:true,account_id:uuid(binding.account),session_id:uuid(binding.session),device_id:uuid(binding.device),line_id:uuid(binding.line),binding_generation:1,peer:binding.peer,phase:'active',consent_live:true,interval_id:uuid(binding.interval),server_now_ms:Date.now().toString(),manifest_version:manifest.version.toString(),trust_generation:'1',root_pin:b64(join(new TextEncoder().encode('ZTRP'),Uint8Array.of(2),binding.account,new Uint8Array([0,0,0,0,0,0,0,1]),manifest.rootPoint)),root_fingerprint:b64(f.comparedRootFingerprint),current_manifest:b64(manifest.bytes),manifest_digest:b64(manifest.digest),phone_reader_id:b64(phone.keyId),phone_reader_point:b64(phone.point),archive_reader_id:b64(reader.keyId),archive_reader_point:b64(reader.point),phone_signer_id:b64(signer.keyId),phone_signer_point:b64(signer.point)})});
      }
      if(url.pathname==='/v1/owner/conversation/enrollment'){
       const value=JSON.parse(body.toString('utf8'));assert.equal(value.predecessor,b64(manifest.digest));
       manifest=await verifyManifest02(new Uint8Array(Buffer.from(value.signed_successor,'base64')),verifiedManifestTrust02(manifest,BigInt(Date.now())),BigInt(Date.now()));
       assert.equal(manifest.version,f.predecessor.version+1n);assert.equal(manifest.keys.filter(k=>k.role===5).length,1);installs++;return route.fulfill({status:204,body:''});
      }
      if(url.pathname.startsWith('/v1/owner/workflow/contexts')){
       assert.equal(installs,1);assert.equal(url.search,'');
       if(request.method()==='POST'){
        posts++;assert.equal(headers.origin,f.origin);assert.equal(headers['x-zrotext-context-revision'],'0');assert.ok(!body.includes(Buffer.from(canary)));head=body;
        assert.equal(new DataView(body.buffer,body.byteOffset).getBigUint64(118),manifest.version);
        if(mode==='late'){await new Promise(resolve=>heldReply=resolve);try{return await route.fulfill({contentType:'application/json',body:'{"revision":1}'});}catch{return;}}
        if(mode==='conflict')return route.fulfill({status:409,body:''});
        if((mode==='unknown'||mode==='unknown-close'||mode==='editor-close')&&posts===1)return route.fulfill({status:503,body:''});
        return route.fulfill({contentType:'application/json',body:'{"revision":1}'});
       }
       assert.ok(head);return route.fulfill({contentType:'application/vnd.zrotext.workflow-context.v1',body:head});
      }
      throw Error('Unexpected owner endpoint '+url.pathname);
     }
     const name=url.pathname==='/owner/conversation'?'conversation.html':url.pathname.split('/').at(-1);
     if(!/^[a-z0-9-]+\.(html|js|css)$/.test(name))return route.abort();
     return route.fulfill({contentType:name.endsWith('.html')?'text/html':name.endsWith('.js')?'text/javascript':'text/css',body:await readFile(path.join(repo,'web/owner',name))});
    });
    const page=await context.newPage();page.setDefaultTimeout(10000);page.on('dialog',dialog=>dialog.accept());
    await page.goto(f.origin+'/owner/conversation');assert.equal(await page.locator('#facts-open').isDisabled(),true);
    await page.locator('#owner-enabled').check();await page.locator('#content-consent').check();await page.locator('#session-custody').check();
    for(const [name,value] of Object.entries({'owner-account':uuid(binding.account),'owner-device':uuid(binding.device),'owner-line':uuid(binding.line),'owner-generation':'1','owner-peer':binding.peer,'owner-fingerprint':mode==='bad-pin'?'00'.repeat(32):hex(f.comparedRootFingerprint),'owner-version':f.predecessor.version.toString(),'owner-digest':hex(f.predecessor.digest)}))await page.locator('#'+name).fill(value);
    await page.locator('#connect').click();
    if(mode==='bad-pin'){await page.waitForFunction(()=>document.getElementById('status').textContent.startsWith('Action unavailable'));assert.equal(installs,0);assert.equal(await page.locator('#facts-open').isDisabled(),true);continue;}
    await page.getByLabel('Existing encrypted archive ZTAB01 file',{exact:true}).setInputFiles({name:'archive.bin',mimeType:'application/octet-stream',buffer:Buffer.from(f.options.encrypted)});
    await page.getByLabel('Separate archive recovery file, exactly 32 bytes',{exact:true}).setInputFiles({name:'recovery.bin',mimeType:'application/octet-stream',buffer:Buffer.from(f.options.recovery)});
    await page.getByLabel('Allow account-wide archive decryption for this session',{exact:true}).check();await page.getByRole('button',{name:'Unlock existing archive for this session',exact:true}).click();
    await page.getByRole('link',{name:'Download public proposal for offline review',exact:true}).waitFor();
    const proposal=Uint8Array.from(await page.evaluate(async()=>Array.from(new Uint8Array(await(await fetch(document.querySelector('a[download="conversation-role5-proposal.bin"]').href)).arrayBuffer()))));
    const unsignedLength=f.predecessor.bytes.length-64+149,offset=proposal.length-unsignedLength-2;assert.equal(new DataView(proposal.buffer).getUint16(offset),unsignedLength);
    const signed=await signFixtureSuccessor02(f,proposal.slice(offset+2));
    await page.getByLabel('Root-signed manifest returned by offline custodian',{exact:true}).setInputFiles({name:'signed-successor.bin',mimeType:'application/octet-stream',buffer:Buffer.from(signed)});
    await page.waitForFunction(()=>document.getElementById('status').textContent==='Conversation authorized for this session.');assert.equal(installs,1);assert.ok(bootstrapVersions.includes((f.predecessor.version+1n).toString()));
    const expiry=BigInt(Date.now()+300000);await page.locator('#facts-context').fill(uuid(contextId));await page.locator('#facts-expires').fill(expiry.toString());await page.locator('#facts-open').click();
    await page.getByRole('textbox',{name:'Facts',exact:true}).waitFor();await page.getByRole('textbox',{name:'Facts',exact:true}).fill(canary);
    if(mode==='scope')await page.locator('#owner-peer').fill('+13');
    if(mode==='scope'){await page.waitForFunction(()=>document.querySelector('[aria-label="Facts"]').disabled);assert.equal(posts,0);continue;}
    await page.getByRole('button',{name:'Review facts',exact:true}).click();await page.getByRole('button',{name:'Save encrypted facts',exact:true}).waitFor();await page.waitForFunction(()=>!Array.from(document.querySelectorAll('button')).find(b=>b.textContent==='Save encrypted facts').disabled);
    assert.equal(await page.locator('#facts-editor pre').textContent(),canary);assert.equal(posts,0);
    if(mode==='clear-review'||mode==='pagehide'||mode==='expiry'){
     if(mode==='clear-review')await page.locator('#clear').click();else if(mode==='pagehide')await page.evaluate(()=>window.dispatchEvent(new Event('pagehide')));else await page.waitForFunction(()=>document.querySelector('[aria-label="Facts"]').disabled,{},{timeout:12000});
     assert.equal(posts,0);assert.equal(await page.getByRole('textbox',{name:'Facts',exact:true}).inputValue(),'');assert.equal(await page.locator('#facts-editor pre').count(),0);continue;
    }
    if(mode==='csrf')await context.addCookies([{name:'__Host-zrotext_csrf',value:'changed-facts-review',url:f.origin,secure:true,sameSite:'Strict'}]);
    await page.getByRole('button',{name:'Save encrypted facts',exact:true}).click();
    if(mode==='csrf'){await page.waitForFunction(()=>document.querySelector('[aria-label="Facts"]').disabled);assert.equal(posts,0);assert.equal(await page.getByRole('textbox',{name:'Facts',exact:true}).inputValue(),'');continue;}
    if(mode==='late'){
     await page.waitForFunction(()=>Array.from(document.querySelectorAll('button')).find(b=>b.textContent==='Save encrypted facts').disabled);while(!heldReply)await new Promise(resolve=>setTimeout(resolve,10));
     await page.locator('#clear').click();const text=await page.locator('#facts-status').textContent();heldReply();await page.waitForTimeout(50);assert.equal(await page.locator('#facts-status').textContent(),text);assert.equal(await page.locator('#facts-open').isDisabled(),true);assert.ok(!await page.locator('#facts-editor').textContent().then(t=>t.includes('saved and current')));continue;
    }
    if(mode==='conflict'){await page.waitForFunction(()=>document.getElementById('facts-editor').textContent.includes('Save refused'));assert.equal(posts,1);continue;}
    if(mode==='unknown'||mode==='unknown-close'||mode==='editor-close'){
     await page.waitForFunction(()=>document.getElementById('facts-editor').textContent.includes('Save outcome unknown'));
     const original=requests.find(r=>r.url==='/v1/owner/workflow/contexts'&&r.method==='POST');
     if(mode==='unknown-close'||mode==='editor-close'){
      if(mode==='unknown-close')await page.locator('#clear').click();else await page.locator('#facts-editor').getByRole('button',{name:'Clear',exact:true}).click();
      await page.waitForFunction(()=>document.getElementById('facts-status').textContent.includes('Save outcome unknown'));assert.ok((await page.locator('#facts-status').textContent()).includes(original.headers['idempotency-key']));assert.equal(await page.locator('#connect').isDisabled(),true);assert.equal(await page.getByRole('button',{name:'Retry same save',exact:true}).isDisabled(),true);
      // Dispatch also exercises the handler guard independently of disabled UI.
      await page.evaluate(()=>document.getElementById('facts-open').dispatchEvent(new Event('click')));await page.waitForTimeout(100);
      assert.equal(await page.locator('#facts-editor section').count(),1);assert.equal(posts,1);continue;
     }
     await page.getByRole('button',{name:'Check saved facts',exact:true}).click();await page.waitForFunction(()=>!Array.from(document.querySelectorAll('button')).find(b=>b.textContent==='Retry same save').disabled);assert.equal(posts,1);
     await page.getByRole('button',{name:'Retry same save',exact:true}).click();
     await page.waitForFunction(()=>document.getElementById('facts-editor').textContent.includes('saved and current'));const attempts=requests.filter(r=>r.url==='/v1/owner/workflow/contexts'&&r.method==='POST');assert.equal(attempts.length,2);assert.deepEqual(attempts[0].body,attempts[1].body);assert.equal(attempts[0].headers['idempotency-key'],attempts[1].headers['idempotency-key']);
    }else await page.waitForFunction(()=>document.getElementById('facts-editor').textContent.includes('saved and current'));
    await page.waitForFunction(()=>document.getElementById('facts-status').textContent==='Encrypted facts saved. Currentness was checked when saved.');
    f.state.current={...f.state.current,manifest,nowMs:BigInt(Date.now())};const lease=await unlockExistingArchive02(f.options);
    try{const expected={kind:1,accountId:binding.account,deviceId:binding.device,lineId:binding.line,intervalId:binding.interval,contextId,bindingGeneration:1n,revision:1n,expiresMs:expiry,trustGeneration:1n,manifestVersion:manifest.version,peerDigest:new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(binding.peer))),readerId:binding.archiveReader,manifestDigest:manifest.digest};const plain=await lease.withKey(binding,key=>openWorkflowContext(manifest,expected,BigInt(Date.now()),key,new Uint8Array(head)));assert.equal(new TextDecoder().decode(plain),canary);plain.fill(0);}finally{lease.close();}
    assert.equal(await page.getByRole('textbox',{name:'Facts',exact:true}).inputValue(),'');assert.equal(await page.locator('#facts-editor pre').count(),0);assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);assert.equal(await page.evaluate(()=>document.cookie.includes('__Host-zrotext_session')),false);assert.equal(await page.locator('#facts-open').isDisabled(),true);
   }finally{heldReply?.();f.controller.abort();await context.close();}
  }
 }finally{await browser?.close();assert.equal(path.dirname(await realpath(assets)),await realpath(os.tmpdir()));await rm(assets,{recursive:true,maxRetries:3,retryDelay:50});}
});
