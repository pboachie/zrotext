// SPDX-License-Identifier: AGPL-3.0-only
// Isolated module with authentic SDK crypto and synthetic browser routes/lifecycle.
// No ordinary setup override is installed; the real page is not integrated here.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createRequire} from 'node:module';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {refreshFixture,signFixtureSuccessor02} from './conversation-refresh-fixture.mjs';
import {verifiedManifestTrust02} from '../dist/draft02-manifest.js';
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..'),require=createRequire(import.meta.url);
const canary='Synthetic browser owner facts <plain text>';
const serialize=value=>JSON.parse(JSON.stringify(value,(_k,v)=>typeof v==='bigint'?v.toString():v instanceof Uint8Array?Array.from(v):v));

test('actual packaged Chromium facts review saves ciphertext and preserves unknown through explicit checking',async t=>{
  const tooling=path.join(repo,'web/owner/node_modules/playwright');
  if(!existsSync(path.join(tooling,'package.json'))){t.skip('Owner Playwright dependency required; ordinary owner-browser CI installs it');return;}
  const {chromium}=require(tooling),assets=await mkdtemp(path.join(tmpdir(),'owner-facts-browser-'));let browser;
  try{
    const build=spawnSync(process.execPath,[path.join(repo,'scripts/package_conversation_browser.mjs'),assets],{encoding:'utf8',timeout:20000});assert.equal(build.status,0,build.stderr);
    assert.ok((await readFile(path.join(assets,'sdk/owner-context-authoring.js'),'utf8')).includes('createOwnerContextAuthoring'));
    const f=await refreshFixture(),manifest=await signFixtureSuccessor02(f),trust=verifiedManifestTrust02(f.predecessor,f.nowMs);
    browser=await chromium.launch({headless:true});
    for(const mode of ['save','conflict','unknown','archive','pagehide','head-changed','latest-close']){
      const context=await browser.newContext();let posts=0,head,releaseLatest;const requests=[];
      try{
        await context.addCookies([{name:'__Host-zrotext_session',value:'synthetic-facts-session',url:f.origin,httpOnly:true,secure:true,sameSite:'Strict'},
          {name:'__Host-zrotext_csrf',value:'synthetic-facts-csrf',url:f.origin,secure:true,sameSite:'Strict'}]);
        await context.route(f.origin+'/**',async route=>{
          const request=route.request(),url=new URL(request.url());
          if(url.pathname.startsWith('/assets/')){const target=path.resolve(assets,url.pathname.slice(8));assert.ok(target.startsWith(assets+path.sep));await route.fulfill({contentType:'text/javascript',body:await readFile(target)});return;}
          if(url.pathname.startsWith('/v1/owner/workflow/contexts')){
            const headers=await request.allHeaders(),body=request.postDataBuffer();requests.push({method:request.method(),url:request.url(),headers,body});
            assert.ok(headers.cookie.includes('__Host-zrotext_session=synthetic-facts-session'));assert.equal(headers['x-zrotext-csrf'],'synthetic-facts-csrf');assert.equal(headers.authorization,undefined);
            if(request.method()==='POST'){
              posts++;head=body;assert.equal(headers.origin,f.origin);assert.equal(headers['x-zrotext-context-revision'],'0');assert.equal(body.includes(Buffer.from(canary)),false);
              if(mode==='conflict')await route.fulfill({status:409,body:''});else if(mode==='unknown'&&posts===1)await route.fulfill({status:503,body:''});else await route.fulfill({contentType:'application/json',body:'{"revision":1}'});
            }else{assert.equal(url.search,'');if(mode==='latest-close')await new Promise(resolve=>releaseLatest=resolve);const latest=Buffer.from(head);if(mode==='head-changed')latest[latest.length-1]^=1;await route.fulfill({contentType:'application/vnd.zrotext.workflow-context.v1',body:latest});}return;
          }
          await route.fulfill({contentType:'text/html',body:'<!doctype html><main id="facts"></main>'});
        });
        const page=await context.newPage();await page.goto(f.origin);
        await page.evaluate(async config=>{
          const {verifyManifest02}=await import('/assets/sdk/draft02-manifest.js'),{createOwnerContextAuthoring}=await import('/assets/sdk/owner-context-authoring.js');
          const binding={...config.binding,generation:BigInt(config.binding.generation)},trust={...config.trust,generation:BigInt(config.trust.generation),version:BigInt(config.trust.version)};
          for(const k of ['account','device','line','interval','session','phoneReader','archiveReader'])binding[k]=Uint8Array.from(binding[k]);
          for(const k of ['accountId','rootPoint','digest','anchorDigest'])trust[k]=Uint8Array.from(trust[k]);
          const now=BigInt(config.now),manifest=await verifyManifest02(Uint8Array.from(config.manifest),trust,now),listeners={setup:[],custody:[],archive:[]};
          window.factControls={listeners};window.factAuthor=createOwnerContextAuthoring({enabled:true,origin:location.origin,host:document.querySelector('#facts'),binding,contextId:new Uint8Array(16).fill(6),expiresMs:now+300000n,
            readCurrent:async()=>({binding,manifest,nowMs:now,ownerSessionLive:true,consentLive:true}),currentCsrf:()=>document.cookie.split('; ').find(v=>v.startsWith('__Host-zrotext_csrf='))?.split('=')[1],
            archiveLease:{onClose:listener=>{listeners.archive.push(listener);return()=>{};},withKey:()=>{throw Error('No key access');},close:()=>{}},onSetupClose:listener=>{listeners.setup.push(listener);},onCustodyClose:listener=>{listeners.custody.push(listener);},signal:new AbortController().signal,timeoutMs:4000,observationMs:4000});
        },{binding:serialize(f.review.binding),trust:serialize(trust),manifest:Array.from(manifest),now:f.nowMs.toString()});
        assert.equal(await page.evaluate(()=>factAuthor.savedSource()),null);
        await page.getByRole('textbox',{name:'Facts',exact:true}).fill(canary);await page.getByRole('button',{name:'Review facts',exact:true}).click();
        await page.waitForFunction(()=>factAuthor.state().phase==='review');assert.equal(posts,0);
        assert.equal(await page.evaluate(()=>factAuthor.savedSource()),null);
        assert.equal(await page.getByRole('region',{name:'Owner facts'}).locator('pre').textContent(),canary);
        assert.equal(await page.locator('pre not-markup').count(),0);
        if(mode==='archive'||mode==='pagehide'){
          await page.evaluate(mode=>{if(mode==='archive')factControls.listeners.archive.forEach(run=>run());else window.dispatchEvent(new Event('pagehide'));},mode);
          await page.waitForFunction(()=>factAuthor.state().phase==='closed');assert.equal(posts,0);
        }else{
          await page.getByRole('button',{name:'Save encrypted facts',exact:true}).click();
          if(mode==='latest-close'){
            await page.waitForFunction(()=>factAuthor.state().phase==='saving');
            for(let n=0;n<300&&!releaseLatest;n++)await new Promise(resolve=>setTimeout(resolve,5));assert.ok(releaseLatest);
            assert.equal(await page.evaluate(()=>factAuthor.savedSource()),null);await page.evaluate(()=>factAuthor.close());releaseLatest();
            await page.waitForFunction(()=>factAuthor.state().phase==='closed');assert.equal(await page.evaluate(()=>factAuthor.savedSource()),null);
          }else await page.waitForFunction(()=>['saved','unknown','refused'].includes(factAuthor.state().phase));
          if(mode==='save'){assert.equal(await page.evaluate(()=>factAuthor.state().phase),'saved');assert.equal(requests.length,2);assert.equal(new DataView(head.buffer,head.byteOffset).getBigUint64(118),f.predecessor.version+1n);}
          if(mode==='conflict'||mode==='head-changed'){assert.equal(await page.evaluate(()=>factAuthor.state().phase),'refused');assert.equal(await page.evaluate(()=>factAuthor.savedSource()),null);}
          if(mode==='unknown'){
            const pending=await page.evaluate(()=>factAuthor.state().pending);assert.ok(pending);
            assert.equal(await page.evaluate(()=>factAuthor.savedSource()),null);
            await page.getByRole('button',{name:'Check saved facts',exact:true}).click();await page.waitForFunction(()=>factAuthor.state().phase==='unknown');assert.deepEqual(await page.evaluate(()=>factAuthor.state().pending),pending);assert.equal(posts,1);
            assert.equal(await page.evaluate(()=>factAuthor.savedSource()),null);
            await page.getByRole('button',{name:'Retry same save',exact:true}).click();await page.waitForFunction(()=>factAuthor.state().phase==='saved');assert.equal(posts,2);
            const sent=requests.filter(v=>v.method==='POST');assert.deepEqual(sent[0].body,sent[1].body);assert.equal(sent[0].headers['idempotency-key'],sent[1].headers['idempotency-key']);
          }
          if(mode==='save'||mode==='unknown'){
            const count=requests.length,source=await page.evaluate(()=>{const first=factAuthor.savedSource(),second=factAuthor.savedSource();if(!first||!second)throw Error('Acknowledged source missing');if(!Object.isFrozen(first)||!Object.isFrozen(first.receipt)||first===second||first.receipt===second.receipt)throw Error('Source copy boundary missing');return first;});
            assert.equal(source.accountId,Buffer.from(f.review.binding.account).toString('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5'));
            const post=requests.find(v=>v.method==='POST');assert.deepEqual(source.receipt,{requestId:post.headers['idempotency-key'],contextId:'06060606-0606-0606-0606-060606060606',revision:1,envelopeDigest:createHash('sha256').update(post.body).digest('hex'),state:'verified_current_snapshot',requestAcknowledged:true});assert.deepEqual(Object.keys(source).sort(),['accountId','receipt']);assert.equal(requests.length,count);
          }
        }
        assert.equal(await page.getByRole('textbox',{name:'Facts',exact:true}).inputValue(),'');assert.equal(await page.locator('pre').count(),0);
        assert.equal(await page.evaluate(()=>document.cookie.includes('__Host-zrotext_session')),false);assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);
        await page.evaluate(()=>factAuthor.close());
        assert.equal(await page.evaluate(()=>factAuthor.savedSource()),null);
      }finally{await context.close();}
    }
  }finally{await browser?.close();await rm(assets,{recursive:true,force:true});}
});
