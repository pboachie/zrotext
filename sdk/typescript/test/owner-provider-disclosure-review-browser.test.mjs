// SPDX-License-Identifier: AGPL-3.0-only
// Actual packaged browser/crypto with synthetic owner GETs, not mounted server authorization.
import assert from 'node:assert/strict';
import test from 'node:test';
import {createRequire} from 'node:module';
import {mkdtemp,readFile,rm,realpath} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {archiveFixture} from './conversation-archive-fixture.mjs';
import {sealWorkflowContext} from '../dist/workflow-context.js';
import {verifiedManifestTrust02} from '../dist/draft02-manifest.js';
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..'),require=createRequire(import.meta.url);
const serialize=v=>JSON.parse(JSON.stringify(v,(_k,v)=>typeof v==='bigint'?v.toString():v instanceof Uint8Array?Array.from(v):v));
const facts='Synthetic browser local owner facts <plain text>',body='Synthetic browser disclosure message';
test('actual Chromium archive unlock and HPKE local review use cookie GETs without provider writes',async t=>{
  const tooling=path.join(repo,'web/owner/node_modules/playwright');
  if(!existsSync(path.join(tooling,'package.json'))){t.skip('Owner Playwright dependency required; owner-browser CI installs it');return;}
  const {chromium}=require(tooling),root=await realpath(tmpdir()),assets=await mkdtemp(path.join(root,'provider-local-review-'));let browser;
  try{
    const packaged=spawnSync(process.execPath,[path.join(repo,'scripts/package_conversation_browser.mjs'),assets],{encoding:'utf8',timeout:20000});assert.equal(packaged.status,0,packaged.stderr);
    const f=await archiveFixture(),b=f.options.binding,scope={kind:1,accountId:b.account,deviceId:b.device,lineId:b.line,intervalId:b.interval,contextId:new Uint8Array(16).fill(6),bindingGeneration:b.generation,revision:1n,expiresMs:f.nowMs+300000n,trustGeneration:f.predecessor.generation,manifestVersion:f.predecessor.version,peerDigest:new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(b.peer))),readerId:b.archiveReader,manifestDigest:f.predecessor.digest};
    const envelope=await sealWorkflowContext(f.predecessor,scope,f.nowMs,new TextEncoder().encode(facts)),envelopeDigest=Buffer.from(await crypto.subtle.digest('SHA-256',envelope)).toString('hex');
    const declaration={adapter:'telnyx-sms-v2',organization_id:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',messaging_profile_id:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',sender:'+15550100001',owner_label:'Example',intended_region:'unverified',retention_policy_ref:null,eligibility_policy_ref:null,cost_policy_ref:null};
    const config={configId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',configVersion:1,recordVersion:1},details={config_id:config.configId,config_version:1,record_version:1,state:'draft',acceptance:'unavailable',declaration,unavailable_reasons:['provider_identity_unverified','sender_eligibility_unverified','policy_unaccepted','cost_bound_unavailable']};
    browser=await chromium.launch({headless:true});
    for(const mode of ['review','unmounted','unknown','pagehide']){
      const context=await browser.newContext(),requests=[];try{
        await context.addCookies([{name:'__Host-zrotext_session',value:'synthetic-local-review-session',url:f.origin,httpOnly:true,secure:true,sameSite:'Strict'},
          {name:'__Host-zrotext_csrf',value:'synthetic-local-review-csrf',url:f.origin,secure:true,sameSite:'Strict'}]);
        await context.route(f.origin+'/**',async route=>{
          const request=route.request(),url=new URL(request.url());
          if(url.pathname.startsWith('/assets/')){const target=path.resolve(assets,url.pathname.slice(8));assert.ok(target.startsWith(assets+path.sep));await route.fulfill({contentType:'text/javascript',body:await readFile(target)});return;}
          if(url.pathname.startsWith('/v1/owner/')){
            const headers=await request.allHeaders();requests.push({method:request.method(),url:request.url(),headers});assert.equal(request.method(),'GET');assert.equal(url.search,'');assert.ok(headers.cookie.includes('__Host-zrotext_session=synthetic-local-review-session'));assert.equal(headers['x-zrotext-csrf'],'synthetic-local-review-csrf');assert.equal(headers.authorization,undefined);assert.equal(request.postData(),null);
            if(url.pathname.includes('workflow/contexts'))await route.fulfill({status:mode==='unmounted'?404:200,contentType:'application/vnd.zrotext.workflow-context.v1',body:Buffer.from(envelope)});
            else if(url.pathname.includes('provider-configurations'))await route.fulfill({status:mode==='unknown'?503:200,contentType:'application/json',body:JSON.stringify(details)});
            else assert.fail('Unexpected owner route');return;
          }
          await route.fulfill({contentType:'text/html',body:'<!doctype html><main id="review"></main>'});
        });
        const page=await context.newPage();await page.goto(f.origin);
        await page.evaluate(async c=>{
          const {verifyManifest02}=await import('/assets/sdk/draft02-manifest.js'),{unlockExistingArchive02}=await import('/assets/sdk/conversation-archive-custody.js'),{createOwnerProviderDisclosureReview}=await import('/assets/sdk/owner-provider-disclosure-review.js');
          const binding={...c.binding,generation:BigInt(c.binding.generation)},trust={...c.trust,generation:BigInt(c.trust.generation),version:BigInt(c.trust.version)},scope={...c.scope};
          for(const k of ['account','device','line','interval','session','phoneReader','archiveReader'])binding[k]=Uint8Array.from(binding[k]);
          for(const k of ['accountId','rootPoint','digest','anchorDigest'])trust[k]=Uint8Array.from(trust[k]);
          for(const k of ['accountId','deviceId','lineId','intervalId','contextId','peerDigest','readerId','manifestDigest'])scope[k]=Uint8Array.from(scope[k]);
          for(const k of ['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'])scope[k]=BigInt(scope[k]);
          const now=BigInt(c.now),manifest=await verifyManifest02(Uint8Array.from(c.manifest),trust,now),controller=new AbortController(),current=async()=>({binding,manifest,nowMs:now,ownerSessionLive:true,consentLive:true});
          window.localLease=await unlockExistingArchive02({encrypted:Uint8Array.from(c.encrypted),recovery:Uint8Array.from(c.recovery),binding,origin:location.origin,comparedRootFingerprint:Uint8Array.from(c.fingerprint),untilMs:now+300000n,readCurrent:current,consumeUnlockDecision:async review=>{if(review.capability!=='account-wide archive decryption')throw Error('Synthetic unlock decision missing');},signal:controller.signal});
          window.localReview=createOwnerProviderDisclosureReview({enabled:true,origin:location.origin,host:document.querySelector('#review'),binding,source:{scope,envelopeDigest:c.envelopeDigest},configuration:c.config,archiveLease:localLease,readCurrent:current,currentCsrf:()=>document.cookie.split('; ').find(v=>v.startsWith('__Host-zrotext_csrf='))?.split('=')[1],onSetupClose:()=>()=>{},onCustodyClose:()=>()=>{},signal:controller.signal});
          try{const ticket=await localReview.prepare(c.body);window.reviewResult=localReview.review(ticket).then(result=>({result}),()=>({refused:true}));}catch{window.reviewResult=Promise.resolve({refused:true});}
        },{binding:serialize(b),trust:serialize(verifiedManifestTrust02(f.predecessor,f.nowMs)),manifest:Array.from(f.predecessor.bytes),scope:serialize(scope),now:f.nowMs.toString(),encrypted:Array.from(f.options.encrypted),recovery:Array.from(f.options.recovery),fingerprint:Array.from(f.options.comparedRootFingerprint),envelopeDigest,config,body});
        if(mode==='review'){
          assert.equal(await page.getByRole('region',{name:'Local disclosure review'}).locator('pre').nth(0).textContent(),facts);assert.equal(await page.getByRole('region',{name:'Local disclosure review'}).locator('pre').nth(1).textContent(),body);
          await page.getByRole('button',{name:'Review locally',exact:true}).click();const result=await page.evaluate(()=>reviewResult);assert.equal(result.result.execution,'unavailable');assert.equal(result.result.state,'local_reviewed_unavailable');assert.equal(requests.length,4);
        }else{
          if(mode==='pagehide')await page.evaluate(()=>window.dispatchEvent(new Event('pagehide')));
          assert.equal((await page.evaluate(()=>reviewResult)).refused,true);assert.equal(await page.evaluate(()=>localReview.state().phase),'closed');
        }
        assert.equal(await page.locator('pre').count(),0);assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);assert.equal(await page.evaluate(()=>document.cookie.includes('__Host-zrotext_session')),false);
        await page.evaluate(()=>{localReview.close();localLease.close();});
      }finally{await context.close();}
    }
  }finally{await browser?.close();assert.equal(path.dirname(await realpath(assets)),root);assert.ok(path.basename(assets).startsWith('provider-local-review-'));await rm(assets,{recursive:true,force:true});}
});
