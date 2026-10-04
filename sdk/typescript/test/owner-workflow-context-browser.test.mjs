// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic HTTPS routes exercise the actual packaged SDK and browser cookie transport.
// This is not a mounted server, owner enrollment, device or application acceptance test.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createRequire} from 'node:module';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {refreshFixture} from './conversation-refresh-fixture.mjs';
import {verifiedManifestTrust02} from '../dist/draft02-manifest.js';
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const require=createRequire(import.meta.url);

test('owner context module is included in the maintained browser package',async()=>{
  const assets=await mkdtemp(path.join(tmpdir(),'owner-context-package-'));
  try{
    const built=spawnSync(process.execPath,[path.join(repo,'scripts/package_conversation_browser.mjs'),assets],{encoding:'utf8',timeout:20000});
    assert.equal(built.status,0,built.stderr);
    const source=await readFile(path.join(assets,'sdk/owner-workflow-context-client.js'),'utf8');
    assert.ok(source.includes('export class OwnerWorkflowContextClient'));
    assert.ok(!source.includes('node:')&&!source.includes('require('));
    // Node-only import fallbacks in the maintained HPKE graph must remain removed.
    assert.ok(!(await readFile(path.join(assets,'vendor/common/src/algorithm.js'),'utf8')).includes('import("crypto")'));
  }finally{await rm(assets,{recursive:true,force:true});}
});

test('Chromium uses same-origin owner cookies CSRF and refuses actual bare conflict',async t=>{
  const tooling=path.join(repo,'web/owner/node_modules/playwright');
  if(!existsSync(path.join(tooling,'package.json'))){t.skip('Rendered owner Playwright dependency required; ordinary owner-browser CI installs it before SDK tests');return;}
  const {chromium}=require(tooling);
  const assets=await mkdtemp(path.join(tmpdir(),'owner-context-browser-'));
  let browser,context;
  try{
    const built=spawnSync(process.execPath,[path.join(repo,'scripts/package_conversation_browser.mjs'),assets],{encoding:'utf8',timeout:20000});assert.equal(built.status,0,built.stderr);
    const f=await refreshFixture(),trust=verifiedManifestTrust02(f.predecessor,f.nowMs);
    const serialize=value=>JSON.parse(JSON.stringify(value,(_key,v)=>typeof v==='bigint'?v.toString():v instanceof Uint8Array?Array.from(v):v));
    browser=await chromium.launch({headless:true});context=await browser.newContext();
    await context.addCookies([{name:'__Host-zrotext_session',value:'synthetic-owner-session',url:f.origin,httpOnly:true,secure:true,sameSite:'Strict'},
      {name:'__Host-zrotext_csrf',value:'synthetic-browser-csrf',url:f.origin,secure:true,sameSite:'Strict'}]);
    let head,posts=0;const requests=[],responses=[];
    context.on('response',response=>{if(new URL(response.url()).pathname.startsWith('/v1/'))responses.push({url:response.url(),status:response.status(),type:response.headers()['content-type']});});
    await context.route(f.origin+'/**',async route=>{
      const request=route.request(),url=new URL(request.url());
      if(url.pathname.startsWith('/assets/')){
        const relative=url.pathname.slice('/assets/'.length),target=path.resolve(assets,relative);
        assert.ok(target.startsWith(assets+path.sep));await route.fulfill({contentType:'text/javascript',body:await readFile(target)});return;
      }
      if(url.pathname.startsWith('/v1/owner/workflow/contexts')){
        const headers=await request.allHeaders();requests.push({method:request.method(),url:request.url(),headers});
        assert.ok(headers.cookie.includes('__Host-zrotext_session=synthetic-owner-session'));
        assert.ok(headers.cookie.includes('__Host-zrotext_csrf=synthetic-browser-csrf'));
        assert.equal(headers['x-zrotext-csrf'],'synthetic-browser-csrf');assert.equal(headers.authorization,undefined);
        if(request.method()==='POST'){
          assert.equal(headers.origin,f.origin);posts++;
          assert.equal(headers['x-zrotext-context-revision'],posts===1?'0':'1');
          if(posts===1){head=request.postDataBuffer();await route.fulfill({contentType:'application/json',body:'{"revision":1}'});}
          else await route.fulfill({status:posts===2?409:503,body:''});
        }else{assert.equal(url.search,'');await route.fulfill({contentType:'application/vnd.zrotext.workflow-context.v1',body:head});}
        return;
      }
      await route.fulfill({contentType:'text/html',body:'<!doctype html><title>Synthetic owner transport fixture</title>'});
    });
    const page=await context.newPage();await page.goto(f.origin);
    const result=await page.evaluate(async ({binding:raw,trust:anchor,manifest:encoded,now})=>{
      const {verifyManifest02}=await import('/assets/sdk/draft02-manifest.js');
      const {sealWorkflowContext}=await import('/assets/sdk/workflow-context.js');
      const {OwnerWorkflowContextClient}=await import('/assets/sdk/owner-workflow-context-client.js');
      const binding={...raw,generation:BigInt(raw.generation)};
      for(const key of ['account','device','line','interval','session','phoneReader','archiveReader'])binding[key]=Uint8Array.from(binding[key]);
      const trust={...anchor,generation:BigInt(anchor.generation),version:BigInt(anchor.version)};
      for(const key of ['accountId','rootPoint','digest','anchorDigest'])trust[key]=Uint8Array.from(trust[key]);
      const time=BigInt(now),manifest=await verifyManifest02(Uint8Array.from(encoded),trust,time),controller=new AbortController();
      const scope={kind:1,accountId:binding.account,deviceId:binding.device,lineId:binding.line,intervalId:binding.interval,contextId:new Uint8Array(16).fill(6),bindingGeneration:binding.generation,revision:1n,expiresMs:time+300000n,trustGeneration:manifest.generation,manifestVersion:manifest.version,peerDigest:new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(binding.peer))),readerId:binding.archiveReader,manifestDigest:manifest.digest};
      let reviews=0;
      const client=new OwnerWorkflowContextClient({enabled:true,origin:location.origin,selection:{binding,contextId:scope.contextId,kind:1},readCurrent:async()=>({binding,manifest,nowMs:time,ownerSessionLive:true,consentLive:true,phase:'active',validForMs:60000}),currentCsrf:()=>document.cookie.split('; ').find(v=>v.startsWith('__Host-zrotext_csrf='))?.split('=')[1],consumeWriteReview:async()=>{reviews++;},signal:controller.signal});
      const envelope=await sealWorkflowContext(manifest,scope,time,new TextEncoder().encode('Synthetic browser private context'));
      let receipt;
      try{receipt=await client.commit(await client.prepare({requestId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',expectedRevision:0,scope,envelope}));}catch(e){return {failure:{code:e.code,state:e.state}};}
      const next={...scope,revision:2n},cipher=await sealWorkflowContext(manifest,next,time,new TextEncoder().encode('Synthetic revised private context'));
      let conflict,unknown;
      try{await client.commit(await client.prepare({requestId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',expectedRevision:1,scope:next,envelope:cipher}));}catch(e){conflict={code:e.code,state:e.state};}
      try{await client.commit(await client.prepare({requestId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',expectedRevision:1,scope:next,envelope:cipher}));}catch(e){unknown={code:e.code,state:e.state};}
      const pending=client.pending();controller.abort();
      return {receipt,conflict,unknown,pending,closedPending:client.pending(),reviews,sessionVisible:document.cookie.includes('__Host-zrotext_session'),storage:localStorage.length+sessionStorage.length};
    },{binding:serialize(f.review.binding),trust:serialize(trust),manifest:Array.from(f.predecessor.bytes),now:f.nowMs.toString()});
    assert.equal(result.failure,undefined,JSON.stringify({result,responses,requests:requests.map(r=>({method:r.method,url:r.url}))}));
    assert.equal(result.receipt.state,'verified_current_snapshot');assert.equal(result.receipt.requestAcknowledged,true);
    assert.deepEqual(result.conflict,{code:'conflict',state:'refused'});assert.deepEqual(result.unknown,{code:'response_unknown',state:'unknown'});
    assert.deepEqual(result.closedPending,result.pending);assert.ok(result.pending);assert.equal(result.reviews,3);
    assert.equal(result.sessionVisible,false);assert.equal(result.storage,0);assert.equal(requests.length,4);
  }finally{await context?.close();await browser?.close();await rm(assets,{recursive:true,force:true});}
});
