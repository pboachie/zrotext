// SPDX-License-Identifier: AGPL-3.0-only
// Actual Chromium DOM/cookies; the HTTPS peer below is synthetic, not DB acceptance.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),{chromium}=require('playwright');
const origin='https://review.example.test',id=n=>'10000000-0000-4000-8000-'+n.toString(16).padStart(12,'0');
const csrfValue=n=>Buffer.alloc(32,n).toString('base64url'),b64=n=>Buffer.alloc(32,n).toString('base64');
const headers={'content-type':'application/json','cache-control':'no-store','content-security-policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"};
async function waitForStage(promise){
 let timer;
 try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Review stage was not reached')),5000);})]);}
 finally{clearTimeout(timer);}
}
async function fixture(browser,{losePrepare=false,holdWorkspace=false}={}){
 const ctx=await browser.newContext({serviceWorkers:'block',viewport:{width:360,height:800}}),calls=[],errors=[];
 let prep,retained=false,releaseWorkspace,enteredWorkspace;
 const entered=new Promise(r=>enteredWorkspace=r),released=new Promise(r=>releaseWorkspace=r);
 async function set(name,value,httpOnly=false){await ctx.addCookies([{name,value,url:origin,secure:true,httpOnly,sameSite:'Strict'}]);}
 const operation=(body,state)=>({version:1,request_id:body.request_id,preparation_id:prep.preparation_id,generation:'1',state,create_deadline_ms:'1300000',delivery_deadline_ms:'1600000',server_now_ms:'1000000'});
 await ctx.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());assert.equal(url.origin,origin);
  if(url.pathname.startsWith('/review/')){
   const name=url.pathname.slice('/review/'.length),file=name==='root'?'root.html':name;
   assert.ok(['root.html','root.css','root.mjs','root-material.mjs','single-flight.mjs'].includes(file));
   return route.fulfill({status:200,body:await readFile(new URL('../../review/'+file,import.meta.url)),headers:{...headers,'content-type':file.endsWith('.html')?'text/html':file.endsWith('.css')?'text/css':'text/javascript'}});
  }
  assert.equal(req.method(),'POST');assert.equal(req.headers().origin,origin);
  const path=url.pathname.replace('/v1/review/',''),body=req.postDataJSON();calls.push({path,body});let value;
  switch(path){
   case 'browser/prepare':case 'browser/confirm':
    value={version:1,request_id:body.request_id,browser_context_commitment_b64:b64(4),issued_ms:'900000',expires_ms:'1600000',server_now_ms:'1000000',outstanding:null,owner_session_issued:false};break;
   case 'preparations':
    prep={request_id:body.request_id,preparation_id:id(200)};
    await set('__Host-ztrw-c-'+id(200).replaceAll('-',''),csrfValue(1));
    await set('__Host-ztrw-p-'+id(200).replaceAll('-',''),'synthetic-private-preparation',true);
    await set('__Host-ztrw-l-'+id(200).replaceAll('-',''),'synthetic-private-selector',true);
    if(losePrepare){losePrepare=false;return route.abort('connectionreset');}
    value=operation(body,'prepared');break;
   case 'preparations/confirm':value=operation(body,'confirmed');break;
   case 'preparations/status':assert.equal(body.request_id,prep.request_id);value=operation(body,'prepared');break;
   case 'preparations/cancel':
    for(const prefix of ['p','c','l'])await ctx.clearCookies({name:'__Host-ztrw-'+prefix+'-'+id(200).replaceAll('-','')});
    value=operation(body,'cancelled_no_effect');break;
   case 'login/bootstrap':assert.equal(body.password,'synthetic-review-password');value=operation(body,'committed_known');break;
   case 'login/status':await set('__Host-ztrw-broker-csrf',csrfValue(2));await set('__Host-ztrw-broker','synthetic-private-broker',true);value=operation(body,'committed_known');break;
   case 'workspace/status':
    if(holdWorkspace){enteredWorkspace();await released;}
    await set('__Host-ztrw-owner-csrf',csrfValue(3));await set('__Host-ztrw-owner','synthetic-private-owner',true);value=operation(body,'committed_known');break;
   case 'session/confirm':
    for(const prefix of ['p','c'])await ctx.clearCookies({name:'__Host-ztrw-'+prefix+'-'+id(200).replaceAll('-','')});
    value=operation(body,'committed_known');break;
   case 'session/context':
    value={version:1,request_id:body.request_id,realm:id(30),database_commitment_b64:b64(5),config_digest_b64:b64(6),config_revision:'1',origin,
     account:id(1),owner_user:id(2),review_owner_session:id(3),broker_principal:id(5),credential_id:id(6),credential_revision:'1',broker_session:id(7),auth_event:id(8),
     issued_ms:'900000',absolute_expiry_ms:'1600000',idle_deadline_ms:'1500000',server_now_ms:'1000000',capabilities:['bootstrap_session','root_issue','root_complete','root_receipt','root_custody_export'],locator_retained:retained,root_state:{kind:'no_root_history'}};break;
   default:throw Error('Unexpected review request '+path);
  }
  return route.fulfill({status:200,body:JSON.stringify(value),headers});
 });
 const page=await ctx.newPage();page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(5000);
 await page.goto(origin+'/review/root');
 try{await page.waitForFunction(()=>!document.querySelector('#login button').disabled);}
 catch(error){const detail={errors,status:await page.locator('#status').textContent(),requests:calls.map(c=>c.path)};await ctx.close();throw Error(JSON.stringify(detail),{cause:error});}
 const login=async()=>{await page.locator('#alias').fill('pilot');await page.locator('#password').fill('synthetic-review-password');await page.locator('#login button').click();};
 return {ctx,page,calls,errors,login,entered,releaseWorkspace,retain:async()=>{retained=true;await ctx.clearCookies({name:'__Host-ztrw-l-'+id(200).replaceAll('-','')});}};
}

test('rendered review page keeps native pause over the whole sign-in chain and gates root on retained locator',{timeout:20000},async()=>{
 const browser=await chromium.launch({headless:true});let f;
 try{
  f=await fixture(browser,{holdWorkspace:true});await f.login();await waitForStage(f.entered);
  const pause=id(90);
  assert.deepEqual(await f.page.evaluate(p=>{document.getElementById('reauth-password').value='discard-on-pause';return {accepted:window.ZrotextReviewRoot.requestPause(p),state:window.ZrotextReviewRoot.pauseStatus(p).state,loginInput:document.getElementById('password').value,reauthInput:document.getElementById('reauth-password').value};},pause),{accepted:true,state:'waiting',loginInput:'',reauthInput:''});
  assert.equal(await f.page.evaluate(p=>window.ZrotextReviewRoot.resume(p),pause),false);
  f.releaseWorkspace();await f.page.waitForFunction(p=>window.ZrotextReviewRoot.pauseStatus(p)?.state==='paused',pause);
  await f.page.locator('#workspace').waitFor({state:'visible'});
  assert.equal(await f.page.locator('#account').textContent(),id(1));assert.equal(await f.page.locator('#issue button').isDisabled(),true);
  const visibleCookies=await f.page.evaluate(()=>document.cookie);
  assert.match(visibleCookies,/__Host-ztrw-owner-csrf=/);assert.doesNotMatch(visibleCookies,/__Host-ztrw-(?:owner|broker)=|__Host-ztrw-[pl]-/);
  await f.retain();assert.equal(await f.page.evaluate(p=>window.ZrotextReviewRoot.resume(p),id(91)),false);
  assert.equal(await f.page.evaluate(p=>window.ZrotextReviewRoot.resume(p),pause),true);
  await f.page.waitForFunction(()=>!document.querySelector('#issue button').disabled);
  assert.equal(await f.page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
  assert.equal(f.calls.filter(c=>c.path==='preparations').length,1);assert.equal(f.calls.filter(c=>c.path==='login/bootstrap').length,1);
  assert.deepEqual(f.errors,[]);
 }finally{if(f){f.releaseWorkspace();await f.ctx.close();}await browser.close();}
});

test('rendered lost preparation keeps the original request and requires positive cancellation before new sign-in',{timeout:20000},async()=>{
 const browser=await chromium.launch({headless:true});let f;
 try{
  f=await fixture(browser,{losePrepare:true});await f.login();await f.page.locator('#recovery').waitFor({state:'visible'});
  await f.page.waitForFunction(()=>!document.getElementById('reconcile').disabled);
  assert.equal(await f.page.locator('#password').inputValue(),'');assert.equal(await f.page.locator('#login').isHidden(),true);
  await f.page.locator('#reconcile').click();await f.page.waitForFunction(()=>document.getElementById('status').textContent.includes('retained and unconfirmed'));
  assert.equal(f.calls.filter(c=>c.path==='preparations').length,1);assert.equal(f.calls.filter(c=>c.path==='login/bootstrap').length,0);
  assert.equal(f.calls.find(c=>c.path==='preparations/status').body.request_id,f.calls.find(c=>c.path==='preparations').body.request_id);
  await f.page.locator('#cancel').click();await f.page.waitForFunction(()=>!document.querySelector('#login button').disabled);
  assert.equal(await f.page.locator('#recovery').isHidden(),true);assert.equal((await f.ctx.cookies()).some(c=>/^__Host-ztrw-[pcl]-/.test(c.name)),false);
  assert.deepEqual(f.errors,[]);
 }finally{if(f)await f.ctx.close();await browser.close();}
});
