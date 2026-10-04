// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const https=require('node:https');
const {execFileSync}=require('node:child_process');
const {pathToFileURL}=require('node:url');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'../../..'),sdk=path.join(root,'sdk/typescript');
let browser;
test.before(async()=>{browser=await chromium.launch();});
test.after(async()=>{await browser?.close();});
const serialized=value=>JSON.stringify(value,(_,v)=>typeof v==='bigint'?{bigint:String(v)}:v instanceof Uint8Array?{bytes:Buffer.from(v).toString('hex')}:v);

async function fixture(mode,run){
 const {templateFixture}=await import(pathToFileURL(path.join(sdk,'test/owner-encrypted-template-client.test.mjs')).href);
 const f=await templateFixture(),temporary=await fs.mkdtemp(path.join(os.tmpdir(),'zrotext-template-browser-'));
 let server,context;const posts=[],reads=[],requests=[];let live=true,stored=Uint8Array.from(f.envelope);
 try{
  const {sealEncryptedTemplate}=await import(pathToFileURL(path.join(sdk,'dist/encrypted-template.js')).href);
  const contradictory=mode==='contradictory'?await sealEncryptedTemplate(f.manifest,f.scope,f.nowMs,{template:'Different synthetic stored version',values:{}}):null;
  const key=path.join(temporary,'key.pem'),cert=path.join(temporary,'cert.pem');
  // A unique self-signed synthetic fixture certificate; no production TLS change.
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-subj','/CN=localhost','-days','1'],{stdio:'ignore',timeout:15000});
  const publicFixture={binding:f.binding,scope:f.scope,envelope:f.envelope,manifestBytes:f.manifestBytes,trust:f.trust,nowMs:f.nowMs};
  server=https.createServer({key:await fs.readFile(key),cert:await fs.readFile(cert)},async(req,res)=>{
   try{
    const url=new URL(req.url,'https://localhost');
    if(url.pathname==='/'){
     res.setHeader('content-type','text/html');res.setHeader('Set-Cookie',['__Host-zrotext_session=synthetic-session; Secure; HttpOnly; Path=/; SameSite=Strict','__Host-zrotext_csrf=synthetic-csrf; Secure; Path=/; SameSite=Strict']);
     res.end(`<script type="importmap">${JSON.stringify({imports:{'@hpke/core':'/vendor/core/mod.js','@hpke/common':'/vendor/common/mod.js'}})}</script><script type="module">
      import {OwnerEncryptedTemplateClient} from '/modules/owner-encrypted-template-client.js';
      import {verifyManifest02} from '/modules/draft02-manifest.js';
      const data=JSON.parse(${JSON.stringify(serialized(publicFixture))},(_,v)=>v&&v.bigint?BigInt(v.bigint):v&&v.bytes?Uint8Array.from(v.bytes.match(/../g),s=>parseInt(s,16)):v);
      const manifest=await verifyManifest02(data.manifestBytes,data.trust,data.nowMs);
      window.createTemplateClient=(timeoutMs=10000)=>new OwnerEncryptedTemplateClient({enabled:true,origin:location.origin,binding:data.binding,templateId:data.scope.templateId,signal:new AbortController().signal,timeoutMs,
       currentCsrf:()=>document.cookie.split('; ').find(v=>v.startsWith('__Host-zrotext_csrf=')).split('=')[1],
       readCurrent:async()=>{const current=await fetch('/fixture/current',{credentials:'same-origin',cache:'no-store'}).then(r=>r.json());return {binding:data.binding,manifest,nowMs:data.nowMs,ownerSessionLive:current.live,consentLive:true,phase:'active',validForMs:60000};},
       consumeCiphertextReview:async review=>{window.review={requestId:review.requestId,revision:String(review.scope.revision),digest:review.encryptedDigest};}});
      window.templateWrite=()=>({requestId:'00000000-0000-0000-0000-000000000009',expectedRevision:0,scope:data.scope,envelope:data.envelope});window.ready=true;
     </script>`);return;
    }
    if(url.pathname.startsWith('/modules/')||url.pathname.startsWith('/vendor/')){
     let base,relative;
     if(url.pathname.startsWith('/modules/')){base=path.join(sdk,'dist');relative=url.pathname.slice(9);}
     else{const parts=url.pathname.slice(8).split('/');const selected=parts.shift();if(!['core','common'].includes(selected)){res.writeHead(404).end();return;}base=path.join(sdk,'node_modules/@hpke',selected,'esm');relative=parts.join('/');}
     if(!relative||relative.split('/').some(p=>p==='..'||p===''||!/^[-A-Za-z0-9_.]+$/.test(p))||!relative.endsWith('.js')){res.writeHead(404).end();return;}
     res.setHeader('content-type','application/javascript');res.end(await fs.readFile(path.join(base,relative)));return;
    }
    requests.push({method:req.method,path:url.pathname,cookie:req.headers.cookie??'',csrf:req.headers['x-zrotext-csrf']});
    if(!(req.headers.cookie??'').includes('__Host-zrotext_session=synthetic-session')){res.writeHead(401).end();return;}
    if(url.pathname==='/fixture/current'){res.setHeader('content-type','application/json');res.end(JSON.stringify({live}));return;}
    if(req.method==='POST'&&url.pathname==='/v1/owner/workflow/templates'){
     if(req.headers['x-zrotext-csrf']!=='synthetic-csrf'){res.writeHead(403).end();return;}
     const chunks=[];for await(const chunk of req)chunks.push(chunk);const body=Buffer.concat(chunks);
     posts.push({id:req.headers['idempotency-key'],revision:req.headers['x-zrotext-template-revision'],body});stored=Uint8Array.from(body);
     if(mode.startsWith('hidden-')){if(posts.length===1){res.socket.destroy();return;}res.writeHead(Number(mode.slice(7))).end();return;}
     // Persist, then refuse acknowledgement deterministically. Chromium may
     // retry an empty socket response itself, obscuring that boundary.
     if(['unknown','contradictory','unknown-401','unknown-403'].includes(mode)&&posts.length===1){res.writeHead(503).end();return;}
     if(mode.startsWith('unknown-')&&posts.length===2){res.writeHead(Number(mode.slice(8))).end();return;}if(mode==='revoked')live=false;
     res.setHeader('content-type','application/json');res.setHeader('cache-control','no-store');res.end('{"revision":1}');return;
    }
    if(req.method==='GET'&&url.pathname.startsWith('/v1/owner/workflow/templates/')){
     reads.push(url.pathname);res.setHeader('content-type','application/vnd.zrotext.workflow-template.v1');res.setHeader('cache-control','no-store');
     if(mode==='deadline'){res.write(Buffer.from(stored.slice(0,64)));return;}res.end(Buffer.from(contradictory??stored));return;
    }
    res.writeHead(404).end();
   }catch{if(!res.headersSent)res.writeHead(500);res.end();}
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'localhost',resolve);});
  context=await browser.newContext({ignoreHTTPSErrors:true});const page=await context.newPage();const failures=[];page.on('pageerror',e=>failures.push(e.message));
  await page.goto(`https://localhost:${server.address().port}`);await page.waitForFunction(()=>window.ready,{},{timeout:10000});assert.deepEqual(failures,[]);
  await run({page,posts,reads,requests,envelope:f.envelope});
 }finally{
  await context?.close();if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}await fs.rm(temporary,{recursive:true,force:true});
 }
}

test('Chromium owner template persistence sends exact opaque bytes with real same-origin cookies and CSRF',async()=>fixture('positive',async({page,posts,reads,requests,envelope})=>{
 const result=await page.evaluate(async()=>{const c=createTemplateClient();const t=await c.prepareSave(templateWrite());const ack=await c.commit(t);const read=await c.readLatest();c.close();return {ack,read:{state:read.state,requestAcknowledged:read.requestAcknowledged,revision:String(read.scope.revision)},review:window.review};});
 assert.equal(result.ack.state,'acknowledged_saved_revision');assert.equal(result.read.requestAcknowledged,false);assert.equal(result.read.revision,'1');assert.equal(result.review.revision,'1');assert.equal(posts.length,1);assert.deepEqual(Uint8Array.from(posts[0].body),envelope);assert.equal(posts[0].body.includes(Buffer.from('Synthetic Example')),false);assert.equal(reads.length,1);assert.ok(requests.every(r=>r.cookie.includes('__Host-zrotext_session=synthetic-session')));assert.equal(requests.find(r=>r.method==='POST').csrf,'synthetic-csrf');
}));
test('Chromium ambiguous response preserves unknown identity through matching GET and exact retry',async()=>fixture('unknown',async({page,posts,reads})=>{
 const result=await page.evaluate(async()=>{const c=createTemplateClient();const t=await c.prepareSave(templateWrite());let state;try{await c.commit(t);}catch(e){state=e.state;}const observed=await c.verifyUnknown(t);const pending=!!c.pending();const ack=await c.retryUnknown(t);c.close();return {state,pending,matching:observed.matchesPending,acknowledged:observed.requestAcknowledged,ack:ack.state};});
 assert.deepEqual(result,{state:'unknown',pending:true,matching:true,acknowledged:false,ack:'acknowledged_saved_revision'});assert.equal(posts.length,2);assert.equal(reads.length,1);assert.deepEqual(posts[0],posts[1]);
}));
test('Chromium current owner revocation after POST refuses late acknowledgement',async()=>fixture('revoked',async({page,posts})=>{
 const result=await page.evaluate(async()=>{const c=createTemplateClient();const t=await c.prepareSave(templateWrite());try{await c.commit(t);return {published:true};}catch(e){return {published:false,state:e.state,pending:!!c.pending()};}finally{c.close();}});
 assert.deepEqual(result,{published:false,state:'unknown',pending:true});assert.equal(posts.length,1);
}));
test('Chromium stalled encrypted body obeys absolute deadline and returns no late snapshot',async()=>fixture('deadline',async({page,reads,posts})=>{
 const result=await page.evaluate(async()=>{const c=createTemplateClient(500);const started=performance.now();try{await c.readLatest();return {published:true};}catch{return {published:false,elapsed:performance.now()-started};}finally{c.close();}});
 assert.equal(result.published,false);assert.ok(result.elapsed<2000);assert.equal(reads.length,1);assert.equal(posts.length,0);
}));
test('Chromium contradictory same revision acknowledgement preserves unknown and observed digest',async()=>fixture('contradictory',async({page,posts})=>{
 const result=await page.evaluate(async()=>{const c=createTemplateClient();const t=await c.prepareSave(templateWrite());try{await c.commit(t);}catch{}const first=await c.verifyUnknown(t);const pending=c.pending();let state;try{await c.retryUnknown(t);}catch(e){state=e.state;}const second=await c.verifyUnknown(t);const result={state,pendingUnchanged:JSON.stringify(c.pending())===JSON.stringify(pending),sameObservedDigest:first.encryptedDigest===second.encryptedDigest,matchesPending:second.matchesPending,acknowledged:second.requestAcknowledged};c.close();return result;});
 assert.deepEqual(result,{state:'unknown',pendingUnchanged:true,sameObservedDigest:true,matchesPending:false,acknowledged:false});assert.equal(posts.length,2);assert.deepEqual(posts[0],posts[1]);
}));
for(const status of [401,403])test(`Chromium authorization ${status} after unknown prevents another POST despite stale host claims`,async()=>fixture(`unknown-${status}`,async({page,posts})=>{
 const result=await page.evaluate(async()=>{const c=createTemplateClient();const t=await c.prepareSave(templateWrite());try{await c.commit(t);}catch{}const pending=c.pending();try{await c.retryUnknown(t);}catch{}let state;try{await c.retryUnknown(t);}catch(e){state=e.state;}const result={state,pendingUnchanged:JSON.stringify(c.pending())===JSON.stringify(pending)};c.close();return result;});
 assert.deepEqual(result,{state:'unknown',pendingUnchanged:true});assert.equal(posts.length,2);assert.deepEqual(posts[0],posts[1]);
}));
for(const status of [401,403])test(`Chromium hidden exact retry after durable write into ${status} retains unknown and closes authority`,{timeout:15000},async()=>fixture(`hidden-${status}`,async({page,posts})=>{
 const first=await page.evaluate(async()=>{const c=window.hiddenClient=createTemplateClient();const t=window.hiddenTicket=await c.prepareSave(templateWrite());let state;try{await c.commit(t);}catch(e){state=e.state;}window.hiddenPending=c.pending();return {state,pending:!!window.hiddenPending};});
 assert.deepEqual(first,{state:'unknown',pending:true});assert.equal(posts.length,2);assert.deepEqual(posts[0],posts[1]);
 // Both identical wire writes must belong to commit alone. A manual retry
 // cannot substitute for the browser's invisible retry in this proof.
 const second=await page.evaluate(async()=>{const c=window.hiddenClient;try{let state;try{await c.retryUnknown(window.hiddenTicket);}catch(e){state=e.state;}return {state,pendingUnchanged:JSON.stringify(c.pending())===JSON.stringify(window.hiddenPending)};}finally{c.close();}});
 assert.deepEqual(second,{state:'unknown',pendingUnchanged:true});assert.equal(posts.length,2);assert.deepEqual(posts[0],posts[1]);
}));
