// SPDX-License-Identifier: AGPL-3.0-only
'use strict';
const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),https=require('node:https');
const {execFileSync}=require('node:child_process'),{pathToFileURL}=require('node:url');
const {chromium}=require('playwright');
const root=path.resolve(__dirname,'../../..'),sdk=path.join(root,'sdk/typescript');
let browser;
test.before(async()=>{browser=await chromium.launch();});
test.after(async()=>{await browser?.close();});
const serialized=value=>JSON.stringify(value,(_,v)=>typeof v==='bigint'?{bigint:String(v)}:v instanceof Uint8Array?{bytes:Buffer.from(v).toString('hex')}:v);
async function fixture(mode,run){
 const {templateFixture}=await import(pathToFileURL(path.join(sdk,'test/owner-encrypted-template-client.test.mjs')).href);
 const f=await templateFixture(),temporary=await fs.mkdtemp(path.join(os.tmpdir(),'zrotext-authoring-browser-'));
 let server,context;const posts=[];let live=true;
 try{
  const key=path.join(temporary,'key.pem'),cert=path.join(temporary,'cert.pem');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-subj','/CN=localhost','-days','1'],{stdio:'ignore',timeout:15000});
  const data={binding:f.binding,scope:f.scope,manifestBytes:f.manifestBytes,trust:f.trust,nowMs:f.nowMs};
  server=https.createServer({key:await fs.readFile(key),cert:await fs.readFile(cert)},async(req,res)=>{
   try{
    const url=new URL(req.url,'https://localhost');
    if(url.pathname==='/'){
     res.setHeader('content-type','text/html');res.setHeader('Set-Cookie',['__Host-zrotext_session=synthetic-session; Secure; HttpOnly; Path=/; SameSite=Strict','__Host-zrotext_csrf=synthetic-csrf; Secure; Path=/; SameSite=Strict']);
     res.end(`<script type="importmap">${JSON.stringify({imports:{'@hpke/core':'/vendor/core/mod.js','@hpke/common':'/vendor/common/mod.js'}})}</script><script type="module">
      import {OwnerTemplateAuthoring} from '/modules/owner-template-authoring.js';
      import {verifyManifest02} from '/modules/draft02-manifest.js';
      const data=JSON.parse(${JSON.stringify(serialized(data))},(_,v)=>v&&v.bigint?BigInt(v.bigint):v&&v.bytes?Uint8Array.from(v.bytes.match(/../g),s=>parseInt(s,16)):v);
      const manifest=await verifyManifest02(data.manifestBytes,data.trust,data.nowMs),mode=${JSON.stringify(mode)};
      window.revision=1n;window.metadata=0;
      window.author=new OwnerTemplateAuthoring({enabled:true,origin:location.origin,binding:data.binding,templateId:data.scope.templateId,signal:new AbortController().signal,timeoutMs:mode==='deadline'?300:10000,
       currentCsrf:()=>document.cookie.split('; ').find(v=>v.startsWith('__Host-zrotext_csrf=')).split('=')[1],
       readCurrent:async()=>{const c=await fetch('/fixture/current',{credentials:'same-origin',cache:'no-store'}).then(r=>r.json());return {binding:data.binding,manifest,nowMs:data.nowMs,ownerSessionLive:c.live,consentLive:true,phase:'active',validForMs:60000};},
       readDraftState:async()=>({epoch:1n,revision:window.revision,custodyLive:true}),
       consumeDraftReview:async r=>{window.review=r;window.phase='plaintext-review';if(mode==='decline')return false;if(mode==='changed')await new Promise(resolve=>{window.releaseReview=resolve;});return true;},
       consumeCiphertextReview:async()=>{window.metadata++;window.phase='ciphertext-review';if(mode==='deadline')await new Promise(resolve=>{window.releaseMetadata=resolve;});}});
      window.input={requestId:'00000000-0000-0000-0000-000000000009',expectedRevision:0,scope:data.scope,template:'Synthetic {{name}} ^',values:{name:'Example'},epoch:1n,draftRevision:1n};
      window.begin=()=>window.author.prepare(window.input).then(t=>{window.ticket=t;return {prepared:true};},e=>({code:e.code}));window.ready=true;
     </script>`);return;
    }
    if(url.pathname==='/fixture/current'){res.setHeader('content-type','application/json');res.end(JSON.stringify({live}));return;}
    if(url.pathname==='/v1/owner/workflow/templates'&&req.method==='POST'){
     assert.match(req.headers.cookie??'',/__Host-zrotext_session=synthetic-session/);assert.equal(req.headers['x-zrotext-csrf'],'synthetic-csrf');
     const chunks=[];let size=0;for await(const b of req){size+=b.length;assert.ok(size<=33075);chunks.push(b);}posts.push({body:Buffer.concat(chunks),id:req.headers['idempotency-key']});
     res.setHeader('content-type','application/json');res.end('{"revision":1}');return;
    }
    let selected;
    if(url.pathname.startsWith('/modules/'))selected=path.join(sdk,'dist',url.pathname.slice(9));
    else if(url.pathname.startsWith('/vendor/core/'))selected=path.join(sdk,'node_modules/@hpke/core/esm',url.pathname.slice(13));
    else if(url.pathname.startsWith('/vendor/common/'))selected=path.join(sdk,'node_modules/@hpke/common/esm',url.pathname.slice(15));
    if(selected){const allowed=path.resolve(sdk);assert.ok(path.resolve(selected).startsWith(allowed+path.sep));res.setHeader('content-type','text/javascript');res.end(await fs.readFile(selected));return;}
    res.writeHead(404).end();
   }catch{res.writeHead(500).end();}
  });
  await new Promise(resolve=>server.listen(0,'localhost',resolve));context=await browser.newContext({ignoreHTTPSErrors:true});const page=await context.newPage();
  await page.goto(`https://localhost:${server.address().port}`);await page.waitForFunction(()=>window.ready===true);
  await run({page,f,posts,revoke(){live=false;}});
 }finally{await context?.close();if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}await fs.rm(temporary,{recursive:true,force:true});}
}
test('Chromium exact local review and real HPKE encryption prepare without POST, then explicit commit saves opaque bytes',async()=>fixture('save',async({page,f,posts})=>{
 const result=await page.evaluate(async()=>{const prepared=await window.begin();return {...prepared,text:window.review.preview.text,encoding:window.review.preview.estimate.encoding};});assert.deepEqual(result,{prepared:true,text:'Synthetic Example ^',encoding:'gsm'});assert.equal(posts.length,0);
 await page.evaluate(()=>window.author.client.commit(window.ticket));assert.equal(posts.length,1);assert.ok(!posts[0].body.includes(Buffer.from('Synthetic')));
 const {openEncryptedTemplate}=await import(pathToFileURL(path.join(sdk,'dist/encrypted-template.js')).href);assert.deepEqual(await openEncryptedTemplate(f.manifest,f.scope,f.nowMs,f.archive.privateKey,new Uint8Array(posts[0].body)),{template:'Synthetic {{name}} ^',values:{name:'Example'}});await page.evaluate(()=>window.author.close());
}));
test('Chromium declined plaintext review reaches no metadata review or persistence POST',async()=>fixture('decline',async({page,posts})=>{assert.deepEqual(await page.evaluate(()=>window.begin()),{code:'review_declined'});assert.equal(await page.evaluate(()=>window.metadata),0);assert.equal(posts.length,0);}));
test('Chromium changed draft during held exact review refuses the late owner decision',async()=>fixture('changed',async({page,posts})=>{await page.evaluate(()=>{window.result=window.begin();});await page.waitForFunction(()=>window.phase==='plaintext-review');await page.evaluate(()=>{window.revision=2n;window.releaseReview();});assert.deepEqual(await page.evaluate(()=>window.result),{code:'draft_changed'});assert.equal(await page.evaluate(()=>window.metadata),0);assert.equal(posts.length,0);}));
test('Chromium outer deadline fences held child metadata review and no late ticket or POST escapes',async()=>fixture('deadline',async({page,posts})=>{const result=await page.evaluate(()=>window.begin());assert.deepEqual(result,{code:'deadline'});assert.equal(await page.evaluate(()=>window.metadata),1);assert.equal(await page.evaluate(()=>!!window.ticket),false);await page.evaluate(()=>window.releaseMetadata());assert.equal(posts.length,0);}));
