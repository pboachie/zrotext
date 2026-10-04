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
const sdk=path.resolve(__dirname,'../../../sdk/typescript');
const serialized=value=>JSON.stringify(value,(_,v)=>typeof v==='bigint'?{bigint:String(v)}:v instanceof Uint8Array?{bytes:Buffer.from(v).toString('hex')}:v);
let browser;
test.before(async()=>{browser=await chromium.launch();});
test.after(async()=>{await browser?.close();});
async function fixture(mode,run){
 const {templateFixture}=await import(pathToFileURL(path.join(sdk,'test/owner-encrypted-template-client.test.mjs')).href);
 const f=await templateFixture(),temporary=await fs.mkdtemp(path.join(os.tmpdir(),'zrotext-opening-browser-'));
 let server,context,live=true;const requests=[];
 try{
  const key=path.join(temporary,'key.pem'),cert=path.join(temporary,'cert.pem');
  execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-subj','/CN=localhost','-days','1'],{stdio:'ignore',timeout:15000});
  // Public synthetic scope only. The explicit synthetic reader key is derived
  // inside Chromium; no private key is served or submitted to this fixture.
  const data={binding:f.binding,scope:f.scope,manifestBytes:f.manifestBytes,trust:f.trust,nowMs:f.nowMs};
  server=https.createServer({key:await fs.readFile(key),cert:await fs.readFile(cert)},async(req,res)=>{
   try{
    const url=new URL(req.url,'https://localhost');
    if(url.pathname==='/'){
     res.setHeader('content-type','text/html');res.setHeader('Set-Cookie',['__Host-zrotext_session=synthetic-session; Secure; HttpOnly; Path=/; SameSite=Strict','__Host-zrotext_csrf=synthetic-csrf; Secure; Path=/; SameSite=Strict']);
     res.end(`<output id="preview"></output><script type="importmap">${JSON.stringify({imports:{'@hpke/core':'/vendor/core/mod.js','@hpke/common':'/vendor/common/mod.js'}})}</script><script type="module">
      import {OwnerEncryptedTemplateClient} from '/modules/owner-encrypted-template-client.js';
      import {OwnerTemplateOpening} from '/modules/owner-template-opening.js';
      import {verifyManifest02} from '/modules/draft02-manifest.js';
      import {CipherSuite,DhkemP256HkdfSha256,HkdfSha256,Aes128Gcm} from '@hpke/core';
      const data=JSON.parse(${JSON.stringify(serialized(data))},(_,v)=>v&&v.bigint?BigInt(v.bigint):v&&v.bytes?Uint8Array.from(v.bytes.match(/../g),s=>parseInt(s,16)):v);
      const manifest=await verifyManifest02(data.manifestBytes,data.trust,data.nowMs);
      const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
      const selected=await suite.kem.deriveKeyPair(new Uint8Array(32).fill(34));
      const csrf=()=>document.cookie.split('; ').find(v=>v.startsWith('__Host-zrotext_csrf=')).split('=')[1];
      const current=async()=>{const c=await fetch('/fixture/current',{credentials:'same-origin',cache:'no-store'}).then(r=>r.json());return {binding:data.binding,manifest,nowMs:data.nowMs,ownerSessionLive:c.live,consentLive:true,phase:'active',validForMs:60000};};
      window.startOpening=async({keyMode='selected',holdCrypto=false,timeoutMs=10000}={})=>{
       let privateKey=selected.privateKey;
       if(keyMode==='public')privateKey=selected.publicKey;
       if(keyMode==='wrong-reader')privateKey=(await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits'])).privateKey;
       if(keyMode==='nonexportable')privateKey=await crypto.subtle.importKey('pkcs8',await crypto.subtle.exportKey('pkcs8',selected.privateKey),{name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
       const signal=window.openingSignal=new AbortController();
       const client=window.openingClient=new OwnerEncryptedTemplateClient({enabled:true,origin:location.origin,binding:data.binding,templateId:data.scope.templateId,readCurrent:current,currentCsrf:csrf,consumeCiphertextReview:async()=>{throw Error('Synthetic forbidden write review');},signal:signal.signal});
       const opening=window.opening=new OwnerTemplateOpening({enabled:true,client,binding:data.binding,templateId:data.scope.templateId,readCurrent:current,currentCsrf:csrf,signal:signal.signal,timeoutMs});
       const decrypt=crypto.subtle.decrypt;
       if(holdCrypto)crypto.subtle.decrypt=async function(...args){const plain=await decrypt.apply(this,args);window.cryptoEntered=true;await new Promise(resolve=>window.releaseCrypto=resolve);return plain;};
       try{const result=await opening.openLatest({privateKey});document.querySelector('#preview').textContent=result.preview.text;return {published:true,text:result.preview.text,parts:result.preview.estimate.parts,acknowledged:result.requestAcknowledged};}
       catch(e){return {published:false,code:e.code};}
       finally{crypto.subtle.decrypt=decrypt;opening.close();}
      };window.ready=true;
     </script>`);return;
    }
    if(url.pathname.startsWith('/modules/')||url.pathname.startsWith('/vendor/')){
     let base,relative;
     if(url.pathname.startsWith('/modules/')){base=path.join(sdk,'dist');relative=url.pathname.slice(9);}
     else{const parts=url.pathname.slice(8).split('/'),selected=parts.shift();if(!['core','common'].includes(selected)){res.writeHead(404).end();return;}base=path.join(sdk,'node_modules/@hpke',selected,'esm');relative=parts.join('/');}
     if(!relative||relative.split('/').some(p=>p==='..'||p===''||!/^[-A-Za-z0-9_.]+$/.test(p))||!relative.endsWith('.js')){res.writeHead(404).end();return;}
     res.setHeader('content-type','application/javascript');res.end(await fs.readFile(path.join(base,relative)));return;
    }
    requests.push({method:req.method,path:url.pathname,cookie:req.headers.cookie??'',csrf:req.headers['x-zrotext-csrf']});
    if(!(req.headers.cookie??'').includes('__Host-zrotext_session=synthetic-session')){res.writeHead(401).end();return;}
    if(url.pathname==='/fixture/current'){res.setHeader('content-type','application/json');res.setHeader('cache-control','no-store');res.end(JSON.stringify({live}));return;}
    if(req.method==='GET'&&url.pathname.startsWith('/v1/owner/workflow/templates/')){
     if(req.headers['x-zrotext-csrf']!=='synthetic-csrf'){res.writeHead(403).end();return;}
     res.setHeader('content-type','application/vnd.zrotext.workflow-template.v1');res.setHeader('cache-control','no-store');
     const envelope=Uint8Array.from(f.envelope);if(mode==='tamper')envelope[envelope.length-1]^=1;
     if(mode==='revoked')live=false;if(mode==='stalled'){res.write(Buffer.from(envelope.slice(0,64)));return;}
     res.end(Buffer.from(envelope));return;
    }
    // Opening has no write authority. Any accidental POST is a test failure.
    res.writeHead(405).end();
   }catch{if(!res.headersSent)res.writeHead(500);res.end();}
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'localhost',resolve);});
  context=await browser.newContext({ignoreHTTPSErrors:true});const page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(`https://localhost:${server.address().port}`);await page.waitForFunction(()=>window.ready,{},{timeout:10000});
  assert.equal(requests.length,0,'constructing local fixture performs no template or currentness request');
  await run({page,requests,revoke:()=>{live=false;}});assert.deepEqual(errors,[]);
  assert.equal(requests.some(r=>r.method!=='GET'),false,'opening never POSTs');
  assert.equal(await page.evaluate(()=>Object.keys(localStorage).length+Object.keys(sessionStorage).length),0);
 }finally{
  await context?.close();if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  const owned=path.resolve(temporary),parent=path.resolve(os.tmpdir());
  assert.equal(path.dirname(owned),parent);assert.ok(path.basename(owned).startsWith('zrotext-opening-browser-'));await fs.rm(owned,{recursive:true,force:true});
 }
}
test('Chromium opens actual selected-reader HPKE ciphertext into local bounded preview with cookies and CSRF, never POST',async()=>fixture('positive',async({page,requests})=>{
 const result=await page.evaluate(()=>startOpening());assert.deepEqual(result,{published:true,text:'Synthetic Example',parts:1,acknowledged:false});
 assert.equal(await page.locator('#preview').textContent(),'Synthetic Example');const reads=requests.filter(r=>r.path.startsWith('/v1/owner/workflow/templates/'));
 assert.equal(reads.length,1);assert.equal(reads[0].csrf,'synthetic-csrf');assert.ok(requests.every(r=>r.cookie.includes('__Host-zrotext_session=synthetic-session')));
}));
for(const mode of ['tamper','revoked'])test(`Chromium ${mode} ciphertext/currentness never publishes plaintext`,async()=>fixture(mode,async({page})=>{
 assert.equal((await page.evaluate(()=>startOpening())).published,false);assert.equal(await page.locator('#preview').textContent(),'');
}));
for(const keyMode of ['public','wrong-reader','nonexportable'])test(`Chromium refuses ${keyMode} selected key case without plaintext`,async()=>fixture('positive',async({page})=>{
 assert.equal((await page.evaluate(keyMode=>startOpening({keyMode}),keyMode)).published,false);assert.equal(await page.locator('#preview').textContent(),'');
}));
for(const event of ['invalidate','abort','revoke','deadline'])test(`Chromium ${event} while real AES result is held blocks late preview`,async()=>fixture('positive',async({page,revoke})=>{
 await page.evaluate(event=>{window.result=startOpening({holdCrypto:true,timeoutMs:event==='deadline'?500:10000});},event);
 await page.waitForFunction(()=>window.cryptoEntered,{},{timeout:10000});
 if(event==='invalidate')await page.evaluate(()=>opening.invalidate());if(event==='abort')await page.evaluate(()=>openingSignal.abort());if(event==='revoke')revoke();
 if(event!=='revoke')assert.equal((await page.evaluate(()=>window.result)).published,false);
 await page.evaluate(()=>releaseCrypto());assert.equal((await page.evaluate(()=>window.result)).published,false);assert.equal(await page.locator('#preview').textContent(),'');
}));
test('Chromium outer budget aborts a stalled real encrypted GET without publishing',async()=>fixture('stalled',async({page})=>{
 const result=await page.evaluate(async()=>{const start=performance.now(),result=await startOpening({timeoutMs:500});return {...result,elapsed:performance.now()-start};});
 assert.equal(result.published,false);assert.ok(result.elapsed<2000);assert.equal(await page.locator('#preview').textContent(),'');
}));
