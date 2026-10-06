// SPDX-License-Identifier: AGPL-3.0-only
// Actual packaged Chromium/IndexedDB with synthetic signed public history. No production page or provider.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createRequire} from 'node:module';
import {mkdtemp,readFile,rm,realpath} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {prepareContactHistoryFixture} from './contact-local-history.test.mjs';
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..'),require=createRequire(import.meta.url);
test('packaged Chromium binds genuine local history and reduces MAX/full records after root loss',async t=>{
  const tooling=path.join(repo,'web/owner/node_modules/playwright');if(!existsSync(path.join(tooling,'package.json'))){t.skip('Owner Playwright dependency required; owner-browser CI installs it');return;}
  const fixture=await prepareContactHistoryFixture(),publicBytes=fixture.publicBytes;fixture.close();
  const assets=await mkdtemp(path.join(tmpdir(),'contact-local-history-browser-'));let browser;
  try{
    const built=spawnSync(process.execPath,[path.join(repo,'scripts/package_conversation_browser.mjs'),assets],{encoding:'utf8',timeout:20_000});assert.equal(built.status,0,built.stderr);
    assert.ok((await readFile(path.join(assets,'sdk/contact-local-history.js'),'utf8')).includes('openContactLocalHistory01'));
    browser=await require(tooling).chromium.launch({headless:true});
    for(const scenario of ['normal','missing','mismatch','lifecycle']){
      const context=await browser.newContext();try{
        await context.route(publicBytes.origin+'/**',async route=>{const u=new URL(route.request().url());if(u.pathname.startsWith('/assets/')){
          const p=path.resolve(assets,u.pathname.slice(8));assert.ok(p.startsWith(assets+path.sep));await route.fulfill({contentType:'text/javascript',body:await readFile(p)});
        }else{assert.equal(u.pathname,'/');assert.equal(route.request().method(),'GET');await route.fulfill({contentType:'text/html',body:'<!doctype html><title>Contact local history fixture</title>'});}});
        const page=await context.newPage();await page.goto(publicBytes.origin);
        const outcome=await page.evaluate(async({data,scenario})=>{
          const {Draft02TrustStore}=await import('/assets/sdk/draft02-trust-store.js'),{verifyContactReaderStatement01}=await import('/assets/sdk/contact-reader-statement.js');
          const c=await import('/assets/sdk/contact-content-contract.js'),{openContactLocalHistory01}=await import('/assets/sdk/contact-local-history.js');
          const b=x=>Uint8Array.from(x),eq=(x,y)=>JSON.stringify(x)===JSON.stringify(y),must=(v)=>{if(!v)throw Error('browser assertion');},hex=x=>Array.from(x,v=>v.toString(16).padStart(2,'0')).join('');
          const root=await Draft02TrustStore.open(),pin=b(data.pin),fingerprint=b(data.fingerprint),account=b(data.account),contact=b(data.contact);let accepted;
          await root.enroll(pin,fingerprint,2000n);for(const m of data.manifests)accepted=await root.acceptManifest(b(m),2000n);
          const statement=await verifyContactReaderStatement01({bytes:b(data.statement),acceptedManifest:accepted,expectedAccountId:account,expectedOrigin:data.origin,expectedRootFingerprint:fingerprint,comparison:'declared_issued_ms'});
          const scope={expectedContactId:contact,expectedRoutingDigest:c.parseContactMutation01(b(data.create)).routingDigest};
          const fields=[];for(const bytes of data.fields)fields.push(await c.verifyContactField01({bytes:b(bytes),statement,...scope}));
          const first=c.verifyContactTransition01({previous:null,next:await c.verifyContactMutation01({bytes:b(data.create),statement,...scope,expectedLegacyGeneration:0n}),replacementFields:fields});
          const options={expectedAccountId:account,expectedOrigin:data.origin,rootPin:pin,independentlyComparedRootFingerprint:fingerprint,maximumRecords:1,mode:'history',signal:new AbortController().signal};
          const stores=[];let store;const open=async(o=options)=>{const s=await openContactLocalHistory01(o);stores.push(s);return s;};
          const raw=async(run)=>{const db=await new Promise((resolve,reject)=>{const q=indexedDB.open('ztse-contact-local-history-v1',1);q.onsuccess=()=>resolve(q.result);q.onerror=()=>reject(q.error);});try{return await new Promise((resolve,reject)=>{
            const tx=db.transaction(['header','contacts'],'readwrite');let value;run(tx,v=>{value=v;});tx.oncomplete=()=>resolve(value);tx.onabort=()=>reject(tx.error);
          });}finally{db.close();}};
          try{store=await open();const saved=await store.accept({expected:null,transition:first,statement});must(saved.kind==='accepted_local_history');
            if(scenario==='normal'){
              const read=await store.lookup(contact);must(read.kind==='accepted_local_history');let refused=false;try{c.verifiedContactTransitionIdentity01(read.token);}catch{refused=true;}must(refused);
              const twin=await open();store.close();must((await twin.lookup(contact)).kind==='accepted_local_history');
              return {scenario,localOnly:true,reopen:true,not794:true};
            }
            if(scenario==='lifecycle'){
              const all=[store];for(let n=0;n<3;n++)all.push(await open());let refused=false;try{await open();}catch{refused=true;}must(refused);
              all[1].close();must((await all[2].lookup(contact)).kind==='accepted_local_history');
              const abort=new AbortController(),owned=await open({...options,signal:abort.signal});abort.abort();let closed=false;try{await owned.lookup(contact);}catch{closed=true;}must(closed);
              // Controlled platform visibility loss; the browser dispatches the real lifecycle event.
              Object.defineProperty(document,'visibilityState',{configurable:true,get:()=> 'hidden'});document.dispatchEvent(new Event('visibilitychange'));
              let invisible=false;try{await all[2].lookup(contact);}catch{invisible=true;}must(invisible);delete document.visibilityState;
              return {scenario,fourBound:true,independentClose:true,actualAbort:true,visibilityEvent:true};
            }
            // Reduction-only MAX representation fixture, not a fabricated signed MAX transition.
            await raw((tx,done)=>{const q=tx.objectStore('contacts').get(hex(contact));q.onsuccess=()=>{const r=q.result;r.revision=(1n<<63n)-1n;tx.objectStore('contacts').put(r,hex(contact));done();};});
            store.close();root.close();await new Promise((resolve,reject)=>{const q=indexedDB.deleteDatabase('ztse-draft02-trust-v1');q.onsuccess=()=>resolve();q.onerror=()=>reject(q.error);q.onblocked=()=>reject(Error('owned root connection leaked'));});
            if(scenario==='mismatch'){
              const key=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),point=new Uint8Array(await crypto.subtle.exportKey('raw',key.publicKey)),changed=Uint8Array.from(pin);changed.set(point,29);
              const transcript=new Uint8Array(new TextEncoder().encode('ZTSE/root-pin/v2\0').length+changed.length);transcript.set(new TextEncoder().encode('ZTSE/root-pin/v2\0'));transcript.set(changed,transcript.length-changed.length);
              const other=await Draft02TrustStore.open();try{await other.enroll(changed,new Uint8Array(await crypto.subtle.digest('SHA-256',transcript)),2000n);}finally{other.close();}
            }
            store=await open({...options,mode:'local_reduction'});const read=await store.lookup(contact);must(read.kind==='unavailable'&&read.reason==='reduction_only');
            let refused=false;try{await store.accept({expected:read.token,transition:first,statement});}catch{refused=true;}must(refused);
            must((await store.markUnavailable({expected:read.token})).reason==='local_stop');for(let n=0;n<5;n++)must((await store.markUnavailable({expected:(await store.lookup(contact)).token})).reason==='local_stop');
            const result=await raw((tx,done)=>{const h=tx.objectStore('header').get('scope'),q=tx.objectStore('contacts').getAll();q.onsuccess=()=>done({count:h.result.count,rows:q.result});});
            must(result.count===1&&result.rows.length===1&&eq(Object.keys(result.rows[0]).sort(),['contactId','schema','state']));
            return {scenario,MAX:true,full:true,scrubbed:true,rowCount:1,remoteDeleted:false};
          }finally{for(const s of stores)s.close();root.close();}
        },{data:publicBytes,scenario});
        assert.equal(outcome.scenario,scenario);if(scenario==='missing'||scenario==='mismatch'){assert.equal(outcome.MAX,true);assert.equal(outcome.scrubbed,true);assert.equal(outcome.remoteDeleted,false);}
      }finally{await context.close();}
    }
  }finally{await browser?.close();const absolute=path.resolve(assets);assert.equal(path.dirname(absolute),path.resolve(tmpdir()));assert.ok(path.basename(absolute).startsWith('contact-local-history-browser-'));assert.equal(await realpath(absolute),absolute);await rm(absolute,{recursive:true,force:true});}
});
