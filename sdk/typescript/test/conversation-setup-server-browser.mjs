// SPDX-License-Identifier: AGPL-3.0-only
// Consumption runner only. The caller owns the compiled HTTPS fixture, CLI
// fixture custody and authenticated phone methods; this module invents none.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

const digest = (...parts) => createHash('sha256').update(Buffer.concat(parts.map(part => Buffer.from(part)))).digest('hex');
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const positive = value => typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value) <= 0x7fffffffffffffffn;
const names = ['signRootCustody', 'signLineRegistration', 'snapshot', 'submitPhoneProof', 'acknowledgePhone'];
export function validateAcceptanceProviders(input) {
  assert.equal(typeof input?.browser?.newContext, 'function', 'Existing browser required');
  for (const name of names) assert.equal(typeof input[name], 'function', `Fixture provider required: ${name}`);
}
export function copyAcceptanceFixture(value) {
  assert.equal(value?.fixtureOnly, true, 'Synthetic fixture required');
  const allowed = new Set(['fixtureOnly','origin','accountId','userId','sessionId','deviceId','lineId','nextGeneration','backupId','rootPin','rootFingerprintHex','rootBackup','publicCard','pairedPoint','pairedFingerprintHex','rootFactor','lineFactor','cookies','lease']);
  assert.ok(Object.keys(value).every(key => allowed.has(key)), 'Unexpected fixture material refused');
  const origin = new URL(value.origin);
  assert.ok(origin.protocol === 'https:' && /\.(test|invalid)$/.test(origin.hostname) && origin.origin === value.origin && !origin.username && !origin.password, 'Reserved HTTPS fixture origin required');
  const result = {...value};
  for (const name of ['accountId','userId','sessionId','deviceId','lineId','backupId']) assert.ok(uuid.test(value[name]) && value[name] !== '00000000-0000-0000-0000-000000000000', 'Fixture identity required');
  assert.ok(positive(value.nextGeneration), 'Fixture generation required');
  for (const [name,min,max] of [['rootPin',94,94],['rootBackup',237,748],['publicCard',134,645],['pairedPoint',65,65]]) {
    assert.ok(value[name] instanceof Uint8Array && value[name].length >= min && value[name].length <= max, 'Bounded public artifact required');
    result[name] = Uint8Array.from(value[name]);
  }
  assert.equal(Buffer.from(result.rootPin.subarray(0,5)).toString('hex'), '5a54525002');
  assert.equal(Buffer.from(result.rootPin.subarray(5,21)).toString('hex'), value.accountId.replaceAll('-',''));
  assert.equal(Buffer.from(result.rootPin).readBigUInt64BE(21), 1n);
  assert.equal(result.rootPin[29], 4); assert.equal(result.pairedPoint[0], 4);
  assert.equal(digest(Buffer.from('ZTSE/root-pin/v2\0'), result.rootPin), value.rootFingerprintHex);
  assert.equal(digest(result.pairedPoint), value.pairedFingerprintHex);
  for (const name of ['rootFactor','lineFactor']) assert.ok(typeof value[name] === 'string' && value[name].length > 0 && value[name].length <= 26 && !/[\r\n]/.test(value[name]), 'Synthetic factor required');
  assert.ok(positive(value.lease?.connectionEpoch) && positive(value.lease?.deploymentEpoch));
  assert.deepEqual(Object.keys(value.lease).sort(), ['connectionEpoch','deploymentEpoch','instanceId','siteId']);
  for (const name of ['siteId','instanceId']) assert.ok(/^[!-~]{1,128}$/.test(value.lease[name]));
  result.lease = {...value.lease};
  assert.ok(Array.isArray(value.cookies) && value.cookies.length === 2);
  assert.deepEqual(value.cookies.map(c=>c.name).sort(), ['__Host-zrotext_csrf','__Host-zrotext_session']);
  result.cookies = value.cookies.map(c => { assert.ok(typeof c.value === 'string' && c.value.length > 0 && c.value.length <= 4096); return {name:c.name,value:c.value,url:value.origin,secure:true,httpOnly:c.name.endsWith('_session'),sameSite:'Strict'}; });
  return result;
}
function counters(value) {
  const result = {};
  for (const key of ['rootCompletions','lineRegistrations','lineApprovals','phoneAcknowledgments']) { assert.ok(Number.isSafeInteger(value?.[key]) && value[key] >= 0, 'Actual fixture counters required'); result[key]=value[key]; }
  return result;
}
export async function readPublicDownload(download,maximum,{timeoutMs=10000}={}) {
  assert.ok(Number.isInteger(maximum)&&maximum>0&&maximum<=1024);
  assert.ok(Number.isInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=10000);
  let stream,timer,expired=false,complete=false;
  const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>{expired=true;stream?.destroy();reject(Error('Public download deadline exceeded'));},timeoutMs);});
  const reading=(async()=>{
    stream=await download.createReadStream();if(expired){stream?.destroy();throw Error('Public download closed');}
    assert.ok(stream,'Public download stream unavailable');let size=0;const parts=[];
    for await(const chunk of stream){size+=chunk.length;assert.ok(size<=maximum,'Public download size exceeded');parts.push(Buffer.from(chunk));}
    assert.ok(size>0,'Empty public download refused');assert.equal(await download.failure(),null,'Public download failed');return Uint8Array.from(Buffer.concat(parts));
  })();
  try{const result=await Promise.race([reading,deadline]);complete=true;return result;}
  finally{clearTimeout(timer);stream?.destroy();try{if(!complete)await download.cancel();}finally{await download.delete();}}
}
export async function assertContentInert(page) {
  assert.equal(await page.locator('#composer').evaluate(element=>element.tagName==='FIELDSET'&&element.disabled===true),true,'Composer fieldset must retain its native disabled gate');
  for(const id of ['body','review','confirm'])assert.equal(await page.locator('#'+id).isDisabled(),true,'Actual content controls must remain effectively disabled');
  assert.equal(await page.locator('#confirmation').isVisible(),false,'No content review may be exposed by line setup');
}
async function artifact(page, host) {
  const link=page.locator(`#${host} a[download]`); await link.waitFor();
  const pending=page.waitForEvent('download');await link.click();const download=await pending;
  const root=host==='root-artifacts';
  if(download.suggestedFilename()!==(root?'root-enrollment-challenge.ztre':'line-owner-key-registration.bin')){try{await download.cancel();}finally{await download.delete();}throw Error('Exact public artifact download required');}
  return readPublicDownload(download,root?663:1024);
}
const upload = (page,id,name,bytes) => page.locator(`#${id}`).setInputFiles({name,mimeType:'application/octet-stream',buffer:Buffer.from(bytes)});

/**
 * Caller starts the compiled fixture and supplies an existing Playwright Browser.
 * fixture contains only synthetic public artifacts, ephemeral authenticated
 * cookies/factors and independently selected scope/lease (see validation above).
 * signRootCustody receives {unsigned,expected,encryptedBackup,publicCard} and
 * returns the existing CLI's two saved public signature lines as Uint8Array.
 * signLineRegistration receives {unsigned,expected}, including the separately
 * displayed approval fingerprint, and returns the existing CLI's raw64 output.
 * Those callbacks must retain real fixture Windows Session/recovery safeguards;
 * this runner supplies no private-key signer or alternate custody implementation.
 * snapshot reads actual durable counts {rootCompletions,lineRegistrations,
 * lineApprovals,phoneAcknowledgments}; each starts at its supplied baseline.
 * submitPhoneProof/acknowledgePhone receive {expected,challenge}; the caller uses
 * authenticated fixture phone methods, never an invented owner HTTP control.
 * Only completion of this function establishes composed-fixture acceptance.
 */
export async function runSetupServerAcceptance(input) {
  validateAcceptanceProviders(input); const f=copyAcceptanceFixture(input.fixture);
  const before=counters(await input.snapshot());
  const context=await input.browser.newContext({ignoreHTTPSErrors:true,acceptDownloads:true});
  let noOriginExport=0; const completions=[];
  try {
    await context.addCookies(f.cookies);
    await context.route('**/*', route => new URL(route.request().url()).origin === f.origin ? route.continue() : route.abort());
    // Causal file-read delay forwards the actual File implementation. It does
    // not replace fetch, application globals, crypto or fixture server replies.
    await context.addInitScript(() => { const generate=crypto.subtle.generateKey.bind(crypto.subtle);globalThis.fixtureGeneratedKeys=[];crypto.subtle.generateKey=async function(...args){const result=await generate(...args);globalThis.fixtureGeneratedKeys.push({algorithm:args[0].name,extractable:result.privateKey?.extractable,usages:result.privateKey?.usages});return result;};const read=File.prototype.arrayBuffer; let release; globalThis.fixtureFileGate={name:null,held:false,release:()=>release?.()}; File.prototype.arrayBuffer=async function(){const bytes=await read.call(this);if(this.name===globalThis.fixtureFileGate.name){globalThis.fixtureFileGate.held=true;await new Promise(r=>{release=r;});}return bytes;}; });
    const page=await context.newPage();
    page.on('dialog', dialog => /^(Enroll this exact existing root|Register this exact session-only line approval key|Approve the paired phone declaration)/.test(dialog.message()) ? dialog.accept() : dialog.dismiss());
    page.on('response', response => { const request=response.request(), path=new URL(response.url()).pathname;
      if(request.method()==='POST' && (path==='/v1/auth/sealed-root'||/\/owner-key\/[^/]+\/complete$/.test(path)||path.endsWith('/approve'))) completions.push({path,status:response.status()});
    });
    const exports=[];
    page.on('response', response => { if(response.request().method()==='GET' && new URL(response.url()).pathname==='/v1/auth/sealed-root') exports.push((async()=>{const headers=await response.request().allHeaders();const text=await response.text();assert.ok(Buffer.byteLength(text)<=4096,'Bounded custody export required');return {origin:headers.origin,status:response.status(),published:JSON.parse(text)};})()); });
    async function selection(){await page.goto(f.origin+'/owner/conversation');await page.locator('#owner-enabled').check();for(const [id,value]of [['owner-account',f.accountId],['owner-device',f.deviceId],['owner-line',f.lineId],['owner-generation',f.nextGeneration],['owner-fingerprint',f.rootFingerprintHex],['root-origin',f.origin]])await page.locator('#'+id).fill(value);}
    async function rootBegin(){await selection();await page.locator('#root-backup-id').fill(f.backupId);await upload(page,'root-backup-file','fixture.backup',f.rootBackup);await upload(page,'root-card-file','fixture.card',f.publicCard);await page.locator('#root-publication-consent').check();await page.locator('#root-begin').click();return artifact(page,'root-artifacts');}
    const expected={accountId:f.accountId,userId:f.userId,sessionId:f.sessionId,deviceId:f.deviceId,lineId:f.lineId,nextGeneration:f.nextGeneration,origin:f.origin,rootFingerprintHex:f.rootFingerprintHex,rootPin:Uint8Array.from(f.rootPin),backupId:f.backupId,pairedFingerprintHex:f.pairedFingerprintHex,lease:{...f.lease}};
    async function cancelHeld(id,button,bytes,name){const count=completions.length;await upload(page,id,name,bytes);await page.evaluate(name=>{fixtureFileGate.name=name;},name);await page.locator('#'+button).click();await page.waitForFunction(()=>fixtureFileGate.held);await page.locator('#clear').click();await page.evaluate(()=>fixtureFileGate.release());await page.waitForFunction(()=>document.querySelector('#status').textContent.startsWith('Action unavailable.'));assert.equal(await page.locator('#root-mfa').inputValue(),'');assert.equal(await page.locator('#line-mfa').inputValue(),'');assert.equal(completions.length,count);assert.equal(await page.locator('#root-artifacts a').count()+await page.locator('#line-artifacts a').count(),0);}
    const bounded=(bytes,min,max)=>{assert.ok(bytes instanceof Uint8Array&&bytes.length>=min&&bytes.length<=max,'Bounded public signer output required');return Uint8Array.from(bytes);};
    let packet=await rootBegin();let signatures=await input.signRootCustody({unsigned:packet,expected:structuredClone(expected),encryptedBackup:Uint8Array.from(f.rootBackup),publicCard:Uint8Array.from(f.publicCard)});
    signatures=bounded(signatures,296,512);
    await page.locator('#root-mfa').fill(f.rootFactor);await cancelHeld('root-signatures-file','root-complete',signatures,'held-root-signatures.txt');assert.deepEqual(counters(await input.snapshot()),before);
    packet=await rootBegin();signatures=await input.signRootCustody({unsigned:packet,expected:structuredClone(expected),encryptedBackup:Uint8Array.from(f.rootBackup),publicCard:Uint8Array.from(f.publicCard)});
    signatures=bounded(signatures,296,512);await upload(page,'root-signatures-file','root-signatures.txt',signatures);await page.locator('#root-mfa').fill(f.rootFactor);await page.locator('#root-complete').click();await page.waitForFunction(()=>document.querySelector('#status').textContent.includes('custody enrolled and independently reread'));for(const exported of await Promise.all(exports)){assert.equal(exported.origin,undefined,'Ordinary GET must not spoof Origin');assert.equal(exported.status,200);noOriginExport++;}assert.equal(noOriginExport,1);const published=(await Promise.all(exports))[0].published;
    async function lineBegin(){await selection();await page.locator('#line-paired-fingerprint').fill(f.pairedFingerprintHex);await upload(page,'line-phone-point-file','paired-public.sec1',f.pairedPoint);await page.locator('#line-session-consent').check();await page.locator('#line-begin').click();const unsigned=await artifact(page,'line-artifacts');const text=await page.locator('#line-artifacts').innerText();const match=/New session approval fingerprint: ([0-9a-f]{64})/.exec(text);assert.ok(match);return bounded(await input.signLineRegistration({unsigned,expected:{...structuredClone(expected),approvalFingerprintHex:match[1]}}),64,64);}
    let lineSignature=await lineBegin();assert.ok(lineSignature instanceof Uint8Array && lineSignature.length===64);await page.locator('#line-mfa').fill(f.lineFactor);const rooted=counters(await input.snapshot());await cancelHeld('line-root-signature-file','line-complete',lineSignature,'held-line-signature.bin');assert.deepEqual(counters(await input.snapshot()),rooted);
    lineSignature=await lineBegin();await upload(page,'line-root-signature-file','line-signature.bin',lineSignature);await page.locator('#line-mfa').fill(f.lineFactor);await page.locator('#line-complete').click();await page.locator('#line-open').waitFor({state:'visible'});await page.waitForFunction(()=>!document.querySelector('#line-open').disabled);
    async function lineClick(id){await page.evaluate(()=>{globalThis.fixtureLineResult=false;const observer=new MutationObserver(()=>{globalThis.fixtureLineResult=true;observer.disconnect();});observer.observe(document.querySelector('#line-status'),{childList:true,characterData:true,subtree:true});});await page.locator('#'+id).click();await page.waitForFunction(()=>fixtureLineResult);}
    const openResponse=page.waitForResponse(r=>r.request().method()==='POST'&&new URL(r.url()).pathname===`/v1/owner/conversation/sealed-line/${f.lineId}/challenges`);await lineClick('line-open');const opened=await(await openResponse).json();await input.submitPhoneProof({expected:structuredClone(expected),challenge:structuredClone(opened)});await lineClick('line-check');await page.waitForFunction(()=>!document.querySelector('#line-approve').disabled);await lineClick('line-approve');await page.waitForFunction(()=>document.querySelector('#line-status').textContent.startsWith('Activation committed.'));
    await lineClick('line-check');await page.waitForFunction(()=>document.querySelector('#line-status').textContent.startsWith('Activation committed.'));assert.ok(!(await page.locator('#line-status').innerText()).includes('installation acknowledged'));
    await input.acknowledgePhone({expected:structuredClone(expected),challenge:structuredClone(opened)});await lineClick('line-check');await page.waitForFunction(()=>document.querySelector('#line-status').textContent.startsWith('SEALED line installation acknowledged'));
    await assertContentInert(page);assert.deepEqual(await page.evaluate(()=>fixtureGeneratedKeys),[{algorithm:'ECDSA',extractable:false,usages:['sign']}]);assert.equal(await page.evaluate(()=>localStorage.length+sessionStorage.length),0);const after=counters(await input.snapshot());for(const key of Object.keys(before))assert.equal(after[key],before[key]+1);assert.equal(completions.length,3);assert.ok(completions.every(c=>c.status>=200&&c.status<300));
    if(input.consumePublishedRoot){assert.equal(typeof input.consumePublishedRoot,'function');await input.consumePublishedRoot({published:structuredClone(published),expected:structuredClone(expected)});}
    return Object.freeze({rootEnrollmentReread:true,noOriginExport:true,cancelZeroCompletion:true,lineRegistration:true,activationDistinctFromPhoneAck:true,contentAuthorityGranted:false});
  } finally {await context.close();}
}
