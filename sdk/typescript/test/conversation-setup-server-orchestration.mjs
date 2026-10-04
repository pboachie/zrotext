// SPDX-License-Identifier: AGPL-3.0-only
// Local fixture consumption only: no compilation, production signing or provisioning.
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import {CleanupFailure,runOwnedProcess} from './owned-process-fixture.mjs';
import { isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { lookup } from 'node:dns/promises';
import { copyAcceptanceFixture, runSetupServerAcceptance } from './conversation-setup-server-browser.mjs';
const {parseRegistration}=createRequire(import.meta.url)('../../../web/owner/conversation-line-setup.js');
const MAX_JSON=16384, MAX_OUTPUT=65536;
const marker='ZT_OWNER_SETUP_RESULT=';
const nativeTest=operation=>operation==='signLineRegistration'?'windows::line_key_registration::tests::native_console_registration_requires_independent_scope_and_fresh_publication':'windows::custody_sign::tests::native_console_custody_signs_only_reviewed_bundle';
const hex=b=>Buffer.from(b).toString('hex');
const uuid=b=>hex(b).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
const integer=s=>typeof s==='string'&&/^[1-9][0-9]{0,18}$/.test(s)&&BigInt(s)<=0x7fffffffffffffffn;
const hash=(...parts)=>createHash('sha256').update(Buffer.concat(parts.map(p=>Buffer.from(p)))).digest('hex');
const rootPoint='046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5';
function keys(value,names){assert.ok(value&&typeof value==='object'&&!Array.isArray(value));assert.deepEqual(Object.keys(value).sort(),names.toSorted());}
function bytes(s,min,max=min){assert.ok(typeof s==='string'&&/^(?:[0-9a-f]{2})+$/.test(s)&&s.length>=min*2&&s.length<=max*2,'Bounded canonical public hex required');return Uint8Array.from(Buffer.from(s,'hex'));}
function canonicalOrigin(value){const u=new URL(value);assert.ok(u.origin===value&&u.protocol==='https:'&&['owner.example.test','owner.invalid'].includes(u.hostname)&&!u.username&&!u.password&&Number(u.port)>=1024,'Reserved explicit fixture HTTPS port required');return u;}
export function validateReady(value){
  keys(value,['version','synthetic','port','controlToken','origin','baseline']);assert.equal(value.version,1);assert.equal(value.synthetic,true);
  assert.ok(Number.isInteger(value.port)&&value.port>0&&value.port<=65535);bytes(value.controlToken,32);canonicalOrigin(value.origin);
  keys(value.baseline,['accountId','userId','sessionId','deviceId','lineId','nextGeneration','pairedPoint','pairedFingerprintHex','rootFactor','lineFactor','cookies','lease']);
  const baseline=value.baseline;
  for(const name of ['accountId','userId','sessionId','deviceId','lineId'])assert.ok(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(baseline[name])&&baseline[name]!=='00000000-0000-0000-0000-000000000000');
  assert.ok(integer(baseline.nextGeneration));const paired=bytes(baseline.pairedPoint,65);assert.equal(paired[0],4);assert.equal(hash(paired),baseline.pairedFingerprintHex);
  keys(baseline.lease,['connectionEpoch','deploymentEpoch','siteId','instanceId']);assert.ok(integer(baseline.lease.connectionEpoch)&&integer(baseline.lease.deploymentEpoch));for(const name of ['siteId','instanceId'])assert.ok(/^[!-~]{1,128}$/.test(baseline.lease[name]));
  for(const name of ['rootFactor','lineFactor'])assert.ok(typeof baseline[name]==='string'&&baseline[name].length===26&&!/[\r\n]/.test(baseline[name]),'Independent one-use fixture recovery factors required');
  assert.ok(baseline.rootFactor!==baseline.lineFactor,'Separate one-use fixture factors required');
  assert.ok(Array.isArray(baseline.cookies)&&baseline.cookies.length===2);assert.deepEqual(baseline.cookies.map(c=>c.name).sort(),['__Host-zrotext_csrf','__Host-zrotext_session']);for(const cookie of baseline.cookies){keys(cookie,['name','value']);assert.ok(typeof cookie.value==='string'&&cookie.value.length>0&&cookie.value.length<=4096);}
  return structuredClone(value);
}
export function parseNativeResult(output,operation){
  assert.ok(['prepareRootFixture','signCustody','signLineRegistration'].includes(operation));
  assert.ok(typeof output==='string'&&Buffer.byteLength(output)<=MAX_OUTPUT&&!output.includes('ZTRK1-'));
  assert.equal(output.split(marker).length,2,'Exactly one native result marker required');
  const prefix=`test ${nativeTest(operation)} ... `;
  const matches=output.split(/\r?\n/).filter(line=>line.startsWith(marker)||line.startsWith(prefix+marker));assert.equal(matches.length,1);
  assert.equal([...output.matchAll(/^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s\r?$/gm)].length,1,'Exactly one selected native test must pass');
  const payload=matches[0].slice(matches[0].startsWith(marker)?marker.length:prefix.length+marker.length);
  assert.ok(Buffer.byteLength(payload)<=4096&&payload.startsWith('{')&&payload.endsWith('}'));const result=JSON.parse(payload);
  keys(result,operation==='prepareRootFixture'?['version','synthetic','operation','artifacts']:['version','synthetic','operation','artifacts','signatures']);
  assert.equal(result.version,1);assert.equal(result.synthetic,true);assert.equal(result.operation,operation);
  keys(result.artifacts,['rootPin','rootFingerprint','bundleId','encryptedBackup','publicCard']);
  bytes(result.artifacts.rootPin,94);bytes(result.artifacts.rootFingerprint,32);bytes(result.artifacts.bundleId,16);bytes(result.artifacts.encryptedBackup,237,748);bytes(result.artifacts.publicCard,134,645);
  if(operation!=='prepareRootFixture'){keys(result.signatures,operation==='signCustody'?['enrollmentSignature','custodySignature']:['rootSignature']);for(const signature of Object.values(result.signatures))bytes(signature,64);}
  return result;
}
export function nativeRequest(operation,expected,artifacts,transcript){
  assert.ok(['prepareRootFixture','signCustody','signLineRegistration'].includes(operation));
  const request={version:1,synthetic:true,operation,expected:structuredClone(expected)};
  if(operation!=='prepareRootFixture'){request.artifacts=structuredClone(artifacts);request.transcript=hex(transcript);}
  const encoded=Buffer.from(JSON.stringify(request));assert.ok(encoded.length<=8192);return encoded.toString('hex');
}
export async function invokeNativeFixture(executable,request){
  assert.ok(isAbsolute(executable),'Caller-selected existing fixture executable required');
  assert.ok(process.platform==='win32'&&executable.toLowerCase().endsWith('.exe')&&process.env.SystemRoot,'Existing Windows native fixture required');
  bytes(request,1,8192);
  const decoded=JSON.parse(Buffer.from(request,'hex'));const operation=decoded.operation;
  const test=nativeTest(operation);
  const output=await runOwnedProcess(executable,['--exact',test,'--nocapture','--test-threads=1'],{env:{SystemRoot:process.env.SystemRoot,ZT_OWNER_SETUP_INTEROP_REQUEST_HEX:request},timeoutMs:60000,maximum:MAX_OUTPUT});
  return parseNativeResult(output,operation);
}
export function verifyIndependentScope(scope,expected,kind,challenge,now=Date.now()){
  const common=['account','origin','rootFingerprint','user','session','challenge','nonce','issued','expires'];
  keys(scope,kind==='root'?common:[...common,'device','line','generation','approvalFingerprint','pairedSigningFingerprint','connectionEpoch','deploymentEpoch','site','instance']);
  for(const [key,value]of Object.entries({account:expected.accountId,user:expected.userId,session:expected.sessionId,origin:expected.origin,rootFingerprint:expected.rootFingerprintHex,challenge}))assert.equal(scope[key],value,'Fixture DB scope differs from independently selected context');
  const nonce=bytes(scope.nonce,32);assert.ok(nonce.some(v=>v!==0));assert.ok(integer(scope.issued)&&integer(scope.expires));
  assert.ok(BigInt(scope.expires)>BigInt(scope.issued)&&BigInt(scope.expires)-BigInt(scope.issued)<=300000n&&BigInt(now)>=BigInt(scope.issued)&&BigInt(now)<BigInt(scope.expires),'Fresh actual DB challenge required');
  if(kind==='line')for(const [key,value]of Object.entries({device:expected.deviceId,line:expected.lineId,generation:expected.nextGeneration,approvalFingerprint:expected.approvalFingerprintHex,pairedSigningFingerprint:expected.pairedFingerprintHex,connectionEpoch:expected.lease.connectionEpoch,deploymentEpoch:expected.lease.deploymentEpoch,site:expected.lease.siteId,instance:expected.lease.instanceId}))assert.equal(scope[key],value,'Fixture DB line lease differs from independent context');
  return structuredClone(scope);
}
export function fixtureControl(ready,{timeoutMs=10000}={}){
  assert.ok(Number.isInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=10000);const r=validateReady(ready);return async(operation,challenge_id)=>{
    assert.ok(['snapshot','root_sign_scope','line_sign_scope','submit_phone_proof','acknowledge_phone','finish'].includes(operation));
    if(operation.endsWith('_scope')||operation==='submit_phone_proof'||operation==='acknowledge_phone')assert.ok(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(challenge_id));else assert.equal(challenge_id,undefined);
    const payload=JSON.stringify({version:1,operation,...(challenge_id?{challenge_id}:{})});
    return new Promise((resolve,reject)=>{
      let ownedResponse,timer,settled=false;
      const settle=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);if(error){ownedResponse?.destroy();request.destroy();reject(Error('Fixture control failed or exceeded its execution bound'));}else resolve(value);};
      const request=http.request({hostname:'localhost',family:4,agent:false,port:r.port,path:'/__fixture/owner-setup',method:'POST',headers:{'content-type':'application/json','content-length':Buffer.byteLength(payload),'x-zrotext-fixture-token':r.controlToken}},response=>{
        ownedResponse=response;let size=0,parts=[];response.on('data',chunk=>{size+=chunk.length;if(size>MAX_JSON){parts=[];settle(true);}else parts.push(chunk);});
        response.on('error',()=>settle(true));response.on('aborted',()=>settle(true));response.on('end',()=>{try{assert.equal(response.statusCode,200);const value=JSON.parse(Buffer.concat(parts));assert.equal(value.version,1);assert.equal(value.synthetic,true);assert.equal(value.operation,operation);keys(value,['version','synthetic','operation',operation==='snapshot'?'counters':operation.endsWith('_scope')?'expected':'ok']);if('ok'in value)assert.equal(value.ok,true);settle(false,value);}catch{settle(true);}});
      });timer=setTimeout(()=>settle(true),timeoutMs);request.on('error',()=>settle(true));request.end(payload);
    });
  };
}
export function fixtureFrontendHandler(ready,{timeoutMs=15000}={}){
  assert.ok(Number.isInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=15000);const r=validateReady(ready);
  return (incoming,outgoing)=>{
    if(!allowFrontendRequest(r.origin,incoming.url,incoming.headers)){outgoing.writeHead(404).end();return;}
    let upstream;const deadline=setTimeout(()=>{incoming.destroy();upstream?.destroy();outgoing.destroy();},timeoutMs);outgoing.once('finish',()=>clearTimeout(deadline));outgoing.once('close',()=>{clearTimeout(deadline);upstream?.destroy();});
    upstream=http.request({hostname:'localhost',family:4,agent:false,port:r.port,path:incoming.url,method:incoming.method,headers:incoming.headers},response=>{outgoing.writeHead(response.statusCode,response.headers);let size=0;response.on('data',chunk=>{size+=chunk.length;if(size>16*1024*1024){upstream.destroy();outgoing.destroy();}});response.on('error',()=>outgoing.destroy());response.pipe(outgoing);});
    let size=0;incoming.on('data',chunk=>{size+=chunk.length;if(size>65536){incoming.destroy();upstream.destroy();}});incoming.on('aborted',()=>upstream.destroy());upstream.on('error',()=>outgoing.destroy());incoming.pipe(upstream);
  };
}
export async function startFixtureFrontend(ready,tls,options){
  const r=validateReady(ready),origin=canonicalOrigin(r.origin);assert.ok(tls?.key&&tls?.cert,'Caller-owned ephemeral TLS fixture required');
  const server=https.createServer({key:tls.key,cert:tls.cert},fixtureFrontendHandler(r,options));
  server.requestTimeout=15000;server.headersTimeout=10000;
  const address=(await lookup('localhost',{family:4})).address;assert.ok(address.startsWith('127.'),'Loopback frontend required');
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(Number(origin.port),address,resolve);});
  return {close:()=>new Promise((resolve,reject)=>{server.close(error=>error?reject(error):resolve());server.closeAllConnections();})};
}
export function allowFrontendRequest(origin,url,headers){
  try{const expected=canonicalOrigin(origin),path=decodeURIComponent(new URL(url,origin).pathname);return typeof url==='string'&&url.startsWith('/')&&!url.startsWith('//')&&!path.startsWith('/__fixture')&&!headers['x-zrotext-fixture-token']&&headers.host===expected.host;}catch{return false;}
}
/** Invoke from a supported, escalated fixture tool process. No elevation or
 * console restrictions are bypassed here; native failures remain failures. */
export async function runCompiledSetupAcceptance({browser,ready,nativeExecutable,tls,consumePublishedRoot}){
  const r=validateReady(ready),control=fixtureControl(r);let frontend,failure;
  try{
    const prepared=await invokeNativeFixture(nativeExecutable,nativeRequest('prepareRootFixture',{account:r.baseline.accountId,origin:r.origin}));
    const artifacts=prepared.artifacts,pin=bytes(artifacts.rootPin,94);assert.equal(hex(pin.subarray(29)),rootPoint,'Independent literal fixture root required');assert.equal(hash(Buffer.from('ZTSE/root-pin/v2\0'),pin),artifacts.rootFingerprint);
    const fixture=copyAcceptanceFixture({...r.baseline,fixtureOnly:true,origin:r.origin,pairedPoint:bytes(r.baseline.pairedPoint,65),rootPin:pin,rootFingerprintHex:artifacts.rootFingerprint,backupId:uuid(bytes(artifacts.bundleId,16)),rootBackup:bytes(artifacts.encryptedBackup,237,748),publicCard:bytes(artifacts.publicCard,134,645)});
    frontend=await startFixtureFrontend(r,tls);
    return await runSetupServerAcceptance({browser,fixture,snapshot:async()=> (await control('snapshot')).counters,
      signRootCustody:async({unsigned,expected})=>{assert.ok(unsigned.length>=151&&unsigned.length<=663);const challenge=uuid(unsigned.subarray(53,69));const scope=verifyIndependentScope((await control('root_sign_scope',challenge)).expected,expected,'root',challenge);const result=await invokeNativeFixture(nativeExecutable,nativeRequest('signCustody',scope,artifacts,unsigned));assert.deepEqual(result.artifacts,artifacts);return new TextEncoder().encode(`Enrollment signature: ${result.signatures.enrollmentSignature}\nCustody signature: ${result.signatures.custodySignature}\n`);},
      signLineRegistration:async({unsigned,expected})=>{const parsed=parseRegistration(unsigned),scope=verifyIndependentScope((await control('line_sign_scope',parsed.challenge)).expected,expected,'line',parsed.challenge);const result=await invokeNativeFixture(nativeExecutable,nativeRequest('signLineRegistration',scope,artifacts,unsigned));assert.deepEqual(result.artifacts,artifacts);return bytes(result.signatures.rootSignature,64);},
      submitPhoneProof:async({challenge})=>{await control('submit_phone_proof',challenge.challenge_id);},acknowledgePhone:async({challenge})=>{await control('acknowledge_phone',challenge.challenge_id);},
      consumePublishedRoot:async({published,expected})=>{
        const decode=(name,min,max)=>{const v=published[name];assert.equal(typeof v,'string');const b=Buffer.from(v,'base64');assert.equal(b.toString('base64'),v);assert.ok(b.length>=min&&b.length<=max);return Uint8Array.from(b);};
        assert.equal(published.account_id,expected.accountId);assert.equal(published.generation,1);
        const {verifyPublishedRootBundle}=await import('../dist/root-custody.js');
        const bundle={rootPin:decode('root_pin_b64',94,94),encryptedBackup:decode('encrypted_backup_b64',237,748),publicCard:decode('public_card_b64',134,645),unsignedEnrollment:decode('unsigned_enrollment_b64',151,663),custodySignature:decode('custody_signature_b64',64,64)};
        const verified=await verifyPublishedRootBundle(expected.rootPin,Uint8Array.from(Buffer.from(expected.rootFingerprintHex,'hex')),expected.origin,bundle);
        assert.equal(verified.trust.generation,1n);assert.equal(hex(verified.trust.accountId),expected.accountId.replaceAll('-',''));assert.deepEqual(verified.rootPin,expected.rootPin);
        for(const changed of [{...bundle,rootPin:Uint8Array.from(bundle.rootPin, (v,i)=>i===5?v^1:v)},{...bundle,custodySignature:Uint8Array.from(bundle.custodySignature,(v,i)=>i===0?v^1:v)}])await assert.rejects(verifyPublishedRootBundle(expected.rootPin,Uint8Array.from(Buffer.from(expected.rootFingerprintHex,'hex')),expected.origin,changed));
        assert.equal(typeof consumePublishedRoot,'function','Actual phone consumer required');
        await consumePublishedRoot({accountId:expected.accountId,rootPin:Buffer.from(verified.rootPin).toString('base64'),comparedFingerprint:expected.rootFingerprintHex,port:r.port,controlToken:r.controlToken});
      }
    });
  }catch(error){failure=error;throw error;}finally{try{try{await frontend?.close();}finally{await control('finish');}}catch(error){if(!(failure instanceof CleanupFailure))throw error;}}
}
