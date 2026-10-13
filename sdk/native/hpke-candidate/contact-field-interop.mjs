// Test-only maintained SDK oracle. Fresh synthetic keys and opaque fixture fields.
import {webcrypto} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
globalThis.crypto ??= webcrypto;
const source=resolve(process.argv[2]);
const load=name=>import(pathToFileURL(resolve(source,'sdk/typescript/dist',name)).href);
const manifests=await load('draft02-manifest.js'),statements=await load('contact-reader-statement.js'),fields=await load('contact-content-contract.js');
const dec=x=>new Uint8Array(Buffer.from(x,'base64')),enc=x=>Buffer.from(x).toString('base64');
const fixturePath=resolve(source,'sdk/native/sealed-candidate/python/contact-interop.mjs');
const extra=['https://xn--xn--a--gua.pt','https://xn--xn---epa','https://xn--a','https://xn--0','https://xn--ls8h.example','https://a..b','https://.example','https://example.',...Array.from({length:94},(_,i)=>'https://xn--a'+String.fromCharCode(33+i)+'.invalid')];
async function statement(f,which){
 const root=await manifests.enrollRootPin02(dec(f.rootPin),dec(f.fingerprint));
 let m=await manifests.verifyManifest02(dec(f.manifest),root,10000n);
 if(which==='nextStatement')m=await manifests.verifyManifest02(dec(f.nextManifest),await manifests.advanceManifestTrust02(root,m),10000n);
 return statements.verifyContactReaderStatement01({bytes:dec(f[which]),acceptedManifest:m,expectedAccountId:dec(f.account),expectedOrigin:f.origin,expectedRootFingerprint:dec(f.fingerprint),comparison:'declared_issued_ms'});
}
if(process.argv[3]==='--consume'){
 let input='';for await(const chunk of process.stdin)input+=chunk;const {fixture,outputs}=JSON.parse(input);
 for(const row of outputs){const st=await statement(fixture,row.statement);await fields.verifyContactField01({bytes:dec(row.bytes),statement:st,expectedContactId:dec(fixture.contact),expectedRoutingDigest:dec(fixture.routing)})}
 process.stdout.write(JSON.stringify({verified:true,fields:outputs.length}));
}else{
 const fixture=JSON.parse(execFileSync(process.execPath,[fixturePath,'--origins'],{input:JSON.stringify(extra),encoding:'utf8'}));
 const rootPoint=dec(fixture.rootPin).slice(29),scalar=new Uint8Array(32);scalar[31]=7;
 const key=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:Buffer.from(rootPoint.slice(1,33)).toString('base64url'),y:Buffer.from(rootPoint.slice(33)).toString('base64url'),d:Buffer.from(scalar).toString('base64url'),ext:true,key_ops:['sign']},{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
 async function sign(domain,unsigned){const length=new Uint8Array(4);new DataView(length.buffer).setUint32(0,unsigned.length);const transcript=Buffer.concat([Buffer.from(domain+'\0'),length,unsigned]);const sig=manifests.canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,transcript)));return enc(Buffer.concat([unsigned,sig]));}
 const signed=[];const raw=dec(fixture.statement),at=40+new DataView(raw.buffer).getUint16(38)+24+32*3+65;
 for(const [name,issued,until] of [['historical-before-local',9000n,20000n],['declared-later-than-local',11000n,20000n],['before-manifest-and-key',8999n,20000n],['equal-end',10000n,100000n],['past-end',10000n,100001n],['empty-window',10000n,10000n]]){
  const unsigned=raw.slice(0,-64),view=new DataView(unsigned.buffer);view.setBigUint64(at,issued);view.setBigUint64(at+8,until);
  const f={...fixture,statement:await sign('ZT/contact-reader/authorization/v1',unsigned)};
  let accepted=true;try{await statement(f,'statement')}catch{accepted=false}
  signed.push({name,fixture:f,operation:'statement',accepted});
 }
 process.stdout.write(JSON.stringify({fixture,signed}));
}
