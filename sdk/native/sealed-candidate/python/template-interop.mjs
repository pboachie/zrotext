// Independent maintained TypeScript template acceptance; synthetic local inputs.
import {execFileSync} from 'node:child_process';
import {webcrypto} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {enrollRootPin02,verifyManifest02} from '../../../typescript/dist/draft02-manifest.js';
import {canonicalTemplateBytes,templateDigest} from '../../../typescript/dist/template-contract.js';
import {encryptedTemplateAad,encryptedTemplateDigest,sealEncryptedTemplate,sealEncryptedTemplateBytes,
  openEncryptedTemplate,openEncryptedTemplateBytes,previewEncryptedTemplate} from '../../../typescript/dist/encrypted-template.js';
import {estimateSegments} from '../../../typescript/dist/sms-segments.js';
import {Aes128Gcm,CipherSuite,DhkemP256HkdfSha256,HkdfSha256} from '../../../typescript/node_modules/@hpke/core/esm/mod.js';
globalThis.crypto ??= webcrypto;
const b64=b=>Buffer.from(b).toString('base64'),decode=b=>new Uint8Array(Buffer.from(b,'base64'));
const numbers=['bindingGeneration','revision','expiresMs','trustGeneration','manifestVersion'];
const scopeOf=f=>Object.fromEntries(Object.entries(f.scope).map(([k,v])=>[k,numbers.includes(k)?BigInt(v):decode(v)]));
async function manifestOf(f){return verifyManifest02(decode(f.manifest),await enrollRootPin02(decode(f.rootPin),decode(f.fingerprint)),BigInt(f.now));}
async function privateOf(f){
 const suite=new CipherSuite({kem:new DhkemP256HkdfSha256(),kdf:new HkdfSha256(),aead:new Aes128Gcm()});
 return suite.kem.deserializePrivateKey(decode(f.archiveScalar));
}
if(process.argv[2]==='--consume'){
 let text='';for await(const part of process.stdin)text+=part;const input=JSON.parse(text),f=input.fixture;
 const manifest=await manifestOf(f),scope=scopeOf(f),key=await privateOf(f),envelope=decode(input.envelope);
 const content=await openEncryptedTemplate(manifest,scope,BigInt(f.now),key,envelope);
 const canonical=canonicalTemplateBytes(content.template,content.values);
 if(b64(canonical)!==input.expectedCanonical)throw Error('native template content mismatch');
 process.stdout.write(JSON.stringify({verified:true,preview:previewEncryptedTemplate(content),digest:b64(await encryptedTemplateDigest(envelope))}));
}else{
 const args=process.argv.slice(2);if(args.length && (args.length!==2 || args[0]!=='--recipient-point'))throw Error('template fixture args');
 const f=JSON.parse(execFileSync(process.execPath,[fileURLToPath(new URL('./produce-fixture.mjs',import.meta.url)),...args],{encoding:'utf8'}));
 const fill=(n,size)=>new Uint8Array(size).fill(n),sha=async b=>new Uint8Array(await crypto.subtle.digest('SHA-256',b));
 const scope={accountId:decode(f.account),deviceId:decode(f.device),lineId:decode(f.line),intervalId:fill(21,16),templateId:fill(22,16),
  bindingGeneration:1n,revision:1n,expiresMs:20000n,trustGeneration:1n,manifestVersion:1n,peerDigest:fill(23,32),readerId:decode(f.reader),manifestDigest:await sha(decode(f.manifest).slice(0,-64))};
 f.scope=Object.fromEntries(Object.entries(scope).map(([k,v])=>[k,typeof v==='bigint'?Number(v):b64(v)]));
 const manifest=await manifestOf(f),content={template:'Hi {{name}} 🌱',values:{name:'reader'}};
 const envelope=await sealEncryptedTemplate(manifest,scope,BigInt(f.now),content);
 if(f.archiveScalar){const opened=await openEncryptedTemplate(manifest,scope,BigInt(f.now),await privateOf(f),envelope);
  if(opened.template!==content.template)throw Error('TS self acceptance');}
 const samples=[{template:'{{z}} {{a}}',values:{z:'"\n\\',a:'🌱'}},{template:'',values:{}},
  {template:'{{name}}',values:{name:'x'.repeat(512)}},{template:'{{name}}',values:{name:'🌱'.repeat(256)}},
  {template:'literal \u2028 /',values:{}},{template:'{{__proto__}}',values:{}},{template:'{bad}',values:{}},
  {template:'{{name}}',values:{name:'x'.repeat(513)}},{template:'x',values:{constructor:'x'}}];
 const vectors=[];for(const item of samples){try{vectors.push({...item,canonical:b64(canonicalTemplateBytes(item.template,item.values)),digest:await templateDigest(item.template,item.values)});}catch{vectors.push({...item,refused:true});}}
 const estimates=['','a'.repeat(160),'a'.repeat(161),'^'.repeat(80),'^'.repeat(81),'🌱'.repeat(35),'🌱'.repeat(36),'€','\f','\t','a'.repeat(919),'🌱'.repeat(202)].map(text=>{
  try{return {text,estimate:estimateSegments(text)};}catch{return {text,refused:true};}});
 const malformed=await sealEncryptedTemplateBytes(manifest,scope,BigInt(f.now),new TextEncoder().encode('{"v":1, "template":"x","values":{}}'));
 const invalidUtf8=await sealEncryptedTemplateBytes(manifest,scope,BigInt(f.now),new Uint8Array([255]));
 process.stdout.write(JSON.stringify({...f,content,envelope:b64(envelope),canonical:b64(canonicalTemplateBytes(content.template,content.values)),
  aad:b64(encryptedTemplateAad(scope)),preview:previewEncryptedTemplate(content),vectors,estimates,malformed:b64(malformed),invalidUtf8:b64(invalidUtf8)}));
}
