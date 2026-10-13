// Fresh synthetic signatures for negative transition relations. No live authority.
import {webcrypto} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
globalThis.crypto??=webcrypto;
const source=path.resolve(process.argv[2]);
const fixture=JSON.parse(execFileSync(process.execPath,[path.join(source,'sdk/native/sealed-candidate/python/contact-interop.mjs')],{encoding:'utf8'}));
const {canonicalSignature02}=await import(pathToFileURL(path.join(source,'sdk/typescript/dist/draft02-manifest.js')));
const point=Buffer.from(fixture.manifest,'base64').subarray(85,150),scalar=Buffer.alloc(32);scalar[31]=7;
const key=await crypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url'),d:scalar.toString('base64url'),ext:true},{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
const signed=[];
async function add(name,mutation,edit){
 const unsigned=Buffer.from(fixture[mutation],'base64').subarray(0,304);edit(unsigned);
 const length=Buffer.alloc(4);length.writeUInt32BE(unsigned.length);
 const transcript=Buffer.concat([Buffer.from('ZT/contact-field/mutation/v1\0'),length,unsigned]);
 const sig=canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,transcript)));
 signed.push({name,mutation,fixture:{...fixture,[mutation]:Buffer.concat([unsigned,sig]).toString('base64')}});
}
await add('wrong predecessor digest','update',b=>{b[70]^=1;});
await add('wrong predecessor revision','update',b=>{b.writeBigUInt64BE(2n,38);b.writeBigUInt64BE(3n,46);});
await add('replacement request mismatch','update',b=>{b[54]^=1;});
await add('retained slot digest mismatch','update',b=>{b[231]^=1;});
await add('replacement slot digest mismatch','update',b=>{b[272]^=1;});
await add('authenticated manifest rollback','clear',b=>{
 const st=Buffer.from(fixture.statement,'base64'),at=40+st.readUInt16BE(38);
 b.writeBigUInt64BE(st.readBigUInt64BE(at+8),110);
 st.copy(b,118,at+56,at+88);
});
// Bind the older statement digest after framing, then independently re-sign.
const rollback=signed.pop(),raw=Buffer.from(rollback.fixture.clear,'base64').subarray(0,304);
Buffer.from(await crypto.subtle.digest('SHA-256',Buffer.from(fixture.statement,'base64'))).copy(raw,150);
const length=Buffer.alloc(4);length.writeUInt32BE(raw.length);
const sig=canonicalSignature02(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,Buffer.concat([Buffer.from('ZT/contact-field/mutation/v1\0'),length,raw]))));
rollback.fixture.clear=Buffer.concat([raw,sig]).toString('base64');rollback.statement='statement';signed.push(rollback);
process.stdout.write(JSON.stringify({fixture,signed}));
