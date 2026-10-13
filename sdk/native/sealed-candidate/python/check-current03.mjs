// Independent maintained TypeScript semantic-currentness decisions.
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import {enrollRootPin02,verifyManifest02} from '../../../typescript/dist/draft02-manifest.js';
import {verifyManifest03From02,verifyManifest03Current,verifiedManifestIdentity03} from '../../../typescript/dist/draft03-manifest.js';
globalThis.crypto??=webcrypto;
const {fixture:f,cases}=JSON.parse(readFileSync(0,'utf8'));
const b=v=>new Uint8Array(Buffer.from(v,'base64'));
const original=b(f.signed02),pin=await enrollRootPin02(b(f.rootPin),b(f.fingerprint));
const prior=await verifyManifest02(original,pin,10000n);
const current=await verifyManifest03From02(b(f.signed03),prior,original,10000n);
const results=[];
for(const entry of cases){
 try{
  const value=await verifyManifest03Current(b(entry.raw),current,BigInt(entry.now));
  const identity=verifiedManifestIdentity03(value,BigInt(entry.now));
  results.push({accepted:true,digest:Buffer.from(identity.digest).toString('base64'),comparison:Number(identity.comparisonMs)});
 }catch{results.push({accepted:false});}
}
process.stdout.write(JSON.stringify({results,originalComparison:Number(verifiedManifestIdentity03(current,10000n).comparisonMs)}));
