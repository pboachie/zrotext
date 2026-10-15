// Public synthetic root fixture only. Independently verify the signed successor.
import {createECDH,createPrivateKey,createHash,sign} from 'node:crypto';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
const source=resolve(process.argv[2],'sdk/typescript/dist');
const {canonicalSignature02,enrollRootPin02,verifyManifest02}=await import(pathToFileURL(resolve(source,'draft02-manifest.js')));
const {verifyManifest03From02,verifyManifest03Successor}=await import(pathToFileURL(resolve(source,'draft03-manifest.js')));
let text='';for await(const part of process.stdin){text+=part;if(text.length>1000000)throw Error('Fixture limit');}const f=JSON.parse(text),b=k=>Buffer.from(f[k],'base64');
const scalar=Buffer.alloc(32);scalar[31]=7;const ec=createECDH('prime256v1');ec.setPrivateKey(scalar);const point=ec.getPublicKey();if(!point.equals(b('rootPin').subarray(29)))throw Error('Unexpected synthetic root');
const key=createPrivateKey({format:'jwk',key:{kty:'EC',crv:'P-256',x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url'),d:scalar.toString('base64url')}});
const raw=Buffer.from(b('signed03').subarray(0,-64));raw[6]=3;raw.writeBigUInt64BE(3n,31);createHash('sha256').update(b('signed03').subarray(0,-64)).digest().copy(raw,55);const length=Buffer.alloc(4);length.writeUInt32BE(raw.length);
const signature=canonicalSignature02(sign('sha256',Buffer.concat([Buffer.from('ZTSE/manifest/v3\0'),length,raw]),{key,dsaEncoding:'ieee-p1363'}));const successor=Buffer.concat([raw,signature]);
const pin=await enrollRootPin02(b('rootPin'),b('fingerprint')),prior=await verifyManifest02(b('signed02'),pin,10000n),accepted=await verifyManifest03From02(new Uint8Array(b('signed03')),prior,new Uint8Array(b('signed02')),BigInt(f.accepted.acceptedAtMs));await verifyManifest03Successor(new Uint8Array(successor),accepted,30000n);
f.successor=successor.toString('base64');process.stdout.write(JSON.stringify(f));
