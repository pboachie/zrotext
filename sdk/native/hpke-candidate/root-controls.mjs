// Synthetic cross-client root succession fixture. No operational keys or authority.
import {createECDH,createHash,createPrivateKey,generateKeyPairSync,randomBytes,sign,webcrypto} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
import {readFileSync} from 'node:fs';
if(process.argv.length!==3)throw Error('Pass the reviewed maintained producer checkout');
const source=resolve(process.argv[2],'sdk/typescript/dist');
const {canonicalSignature02,enrollRootPin02,verifyManifest02,advanceManifestTrust02,verifyRootTransition02}=await import(pathToFileURL(resolve(source,'draft02-manifest.js')));
const {prepareInboundEnvelope02}=await import(pathToFileURL(resolve(source,'draft02-envelope-prep.js')));
let input='';for await(const chunk of process.stdin){input+=chunk;if(input.length>1000000)throw Error('fixture size');}
const f=JSON.parse(input),b=name=>Buffer.from(f[name],'base64'),sha=x=>createHash('sha256').update(x).digest();
function synthetic(n){const scalar=Buffer.alloc(32);scalar[31]=n;const ec=createECDH('prime256v1');ec.setPrivateKey(scalar);const point=ec.getPublicKey();const jwk={kty:'EC',crv:'P-256',x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url'),d:scalar.toString('base64url')};return {point,key:createPrivateKey({format:'jwk',key:jwk}),jwk};}
const old=synthetic(7),origin=synthetic(6),fresh=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),jwk=fresh.publicKey.export({format:'jwk'}),point=Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]);
if(!old.point.equals(b('rootPin').subarray(29)))throw Error('Unexpected synthetic old root');
const u64=n=>{const b=Buffer.alloc(8);b.writeBigUInt64BE(BigInt(n));return b;};
const signature=(key,label,unsigned)=>{const size=Buffer.alloc(4);size.writeUInt32BE(unsigned.length);return Buffer.from(canonicalSignature02(sign('sha256',Buffer.concat([Buffer.from(label+'\0'),size,unsigned]),{key,dsaEncoding:'ieee-p1363'})));};
const unsigned=Buffer.concat([Buffer.from('ZTRT\x02'),b('account'),u64(1),u64(2),old.point,point,sha(b('manifest').subarray(0,-64)),u64(11000),u64(90000)]);
const transition=Buffer.concat([unsigned,signature(old.key,'ZTSE/root-transition/v2',unsigned),signature(fresh.privateKey,'ZTSE/root-transition/v2',unsigned)]);
const genesis=Buffer.from(b('manifest').subarray(0,-64));genesis.writeBigUInt64BE(2n,21);genesis.writeBigUInt64BE(11000n,37);sha(unsigned).copy(genesis,53);point.copy(genesis,85);
for(let i=0;i<genesis[150];i++){const at=151+149*i;if(genesis[at]===6){sha(Buffer.concat([Buffer.from('ZTSE/key/v1\0'),Buffer.from([1,1]),point])).copy(genesis,at+1);point.copy(genesis,at+33);}}
const signed=Buffer.concat([genesis,signature(fresh.privateKey,'ZTSE/manifest/v2',genesis)]);
const pin=await enrollRootPin02(b('rootPin'),b('fingerprint')),before=await verifyManifest02(b('manifest'),pin,10000n),advanced=advanceManifestTrust02(pin,before),nextPin=await verifyRootTransition02(transition,advanced,11000n,point),next=await verifyManifest02(signed,nextPin,11000n);
let archive;for(let i=0;i<genesis[150];i++){const at=151+149*i;if(genesis[at]===2)archive=genesis.subarray(at+33,at+98);}
const privateKey=await webcrypto.subtle.importKey('jwk',origin.jwk,{name:'ECDSA',namedCurve:'P-256'},false,['sign']);
const opened=await prepareInboundEnvelope02({manifest:next,nowMs:11000n,messageId:Buffer.alloc(16,49),deviceId:b('device'),lineId:b('line'),peer:Buffer.from('+12'),observedMs:11000n,content:f.text,cek:randomBytes(32),nonce:randomBytes(12),kind:2,eventId:Buffer.alloc(16,49),localSequence:8n,signer:{privateKey,publicPoint:origin.point},recipients:[{role:2,keyId:b('reader'),point:archive,ekm:randomBytes(32)}]});
const successor=Buffer.from(genesis);successor.writeBigUInt64BE(2n,29);sha(genesis).copy(successor,53);const signedSuccessor=Buffer.concat([successor,signature(fresh.privateKey,'ZTSE/manifest/v2',successor)]);await verifyManifest02(signedSuccessor,advanceManifestTrust02(nextPin,next),11000n);
const highS=(bytes,at)=>{const copy=Buffer.from(bytes),order=BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');Buffer.from((order-BigInt('0x'+copy.subarray(at,at+32).toString('hex'))).toString(16).padStart(64,'0'),'hex').copy(copy,at);return copy.toString('base64');};
Object.assign(f,{highOld:highS(transition,247),highNew:highS(transition,311),newSuccessor:signedSuccessor.toString('base64'),transition:transition.toString('base64'),newManifest:signed.toString('base64'),newPoint:point.toString('base64'),newInbound:Buffer.from(opened.envelope).toString('base64'),rotation:JSON.parse(readFileSync(new URL('../../typescript/test/vectors/draft02-rotation.json',import.meta.url)))});
process.stdout.write(JSON.stringify(f));
