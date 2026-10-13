// Synthetic fixture adapter only: independently sign valid successor controls.
import {createECDH,createHash,createPrivateKey,generateKeyPairSync,sign} from 'node:crypto';
let input='';for await(const chunk of process.stdin){input+=chunk;if(input.length>1000000)throw Error('fixture size');}
const fixture=JSON.parse(input),decode=name=>Buffer.from(fixture[name],'base64');
const hash=b=>createHash('sha256').update(b).digest();
const scalar=Buffer.alloc(32);scalar[31]=7; // Public synthetic fixture signer, never production custody.
const ec=createECDH('prime256v1');ec.setPrivateKey(scalar);const publicPoint=ec.getPublicKey();
if(!decode('rootPin').subarray(29).equals(publicPoint))throw Error('unexpected fixture root');
const privateKey=createPrivateKey({format:'jwk',key:{kty:'EC',crv:'P-256',x:publicPoint.subarray(1,33).toString('base64url'),y:publicPoint.subarray(33).toString('base64url'),d:scalar.toString('base64url')}});
const order=BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
function signature(unsigned){const size=Buffer.alloc(4);size.writeUInt32BE(unsigned.length);const raw=sign('sha256',Buffer.concat([Buffer.from('ZTSE/manifest/v2\0'),size,unsigned]),{key:privateKey,dsaEncoding:'ieee-p1363'});let s=BigInt('0x'+raw.subarray(32).toString('hex'));if(s>order/2n)s=order-s;return Buffer.concat([raw.subarray(0,32),Buffer.from(s.toString(16).padStart(64,'0'),'hex')]);}
const old=decode('manifest').subarray(0,-64);const next=Buffer.from(old);next.writeBigUInt64BE(2n,29);hash(old).copy(next,53);
fixture.liveSuccessor=Buffer.concat([next,signature(next)]).toString('base64');
const rotated=Buffer.from(next),jwk=generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({format:'jwk'}),point=Buffer.concat([Buffer.from([4]),Buffer.from(jwk.x,'base64url'),Buffer.from(jwk.y,'base64url')]);
const id=hash(Buffer.concat([Buffer.from('ZTSE/key/v1\0'),Buffer.from([0,16]),point]));
let changed=0;for(let i=0;i<rotated[150];i++){const at=151+i*149;if(rotated[at]===2){id.copy(rotated,at+1);point.copy(rotated,at+33);changed++;}}
if(changed!==1)throw Error('archive count');fixture.rotatedSuccessor=Buffer.concat([rotated,signature(rotated)]).toString('base64');
process.stdout.write(JSON.stringify(fixture));
