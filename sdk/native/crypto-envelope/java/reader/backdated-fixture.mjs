// Test-only invalid signed observation, using the producer's public synthetic scalar6.
// No production key or authority is accepted by this adapter.
import { createECDH, webcrypto } from 'node:crypto';
let text='';for await(const chunk of process.stdin)text+=chunk;
const fixture=JSON.parse(text), wire=Buffer.from(fixture.inbound,'base64');
const scalar=Buffer.alloc(32);scalar[31]=6;
const curve=createECDH('prime256v1');curve.setPrivateKey(scalar);const point=curve.getPublicKey();
const key=await webcrypto.subtle.importKey('jwk',{kty:'EC',crv:'P-256',d:scalar.toString('base64url'),
  x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url')},
  {name:'ECDSA',namedCurve:'P-256'},false,['sign']);
const unsigned=Buffer.from(wire.subarray(0,-64));unsigned.writeBigUInt64BE(8000n,146);
const size=Buffer.alloc(4);size.writeUInt32BE(unsigned.length);
const signature=Buffer.from(await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},key,
  Buffer.concat([Buffer.from('ZTSE/sign/v2\0'),size,unsigned])));
const order=BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const s=BigInt('0x'+signature.subarray(32).toString('hex'));
if(s>order/2n)Buffer.from((order-s).toString(16).padStart(64,'0'),'hex').copy(signature,32);
fixture.inboundBackdated=Buffer.concat([unsigned,signature]).toString('base64');
process.stdout.write(JSON.stringify(fixture));
