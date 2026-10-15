// Synthetic primitive-only vector. No original envelope key or authority is supplied.
import { webcrypto } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
const original = JSON.parse(readFileSync(new URL('../../../../../protocol/v1/vectors/sealed-profile03-sdk-outbound-01.json', import.meta.url)));
const key = Buffer.alloc(32, 7), nonce = Buffer.alloc(12, 8);
const aad = Buffer.from(original.body_aad_b64, 'base64');
const text = 'synthetic candidate body v3';
const imported = await webcrypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
const ciphertext = Buffer.from(await webcrypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad,tagLength:128}, imported, Buffer.from(text)));
const vector = JSON.stringify({status:'SYNTHETIC_PRIMITIVE_ONLY',keyHex:key.toString('hex'),nonceHex:nonce.toString('hex'),aadHex:aad.toString('hex'),ciphertextHex:ciphertext.toString('hex'),text}, null, 2)+'\n';
const target = new URL('./profile03-body.json', import.meta.url);
if(process.argv.includes('--check')) {
 if(readFileSync(target,'utf8') !== vector) throw new Error('Synthetic profile03 primitive vector differs');
} else writeFileSync(target,vector);
