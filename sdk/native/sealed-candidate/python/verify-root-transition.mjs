// Independent maintained TypeScript verification of synthetic rotation input.
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import {enrollRootPin02,verifyManifest02,advanceManifestTrust02,verifyRootTransition02} from '../../../typescript/dist/draft02-manifest.js';
globalThis.crypto??=webcrypto;
const f=JSON.parse(readFileSync(0,'utf8')),b=s=>new Uint8Array(Buffer.from(s,'base64'));
const pin=await enrollRootPin02(b(f.old_root_pin_b64),b(f.old_root_fingerprint_b64));
const old=await verifyManifest02(b(f.old_manifest_b64),pin,BigInt(f.now_ms));
const rotated=await verifyRootTransition02(b(f.transition_b64),advanceManifestTrust02(pin,old),BigInt(f.now_ms),b(f.new_root_point_b64));
const next=await verifyManifest02(b(f.new_manifest_b64),rotated,BigInt(f.now_ms));
process.stdout.write(JSON.stringify({generation:Number(next.generation),version:Number(next.version),digest:Buffer.from(next.digest).toString('base64')}));
