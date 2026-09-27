// SPDX-License-Identifier: AGPL-3.0-only
// Independent fixture producer: Node WebCrypto plus the existing SDK @hpke/core dependency.
// All scalar values and content are public synthetic test material, never application keys.
import { createECDH, createHash, webcrypto } from "node:crypto";
import { createRequire } from "node:module";
import { writeFileSync } from "node:fs";
const require = createRequire(new URL("../../sdk/typescript/package.json", import.meta.url));
const { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } = require("@hpke/core");
const crypto = webcrypto;
const cat = (...a) => Buffer.concat(a.map(x => Buffer.from(x)));
const ascii = x => Buffer.from(x, "utf8");
const hex = x => Buffer.from(x).toString("hex");
const hash = x => createHash("sha256").update(x).digest();
const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u16 = n => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const fixed = n => Buffer.from(n.toString(16).padStart(64, "0"), "hex");
const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
function point(scalar) { const e = createECDH("prime256v1"); e.setPrivateKey(fixed(BigInt(scalar))); return e.getPublicKey(); }
async function signer(scalar) {
  const p = point(scalar);
  return crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: p.subarray(1,33).toString("base64url"),
    y: p.subarray(33).toString("base64url"), d: fixed(BigInt(scalar)).toString("base64url"), ext: true },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}
async function signed(unsigned, key, label) {
  const sig = Buffer.from(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key,
    cat(ascii(label + "\0"), u32(unsigned.length), unsigned)));
  const s = BigInt("0x" + sig.subarray(32).toString("hex"));
  return cat(unsigned, sig.subarray(0,32), fixed(s > order / 2n ? order - s : s));
}
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
const now = 1700000000000;
const account = Buffer.alloc(16,1), message = Buffer.alloc(16,4), device = Buffer.alloc(16,2), line = Buffer.alloc(16,3);
const peer = ascii("+12");
const root = point(1), devicePoint = point(7), archive = point(9), signerPoint = point(5);
const id = (p, kem) => hash(cat(ascii("ZTSE/key/v1\0"), kem ? [0,16] : [1,1], p));
const deviceId = id(devicePoint,true), archiveId = id(archive,true), signerId = id(signerPoint,false);
const rootPin = cat(ascii("ZTRP"), [2], account, u64(1), root);
const rootFingerprint = hash(cat(ascii("ZTSE/root-pin/v2\0"), rootPin));
const records = [ [1,deviceId,devicePoint,device,line,4], [2,archiveId,archive,Buffer.alloc(16),Buffer.alloc(16),12],
  [5,signerId,signerPoint,Buffer.alloc(16),line,1], [6,id(root,false),root,Buffer.alloc(16),Buffer.alloc(16),0] ];
const unsignedManifest = cat(ascii("ZTMA"), [2], account, u64(1), u64(1), u64(now-1000), u64(now+60000),
  Buffer.alloc(32), root, [4], ...records.map(([role,key,p,d,l,scope]) => cat([role],key,p,d,l,u16(scope),u64(now-1000),u64(now+60000),[1])));
const manifest = await signed(unsignedManifest, await signer(1), "ZTSE/manifest/v2");
const protectedBytes = cat(account,message,device,line,u64(1),hash(unsignedManifest),signerId,u64(now),u64(now+20000),[1,peer.length],peer);
const header = cat(ascii("ZTSE"),[2,1,0,0],u16(protectedBytes.length));
const cek = Buffer.alloc(32,0xc2);
const bodyKey = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
const signingKey = await signer(5);
async function wrap(role,key,p,context) {
  const recipientPublicKey = await suite.kem.deserializePublicKey(p);
  const sender = await suite.createSenderContext({ recipientPublicKey, info: cat(ascii("ZTSE/wrap/v2\0"),header,context,[role],key) });
  return cat([role],key,sender.enc,await sender.seal(cek,new Uint8Array()));
}
const cases = {};
async function envelope(name,body,nonceByte,edit) {
  const nonce = Buffer.alloc(12,nonceByte);
  const ct = Buffer.from(await crypto.subtle.encrypt({ name:"AES-GCM", iv:nonce,
    additionalData:cat(ascii("ZTSE/body/v2\0"),header,protectedBytes) },bodyKey,body));
  const unsigned = cat(header,protectedBytes,nonce,u32(ct.length),ct,[2],
    await wrap(1,deviceId,devicePoint,protectedBytes),await wrap(2,archiveId,archive,protectedBytes));
  if(edit) edit(unsigned);
  cases[name] = hex(await signed(unsigned,signingKey,"ZTSE/sign/v2"));
}
await envelope("normal",ascii("Candidate sealed text ✓"),1);
await envelope("malformedUtf8",Buffer.from([0xc0,0x80]),2);
await envelope("nul",Buffer.from([65,0,66]),3);
await envelope("bom",Buffer.from([0xef,0xbb,0xbf,65]),4);
await envelope("wrongNonce",ascii("Candidate sealed text ✓"),5,b=>b[167]^=1);
await envelope("wrongBody",ascii("Candidate sealed text ✓"),6,b=>b[183]^=1);
await envelope("gsmSix",ascii("A".repeat(918)),7);
await envelope("gsmSeven",ascii("A".repeat(919)),8);
await envelope("unicodeSix",ascii("Ā".repeat(402)),9);
await envelope("unicodeSeven",ascii("Ā".repeat(403)),10);
await envelope("extensionSix",ascii("^".repeat(456)),11);
await envelope("extensionSeven",ascii("^".repeat(457)),12);
const changed = Buffer.from(protectedBytes); changed[16]^=1;
const old = Buffer.from(cases.normal,"hex"), bodyEnd = 183+old.readUInt32BE(179);
const wrongAad = cat(header,changed,old.subarray(167,bodyEnd),[2],
  await wrap(1,deviceId,devicePoint,changed),await wrap(2,archiveId,archive,changed));
cases.wrongBodyAad = hex(await signed(wrongAad,signingKey,"ZTSE/sign/v2"));
const output = { status:"CANDIDATE_SYNTHETIC_DECRYPTABLE", producer:"Node WebCrypto and @hpke/core 1.7.5",
  now, deviceScalar:7, rootPin:hex(rootPin), rootFingerprint:hex(rootFingerprint), manifest:hex(manifest),
  devicePoint:hex(devicePoint), deviceKeyId:hex(deviceId), archiveKeyId:hex(archiveId), signerKeyId:hex(signerId), cases };
writeFileSync(new URL("../app/src/sharedTest/resources/candidate02-preparation.json",import.meta.url),JSON.stringify(output,null,2)+"\n");
