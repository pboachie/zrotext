// SPDX-License-Identifier: AGPL-3.0-only
// Explicit simulator CLI: synthetic fixture keys/content only, no network or carrier API.
import { webcrypto, randomBytes, createECDH } from "node:crypto";
import { enrollRootPin02, verifyManifest02, advanceManifestTrust02 } from "../dist/draft02-manifest.js";
import { prepareInboundEnvelope02 } from "../dist/draft02-envelope-prep.js";
import { authorizeInbound02, canonicalSignature02 } from "../dist/draft02-manifest.js";
import { openFixtureWrap } from "./conversation-simulator-wrap.mjs";
globalThis.crypto ??= webcrypto;
const decode = (s) => Uint8Array.from(Buffer.from(s, "base64"));
const encode = (b) => Buffer.from(b).toString("base64");
const uuid = (s) => Uint8Array.from(Buffer.from(s.replaceAll("-", ""), "hex"));
let text = "";
for await (const chunk of process.stdin) {
  text += chunk;
  if (text.length > 100_000) throw new Error("fixture input bound");
}
const input = JSON.parse(text);
const ready = input.ready;
let trust = await enrollRootPin02(decode(ready.pin), decode(ready.fingerprint));
const now = BigInt(Date.now());
const predecessor = await verifyManifest02(decode(ready.predecessor), trust, now);
trust = advanceManifestTrust02(trust, predecessor);
const manifest = await verifyManifest02(decode(ready.manifest), trust, now);
const signerPoint = decode(ready.signerPoint);
const archivePoint = decode(ready.archivePoint);
const jwk = (point, scalar) => ({ kty: "EC", crv: "P-256",
  x: Buffer.from(point.subarray(1, 33)).toString("base64url"),
  y: Buffer.from(point.subarray(33)).toString("base64url"),
  d: Buffer.from(decode(scalar)).toString("base64url"), ext: false });
const signer = manifest.keys.find((k) => k.role === 4);
const archive = manifest.keys.find((k) => k.role === 2);
let envelope;
let preparedWrap;
if (input.op === "prepare") {
  const privateKey = await crypto.subtle.importKey("jwk", jwk(signerPoint, ready.eventScalar),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const prepared = await prepareInboundEnvelope02({ kind: 2, manifest, nowMs: now,
    messageId: uuid(input.capture), eventId: uuid(input.capture), deviceId: uuid(input.device),
    lineId: uuid(input.line), peer: new TextEncoder().encode(input.peer), observedMs: BigInt(input.observed),
    localSequence: BigInt(input.sequence), content: input.body, cek: randomBytes(32), nonce: randomBytes(12),
    signer: { privateKey, publicPoint: signerPoint },
    recipients: [{ role: 2, keyId: archive.keyId, point: archivePoint, ekm: randomBytes(32) }] });
  envelope = prepared.envelope;
  preparedWrap=prepared.wraps[0];
} else if (input.op === "open") envelope = decode(input.envelope);
else throw new Error("fixture operation");
const derived = createECDH("prime256v1"); derived.setPrivateKey(decode(ready.archiveScalar));
if (!derived.getPublicKey().equals(Buffer.from(archivePoint))) throw new Error("fixture archive scalar/point mismatch");
const privateKey = await crypto.subtle.importKey("jwk", jwk(archivePoint, ready.archiveScalar),
  { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
// Independent, strictly bounded profile-02 consumer for this simulator only.
const b = Buffer.from(envelope);
const check = (value) => { if (!value) throw new Error("fixture profile-02 reader boundary"); };
check(b.length <= 34_400 && b.subarray(0, 8).equals(Buffer.from([0x5a,0x54,0x53,0x45,2,2,0,0])));
const protectedLength = b.readUInt16BE(8);
check(protectedLength >= 172 && protectedLength <= 185);
const protectedBytes = b.subarray(10, 10 + protectedLength);
if (input.capture) check(protectedBytes.subarray(16,32).equals(Buffer.from(uuid(input.capture))) && protectedBytes.subarray(144,160).equals(Buffer.from(uuid(input.capture))));
const peerLength = protectedBytes[168];
check(protectedLength === 169 + peerLength && peerLength >= 3 && peerLength <= 16);
check(protectedBytes.subarray(0,16).equals(Buffer.from(manifest.accountId)));
check(protectedBytes.subarray(32,48).equals(Buffer.from(uuid(input.device))));
check(protectedBytes.subarray(48,64).equals(Buffer.from(uuid(input.line))));
check(protectedBytes.subarray(72,104).equals(Buffer.from(manifest.digest)));
check(protectedBytes.subarray(169).equals(Buffer.from(input.peer, "ascii")));
check(protectedBytes.subarray(104,136).equals(Buffer.from(signer.keyId)));
const at = 10 + protectedLength;
const bodyLength = b.readUInt32BE(at + 12);
check(bodyLength >= 17 && bodyLength <= 32784);
const wrapAt = at + 16 + bodyLength;
check(b[wrapAt] === 1 && b.length === wrapAt + 1 + 146 + 64);
const wrap = b.subarray(wrapAt + 1, wrapAt + 147);
check(wrap[0] === 2 && wrap.subarray(1,33).equals(Buffer.from(archive.keyId)));
const unsigned = b.subarray(0,b.length-64);
const signature = b.subarray(b.length-64);
check(Buffer.from(canonicalSignature02(signature)).equals(signature));
const length = Buffer.alloc(4); length.writeUInt32BE(unsigned.length);
const signerKey = await crypto.subtle.importKey("raw", signerPoint, { name:"ECDSA", namedCurve:"P-256" }, false,["verify"]);
check(await crypto.subtle.verify({ name:"ECDSA", hash:"SHA-256" }, signerKey, signature,
  Buffer.concat([Buffer.from("ZTSE/sign/v2\0"),length,unsigned])));
authorizeInbound02(manifest, { kind:2, messageId:protectedBytes.subarray(16,32),eventId:protectedBytes.subarray(144,160),localSequence:protectedBytes.readBigUInt64BE(160),manifestDigest:manifest.digest,accountId:manifest.accountId,deviceId:uuid(input.device),lineId:uuid(input.line),
  peer:Buffer.from(input.peer),keysetVersion:protectedBytes.readBigUInt64BE(64),signerKeyId:signer.keyId,
  wraps:[{role:2,keyId:archive.keyId}] }, now);
const info=Buffer.concat([Buffer.from("ZTSE/wrap/v2\0"),b.subarray(0,10),protectedBytes,wrap.subarray(0,33)]);
if (preparedWrap) {
  check(Buffer.from(preparedWrap.enc).equals(wrap.subarray(33,98)));
  check(Buffer.from(preparedWrap.ct).equals(wrap.subarray(98)));
  check(Buffer.from(preparedWrap.info).equals(info));
}
const cek = await openFixtureWrap(privateKey, archivePoint, wrap.subarray(33,98), info, wrap.subarray(98));
check(cek.length === 32);
const bodyKey = await crypto.subtle.importKey("raw",cek,"AES-GCM",false,["decrypt"]);
const plain = await crypto.subtle.decrypt({name:"AES-GCM",iv:b.subarray(at,at+12),tagLength:128,
  additionalData:Buffer.concat([Buffer.from("ZTSE/body/v2\0"),b.subarray(0,10),protectedBytes])},bodyKey,b.subarray(at+16,wrapAt));
const opened = new TextDecoder("utf-8",{fatal:true}).decode(plain);
check(opened.length > 0 && !opened.includes("\0") && !opened.startsWith("\uFEFF"));
process.stdout.write(JSON.stringify({ envelope: encode(envelope), opened }));
