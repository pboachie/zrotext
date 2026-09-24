// Fixture generator for the unapproved draft profile. All keys and HPKE ephemeral inputs are public test material.
// ECDSA uses Web Crypto randomness; generated signatures may vary, while all signed unsigned bytes are stable.
import { createECDH, createHash, webcrypto } from "node:crypto";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { keyId } from "../dist/draft01.js";

globalThis.crypto ??= webcrypto;
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
const utf8 = (text) => new TextEncoder().encode(text);
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const bytes = (hexString) => Uint8Array.from(Buffer.from(hexString, "hex"));
const sha = (data) => Uint8Array.from(createHash("sha256").update(data).digest());
const join = (...items) => Uint8Array.from(Buffer.concat(items.map((item) => Buffer.from(item))));
const n = (value, count) => { const result = new Uint8Array(count); new DataView(result.buffer).setBigUint64(0, BigInt(value), false); return result.subarray(8 - count); };
const u16 = (value) => Uint8Array.of(value >> 8, value & 255);
const u32 = (value) => Uint8Array.of(value >>> 24, value >>> 16, value >>> 8, value);
const repeat = (value, count) => Uint8Array.from({ length: count }, () => value);
const b64url = (data) => Buffer.from(data).toString("base64url");

const scalar = new Uint8Array(32); scalar[31] = 5;
const ec = createECDH("prime256v1"); ec.setPrivateKey(scalar);
const signPoint = Uint8Array.from(ec.getPublicKey(undefined, "uncompressed"));
const signer = await crypto.subtle.importKey("jwk", {
  kty: "EC", crv: "P-256", x: b64url(signPoint.subarray(1, 33)), y: b64url(signPoint.subarray(33)),
  d: b64url(scalar), ext: true, key_ops: ["sign"],
}, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
const signerId = await keyId(0x0101, signPoint);

async function key(ikmByte) {
  const ikm = repeat(ikmByte, 32);
  const pair = await suite.kem.deriveKeyPair(ikm);
  const point = new Uint8Array(await suite.kem.serializePublicKey(pair.publicKey));
  return { ikm, pair, point, keyId: await keyId(0x0010, point) };
}
const device = await key(0x11);
const archive = await key(0x22);
const fixed = {
  account: repeat(0xa1, 16), device: repeat(0xd1, 16), line: repeat(0xb1, 16),
  digest: repeat(0x4d, 32), peer: utf8("+12"),
};

async function envelope(kind) {
  const message = repeat(kind === 1 ? 0x31 : 0x32, 16);
  const observed = n(1_700_000_000_000, 8);
  const common = join(fixed.account, message, fixed.device, fixed.line, n(3, 8), fixed.digest, signerId, observed);
  const protectedBytes = kind === 1
    ? join(common, n(1_700_000_100_000, 8), Uint8Array.of(1, fixed.peer.length), fixed.peer)
    : join(common, message, n(7, 8), Uint8Array.of(fixed.peer.length), fixed.peer);
  const header = join(utf8("ZTSE"), Uint8Array.of(1, kind, 0, 0), u16(protectedBytes.length));
  const cek = repeat(kind === 1 ? 0xc1 : 0xc2, 32);
  const nonce = repeat(kind === 1 ? 0xa5 : 0xa6, 12);
  const aad = join(utf8("ZTSE/body/v1\0"), header, protectedBytes);
  const plaintext = utf8(kind === 1 ? "Draft outbound ✉" : "Draft inbound ✓");
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const bodyCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 }, aes, plaintext));
  const recipientKeys = kind === 1 ? [[1, device], [2, archive]] : [[2, archive]];
  const wraps = [];
  const wrapTranscripts = [];
  for (const [role, recipient] of recipientKeys) {
    const info = join(utf8("ZTSE/wrap/v1\0"), sha(protectedBytes), Uint8Array.of(role), recipient.keyId);
    const wrapAad = join(utf8("ZTSE/wrap-aad/v1\0"), protectedBytes, Uint8Array.of(role), recipient.keyId);
    const ekm = repeat(role === 1 ? 0x51 : kind === 1 ? 0x52 : 0x53, 32);
    const sender = await suite.createSenderContext({ recipientPublicKey: recipient.pair.publicKey, info, ekm });
    const ct = new Uint8Array(await sender.seal(cek, wrapAad));
    wraps.push(join(Uint8Array.of(role), recipient.keyId, new Uint8Array(sender.enc), ct));
    wrapTranscripts.push({ role, keyIdHex: hex(recipient.keyId), infoHex: hex(info), aadHex: hex(wrapAad) });
  }
  const unsigned = join(header, protectedBytes, nonce, u32(bodyCt.length), bodyCt, Uint8Array.of(wraps.length), ...wraps);
  const transcript = join(utf8("ZTSE/sign/v1\0"), u32(unsigned.length), unsigned);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signer, transcript));
  if (signature.length !== 64) throw new Error("unexpected signature width");
  return {
    kind, plaintext: new TextDecoder().decode(plaintext), protectedHex: hex(protectedBytes),
    unsignedHex: hex(unsigned), signatureHex: hex(signature), envelopeHex: hex(join(unsigned, signature)),
    unsignedSha256: hex(sha(unsigned)), bodyAadHex: hex(aad), wrapTranscripts,
  };
}

const fixture = {
  status: "UNAPPROVED_DRAFT_01", source: "ZT-009 candidate profile, not a production contract",
  signerPublicPointHex: hex(signPoint),
  deviceIkmHex: hex(device.ikm), archiveIkmHex: hex(archive.ikm),
  accountIdHex: hex(fixed.account), deviceIdHex: hex(fixed.device), lineIdHex: hex(fixed.line),
  manifestDigestHex: hex(fixed.digest), peer: "+12",
  outbound: await envelope(1), inbound: await envelope(2),
};
const path = fileURLToPath(new URL("../../../protocol/v1/vectors/ztse-draft-01.json", import.meta.url));
writeFileSync(path, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(path);
