// SPDX-License-Identifier: AGPL-3.0-only
// Synthetic signed phone event and independently accepted root/manifest, no carrier path.
import { webcrypto, createECDH, createHash } from "node:crypto";
import { enrollRootPin02, verifyManifest02, verifiedManifestTrust02, canonicalSignature02 } from "../dist/draft02-manifest.js";
import { prepareInboundEnvelope02 } from "../dist/draft02-envelope-prep.js";
import { verifyOriginalReplySelection02 } from "../dist/original-reply-selection.js";
globalThis.crypto ??= webcrypto;
const enc = new TextEncoder(), hash = b => Uint8Array.from(createHash("sha256").update(b).digest());
export const join = (...parts) => Uint8Array.from(Buffer.concat(parts.map(b => Buffer.from(b))));
const u64 = n => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, n); return b; };
const text = s => join(Uint8Array.of(enc.encode(s).length), enc.encode(s));
function key(n) { const d = new Uint8Array(32); d[31] = n; const curve = createECDH("prime256v1"); curve.setPrivateKey(d); return { d, point: Uint8Array.from(curve.getPublicKey()) }; }
async function importKey(k, name, usages) { return crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: Buffer.from(k.point.subarray(1, 33)).toString("base64url"), y: Buffer.from(k.point.subarray(33)).toString("base64url"), d: Buffer.from(k.d).toString("base64url"), ext: false }, { name, namedCurve: "P-256" }, false, usages); }
async function sign(k, label, bytes) { const n = new Uint8Array(4); new DataView(n.buffer).setUint32(0, bytes.length); return canonicalSignature02(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, await importKey(k, "ECDSA", ["sign"]), join(enc.encode(label + "\0"), n, bytes)))); }
export async function originalReplyFixture({ observedMs = 2000n, currentMs = observedMs, canonicalIds = false, content = "synthetic original reply" } = {}) {
  const id = n => { const value = new Uint8Array(16).fill(n); if (canonicalIds) { value[6] = 0x40 | (value[6] & 15); value[8] = 0x80 | (value[8] & 63); } return value; };
  const now = 2000n, root = key(1), archive = key(3), phone = key(4), customer = key(6);
  const account = id(1), device = id(4), line = id(5), zero = new Uint8Array(16), previous = new Uint8Array(32).fill(9);
  const records = [{ role: 2, k: archive, scope: 12, device: zero, line: zero }, { role: 3, k: customer, scope: 8, device: zero, line: zero }, { role: 4, k: phone, scope: 2, device, line }, { role: 6, k: root, scope: 0, device: zero, line: zero }].map(r => ({ ...r, keyId: hash(join(enc.encode("ZTSE/key/v1\0"), Uint8Array.of(r.role <= 3 ? 0 : 1, r.role <= 3 ? 16 : 1), r.k.point)) }));
  const pinBytes = join(enc.encode("ZTRP"), Uint8Array.of(2), account, u64(1n), root.point);
  const pin = await enrollRootPin02(pinBytes, hash(join(enc.encode("ZTSE/root-pin/v2\0"), pinBytes)));
  // An independently established synthetic local high-water, never derived from a read response.
  const trust = { ...pin, version: 6n, digest: previous };
  const unsigned = join(enc.encode("ZTMA"), Uint8Array.of(2), account, u64(1n), u64(7n), u64(1000n), u64(100000n), previous, root.point, Uint8Array.of(records.length), ...records.map(r => join(Uint8Array.of(r.role), r.keyId, r.k.point, r.device, r.line, Uint8Array.of(0, r.scope), u64(1000n), u64(100000n), Uint8Array.of(1))));
  const manifest = await verifyManifest02(join(unsigned, await sign(root, "ZTSE/manifest/v2", unsigned)), trust, now);
  const archiveId = records[0].keyId, readerId = records[1].keyId, signerId = records[2].keyId;
  const scope = { account, device, line, interval: id(7), connector: id(8), readGrant: id(9), reader: readerId, peer: "+12" };
  const disclosure = "With your approval, ZROtext transfers encrypted SMS content for this selected phone line and conversation to your paired browser and the explicitly listed customer-controlled readers. Stop closes new capture and transfer; retained encrypted content is deleted separately.";
  const statement = join(enc.encode("ZTCA"), Uint8Array.of(2), account, device, line, u64(1n), scope.interval, id(10), id(11), new Uint8Array(32).fill(12), u64(5000n), text(scope.peer), text("conversation-content-v1"), hash(enc.encode(disclosure)), archiveId, signerId, u64(1n), u64(6n), previous, u64(7n), manifest.digest, u64(1n), u64(1n), text("fixture-site"), text("fixture-instance"), Uint8Array.of(1), scope.connector, scope.readGrant, readerId);
  const approval = await sign(phone, "zrotext/conversation/approve/v2", statement), installation = await sign(phone, "zrotext/conversation/install/v2", statement);
  const selection = await verifyOriginalReplySelection02(statement, approval, installation, manifest, now, scope);
  const event = id(13), prepared = await prepareInboundEnvelope02({ kind: 2, manifest, nowMs: observedMs, messageId: event, eventId: event, deviceId: device, lineId: line, peer: enc.encode(scope.peer), observedMs, localSequence: 1n, content, cek: new Uint8Array(32).fill(7), nonce: new Uint8Array(12).fill(8), signer: { privateKey: await importKey(phone, "ECDSA", ["sign"]), publicPoint: phone.point }, recipients: [{ role: 2, keyId: archiveId, point: archive.point, ekm: new Uint8Array(32).fill(14) }, { role: 3, keyId: readerId, point: customer.point, ekm: new Uint8Array(32).fill(15) }] });
  const authority = { ...scope, revision: "scope-current", expiresMs: 90000n, nowMs: currentMs, manifest };
  const successorUnsigned = unsigned.slice(); new DataView(successorUnsigned.buffer).setBigUint64(29, 8n); successorUnsigned.set(manifest.digest, 53);
  const successor = await verifyManifest02(join(successorUnsigned, await sign(root, "ZTSE/manifest/v2", successorUnsigned)), verifiedManifestTrust02(manifest, now), now);
  return { scope, manifest, successor, statement, approval, installation, selection, event, envelope: prepared.envelope, privateKey: await importKey(customer, "ECDH", ["deriveBits"]), archivePrivateKey: await importKey(archive, "ECDH", ["deriveBits"]), authority,
    signSelection: async bytes => ({ approval: await sign(phone, "zrotext/conversation/approve/v2", bytes), installation: await sign(phone, "zrotext/conversation/install/v2", bytes) }) };
}
