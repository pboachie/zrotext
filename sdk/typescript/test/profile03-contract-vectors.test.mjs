// SPDX-License-Identifier: AGPL-3.0-only
// Proposal-only cryptographic/encoding checks, NOT production authority adapters.
import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";
import { createHash, createPublicKey, ECDH, verify, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { enrollRootPin02, verifyManifest02 } from "../dist/draft02-manifest.js";

globalThis.crypto ??= webcrypto;
const vector = JSON.parse(readFileSync(new URL("../../../protocol/v1/vectors/sealed-profile03-contract-01.json", import.meta.url)));
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const MAX = (1n << 63n) - 1n;
const hex = (value) => {
  assert.equal(typeof value, "string");
  assert.match(value, /^(?:[0-9a-f]{2})+$/);
  return Buffer.from(value, "hex");
};
const sha = (value) => createHash("sha256").update(value).digest();
const label = (value) => { assert(!value.includes("\0") && /^[\x01-\x7f]+$/.test(value), "unterminated ASCII domain"); return Buffer.from(value + "\0", "ascii"); };
const u32 = (value) => { const b = Buffer.alloc(4); b.writeUInt32BE(value); return b; };
const u64 = (value) => {
  assert(typeof value === "bigint" || (typeof value === "number" && Number.isSafeInteger(value)), "exact integer before BigInt conversion");
  const n = BigInt(value); assert(n > 0n && n <= MAX);
  const b = Buffer.alloc(8); b.writeBigUInt64BE(n); return b;
};
const framed = (domain, bytes) => Buffer.concat([label(domain), u32(bytes.length), bytes]);
const integer = (bytes) => BigInt("0x" + bytes.toString("hex"));
const nonzero = (bytes) => assert(bytes.some((b) => b !== 0));
const point = (bytes) => {
  assert.equal(bytes.length, 65); assert.equal(bytes[0], 4);
  assert.deepEqual(ECDH.convertKey(bytes, "prime256v1", undefined, undefined, "uncompressed"), bytes);
  return createPublicKey({ key: { kty: "EC", crv: "P-256", x: bytes.subarray(1, 33).toString("base64url"), y: bytes.subarray(33).toString("base64url") }, format: "jwk" });
};
const keyId = (role, bytes) => sha(Buffer.concat([label("ZTSE/key/v1"), Buffer.from(role <= 3 ? [0, 16] : [1, 1]), bytes]));
function signature(key, transcript, raw) {
  assert.equal(raw.length, 64);
  const r = integer(raw.subarray(0, 32)), s = integer(raw.subarray(32));
  assert(r > 0n && r < N && s > 0n && s <= N / 2n, "strict low-s scalar range");
  assert(verify("sha256", transcript, { key: point(key), dsaEncoding: "ieee-p1363" }, raw), "signature verification");
}
function read64(bytes, at, positive = true) {
  const n = bytes.readBigUInt64BE(at); assert(n <= MAX && (!positive || n > 0n)); return n;
}
const equal = (a, b) => assert.deepEqual(a, b);
const mutation = (bytes, at) => { const b = Buffer.from(bytes); b[at] ^= 1; return b; };
function highS(raw) {
  const result = Buffer.from(raw);
  Buffer.from((N - integer(raw.subarray(32))).toString(16).padStart(64, "0"), "hex").copy(result, 32);
  return result;
}

// Test-only contract decoder. It does not create an SDK trusted object, persist
// authority or validate current server/phone session, binding or grant state.
function manifest03(bytes, expected, now = BigInt(vector.nowMs)) {
  assert(bytes.length >= 366 && bytes.length <= 9753, "manifest bound");
  equal(bytes.subarray(0, 6), Buffer.from("5a544d410303", "hex"));
  const previousProfile = bytes[6], count = bytes[152];
  assert([0, 2, 3].includes(previousProfile) && count >= 1 && count <= 64);
  assert.equal(bytes.length, 217 + 149 * count);
  const account = bytes.subarray(7, 23), generation = read64(bytes, 23), version = read64(bytes, 31);
  const issued = read64(bytes, 39), expires = read64(bytes, 47), previous = bytes.subarray(55, 87);
  const rootPoint = bytes.subarray(87, 152), unsigned = bytes.subarray(0, -64), digest = sha(unsigned);
  nonzero(account); equal(account, expected.account); equal(rootPoint, expected.root);
  assert.equal(generation, expected.generation);
  assert(now > 0n && now <= MAX && issued <= now + 300000n && now < expires && expires > issued && expires - issued <= 86400000n);
  signature(rootPoint, framed("ZTSE/manifest/v3", unsigned), bytes.subarray(-64));
  let last, roots = 0, archives = 0;
  const seen = new Set(), records = [];
  for (let i = 0; i < count; i++) {
    const r = bytes.subarray(153 + 149 * i, 302 + 149 * i);
    const role = r[0], id = r.subarray(1, 33), pub = r.subarray(33, 98);
    const device = r.subarray(98, 114), line = r.subarray(114, 130), scope = r.readUInt16BE(130);
    const from = read64(r, 132, false), until = read64(r, 140, false), state = r[148];
    assert(role >= 1 && role <= 6 && [1, 2].includes(state) && from <= until);
    point(pub); equal(id, keyId(role, pub));
    const ordering = r.subarray(0, 33);
    assert(!last || Buffer.compare(last, ordering) < 0); last = ordering;
    const pubHex = pub.toString("hex"); assert(!seen.has(pubHex)); seen.add(pubHex);
    const dz = device.every((b) => b === 0), lz = line.every((b) => b === 0);
    const subjects = role === 1 ? scope === 4 && !dz && !lz
      : role === 2 ? scope === 12 && dz && lz
      : role === 3 ? [4, 8, 12].includes(scope) && dz && lz
      : role === 4 ? scope === 2 && !dz && !lz
      : role === 5 ? scope === 1 && dz && !lz : scope === 0 && dz && lz;
    assert(subjects, "role/scope/subject");
    if (role === 6) { roots++; equal(pub, rootPoint); assert(state === 1 && from <= issued && until >= expires); }
    if (role === 2 && state === 1) archives++;
    records.push({ role, id, pub, device, line, scope, from, until, state });
  }
  assert.equal(roots, 1); assert.equal(archives, 1);
  if (expected.kind === "genesis-contract-only") {
    assert.equal(expected.authorityAbsent, true); assert.equal(generation, 1n); assert.equal(version, 1n);
    assert.equal(previousProfile, 0); equal(previous, Buffer.alloc(32));
  } else if (expected.kind === "current") {
    assert.equal(expected.profile, 3); assert.equal(version, expected.version);
    equal(digest, expected.digest); assert.equal(previousProfile, expected.previousProfile);
  } else {
    assert.equal(previousProfile, expected.profile);
    assert([2, 3].includes(expected.profile) && expected.version > 0n && expected.version < MAX);
    assert.equal(version, expected.version + 1n); equal(previous, expected.digest);
  }
  return { digest, version, generation, account, root: rootPoint, records, previousProfile };
}
const manifests = vector.manifests;
const trusted02 = { account: hex(vector.identitiesHex.account), root: hex(vector.publicPointsHex.root), generation: 1n, kind: "after", profile: 2, version: 1n, digest: hex(manifests.prior02.semanticDigestHex) };
const successor = () => manifest03(hex(manifests.successor03.signedHex), trusted02);

function core03(core) {
  assert.equal(core.length, 500);
  equal(core.subarray(0, 8), Buffer.from("5a54504503010203", "hex"));
  for (const at of [8, 24, 40, 56, 72]) nonzero(core.subarray(at, at + 16));
  for (const at of [88, 96, 168, 176, 216, 384, 392]) read64(core, at);
  assert(read64(core, 96) > read64(core, 88));
  assert.equal(read64(core, 216), read64(core, 176) + 1n);
  const issued = read64(core, 384), expires = read64(core, 392), now = BigInt(vector.nowMs);
  assert(issued <= now && now < expires && expires - issued <= 300000n);
  for (const at of [104, 136, 184, 224, 256, 288, 320, 352, 400, 432, 464]) nonzero(core.subarray(at, at + 32));
  equal(core.subarray(496), Buffer.alloc(4));
}
function election03(bundle) {
  assert.equal(bundle.length, 628);
  const core = bundle.subarray(0, 500), device = bundle.subarray(500, 564), owner = bundle.subarray(564);
  core03(core);
  signature(hex(vector.publicPointsHex.deviceEnrollment), framed("ZTSE/line/payload-profile/device/v1", core), device);
  signature(hex(vector.publicPointsHex.ownerApproval), framed("ZTSE/line/payload-profile/owner/v1", Buffer.concat([core, sha(device)])), owner);
  equal(core.subarray(8, 24), trusted02.account);
  equal(core.subarray(184, 216), trusted02.digest); equal(core.subarray(224, 256), successor().digest);
  equal(core.subarray(136, 168), hex(vector.rootFingerprintHex));
  equal(core.subarray(256, 288), keyId(1, hex(vector.publicPointsHex.payload)));
  equal(core.subarray(288, 320), keyId(4, hex(vector.publicPointsHex.deviceEnrollment)));
  equal(core.subarray(320, 352), keyId(6, hex(vector.publicPointsHex.ownerApproval)));
  return core;
}
function digest(value) {
  assert.equal(typeof value, "string"); assert.match(value, /^[A-Za-z0-9_-]{43}$/);
  const b = Buffer.from(value, "base64url"); assert.equal(b.length, 32); assert.equal(b.toString("base64url"), value); return b;
}
function uuid(value) {
  assert.match(value, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  const b = Buffer.from(value.replaceAll("-", ""), "hex"); nonzero(b); return b;
}
const idFields = ["account_id", "device_id", "line_id", "message_id", "attempt_id"];
const numberFields = ["connection_epoch", "deployment_epoch", "binding_generation", "attempt_generation", "expires_at_ms", "trust_generation", "manifest_version"];
const digestFields = ["reader_key_id", "envelope_sha256", "unsigned_sha256", "manifest_digest", "root_fingerprint", "election_digest"];
const fixed = { v: 1, type: "sealed_execution_grant", grant_version: 3, envelope_profile: 3, manifest_profile: 3, reader_role: 1 };
function fetch03(frame) {
  equal(Object.keys(frame).sort(), [...Object.keys(fixed), ...idFields, ...numberFields, ...digestFields, "segment_count"].sort());
  for (const [key, value] of Object.entries(fixed)) assert.equal(frame[key], value);
  assert(Number.isInteger(frame.segment_count) && frame.segment_count >= 1 && frame.segment_count <= 6);
  for (const key of numberFields) assert(Number.isSafeInteger(frame[key]));
  return Buffer.concat([label("ZT/sealed-envelope-fetch/v3"), Buffer.from([1, 3, 3, 3, 1, frame.segment_count]), ...idFields.map((k) => uuid(frame[k])), ...numberFields.map((k) => u64(frame[k])), ...digestFields.map((k) => digest(frame[k]))]);
}
function ready03(frame) {
  const numbers = ["connection_epoch", "deployment_epoch", "binding_generation", "trust_generation", "manifest_version"];
  const digests = ["reader_key_id", "manifest_digest", "root_fingerprint", "election_digest"];
  const header = { v: 1, type: "sealed_ready", grant_version: 3, envelope_profile: 3, manifest_profile: 3 };
  equal(Object.keys(frame).sort(), [...Object.keys(header), ...numbers, ...digests, "line_id"].sort());
  for (const [key, value] of Object.entries(header)) assert.equal(frame[key], value);
  uuid(frame.line_id);
  for (const key of numbers) { assert(Number.isSafeInteger(frame[key])); u64(frame[key]); }
  for (const key of digests) digest(frame[key]);
  // Wire grammar only; no authenticated session or currentness is manufactured.
}
function rawDer(encoded) {
  assert.equal(typeof encoded, "string"); assert.match(encoded, /^[A-Za-z0-9_-]+$/);
  const b = Buffer.from(encoded, "base64url"); assert.equal(b.toString("base64url"), encoded);
  assert(b.length >= 8 && b.length <= 71 && b[0] === 0x30 && b[1] === b.length - 2);
  let at = 2;
  const scalar = () => {
    assert.equal(b[at++], 2); const count = b[at++]; assert(count >= 1 && count <= 33 && at + count <= b.length);
    let n = b.subarray(at, at + count); at += count;
    assert(!(n[0] & 128) && (count === 1 || n[0] !== 0 || (n[1] & 128)), "minimal positive DER");
    if (n[0] === 0) n = n.subarray(1);
    assert(n.length >= 1 && n.length <= 32); return Buffer.concat([Buffer.alloc(32 - n.length), n]);
  };
  const r = scalar(), s = scalar(); assert.equal(at, b.length); return Buffer.concat([r, s]);
}

test("independent signed02 predecessor and root pin authenticate the proposed03 chain", async () => {
  assert.throws(() => framed("ZTSE/manifest/v3\0", Buffer.alloc(1)), /unterminated ASCII/);
  const pin = hex(vector.rootPinHex), fingerprint = hex(vector.rootFingerprintHex);
  equal(sha(Buffer.concat([label("ZTSE/root-pin/v2"), pin])), fingerprint);
  const trust = await enrollRootPin02(pin, fingerprint);
  const prior = await verifyManifest02(hex(manifests.prior02.signedHex), trust, BigInt(vector.nowMs));
  equal(Buffer.from(prior.digest), trusted02.digest);
  const current = successor(); equal(current.digest, hex(manifests.successor03.semanticDigestHex));
  const after = manifest03(hex(manifests.after03.signedHex), { ...trusted02, profile: 3, version: 2n, digest: current.digest });
  assert.equal(after.version, 3n);
  manifest03(hex(manifests.genesis03ContractOnly.signedHex), { ...trusted02, kind: "genesis-contract-only", authorityAbsent: true });
  assert.throws(() => manifest03(hex(manifests.genesis03ContractOnly.signedHex), { ...trusted02, kind: "genesis-contract-only", authorityAbsent: false }));
});

test("03 chain refuses second genesis, forks, rollback, wrong root/account and malformed bounds", () => {
  const b = hex(manifests.successor03.signedHex), current = successor();
  const expected = { ...trusted02, kind: "current", profile: 3, version: 2n, digest: current.digest, previousProfile: 2 };
  manifest03(b, expected);
  const alternate = hex(manifests.alternateSignature03.signedHex);
  equal(manifest03(alternate, expected).digest, current.digest);
  assert.notDeepEqual(alternate, b, "same semantic identity does not authorize replacing stored signed evidence");
  for (const [bytes, trust] of [
    [hex(manifests.genesis03ContractOnly.signedHex), trusted02],
    [hex(manifests.sameVersionFork03.signedHex), expected],
    [b, { ...trusted02, version: 3n }], [b, { ...trusted02, profile: 3 }],
    [b, { ...trusted02, root: hex(vector.publicPointsHex.signer) }],
    [b, { ...trusted02, account: hex(vector.identitiesHex.device) }],
    [mutation(b, 55), trusted02], [mutation(b, 7), trusted02],
    [b.subarray(0, -1), trusted02], [Buffer.concat([b, Buffer.alloc(1)]), trusted02],
    [Buffer.alloc(9754), trusted02], [mutation(b, 152), trusted02],
  ]) assert.throws(() => manifest03(bytes, trust));
  assert.throws(() => manifest03(b, trusted02, BigInt(vector.nowMs) + 3600000n));
  assert.throws(() => manifest03(b, trusted02, 1n));
  const high = Buffer.from(b); highS(b.subarray(-64)).copy(high, b.length - 64);
  assert.throws(() => manifest03(high, trusted02), /low-s/);
  assert.throws(() => signature(hex(vector.publicPointsHex.ownerApproval), framed("ZTSE/manifest/v3", b.subarray(0, -64)), b.subarray(-64)));
});

test("owner election binds exact core and device proof with distinct signing keys/domains", () => {
  const e = vector.election, bundle = hex(e.bundleHex), core = election03(bundle);
  equal(core, hex(e.coreHex));
  equal(framed("ZTSE/line/payload-profile/device/v1", core), hex(e.deviceTranscriptHex));
  equal(framed("ZTSE/line/payload-profile/owner/v1", Buffer.concat([core, sha(bundle.subarray(500, 564))])), hex(e.ownerTranscriptHex));
  equal(sha(framed("ZTSE/line/payload-profile/commitment/v1", core)), hex(e.semanticCommitmentHex));
  // Every semantic field changes the signed bytes; representative offsets span
  // every fixed field (the combined operation/profile header is checked bytewise).
  for (const at of [0, 5, 6, 7, 8, 24, 40, 56, 72, 88, 96, 104, 136, 168, 176, 184, 216, 224, 256, 288, 320, 352, 384, 392, 400, 432, 464, 496, 500, 564]) assert.throws(() => election03(mutation(bundle, at)));
  assert.throws(() => election03(bundle.subarray(0, -1)));
  assert.throws(() => election03(Buffer.concat([bundle, Buffer.alloc(1)])));
  const substituted = Buffer.from(bundle); highS(bundle.subarray(500, 564)).copy(substituted, 500);
  assert.throws(() => election03(substituted), /low-s/);
  assert.throws(() => signature(hex(vector.publicPointsHex.deviceEnrollment), hex(e.ownerTranscriptHex), hex(e.ownerSignatureHex)));
  assert.throws(() => signature(hex(vector.publicPointsHex.ownerApproval), framed("ZTSE/line/payload-profile/device/v1", core), hex(e.ownerSignatureHex)));
  // Isolate the owner's commitment even from the earlier device low-s check:
  // the mathematically valid high-s twin changes the EXACT raw proof digest.
  assert.throws(() => signature(hex(vector.publicPointsHex.ownerApproval), framed("ZTSE/line/payload-profile/owner/v1", Buffer.concat([core, sha(highS(bundle.subarray(500, 564)))])), hex(e.ownerSignatureHex)));
});

test("closed03 grant signed fetch binds all fields and refuses noncanonical DER/base64/UUID", () => {
  const frame = vector.grant.frame, transcript = fetch03(frame), raw = rawDer(vector.grant.signatureDerBase64url);
  assert.equal(transcript.length, 362); equal(transcript, hex(vector.grant.transcriptHex));
  ready03(vector.readyFrame);
  assert.equal(Object.keys(vector.readyFrame).length, 15);
  for (const key of Object.keys(vector.readyFrame)) assert.equal(vector.readyFrame[key], key === "type" ? "sealed_ready" : frame[key], "synthetic readiness/grant fixture identities agree; no live session is inferred");
  for (const [key, value] of [["v", 2], ["type", "sealed_execution_grant"], ["manifest_profile", 2], ["line_id", null], ["connection_epoch", "2"], ["binding_generation", 2 ** 53], ["reader_key_id", frame.reader_key_id + "="], ["unknown", 1]]) assert.throws(() => ready03({ ...vector.readyFrame, [key]: value }));
  const missingReadyHeader = { ...vector.readyFrame }; delete missingReadyHeader.type;
  assert.throws(() => ready03(missingReadyHeader));
  assert.equal(u64(MAX).toString("hex"), "7fffffffffffffff", "binary BigInt bound is exact");
  assert.throws(() => u64(MAX + 1n));
  assert.throws(() => u64(2 ** 53), /exact integer/);
  for (const value of [2 ** 53, Number(MAX), "7", 1.5, 0, -1]) assert.throws(() => fetch03({ ...frame, attempt_generation: value }), "JSON numeric subset cannot use unsafe Numbers or numeric-string substitutes");
  const pub = hex(vector.publicPointsHex.deviceEnrollment); signature(pub, transcript, raw);
  for (const key of [...idFields, ...numberFields, ...digestFields, "segment_count", ...Object.keys(fixed)]) {
    const changed = { ...frame };
    changed[key] = idFields.includes(key) ? frame[key].replace(/^./, frame[key][0] === "f" ? "e" : "f")
      : digestFields.includes(key) ? mutation(digest(frame[key]), 0).toString("base64url")
      : typeof frame[key] === "number" ? frame[key] + 1 : "other";
    assert.throws(() => signature(pub, fetch03(changed), raw));
    const missing = { ...frame }; delete missing[key]; assert.throws(() => fetch03(missing));
  }
  assert.throws(() => fetch03({ ...frame, unknown: 1 }));
  for (const value of [frame.account_id.toUpperCase(), frame.account_id.replaceAll("-", ""), "00000000-0000-0000-0000-000000000000"]) assert.throws(() => fetch03({ ...frame, account_id: value }));
  for (const value of [frame.reader_key_id + "=", frame.reader_key_id.slice(1)]) assert.throws(() => fetch03({ ...frame, reader_key_id: value }));
  for (const value of [vector.grant.signatureDerBase64url + "=", Buffer.concat([Buffer.from(vector.grant.signatureDerBase64url, "base64url"), Buffer.alloc(1)]).toString("base64url"), "MAA", "MAYCAQACAQE"]) assert.throws(() => signature(pub, transcript, rawDer(value)));
  const der = Buffer.from(vector.grant.signatureDerBase64url, "base64url");
  assert.throws(() => rawDer(mutation(der, 1).toString("base64url")));
  assert.throws(() => signature(pub, transcript, highS(raw)), /low-s/);
  assert.throws(() => signature(pub, Buffer.concat([label("ZT/sealed-envelope-fetch/v1"), transcript.subarray(28)]), raw));
});

test("fresh-memory HPKE strict03 context opens once and rejects empty/changed AAD or wrong info", async () => {
  const c = vector.hpkeContext, header = hex(c.headerHex), protectedBytes = hex(c.protectedHex);
  const suffix = Buffer.concat([header, protectedBytes, Buffer.from([c.recipientRole]), hex(c.recipientKeyIdHex)]);
  const info = Buffer.concat([label("ZTSE/wrap/v3"), suffix]), aad = Buffer.concat([label("ZTSE/wrap-aad/v3"), suffix]);
  equal(info, hex(c.infoHex)); equal(aad, hex(c.aadHex));
  equal(Buffer.concat([label("ZTSE/body/v3"), header, protectedBytes]), hex(c.bodyAadHex));
  assert(info.length > 0 && aad.length > 0 && !info.equals(aad));
  const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() });
  const recipient = await suite.kem.generateKeyPair();
  // The fresh component recipient has its own correct point-derived identity;
  // fixture manifest/session authority is deliberately NOT installed or claimed.
  const freshId = keyId(1, Buffer.from(await suite.kem.serializePublicKey(recipient.publicKey)));
  const freshSuffix = Buffer.concat([header, protectedBytes, Buffer.from([1]), freshId]);
  const freshInfo = Buffer.concat([label("ZTSE/wrap/v3"), freshSuffix]);
  const freshAad = Buffer.concat([label("ZTSE/wrap-aad/v3"), freshSuffix]);
  const cek = webcrypto.getRandomValues(new Uint8Array(32));
  try {
    const sender = await suite.createSenderContext({ recipientPublicKey: recipient.publicKey, info: freshInfo });
    const ct = await sender.seal(cek, freshAad); assert.equal(sender.enc.byteLength, 65); assert.equal(ct.byteLength, 48);
    const receiver = async (contextInfo) => suite.createRecipientContext({ recipientKey: recipient.privateKey, enc: sender.enc, info: contextInfo });
    equal(Buffer.from(await (await receiver(freshInfo)).open(ct, freshAad)), Buffer.from(cek));
    for (const [badInfo, badAad] of [[freshInfo, Buffer.alloc(0)], [freshInfo, mutation(freshAad, 0)], [mutation(freshInfo, 0), freshAad], [Buffer.concat([label("ZTSE/wrap/v2"), freshSuffix]), freshAad]]) await assert.rejects(async () => (await receiver(badInfo)).open(ct, badAad));
    await assert.rejects(async () => (await receiver(freshInfo)).open(mutation(Buffer.from(ct), 0), freshAad));
  } finally { cek.fill(0); }
});

test("independent Python complete-byte reconstruction runs in the existing Node CI discovery", () => {
  const script = fileURLToPath(new URL("../../../protocol/v1/tests/test_sealed_profile03_contract_vectors.py", import.meta.url));
  const cwd = fileURLToPath(new URL("../../../", import.meta.url));
  const python = process.platform === "win32" ? "python" : "python3";
  const options = { cwd, timeout: 30000, maxBuffer: 1024 * 1024, stdio: "pipe" };
  execFileSync(python, ["-B", script], options);
  assert.throws(() => execFileSync(python, ["-B", script, "--unknown-contract-test-option"], options), (error) => error.status === 2, "Python failure must propagate through the discovered Node test");
});
