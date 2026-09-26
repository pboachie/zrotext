// Test-only full profile-02 outbound envelope from independent browser primitives to Android.
import { execFile } from "node:child_process";
import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { promisify } from "node:util";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { canonicalSignature02 } from "../dist/draft02-manifest.js";

globalThis.crypto ??= webcrypto;
const exec = promisify(execFile);
const sdk = process.env.ANDROID_HOME;
if (!sdk) throw new Error("ANDROID_HOME is required");
const serial = process.env.ANDROID_SERIAL || "emulator-5554";
if (!/^emulator-\d+$/.test(serial)) throw new Error("Only an AVD emulator serial is allowed");
const platformTools = join(sdk, "platform-tools");
const adbEnv = { ...process.env };
const pathKey = Object.keys(adbEnv).find((key) => key.toLowerCase() === "path") ?? "PATH";
adbEnv[pathKey] = `${platformTools}${delimiter}${adbEnv[pathKey] ?? ""}`;
const runner = "org.zrotext.gateway.test/androidx.test.runner.AndroidJUnitRunner";
const testClass = "org.zrotext.gateway.Draft02EnvelopeDeviceTest";
const hex = (value) => Buffer.from(value).toString("hex");
const bytes = (value) => Uint8Array.from(Buffer.from(value, "hex"));
const ascii = (value) => new TextEncoder().encode(value);
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((part) => Buffer.from(part))));
const sha256 = (value) => Uint8Array.from(createHash("sha256").update(value).digest());
const u16 = (value) => Uint8Array.of(value >>> 8, value & 255);
const u32 = (value) => Uint8Array.of(value >>> 24, value >>> 16, value >>> 8, value);
const u64 = (value) => { const out = new Uint8Array(8); new DataView(out.buffer).setBigUint64(0, BigInt(value), false); return out; };
const arrayBuffer = (value) => Uint8Array.from(value).buffer;
const p256Order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const scalar = (value) => value.reduce((n, b) => (n << 8n) | BigInt(b), 0n);
function fixed32(value) {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(value & 255n); value >>= 8n; }
  return out;
}
function highSTwin(low) {
  return concat(low.subarray(0, 32), fixed32(p256Order - scalar(low.subarray(32))));
}

async function adbCall(...args) {
  return (await exec("adb", ["-s", serial, ...args], {
    env: adbEnv,
    maxBuffer: 1024 * 1024,
  })).stdout.trim();
}
async function instrument(method, extras = {}) {
  const args = ["shell", "am", "instrument", "-w", "-e", "class", `${testClass}#${method}`,
    "-e", "m2_draft02_envelope_host_driver", "1"];
  for (const [name, value] of Object.entries(extras)) args.push("-e", name, value);
  const output = await adbCall(...args, runner);
  if (!output.includes("OK (1 test)")) throw new Error(`${method} failed:\n${output}`);
  return output;
}

if (await adbCall("shell", "getprop", "ro.kernel.qemu") !== "1") {
  throw new Error("Refusing to run outside an emulator");
}
if (Number(await adbCall("shell", "getprop", "ro.build.version.sdk")) < 31) {
  throw new Error("API 31+ is required for Keystore ECDH");
}

const suite = new CipherSuite({
  kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm(),
});
const fixture = JSON.parse(readFileSync(new URL("../../../protocol/v1/vectors/ztse-draft-01.json", import.meta.url)));
const fixtureProtected = bytes(fixture.outbound.protectedHex);
if (fixtureProtected.length !== 157) throw new Error("Unexpected public fixture shape");
const header = concat(ascii("ZTSE"), Uint8Array.of(2, 1, 0, 0), u16(fixtureProtected.length));
const signerPoint = bytes(fixture.signerPublicPointHex);
const signerScalar = new Uint8Array(32); signerScalar[31] = 5; // Public deterministic fixture only.
const b64url = (value) => Buffer.from(value).toString("base64url");
const signer = await crypto.subtle.importKey("jwk", {
  kty: "EC", crv: "P-256", x: b64url(signerPoint.subarray(1, 33)),
  y: b64url(signerPoint.subarray(33)), d: b64url(signerScalar), ext: true, key_ops: ["sign"],
}, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);

async function signWith(key, label, unsigned) {
  const transcript = concat(ascii(`${label}\0`), u32(unsigned.length), unsigned);
  return canonicalSignature02(new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, key, arrayBuffer(transcript))));
}
async function signed(unsigned) { return concat(unsigned, await signWith(signer, "ZTSE/sign/v2", unsigned)); }

try {
  const prepared = await instrument("prepareRecipient");
  const pointHex = prepared.match(/m2_draft02_envelope_recipient_point_hex=([0-9a-f]{130})/)?.[1];
  if (!pointHex) throw new Error("No recipient public point returned");
  const devicePoint = bytes(pointHex);
  const devicePublicKey = await suite.kem.deserializePublicKey(arrayBuffer(devicePoint));
  const deviceKeyId = sha256(concat(ascii("ZTSE/key/v1\0"), Uint8Array.of(0, 16), devicePoint));

  const archivePair = await suite.kem.deriveKeyPair(bytes(fixture.archiveIkmHex));
  const archivePoint = new Uint8Array(await suite.kem.serializePublicKey(archivePair.publicKey));
  const archiveKeyId = sha256(concat(ascii("ZTSE/key/v1\0"), Uint8Array.of(0, 16), archivePoint));
  if (hex(archiveKeyId) !== fixture.outbound.wrapTranscripts[1].keyIdHex) {
    throw new Error("Archive fixture identity mismatch");
  }

  const now = BigInt(Date.now());
  const root = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const attacker = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const rootPoint = new Uint8Array(await crypto.subtle.exportKey("raw", root.publicKey));
  const accountId = fixtureProtected.subarray(0, 16);
  const deviceId = fixtureProtected.subarray(32, 48);
  const lineId = fixtureProtected.subarray(48, 64);
  const rootPin = concat(ascii("ZTRP"), Uint8Array.of(2), accountId, u64(1), rootPoint);
  const rootFingerprint = sha256(concat(ascii("ZTSE/root-pin/v2\0"), rootPin));
  const signerKeyId = sha256(concat(ascii("ZTSE/key/v1\0"), Uint8Array.of(1, 1), signerPoint));
  if (hex(signerKeyId) !== hex(fixtureProtected.subarray(104, 136))) {
    throw new Error("Signer fixture identity mismatch");
  }

  async function buildManifest({ issued = now - 1_000n, expires = now + 3_600_000n,
                                 signerState = 1, signerScope = 1, signerLine = lineId,
                                 signingKey = root.privateKey,
                                 manifestRootPoint = rootPoint, generation = 1n,
                                 previousDigest = new Uint8Array(32) } = {}) {
    const records = [
      { role: 1, id: deviceKeyId, point: devicePoint, device: deviceId, line: lineId, scope: 4, state: 1 },
      { role: 2, id: archiveKeyId, point: archivePoint, device: new Uint8Array(16), line: new Uint8Array(16), scope: 12, state: 1 },
      { role: 5, id: signerKeyId, point: signerPoint, device: new Uint8Array(16), line: signerLine, scope: signerScope, state: signerState },
      { role: 6, id: sha256(concat(ascii("ZTSE/key/v1\0"), Uint8Array.of(1, 1), manifestRootPoint)),
        point: manifestRootPoint, device: new Uint8Array(16), line: new Uint8Array(16), scope: 0, state: 1 },
    ];
    const unsigned = concat(ascii("ZTMA"), Uint8Array.of(2), accountId, u64(generation), u64(1),
      u64(issued), u64(expires), previousDigest, manifestRootPoint, Uint8Array.of(records.length),
      ...records.map((r) => concat(Uint8Array.of(r.role), r.id, r.point, r.device, r.line,
        u16(r.scope), u64(issued), u64(expires), Uint8Array.of(r.state))));
    return { bytes: concat(unsigned, await signWith(signingKey, "ZTSE/manifest/v2", unsigned)),
      digest: sha256(unsigned) };
  }
  const manifest = await buildManifest();
  const staleManifest = await buildManifest({ issued: now - 7_200_000n, expires: now - 1n });
  const forgedManifest = await buildManifest({ signingKey: attacker.privateKey });
  const forkManifest = await buildManifest({ issued: now - 2_000n });
  const revokedManifest = await buildManifest({ signerState: 2 });
  const wrongScopeManifest = await buildManifest({ signerScope: 2 });
  const wrongLineManifest = await buildManifest({ signerLine: Uint8Array.from(deviceId) });
  const zeroLineManifest = await buildManifest({ signerLine: new Uint8Array(16) });
  const rotatedRoot = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const rotatedRootPoint = new Uint8Array(await crypto.subtle.exportKey("raw", rotatedRoot.publicKey));
  const transitionUnsigned = concat(ascii("ZTRT"), Uint8Array.of(2), accountId,
    u64(1), u64(2), rootPoint, rotatedRootPoint, manifest.digest,
    u64(now - 1_000n), u64(now + 3_600_000n));
  const transition = concat(transitionUnsigned,
    await signWith(root.privateKey, "ZTSE/root-transition/v2", transitionUnsigned),
    await signWith(rotatedRoot.privateKey, "ZTSE/root-transition/v2", transitionUnsigned));
  const forgedTransition = concat(transitionUnsigned,
    await signWith(root.privateKey, "ZTSE/root-transition/v2", transitionUnsigned),
    await signWith(attacker.privateKey, "ZTSE/root-transition/v2", transitionUnsigned));
  const rotatedManifest = await buildManifest({ signingKey: rotatedRoot.privateKey,
    manifestRootPoint: rotatedRootPoint, generation: 2n, previousDigest: sha256(transitionUnsigned) });
  const protectedBytes = Uint8Array.from(fixtureProtected);
  protectedBytes.set(u64(1), 64);
  protectedBytes.set(manifest.digest, 72);
  const revokedProtected = Uint8Array.from(protectedBytes);
  revokedProtected.set(revokedManifest.digest, 72);
  const wrongLineProtected = Uint8Array.from(protectedBytes);
  wrongLineProtected.set(wrongLineManifest.digest, 72);
  const cek = new Uint8Array(32).fill(0xc2);
  const bodyKey = await crypto.subtle.importKey("raw", arrayBuffer(cek), "AES-GCM", false, ["encrypt"]);

  async function wrap(role, keyId, recipientPublicKey, context = protectedBytes) {
    const info = concat(ascii("ZTSE/wrap/v2\0"), header, context, Uint8Array.of(role), keyId);
    const sender = await suite.createSenderContext({ recipientPublicKey, info: arrayBuffer(info) });
    const ct = new Uint8Array(await sender.seal(arrayBuffer(cek), new Uint8Array()));
    const enc = new Uint8Array(sender.enc);
    if (info.length !== 213 || enc.length !== 65 || ct.length !== 48) {
      throw new Error("Unexpected draft-02 HPKE transcript or wrap size");
    }
    return concat(Uint8Array.of(role), keyId, enc, ct);
  }
  async function buildEnvelope(context, nonceByte) {
    const nonce = new Uint8Array(12).fill(nonceByte);
    const bodyAad = concat(ascii("ZTSE/body/v2\0"), header, context);
    const body = new Uint8Array(await crypto.subtle.encrypt({
      name: "AES-GCM", iv: arrayBuffer(nonce), additionalData: arrayBuffer(bodyAad), tagLength: 128,
    }, bodyKey, arrayBuffer(ascii("Draft02 outbound ✓"))));
    const unsigned = concat(header, context, nonce, u32(body.length), body,
      Uint8Array.of(2), await wrap(1, deviceKeyId, devicePublicKey, context),
      await wrap(2, archiveKeyId, archivePair.publicKey, context));
    return { nonce, body, unsigned, envelope: await signed(unsigned) };
  }
  const normal = await buildEnvelope(protectedBytes, 0xa8);
  const revoked = await buildEnvelope(revokedProtected, 0xa9);
  const wrongLine = await buildEnvelope(wrongLineProtected, 0xaa);
  const { nonce, body, unsigned, envelope } = normal;
  const nonceMutantUnsigned = Uint8Array.from(unsigned);
  nonceMutantUnsigned[header.length + protectedBytes.length] ^= 1;
  const nonceMutant = await signed(nonceMutantUnsigned);
  const manifestMutantUnsigned = Uint8Array.from(unsigned);
  manifestMutantUnsigned[header.length + 72] ^= 1;
  const manifestMutant = await signed(manifestMutantUnsigned);
  // Keep the old body ciphertext, but rewrap the CEK and sign for a changed message ID.
  // HPKE must open; the nonempty body AAD must then reject the altered Protected bytes.
  const changedProtected = Uint8Array.from(protectedBytes);
  changedProtected[16] ^= 1;
  const bodyAadMutantUnsigned = concat(header, changedProtected, nonce, u32(body.length), body,
    Uint8Array.of(2),
    await wrap(1, deviceKeyId, devicePublicKey, changedProtected),
    await wrap(2, archiveKeyId, archivePair.publicKey, changedProtected));
  const bodyAadMutant = await signed(bodyAadMutantUnsigned);
  const highSEnvelope = Uint8Array.from(envelope);
  highSEnvelope.set(highSTwin(highSEnvelope.subarray(highSEnvelope.length - 64)), highSEnvelope.length - 64);

  const opened = await instrument("openBrowserEnvelopeAndDenyMutations", {
    m2_draft02_root_pin_hex: hex(rootPin),
    m2_draft02_root_fingerprint_hex: hex(rootFingerprint),
    m2_draft02_manifest_hex: hex(manifest.bytes),
    m2_draft02_stale_manifest_hex: hex(staleManifest.bytes),
    m2_draft02_forged_manifest_hex: hex(forgedManifest.bytes),
    m2_draft02_fork_manifest_hex: hex(forkManifest.bytes),
    m2_draft02_revoked_manifest_hex: hex(revokedManifest.bytes),
    m2_draft02_wrong_scope_manifest_hex: hex(wrongScopeManifest.bytes),
    m2_draft02_wrong_line_manifest_hex: hex(wrongLineManifest.bytes),
    m2_draft02_zero_line_manifest_hex: hex(zeroLineManifest.bytes),
    m2_draft02_transition_hex: hex(transition),
    m2_draft02_forged_transition_hex: hex(forgedTransition),
    m2_draft02_rotated_root_hex: hex(rotatedRootPoint),
    m2_draft02_rotated_manifest_hex: hex(rotatedManifest.bytes),
    m2_draft02_envelope_hex: hex(envelope),
    m2_draft02_revoked_envelope_hex: hex(revoked.envelope),
    m2_draft02_wrong_line_envelope_hex: hex(wrongLine.envelope),
    m2_draft02_high_s_envelope_hex: hex(highSEnvelope),
    m2_draft02_nonce_mutant_hex: hex(nonceMutant),
    m2_draft02_manifest_mutant_hex: hex(manifestMutant),
    m2_draft02_body_aad_mutant_hex: hex(bodyAadMutant),
  });
  if (!opened.includes("m2_draft02_full_envelope_open=PASSED") ||
      !opened.includes("m2_draft02_public_jca_tink_equivalence=PASSED") ||
      !opened.includes("m2_draft02_signed_manifest_denials=PASSED") ||
      !opened.includes("m2_draft02_envelope_alias_removed=PASSED")) {
    throw new Error("Android did not confirm full draft-02 envelope and denials");
  }
  cek.fill(0);
  console.log("PASS: @hpke/core signed draft-02 envelope opened with public JCA and Android Keystore; Tink CEK matched");
} finally {
  const cleaned = await instrument("cleanupRecipient");
  if (!cleaned.includes("m2_draft02_envelope_alias_removed=PASSED")) {
    throw new Error("Temporary Keystore alias cleanup was not confirmed");
  }
}
