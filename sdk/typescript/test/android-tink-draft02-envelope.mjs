// Test-only full profile-02 outbound envelope from independent browser primitives to Android.
import { execFile } from "node:child_process";
import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";

globalThis.crypto ??= webcrypto;
const exec = promisify(execFile);
const sdk = process.env.ANDROID_HOME;
if (!sdk) throw new Error("ANDROID_HOME is required");
const serial = process.env.ANDROID_SERIAL || "emulator-5554";
if (!/^emulator-\d+$/.test(serial)) throw new Error("Only an AVD emulator serial is allowed");
const adb = join(sdk, "platform-tools", process.platform === "win32" ? "adb.exe" : "adb");
const runner = "org.zrotext.gateway.test/androidx.test.runner.AndroidJUnitRunner";
const testClass = "org.zrotext.gateway.M2Draft02EnvelopeTest";
const hex = (value) => Buffer.from(value).toString("hex");
const bytes = (value) => Uint8Array.from(Buffer.from(value, "hex"));
const ascii = (value) => new TextEncoder().encode(value);
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((part) => Buffer.from(part))));
const sha256 = (value) => Uint8Array.from(createHash("sha256").update(value).digest());
const u16 = (value) => Uint8Array.of(value >>> 8, value & 255);
const u32 = (value) => Uint8Array.of(value >>> 24, value >>> 16, value >>> 8, value);
const arrayBuffer = (value) => Uint8Array.from(value).buffer;

async function adbCall(...args) {
  return (await exec(adb, ["-s", serial, ...args], { maxBuffer: 1024 * 1024 })).stdout.trim();
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
const protectedBytes = bytes(fixture.outbound.protectedHex);
if (protectedBytes.length !== 157) throw new Error("Unexpected public fixture shape");
const header = concat(ascii("ZTSE"), Uint8Array.of(2, 1, 0, 0), u16(protectedBytes.length));
const signerPoint = bytes(fixture.signerPublicPointHex);
const signerScalar = new Uint8Array(32); signerScalar[31] = 5; // Public deterministic fixture only.
const b64url = (value) => Buffer.from(value).toString("base64url");
const signer = await crypto.subtle.importKey("jwk", {
  kty: "EC", crv: "P-256", x: b64url(signerPoint.subarray(1, 33)),
  y: b64url(signerPoint.subarray(33)), d: b64url(signerScalar), ext: true, key_ops: ["sign"],
}, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);

async function signed(unsigned) {
  const transcript = concat(ascii("ZTSE/sign/v2\0"), u32(unsigned.length), unsigned);
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, signer, arrayBuffer(transcript)));
  if (signature.length !== 64) throw new Error("Unexpected signature width");
  return concat(unsigned, signature);
}

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

  const cek = new Uint8Array(32).fill(0xc2);
  const nonce = new Uint8Array(12).fill(0xa8);
  const bodyAad = concat(ascii("ZTSE/body/v2\0"), header, protectedBytes);
  const bodyKey = await crypto.subtle.importKey("raw", arrayBuffer(cek), "AES-GCM", false, ["encrypt"]);
  const body = new Uint8Array(await crypto.subtle.encrypt({
    name: "AES-GCM", iv: arrayBuffer(nonce), additionalData: arrayBuffer(bodyAad), tagLength: 128,
  }, bodyKey, arrayBuffer(ascii("Draft02 outbound ✓"))));

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
  const deviceWrap = await wrap(1, deviceKeyId, devicePublicKey);
  const archiveWrap = await wrap(2, archiveKeyId, archivePair.publicKey);
  const unsigned = concat(header, protectedBytes, nonce, u32(body.length), body,
    Uint8Array.of(2), deviceWrap, archiveWrap);
  const envelope = await signed(unsigned);
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

  const opened = await instrument("openBrowserEnvelopeAndDenyMutations", {
    m2_draft02_envelope_hex: hex(envelope),
    m2_draft02_nonce_mutant_hex: hex(nonceMutant),
    m2_draft02_manifest_mutant_hex: hex(manifestMutant),
    m2_draft02_body_aad_mutant_hex: hex(bodyAadMutant),
  });
  if (!opened.includes("m2_draft02_full_envelope_open=PASSED") ||
      !opened.includes("m2_draft02_signed_body_manifest_replay_denials=PASSED") ||
      !opened.includes("m2_draft02_envelope_alias_removed=PASSED")) {
    throw new Error("Android did not confirm full draft-02 envelope and denials");
  }
  cek.fill(0);
  console.log("PASS: @hpke/core signed draft-02 envelope opened with Tink and Android Keystore");
} finally {
  const cleaned = await instrument("cleanupRecipient");
  if (!cleaned.includes("m2_draft02_envelope_alias_removed=PASSED")) {
    throw new Error("Temporary Keystore alias cleanup was not confirmed");
  }
}
