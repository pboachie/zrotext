// Test-only, emulator-only: independent @hpke/core sender -> generated Android Keystore key.
// The matching receiver is an androidTest RFC composition, not production sealed mode.
import { execFile } from "node:child_process";
import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { promisify } from "node:util";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";
import { parseDraftEnvelope, wrapAad, wrapInfo } from "../dist/draft01.js";

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
const testClass = "org.zrotext.gateway.M2KeystoreHpkeProofTest";
const runner = "org.zrotext.gateway.test/androidx.test.runner.AndroidJUnitRunner";
const hex = (value) => Buffer.from(value).toString("hex");
const bytes = (value) => Uint8Array.from(Buffer.from(value, "hex"));
const ascii = (value) => new TextEncoder().encode(value);
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((part) => Buffer.from(part))));
const sha256 = (value) => Uint8Array.from(createHash("sha256").update(value).digest());
const u32 = (value) => Uint8Array.of(value >>> 24, value >>> 16, value >>> 8, value);
const equal = (a, b) => Buffer.from(a).equals(Buffer.from(b));

async function adbCall(...args) {
  return (await exec("adb", ["-s", serial, ...args], {
    env: adbEnv,
    maxBuffer: 1024 * 1024,
  })).stdout.trim();
}

async function instrument(method, extras = {}) {
  const args = ["shell", "am", "instrument", "-w", "-e", "class", `${testClass}#${method}`,
    "-e", "m2_host_driver", "1"];
  for (const [name, value] of Object.entries(extras)) args.push("-e", name, value);
  const output = await adbCall(...args, runner);
  if (!output.includes("OK (1 test)")) throw new Error(`${method} failed:\n${output}`);
  return output;
}

if (await adbCall("shell", "getprop", "ro.kernel.qemu") !== "1") {
  throw new Error("Refusing to run outside an emulator");
}
if (Number(await adbCall("shell", "getprop", "ro.build.version.sdk")) < 31) {
  throw new Error("Emulator does not support Keystore ECDH");
}

try {
  const prepared = await instrument("prepareBrowserInteropRecipient");
  const pointHex = prepared.match(/m2_browser_interop_recipient_point_hex=([0-9a-f]{130})/)?.[1];
  if (!pointHex) throw new Error("No recipient public point returned");
  const point = bytes(pointHex);
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm(),
  });
  const recipientPublicKey = await suite.kem.deserializePublicKey(point);
  const fixture = JSON.parse(readFileSync(new URL("../../../protocol/v1/vectors/ztse-draft-01.json", import.meta.url)));
  const baseline = parseDraftEnvelope(bytes(fixture.outbound.envelopeHex));
  const protectedBytes = baseline.protected;
  const role = Uint8Array.of(1);
  const keyId = sha256(concat(ascii("ZTSE/key/v1\0"), Uint8Array.of(0, 16), point));
  const info = concat(ascii("ZTSE/wrap/v1\0"), sha256(protectedBytes), role, keyId);
  const aad = concat(ascii("ZTSE/wrap-aad/v1\0"), protectedBytes, role, keyId);
  const cek = new Uint8Array(32).fill(0xc1); // Pinned fixture body uses this public test key.
  const sender = await suite.createSenderContext({ recipientPublicKey, info });
  const ct = new Uint8Array(await sender.seal(cek, aad));
  const enc = new Uint8Array(sender.enc);
  if (enc.length !== 65 || ct.length !== 48) throw new Error("Unexpected draft wrap size");
  const archive = baseline.wraps.find((wrap) => wrap.role === 2);
  if (!archive || baseline.wraps.length !== 2) throw new Error("Unexpected pinned outbound recipient set");
  const deviceRaw = concat(Uint8Array.of(1), keyId, enc, ct);
  const archiveRaw = concat(Uint8Array.of(archive.role), archive.keyId, archive.enc, archive.ct);
  const prefixLength = baseline.unsigned.length - 1 - baseline.wraps.length * 146;
  const unsigned = concat(baseline.unsigned.subarray(0, prefixLength), Uint8Array.of(2), deviceRaw, archiveRaw);
  const signerPoint = bytes(fixture.signerPublicPointHex);
  const signerScalar = new Uint8Array(32); signerScalar[31] = 5;
  const b64url = (value) => Buffer.from(value).toString("base64url");
  const signer = await crypto.subtle.importKey("jwk", {
    kty: "EC", crv: "P-256", x: b64url(signerPoint.subarray(1, 33)),
    y: b64url(signerPoint.subarray(33)), d: b64url(signerScalar), ext: true, key_ops: ["sign"],
  }, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signatureInput = concat(ascii("ZTSE/sign/v1\0"), u32(unsigned.length), unsigned);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signer, signatureInput));
  if (signature.length !== 64) throw new Error("Unexpected signature width");
  const envelope = concat(unsigned, signature);
  const parsed = parseDraftEnvelope(envelope);
  if (!equal(await wrapInfo(parsed, parsed.wraps[0]), info) || !equal(wrapAad(parsed, parsed.wraps[0]), aad)) {
    throw new Error("Draft transcript mismatch");
  }
  const opened = await instrument("openBrowserInteropEnvelope", { m2_envelope_hex: hex(envelope) });
  if (!opened.includes("m2_browser_envelope_open=PASSED") ||
      !opened.includes("m2_browser_envelope_lost_key_denied=PASSED")) {
    throw new Error("Android did not confirm full draft envelope opening and key-loss denial");
  }
  console.log("PASS: @hpke/core draft-01 envelope opened with generated Android Keystore key");
} finally {
  const cleaned = await instrument("cleanupBrowserInteropRecipient");
  if (!cleaned.includes("m2_browser_interop_alias_removed=PASSED")) {
    throw new Error("Temporary Keystore alias cleanup was not confirmed");
  }
}
