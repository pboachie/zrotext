// Test-only, emulator-only: independent @hpke/core sender -> generated Android Keystore key.
// The matching receiver is an androidTest RFC composition, not production sealed mode.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { promisify } from "node:util";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";

const exec = promisify(execFile);
const sdk = process.env.ANDROID_HOME;
if (!sdk) throw new Error("ANDROID_HOME is required");
const serial = process.env.ANDROID_SERIAL || "emulator-5554";
if (!/^emulator-\d+$/.test(serial)) throw new Error("Only an AVD emulator serial is allowed");
const adb = join(sdk, "platform-tools", process.platform === "win32" ? "adb.exe" : "adb");
const testClass = "org.zrotext.gateway.M2KeystoreHpkeProofTest";
const runner = "org.zrotext.gateway.test/androidx.test.runner.AndroidJUnitRunner";
const hex = (value) => Buffer.from(value).toString("hex");
const bytes = (value) => Uint8Array.from(Buffer.from(value, "hex"));
const ascii = (value) => new TextEncoder().encode(value);
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((part) => Buffer.from(part))));
const sha256 = (value) => Uint8Array.from(createHash("sha256").update(value).digest());

async function adbCall(...args) {
  return (await exec(adb, ["-s", serial, ...args], { maxBuffer: 1024 * 1024 })).stdout.trim();
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
  const protectedBytes = Uint8Array.from({ length: 157 }, (_, index) => index);
  const role = Uint8Array.of(1);
  const keyId = sha256(concat(ascii("ZTSE/key/v1\0"), Uint8Array.of(0, 16), point));
  const info = concat(ascii("ZTSE/wrap/v1\0"), sha256(protectedBytes), role, keyId);
  const aad = concat(ascii("ZTSE/wrap-aad/v1\0"), protectedBytes, role, keyId);
  const cek = new Uint8Array(32).fill(0xc1);
  const sender = await suite.createSenderContext({ recipientPublicKey, info });
  const ct = new Uint8Array(await sender.seal(cek, aad));
  const enc = new Uint8Array(sender.enc);
  if (enc.length !== 65 || ct.length !== 48) throw new Error("Unexpected draft wrap size");
  const opened = await instrument("openBrowserInteropWrap", {
    m2_enc_hex: hex(enc), m2_ct_hex: hex(ct), m2_cek_hex: hex(cek),
  });
  if (!opened.includes("m2_browser_to_keystore_open=PASSED")) {
    throw new Error("Android did not confirm browser wrap opening");
  }
  console.log("PASS: @hpke/core P-256 draft wrap opened with generated Android Keystore key");
} finally {
  const cleaned = await instrument("cleanupBrowserInteropRecipient");
  if (!cleaned.includes("m2_browser_interop_alias_removed=PASSED")) {
    throw new Error("Temporary Keystore alias cleanup was not confirmed");
  }
}
