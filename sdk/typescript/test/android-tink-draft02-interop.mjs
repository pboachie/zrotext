// Emulator-only draft-02 probe: independent @hpke/core sender -> Tink Keystore helper.
import { execFile } from "node:child_process";
import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { promisify } from "node:util";
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";

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
const testClass = "org.zrotext.gateway.Draft02TinkKeystoreDeviceTest";
const hex = (value) => Buffer.from(value).toString("hex");
const bytes = (value) => Uint8Array.from(Buffer.from(value, "hex"));
const ascii = (value) => new TextEncoder().encode(value);
const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map((part) => Buffer.from(part))));
const sha256 = (value) => Uint8Array.from(createHash("sha256").update(value).digest());

async function adbCall(...args) {
  return (await exec("adb", ["-s", serial, ...args], {
    env: adbEnv,
    maxBuffer: 1024 * 1024,
  })).stdout.trim();
}

async function instrument(method, extras = {}) {
  const args = ["shell", "am", "instrument", "-w", "-e", "class", `${testClass}#${method}`,
    "-e", "m2_draft02_host_driver", "1"];
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
  const prepared = await instrument("prepareRecipient");
  const pointHex = prepared.match(/m2_draft02_recipient_point_hex=([0-9a-f]{130})/)?.[1];
  if (!pointHex) throw new Error("No recipient public point returned");
  const point = bytes(pointHex);
  const suite = new CipherSuite({
    kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm(),
  });
  const recipientPublicKey = await suite.kem.deserializePublicKey(point);
  const fixture = JSON.parse(readFileSync(new URL("../../../protocol/v1/vectors/ztse-draft-01.json", import.meta.url)));
  const protectedBytes = bytes(fixture.outbound.protectedHex);
  if (protectedBytes.length !== 157) throw new Error("Unexpected public Protected fixture length");
  const header = Uint8Array.of(0x5a, 0x54, 0x53, 0x45, 2, 1, 0, 0, 0, 157);
  const role = Uint8Array.of(1);
  const keyId = sha256(concat(ascii("ZTSE/key/v1\0"), Uint8Array.of(0, 16), point));
  const info = concat(ascii("ZTSE/wrap/v2\0"), header, protectedBytes, role, keyId);
  if (info.length !== 213) throw new Error("Unexpected draft-02 info length");
  const cek = new Uint8Array(32).fill(0xc2);
  const sender = await suite.createSenderContext({ recipientPublicKey, info });
  const ct = new Uint8Array(await sender.seal(cek, new Uint8Array()));
  const enc = new Uint8Array(sender.enc);
  if (enc.length !== 65 || ct.length !== 48) throw new Error("Unexpected draft-02 wrap size");
  const opened = await instrument("openBrowserWrapWithTinkHelper", {
    m2_draft02_enc_hex: hex(enc), m2_draft02_ct_hex: hex(ct), m2_draft02_cek_hex: hex(cek),
  });
  if (!opened.includes("m2_draft02_tink_open=PASSED") ||
      !opened.includes("m2_draft02_changed_info_denied=PASSED") ||
      !opened.includes("m2_draft02_lost_key_denied=PASSED")) {
    throw new Error("Android did not confirm Tink open and fail-closed cases");
  }
  cek.fill(0);
  console.log("PASS: @hpke/core draft-02 wrap opened by Tink helper with generated Android Keystore key");
} finally {
  const cleaned = await instrument("cleanupRecipient");
  if (!cleaned.includes("m2_draft02_alias_removed=PASSED")) {
    throw new Error("Temporary Keystore alias cleanup was not confirmed");
  }
}
