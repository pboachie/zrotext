import assert from "node:assert/strict";
import test from "node:test";
import {
  WebhookVerificationError,
  secretFromBase64Url,
  signWebhook,
  verifyWebhook,
} from "../dist/index.js";

// Pinned in crates/server/src/webhook_egress.rs
// (signature_uses_exact_raw_body_and_timestamp).
const KEY_BYTES = new TextEncoder().encode("0123456789abcdef0123456789abcdef");
const BODY = '{"event":"test"}';
const TS = 1_700_000_000;
const SIG = "v1=036f0ddc8ddd72da03802b4a2b49547d6516ad1a6a5347527a093387536cb405";

const base = { signingKey: KEY_BYTES, timestamp: String(TS), signature: SIG, body: BODY, nowSeconds: TS };
const reason = (r) => (e) => e instanceof WebhookVerificationError && e.reason === r;

test("signing reproduces the server-pinned vector", async () => {
  assert.equal(await signWebhook(KEY_BYTES, TS, BODY), SIG);
  assert.equal(await signWebhook(KEY_BYTES, TS, new TextEncoder().encode(BODY)), SIG);
});

test("valid delivery verifies for string and byte bodies", async () => {
  await verifyWebhook(base);
  await verifyWebhook({ ...base, body: new TextEncoder().encode(BODY) });
});

test("exact raw body, timestamp and secret are bound", async () => {
  await assert.rejects(verifyWebhook({ ...base, body: '{ "event":"test"}' }), reason("signature_mismatch"));
  await assert.rejects(verifyWebhook({ ...base, timestamp: String(TS + 1) }), reason("signature_mismatch"));
  await assert.rejects(
    verifyWebhook({ ...base, signingKey: new TextEncoder().encode("x".repeat(32)) }),
    reason("signature_mismatch"),
  );
});

test("five-minute window is inclusive and symmetric", async () => {
  await verifyWebhook({ ...base, nowSeconds: TS + 300 });
  await verifyWebhook({ ...base, nowSeconds: TS - 300 });
  await assert.rejects(verifyWebhook({ ...base, nowSeconds: TS + 301 }), reason("timestamp_out_of_window"));
  await assert.rejects(verifyWebhook({ ...base, nowSeconds: TS - 301 }), reason("timestamp_out_of_window"));
});

test("malformed timestamp and signature are rejected before the MAC", async () => {
  for (const t of ["", "01700000000", "1700000000.0", " 1700000000", "-1", "1e9"]) {
    await assert.rejects(verifyWebhook({ ...base, timestamp: t }), reason("bad_timestamp"));
  }
  for (const s of ["", SIG.slice(3), SIG.toUpperCase(), SIG + "0", "v2=" + SIG.slice(3), SIG.slice(0, -1)]) {
    await assert.rejects(verifyWebhook({ ...base, signature: s }), reason("bad_signature_format"));
  }
});

test("secretFromBase64Url decodes the unpadded base64url create/rotate secret", () => {
  const bytes = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);
  const b64url = Buffer.from(bytes).toString("base64url");
  assert.equal(b64url.length, 43);
  assert.deepEqual(secretFromBase64Url(b64url), bytes);
  assert.throws(() => secretFromBase64Url("not+base64/"), TypeError);
});
