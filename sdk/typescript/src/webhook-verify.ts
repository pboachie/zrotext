/**
 * Webhook signature verifier for ZROtext webhook deliveries.
 *
 * Scheme (crates/server/src/webhook_egress.rs `signature_header`): the
 * `x-zrotext-signature` header is `v1=` plus lowercase hex of
 * HMAC-SHA256(key = the decoded signing secret bytes,
 * message = ASCII decimal `x-zrotext-timestamp` + "." + exact raw body bytes).
 * The receiver must check a five-minute timestamp window and should
 * deduplicate the event ID inside the signed body.
 *
 * Pass the RAW request body bytes. Re-serialized JSON will not verify.
 */

export const WEBHOOK_TOLERANCE_SECONDS = 300;

export type WebhookVerifyFailure =
  | "bad_timestamp"
  | "timestamp_out_of_window"
  | "bad_signature_format"
  | "signature_mismatch";

export class WebhookVerificationError extends Error {
  readonly reason: WebhookVerifyFailure;
  constructor(reason: WebhookVerifyFailure) {
    super(`webhook verification failed: ${reason}`);
    this.name = "WebhookVerificationError";
    this.reason = reason;
  }
}

export interface VerifyWebhookInput {
  /** Decoded signing secret bytes (the HMAC key) (see secretFromBase64Url). */
  signingKey: Uint8Array;
  /** The x-zrotext-timestamp header value (Unix seconds, canonical decimal). */
  timestamp: string;
  /** The x-zrotext-signature header value (`v1=` + 64 lowercase hex). */
  signature: string;
  /** The exact raw request body. */
  body: Uint8Array | string;
  /** Override the clock (Unix seconds); default Date.now()/1000. */
  nowSeconds?: number;
  /** Override the window, default 300 seconds. */
  toleranceSeconds?: number;
}

/** Decode `signing_secret_b64url` from the webhook create/rotate response. */
export function secretFromBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("secret is not unpadded base64url");
  const std = value.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(std + "=".repeat((4 - (std.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** Compute the `v1=<hex>` header value; useful for tests and local simulators. */
export async function signWebhook(
  secret: Uint8Array,
  timestampSeconds: number,
  body: Uint8Array | string,
): Promise<string> {
  const key = await crypto.subtle.importKey("raw", secret as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, signedBytes(String(timestampSeconds), body) as BufferSource),
  );
  return "v1=" + Array.from(mac, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Verify one delivery. Resolves on success and throws
 * WebhookVerificationError otherwise. The MAC comparison is constant-time
 * (WebCrypto HMAC verify).
 */
export async function verifyWebhook(input: VerifyWebhookInput): Promise<void> {
  if (!/^(0|[1-9][0-9]{0,15})$/.test(input.timestamp)) throw new WebhookVerificationError("bad_timestamp");
  const ts = Number(input.timestamp);
  const now = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  const tolerance = input.toleranceSeconds ?? WEBHOOK_TOLERANCE_SECONDS;
  if (!Number.isSafeInteger(ts) || Math.abs(now - ts) > tolerance) {
    throw new WebhookVerificationError("timestamp_out_of_window");
  }
  const match = /^v1=([0-9a-f]{64})$/.exec(input.signature);
  if (!match) throw new WebhookVerificationError("bad_signature_format");
  const expected = Uint8Array.from(match[1]!.match(/../g)!, (h) => parseInt(h, 16));
  const key = await crypto.subtle.importKey("raw", input.signingKey as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("HMAC", key, expected as BufferSource, signedBytes(input.timestamp, input.body) as BufferSource);
  if (!ok) throw new WebhookVerificationError("signature_mismatch");
}

function signedBytes(timestamp: string, body: Uint8Array | string): Uint8Array {
  const enc = new TextEncoder();
  const head = enc.encode(timestamp + ".");
  const raw = typeof body === "string" ? enc.encode(body) : body;
  const out = new Uint8Array(head.length + raw.length);
  out.set(head, 0);
  out.set(raw, head.length);
  return out;
}
