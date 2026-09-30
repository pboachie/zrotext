// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Production-shaped sealed outbound submission client (issue #537 slice B).
 *
 * `SealedClient.submitSealedMessage` posts exactly one composed envelope
 * (slice A's `composeSealedOutboundEnvelope`) to the sealed v1 message plane,
 * `POST /v1/sealed/messages`, as raw binary request bytes with the single
 * allowed content type `application/vnd.zrotext.sealed.v1` and nothing else
 * alongside it: no JSON encoding, no multipart, no plaintext fallback and no
 * `idempotency-key` header — idempotency is the SHA-256 digest of the unsigned
 * envelope bytes (Q6), so the identity travels inside the bytes, and the
 * server refuses a caller-supplied key. The API key is sent only in the
 * `Authorization: Bearer` header; it never enters a URL, a query string or an
 * error message.
 *
 * Retries resend the exact same `Uint8Array` object. Only transport failures
 * without a response (network), `503` (`unavailable`/`billing_pending`) and
 * `429 rate_limited` are retried, bounded by the configured attempt count and
 * delay ceiling, with the server's `Retry-After` honored up to that ceiling.
 * Terminal admission failures — every other 4xx, and `queue_full`/
 * `quota_exceeded`, which immediate retries cannot help and only worsen —
 * surface at once as typed `SealedClientError`s. `409 idempotency_conflict`
 * carries both the digest that was sent and the server code, and the client
 * never recomposes or resends after it. A per-attempt timeout aborts the
 * exchange and surfaces immediately without retrying, because whether the
 * envelope was admitted is then unknown; the caller decides whether to replay
 * the same digest identity itself. Off-taxonomy statuses, unknown codes and
 * malformed bodies fail closed as `unexpected_response`: never a crash, never
 * a silent success.
 *
 * This module has no plaintext path, no synthetic-alpha route and no
 * downgrade. The server route is mounted only when an operator sets
 * `SEALED_ADMISSION_ENABLED=true`; against a default deployment every request
 * here fails, and that is the intended failure mode.
 */
import { SEALED_CONTENT_TYPE } from "./sealed-envelope.js";

export { SEALED_CONTENT_TYPE } from "./sealed-envelope.js";

const OUTBOUND_PATH = "/v1/sealed/messages";
/** Lowercase UUID text; the contract does not constrain version or variant bits. */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_MAX_DELAY_MS = 30_000;

/** Admission-failure codes the sealed v1 message plane defines for outbound submission. */
export type SealedServerErrorCode =
  | "invalid_request"
  | "unauthorized"
  | "forbidden"
  | "idempotency_conflict"
  | "unsupported_media_type"
  | "rate_limited"
  | "queue_full"
  | "quota_exceeded"
  | "billing_pending"
  | "unavailable";

/** Transport classifications plus the fail-closed bucket for contract violations. */
export type SealedClientErrorCode = SealedServerErrorCode | "network" | "timeout" | "unexpected_response";

/** Status and retry classification per server code; the client mirrors, never widens. */
const TAXONOMY: Readonly<Record<SealedServerErrorCode, Readonly<{ status: number; retryable: boolean }>>> = {
  invalid_request: { status: 400, retryable: false },
  unauthorized: { status: 401, retryable: false },
  forbidden: { status: 403, retryable: false },
  idempotency_conflict: { status: 409, retryable: false },
  unsupported_media_type: { status: 415, retryable: false },
  rate_limited: { status: 429, retryable: true },
  queue_full: { status: 429, retryable: false },
  quota_exceeded: { status: 429, retryable: false },
  billing_pending: { status: 503, retryable: true },
  unavailable: { status: 503, retryable: true },
};

/** `202` acceptance metadata; no recipient, no plaintext, no envelope bytes. */
export type SealedSubmission = Readonly<{ messageId: string; created: boolean }>;

/** Minimal transport shape; the platform `fetch` satisfies it. */
export type SealedFetch = (
  url: string,
  init: Readonly<{
    method: "POST";
    headers: Readonly<Record<string, string>>;
    body: Uint8Array;
    signal: AbortSignal;
  }>,
) => Promise<Response>;

export type SealedClientRetryOptions = Readonly<{
  /** Total attempts per submission, first send included. Default 3. */
  maxAttempts?: number;
  /** Ceiling on any single retry sleep, applied after `Retry-After`. Default 30_000. */
  maxDelayMs?: number;
  /** Backoff in ms by attempt number for retries without a usable `Retry-After`. Default attempt * 1000. */
  backoffMs?: (attempt: number) => number;
}>;

export type SealedClientOptions = Readonly<{
  /** HTTPS origin only: no path, query, fragment or embedded credentials. */
  baseUrl: string;
  /** Bearer API key token; sent only in the Authorization header, never logged. */
  apiToken: string;
  /** Per-attempt timeout in milliseconds. Default 15_000. */
  timeoutMs?: number;
  retry?: SealedClientRetryOptions;
  /** Injectable transport; defaults to the platform global `fetch`. */
  fetchImpl?: SealedFetch;
  /** Injectable sleep, primarily so tests can observe retry delays without waiting. */
  sleep?: (ms: number) => Promise<void>;
}>;

export class SealedClientError extends Error {
  readonly code: SealedClientErrorCode;
  /** HTTP status of the last response; 0 when none arrived (network, timeout). */
  readonly status: number;
  /** The raw JSON `code` string when the server sent a parseable one. */
  readonly serverCode: string | undefined;
  /** The Q6 unsigned digest of the exact bytes this submission sent. */
  readonly digest: Uint8Array | undefined;
  /** The server's `Retry-After` hint in ms when the last response carried a parseable one. */
  readonly retryAfterMs: number | undefined;
  /** Attempts made, first send included. */
  readonly attempts: number;
  /** Whether this failure class is retryable under the contract, for caller-driven policies. */
  readonly retryable: boolean;

  constructor(
    fields: Readonly<{
      code: SealedClientErrorCode;
      status: number;
      serverCode?: string;
      digest?: Uint8Array;
      retryAfterMs?: number;
      attempts: number;
      retryable: boolean;
    }>,
    detail: string,
    options?: Readonly<{ cause?: unknown }>,
  ) {
    super(`ZTSE sealed client: ${detail}`, options);
    this.name = "SealedClientError";
    this.code = fields.code;
    this.status = fields.status;
    this.serverCode = fields.serverCode;
    this.digest = fields.digest;
    this.retryAfterMs = fields.retryAfterMs;
    this.attempts = fields.attempts;
    this.retryable = fields.retryable;
  }
}

export function isSealedClientError(value: unknown): value is SealedClientError {
  return value instanceof SealedClientError;
}

function fail(why: string): never {
  throw new Error(`ZTSE sealed client: ${why}`);
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function isServerCode(value: string): value is SealedServerErrorCode {
  return Object.prototype.hasOwnProperty.call(TAXONOMY, value);
}

function unexpected(
  attempt: number,
  digest: Uint8Array,
  status: number,
  detail: string,
  serverCode?: string,
): SealedClientError {
  return new SealedClientError(
    { code: "unexpected_response", status, serverCode, digest, attempts: attempt, retryable: false },
    detail,
  );
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/** Delay-seconds only; the server emits integers, and anything else falls back to the bounded backoff. */
function parseRetryAfterMs(value: string | null): number | undefined {
  if (value === null) return undefined;
  const trimmed = value.trim();
  if (!/^\d{1,10}$/.test(trimmed)) return undefined;
  return Number(trimmed) * 1000;
}

function parseAccepted(attempt: number, digest: Uint8Array, text: string, status: number): SealedSubmission {
  const body = parseJson(text);
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw unexpected(attempt, digest, status, "202 body is not a JSON object");
  }
  const record = body as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.length !== 2 || keys[0] !== "created" || keys[1] !== "message_id") {
    throw unexpected(attempt, digest, status, "202 body must contain exactly message_id and created");
  }
  const messageId = record["message_id"];
  if (typeof messageId !== "string" || !UUID.test(messageId)) {
    throw unexpected(attempt, digest, status, "202 message_id is not a lowercase UUID");
  }
  const created = record.created;
  if (typeof created !== "boolean") {
    throw unexpected(attempt, digest, status, "202 created is not a boolean");
  }
  return { messageId, created };
}

function parseServerCode(attempt: number, digest: Uint8Array, text: string, status: number): SealedServerErrorCode {
  const body = parseJson(text);
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw unexpected(attempt, digest, status, "error body is not a JSON object");
  }
  const record = body as Record<string, unknown>;
  const raw = record.code;
  const rawCode = typeof raw === "string" ? raw : undefined;
  const keys = Object.keys(record);
  if (keys.length !== 1 || keys[0] !== "code" || rawCode === undefined) {
    throw unexpected(attempt, digest, status, "error body must contain exactly one code field", rawCode);
  }
  if (!isServerCode(rawCode)) {
    throw unexpected(attempt, digest, status, `unknown error code ${rawCode}`, rawCode);
  }
  return rawCode;
}

export class SealedClient {
  private readonly url: string;
  private readonly apiToken: string;
  private readonly timeoutMs: number;
  private readonly maxAttempts: number;
  private readonly maxDelayMs: number;
  private readonly backoffMs: (attempt: number) => number;
  private readonly fetchImpl: SealedFetch;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(options: SealedClientOptions) {
    let parsed: URL;
    try {
      parsed = new URL(options.baseUrl);
    } catch {
      fail("base URL is not a URL");
    }
    if (parsed.protocol !== "https:") fail("base URL protocol must be https");
    if (parsed.pathname !== "/" && parsed.pathname !== "") fail("base URL must not carry a path");
    if (parsed.search) fail("base URL must not carry a query");
    if (parsed.hash) fail("base URL must not carry a fragment");
    if (parsed.username || parsed.password) fail("base URL must not carry credentials");
    if (
      typeof options.apiToken !== "string" || options.apiToken.length === 0 || !/^[\x21-\x7e]+$/.test(options.apiToken)
    ) {
      fail("API token must be nonempty printable ASCII without spaces");
    }
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) fail("timeoutMs must be a positive integer of milliseconds");
    const retry = options.retry ?? {};
    const maxAttempts = retry.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1) fail("retry maxAttempts must be an integer of at least 1");
    const maxDelayMs = retry.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;
    if (!Number.isInteger(maxDelayMs) || maxDelayMs < 0) fail("retry maxDelayMs must be a nonnegative integer");
    if (retry.backoffMs !== undefined && typeof retry.backoffMs !== "function") {
      fail("retry backoffMs must be a function of the attempt number");
    }
    this.url = `${parsed.origin}${OUTBOUND_PATH}`;
    this.apiToken = options.apiToken;
    this.timeoutMs = timeoutMs;
    this.maxAttempts = maxAttempts;
    this.maxDelayMs = maxDelayMs;
    this.backoffMs = retry.backoffMs ?? ((attempt: number) => attempt * 1000);
    this.fetchImpl = options.fetchImpl ?? ((url, init) => fetch(url, init as unknown as RequestInit));
    this.sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  }

  /**
   * Submits one sealed outbound envelope. The envelope bytes are the entire
   * request body and are resent as the same object on every retry; the digest
   * is verified locally against the unsigned envelope first, so a mismatched
   * pair — one whose reported Q6 identity would lie — never leaves the client.
   */
  async submitSealedMessage(envelope: Uint8Array, unsignedDigest: Uint8Array): Promise<SealedSubmission> {
    if (!(envelope instanceof Uint8Array)) {
      fail("envelope must be the exact envelope bytes as a Uint8Array, never JSON or base64");
    }
    if (!(unsignedDigest instanceof Uint8Array)) {
      fail("unsignedDigest must be a Uint8Array");
    }
    if (unsignedDigest.byteLength !== 32) {
      fail("unsignedDigest must be the 32-byte SHA-256 digest of the unsigned envelope bytes");
    }
    if (envelope.byteLength <= 64) fail("envelope is shorter than the sealed v1 signature trailer");
    // Mirrors the existing client convention: the DOM lib types cannot express
    // that a Uint8Array view is a valid BufferSource for this engine.
    const computed = new Uint8Array(
      await crypto.subtle.digest("SHA-256", envelope.subarray(0, envelope.byteLength - 64) as unknown as ArrayBuffer),
    );
    if (!same(computed, unsignedDigest)) {
      fail("unsignedDigest does not match the envelope bytes (the Q6 identity); refusing to send mismatched bytes");
    }
    for (let attempt = 1; ; attempt++) {
      try {
        return await this.sendOnce(envelope, unsignedDigest, attempt);
      } catch (error) {
        if (!(error instanceof SealedClientError) || !error.retryable || attempt >= this.maxAttempts) throw error;
        await this.sleep(this.retryDelayMs(error, attempt));
      }
    }
  }

  private retryDelayMs(error: SealedClientError, attempt: number): number {
    const candidate = error.retryAfterMs ?? this.backoffMs(attempt);
    const safe = Number.isFinite(candidate) && candidate > 0 ? candidate : 0;
    return Math.min(safe, this.maxDelayMs);
  }

  private async sendOnce(envelope: Uint8Array, digest: Uint8Array, attempt: number): Promise<SealedSubmission> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    let text: string;
    try {
      response = await this.fetchImpl(this.url, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.apiToken}`,
          "content-type": SEALED_CONTENT_TYPE,
          accept: "application/json",
        },
        body: envelope,
        signal: controller.signal,
      });
      text = await response.text();
    } catch (cause) {
      const fields = controller.signal.aborted
        ? { code: "timeout" as const, detail: `request exceeded the ${this.timeoutMs} ms timeout`, retryable: false }
        : { code: "network" as const, detail: "transport failed without a response", retryable: true };
      throw new SealedClientError(
        { code: fields.code, status: 0, digest, attempts: attempt, retryable: fields.retryable },
        fields.detail,
        { cause },
      );
    } finally {
      clearTimeout(timer);
    }
    const retryAfterMs = parseRetryAfterMs(response.headers.get("retry-after"));
    if (response.status === 202) return parseAccepted(attempt, digest, text, response.status);
    const code = parseServerCode(attempt, digest, text, response.status);
    const known = TAXONOMY[code];
    if (known.status !== response.status) {
      throw unexpected(
        attempt,
        digest,
        response.status,
        `code ${code} arrived on HTTP ${response.status}, expected ${known.status}`,
        code,
      );
    }
    throw new SealedClientError(
      { code, status: response.status, serverCode: code, digest, retryAfterMs, attempts: attempt, retryable: known.retryable },
      `admission failed: ${code}`,
    );
  }
}
