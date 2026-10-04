/**
 * Minimal, dependency-free client for the allowlisted synthetic-alpha test
 * plane: POST /v1/alpha/messages, GET /v1/alpha/messages/{id} and
 * POST /v1/alpha/messages/{id}/cancel (protocol/v1/openapi/public-v1.json).
 *
 * This is NOT a general send API. A general POST /v1/messages does not exist
 * in this build, the alpha plane is mounted only for allowlisted accounts and
 * recipients, and the caller never supplies message content (only a short
 * test-case identifier). No hosted service is implied.
 *
 * The client never retries on its own. Submission requires an explicit,
 * caller-chosen Idempotency-Key; a transport failure or timeout on submit is
 * reported as an unknown outcome and the caller decides whether to resubmit
 * the identical request with the identical key. A message in the `unknown`
 * writer state must never be resent automatically: reconcile it from the
 * device or provider evidence instead (docs/DELIVERY-STATES.md).
 */

export type AlphaMessageState =
  | "accepted"
  | "queued"
  | "claimed"
  | "submitting"
  | "submitted"
  | "delivered"
  | "delivery_unknown"
  | "unknown"
  | "failed"
  | "cancelled"
  | "expired";

export type AlphaErrorCode =
  | "invalid_request"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "queue_full"
  | "quota_exceeded"
  | "billing_pending"
  | "payment_hold"
  | "recipient_suppressed"
  | "unavailable";

export interface AlphaSubmitRequest {
  /** Caller-allocated UUID; reusing it with different content is a conflict. */
  clientMessageId: string;
  /** Enrolled, unrevoked device UUID the API key is bound to. */
  deviceId: string;
  /** Allowlisted test recipient in E.164 form. */
  recipientE164: string;
  /** 1-32 ASCII alphanumeric, dash or underscore bytes. */
  testCaseId: string;
  /** Unix millisecond deadline after which an undispatched message expires. */
  expiresAtMs: number;
}

export interface AlphaAccepted {
  messageId: string;
  /** false for an identical idempotent replay of the same Idempotency-Key. */
  created: boolean;
}

export interface AlphaStatus {
  messageId: string;
  deviceId: string;
  state: AlphaMessageState;
  stateVersion: number;
  createdAtMs: number;
  updatedAtMs: number;
}

const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9._-]{1,128}$/;
const E164 = /^\+[1-9][0-9]{1,14}$/;
const TEST_CASE = /^[A-Za-z0-9_-]{1,32}$/;

/** The server answered with a non-success status. */
export class AlphaApiError extends Error {
  readonly status: number;
  /** The JSON error code when the body carried one (framework 400/413/408 and bare 503 have none). */
  readonly code: AlphaErrorCode | undefined;
  /** Seconds from a Retry-After header, when present. Advisory only. */
  readonly retryAfterSeconds: number | undefined;

  constructor(status: number, code: AlphaErrorCode | undefined, retryAfterSeconds?: number) {
    super(`alpha request failed with HTTP ${status}${code ? ` (${code})` : ""}`);
    this.name = "AlphaApiError";
    this.status = status;
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * The request may or may not have reached the server (network error,
 * timeout, or an unparseable success response). For a submission the outcome
 * is unknown: query status, or resubmit the IDENTICAL request with the SAME
 * Idempotency-Key. Never generate a new key for the same logical message.
 */
export class AlphaOutcomeUnknownError extends Error {
  readonly operation: "submit" | "status" | "cancel";
  constructor(operation: "submit" | "status" | "cancel", cause?: unknown) {
    super(`alpha ${operation} outcome unknown: the response was not received intact`);
    this.name = "AlphaOutcomeUnknownError";
    this.operation = operation;
    if (cause !== undefined) (this as { cause?: unknown }).cause = cause;
  }
}

export interface AlphaClientOptions {
  /** Server origin, for example the base URL of your own self-hosted server. */
  baseUrl: string;
  /** Scoped API-key token (messages:send / messages:read bound to the device). */
  apiKey: string;
  /** Injectable fetch, default globalThis.fetch. */
  fetch?: typeof fetch;
  /** Per-request timeout in milliseconds, default 35000 (server deadline is 30 s). */
  timeoutMs?: number;
}

/** True when a writer state must not be resent automatically. */
export function requiresReconciliation(state: AlphaMessageState): boolean {
  return state === "unknown" || state === "delivery_unknown";
}

export class AlphaClient {
  readonly #base: string;
  readonly #key: string;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;

  constructor(options: AlphaClientOptions) {
    if (!options.apiKey || /[\r\n]/.test(options.apiKey)) {
      throw new TypeError("apiKey must be a non-empty single-line token");
    }
    const url = new URL(options.baseUrl);
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      throw new TypeError("baseUrl must be http(s)");
    }
    this.#base = url.origin;
    this.#key = options.apiKey;
    const f = options.fetch ?? globalThis.fetch;
    if (typeof f !== "function") throw new TypeError("no fetch implementation available");
    this.#fetch = f;
    this.#timeoutMs = options.timeoutMs ?? 35_000;
  }

  /**
   * Submit one synthetic-alpha test message. `idempotencyKey` is mandatory
   * and must be reused verbatim to retry the same logical submission. No
   * automatic retry is performed.
   */
  async submit(request: AlphaSubmitRequest, idempotencyKey: string): Promise<AlphaAccepted> {
    if (typeof idempotencyKey !== "string" || !IDEMPOTENCY_KEY.test(idempotencyKey)) {
      throw new TypeError("idempotencyKey must be 1-128 ASCII alphanumeric, dash, dot or underscore characters");
    }
    requireUuid(request.clientMessageId, "clientMessageId");
    requireUuid(request.deviceId, "deviceId");
    if (!E164.test(request.recipientE164)) throw new TypeError("recipientE164 must be E.164");
    if (!TEST_CASE.test(request.testCaseId)) {
      throw new TypeError("testCaseId must be 1-32 alphanumeric, dash or underscore characters");
    }
    if (!Number.isSafeInteger(request.expiresAtMs) || request.expiresAtMs < 0) {
      throw new TypeError("expiresAtMs must be a non-negative integer");
    }
    const body = JSON.stringify({
      client_message_id: request.clientMessageId,
      device_id: request.deviceId,
      recipient_e164: request.recipientE164,
      test_case_id: request.testCaseId,
      expires_at_ms: request.expiresAtMs,
    });
    const json = await this.#send(
      "submit",
      "POST",
      "/v1/alpha/messages",
      202,
      { "content-type": "application/json", "idempotency-key": idempotencyKey },
      body,
    );
    const o = asObject(json);
    if (typeof o.message_id !== "string" || typeof o.created !== "boolean") {
      throw new AlphaOutcomeUnknownError("submit");
    }
    return { messageId: o.message_id, created: o.created };
  }

  /** Read the writer's current state snapshot for one message. */
  async getStatus(messageId: string): Promise<AlphaStatus> {
    requireUuid(messageId, "messageId");
    const json = await this.#send("status", "GET", `/v1/alpha/messages/${messageId}`, 200);
    const o = asObject(json);
    if (
      typeof o.message_id !== "string" ||
      typeof o.device_id !== "string" ||
      typeof o.state !== "string" ||
      typeof o.state_version !== "number" ||
      typeof o.created_at_ms !== "number" ||
      typeof o.updated_at_ms !== "number"
    ) {
      throw new AlphaOutcomeUnknownError("status");
    }
    return {
      messageId: o.message_id,
      deviceId: o.device_id,
      state: o.state as AlphaMessageState,
      stateVersion: o.state_version,
      createdAtMs: o.created_at_ms,
      updatedAtMs: o.updated_at_ms,
    };
  }

  /**
   * Request cancellation before dispatch. Resolves on 204. A message that was
   * already claimed, submitting, submitted or terminal answers 409
   * (AlphaApiError code "conflict").
   */
  async cancel(messageId: string): Promise<void> {
    requireUuid(messageId, "messageId");
    await this.#send("cancel", "POST", `/v1/alpha/messages/${messageId}/cancel`, 204);
  }

  async #send(
    operation: "submit" | "status" | "cancel",
    method: string,
    path: string,
    okStatus: number,
    headers: Record<string, string> = {},
    body?: string,
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await this.#fetch(this.#base + path, {
        method,
        headers: { ...headers, authorization: `Bearer ${this.#key}`, accept: "application/json" },
        body,
        redirect: "error",
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (cause) {
      throw new AlphaOutcomeUnknownError(operation, cause);
    }
    if (response.status !== okStatus) {
      const failure = await apiError(response);
      // A submit that ends in a deadline (408) or a 5xx without the server's JSON
      // error body (a proxy or crash) may still have been accepted: the outcome is
      // unknown, so the only safe move is the identical request with the same key.
      if (operation === "submit" && (response.status === 408 || (response.status >= 500 && failure.code === undefined))) {
        throw new AlphaOutcomeUnknownError(operation);
      }
      throw failure;
    }
    if (okStatus === 204) return undefined;
    try {
      return await response.json();
    } catch (cause) {
      throw new AlphaOutcomeUnknownError(operation, cause);
    }
  }
}

function requireUuid(value: string, name: string): void {
  if (typeof value !== "string" || !UUID.test(value)) throw new TypeError(`${name} must be a UUID`);
}

function asObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
  return value as Record<string, unknown>;
}

async function apiError(response: Response): Promise<AlphaApiError> {
  let code: AlphaErrorCode | undefined;
  try {
    const parsed = asObject(JSON.parse(await response.text()));
    if (typeof parsed.code === "string") code = parsed.code as AlphaErrorCode;
  } catch {
    // Framework 400/408/413 and the bare admission 503 have no JSON body.
  }
  const raw = response.headers.get("retry-after");
  const retry = raw !== null && /^[0-9]{1,6}$/.test(raw) ? Number(raw) : undefined;
  return new AlphaApiError(response.status, code, retry);
}
