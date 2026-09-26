/**
 * Experimental ZTSE sealed message-plane client. Test-only.
 *
 * Binds to the slice-1 HTTP contract (protocol/v1/sealed-api-v1.md and
 * protocol/v1/openapi/sealed-v1.json): a proposal with no mounted server
 * route. The sealed runtime stays disabled; this module must not be
 * published as a production SDK or wired to a send, inbound, webhook or
 * radio path. It never constructs a plaintext alternative, never targets the
 * synthetic-alpha route, and never accepts a caller-supplied idempotency
 * key: the unsigned-envelope digest is the identity (Q6).
 */
import { parseDraftEnvelope } from "./draft01.js";

export const SEALED_CONTENT_TYPE = "application/vnd.zrotext.sealed.v1";

const OUTBOUND_PATH = "/v1/sealed/messages";
const INBOUND_PATH = "/v1/sealed/inbound-events";

/** Every admission-failure code the contract's error taxonomy defines. */
export type SealedErrorCode =
  | "invalid_request"
  | "future_manifest"
  | "stale_event"
  | "unauthorized"
  | "forbidden"
  | "stale_manifest"
  | "re_enrollment_required"
  | "idempotency_conflict"
  | "event_id_conflict"
  | "sequence_conflict"
  | "unsupported_media_type"
  | "rate_limited"
  | "queue_full"
  | "quota_exceeded"
  | "billing_pending"
  | "unavailable";

/** Client-side classifications for responses that violate the contract. */
export type SealedClientErrorCode = "unexpected_response" | "envelope_mutated";

const TAXONOMY: Readonly<Record<SealedErrorCode, Readonly<{ status: number; retryable: boolean }>>> = {
  invalid_request: { status: 400, retryable: false },
  future_manifest: { status: 400, retryable: false },
  stale_event: { status: 400, retryable: false },
  unauthorized: { status: 401, retryable: false },
  forbidden: { status: 403, retryable: false },
  stale_manifest: { status: 403, retryable: false },
  re_enrollment_required: { status: 403, retryable: false },
  idempotency_conflict: { status: 409, retryable: false },
  event_id_conflict: { status: 409, retryable: false },
  sequence_conflict: { status: 409, retryable: false },
  unsupported_media_type: { status: 415, retryable: false },
  rate_limited: { status: 429, retryable: true },
  queue_full: { status: 429, retryable: true },
  quota_exceeded: { status: 429, retryable: true },
  billing_pending: { status: 503, retryable: true },
  unavailable: { status: 503, retryable: true },
};

const ERROR_CODES = new Set<string>(Object.keys(TAXONOMY));

export function isRetryableSealedCode(code: SealedErrorCode): boolean {
  return TAXONOMY[code].retryable;
}

export class SealedApiError extends Error {
  readonly code: SealedErrorCode | SealedClientErrorCode;
  readonly status: number;
  readonly retryable: boolean;

  constructor(code: SealedErrorCode | SealedClientErrorCode, status: number, retryable: boolean, detail: string) {
    super(`Sealed message plane ${code} (HTTP ${status}): ${detail}`);
    this.name = "SealedApiError";
    this.code = code;
    this.status = status;
    this.retryable = retryable;
  }
}

function fail(message: string): never {
  throw new Error(`ZTSE message-plane client: ${message}`);
}

/** Minimal transport shape; the platform `fetch` satisfies it. */
export type SealedFetch = (
  url: string,
  init: Readonly<{ method: "POST"; headers: Readonly<Record<string, string>>; body: Uint8Array }>,
) => Promise<{ status: number; json(): Promise<unknown> }>;

export type SealedOutboundAccepted = Readonly<{ messageId: string; created: boolean }>;
export type SealedInboundAccepted = Readonly<{ eventId: string; created: boolean }>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function acceptedFields(body: unknown, identity: "message_id" | "event_id", status: number): { id: string; created: boolean } {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new SealedApiError("unexpected_response", status, false, "202 body is not a JSON object");
  }
  const record = body as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.length !== 2 || !keys.includes(identity) || !keys.includes("created")) {
    throw new SealedApiError("unexpected_response", status, false, `202 body must contain exactly ${identity} and created`);
  }
  const id = record[identity];
  if (typeof id !== "string" || !UUID.test(id)) {
    throw new SealedApiError("unexpected_response", status, false, `202 ${identity} is not a lowercase UUID`);
  }
  if (typeof record.created !== "boolean") {
    throw new SealedApiError("unexpected_response", status, false, "202 created is not a boolean");
  }
  return { id, created: record.created };
}

function errorCode(body: unknown, status: number): SealedErrorCode {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new SealedApiError("unexpected_response", status, false, "error body is not a JSON object");
  }
  const record = body as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 1 || keys[0] !== "code") {
    throw new SealedApiError("unexpected_response", status, false, "error body must contain exactly one code field");
  }
  const code = record.code;
  if (typeof code !== "string" || !ERROR_CODES.has(code)) {
    throw new SealedApiError("unexpected_response", status, false, `unknown error code ${String(code)}`);
  }
  return code as SealedErrorCode;
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes as unknown as ArrayBuffer);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Sends one envelope and maps the response. The request body is the exact
 * bytes; retries, when the caller uses `withRetry`, resend the identical
 * digest. Bounded syntax is validated locally first via the draft-01 reader,
 * including the kind, so a mismatched envelope never leaves the client.
 */
export class SealedMessagePlaneClient {
  private readonly origin: string;
  private readonly bearer: string;
  private readonly fetchImpl: SealedFetch;

  constructor(options: Readonly<{ origin: string; bearer: string; fetchImpl: SealedFetch }>) {
    let parsed: URL;
    try {
      parsed = new URL(options.origin);
    } catch {
      fail("origin is not a URL");
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") fail("origin protocol must be http or https");
    if (parsed.pathname !== "/" && parsed.pathname !== "") fail("origin must not carry a path");
    if (parsed.search || parsed.hash) fail("origin must not carry a query or fragment");
    if (parsed.username || parsed.password) fail("origin must not carry credentials");
    if (typeof options.bearer !== "string" || options.bearer.length === 0 || /[^\x21-\x7e]/.test(options.bearer)) {
      fail("bearer token must be nonempty printable ASCII without spaces");
    }
    this.origin = parsed.origin;
    this.bearer = options.bearer;
    this.fetchImpl = options.fetchImpl;
  }

  async submitOutbound(envelope: Uint8Array): Promise<SealedOutboundAccepted> {
    const accepted = await this.post(OUTBOUND_PATH, envelope, 1);
    return { messageId: accepted.id, created: accepted.created };
  }

  async uploadInboundEvent(envelope: Uint8Array): Promise<SealedInboundAccepted> {
    const accepted = await this.post(INBOUND_PATH, envelope, 2);
    return { eventId: accepted.id, created: accepted.created };
  }

  /**
   * Retries a submission with the exact same bytes on retryable admission
   * failures (rate_limited, queue_full, quota_exceeded, billing_pending,
   * unavailable) and never otherwise. The envelope digest is pinned before
   * the first attempt; a mutated envelope between attempts is refused
   * instead of silently sending different content.
   */
  async withRetry<T>(
    submit: (envelope: Uint8Array) => Promise<T>,
    envelope: Uint8Array,
    options: Readonly<{ maxAttempts: number; sleepMs: (attempt: number) => number; sleep?: (ms: number) => Promise<void> }>,
  ): Promise<T> {
    if (!Number.isInteger(options.maxAttempts) || options.maxAttempts < 1) fail("maxAttempts must be a positive integer");
    const digest = await sha256(envelope);
    let lastError: SealedApiError | undefined;
    for (let attempt = 1; attempt <= options.maxAttempts; attempt++) {
      if (await sha256(envelope) !== digest) {
        throw new SealedApiError("envelope_mutated", 0, false, "envelope bytes changed between retry attempts");
      }
      try {
        return await submit(envelope);
      } catch (error) {
        if (!(error instanceof SealedApiError) || !error.retryable) throw error;
        lastError = error;
      }
      if (attempt < options.maxAttempts) {
        const sleep = options.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
        await sleep(options.sleepMs(attempt));
      }
    }
    throw lastError;
  }

  private async post(path: string, envelope: Uint8Array, kind: 1 | 2): Promise<{ id: string; created: boolean }> {
    if (!(envelope instanceof Uint8Array)) fail("envelope must be raw Uint8Array bytes, never JSON or base64");
    const parsed = parseDraftEnvelope(envelope);
    if (parsed.kind !== kind) fail(`envelope kind ${parsed.kind} does not belong on ${path}`);
    const response = await this.fetchImpl(`${this.origin}${path}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.bearer}`,
        "content-type": SEALED_CONTENT_TYPE,
        accept: "application/json",
      },
      body: envelope,
    });
    if (response === null || response === undefined || typeof response.status !== "number" || typeof response.json !== "function") {
      throw new SealedApiError("unexpected_response", 0, false, "transport returned a malformed response");
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new SealedApiError("unexpected_response", response.status, false, "response body is not JSON");
    }
    if (response.status === 202) return acceptedFields(body, kind === 1 ? "message_id" : "event_id", response.status);
    const code = errorCode(body, response.status);
    const known = TAXONOMY[code];
    if (known.status !== response.status) {
      throw new SealedApiError("unexpected_response", response.status, false, `code ${code} arrived on wrong status`);
    }
    throw new SealedApiError(code, response.status, known.retryable, "admission failure");
  }
}
