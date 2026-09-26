import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { SealedApiError, SealedMessagePlaneClient, SEALED_CONTENT_TYPE, isRetryableSealedCode } from "../dist/msgplane-client.js";

globalThis.crypto ??= webcrypto;

const fixture = JSON.parse(await readFile(new URL("../../../protocol/v1/vectors/ztse-draft-01.json", import.meta.url)));
const outbound = Uint8Array.from(Buffer.from(fixture.outbound.envelopeHex, "hex"));
const inbound = Uint8Array.from(Buffer.from(fixture.inbound.envelopeHex, "hex"));

function jsonResponse(status, body) {
  return { status, json: async () => body };
}

function recordingTransport(responses) {
  const calls = [];
  const queue = [...responses];
  const fetchImpl = async (url, init) => {
    calls.push({ url, method: init.method, headers: { ...init.headers }, body: Uint8Array.from(init.body) });
    const next = queue.shift();
    return typeof next === "function" ? next(calls.length) : next;
  };
  return { calls, fetchImpl };
}

function client(fetchImpl) {
  return new SealedMessagePlaneClient({ origin: "https://relay.example", bearer: "test-token", fetchImpl });
}

test("outbound submission sends exact raw bytes with the sealed content type and no idempotency header", async () => {
  const transport = recordingTransport([jsonResponse(202, { message_id: "1f0e5b0a-9c2d-4b6a-8e3f-7a1c2d4e5f60", created: true })]);
  const accepted = await client(transport.fetchImpl).submitOutbound(outbound);
  assert.deepEqual(accepted, { messageId: "1f0e5b0a-9c2d-4b6a-8e3f-7a1c2d4e5f60", created: true });
  assert.equal(transport.calls.length, 1);
  const call = transport.calls[0];
  assert.equal(call.url, "https://relay.example/v1/sealed/messages");
  assert.equal(call.method, "POST");
  assert.equal(call.headers["content-type"], SEALED_CONTENT_TYPE);
  assert.equal(call.headers.authorization, "Bearer test-token");
  assert.equal(call.headers["idempotency-key"], undefined);
  assert.equal(call.headers["x-idempotency-key"], undefined);
  assert.deepEqual(call.body, outbound);
});

test("inbound upload targets the separate sealed inbound route and maps event_id", async () => {
  const transport = recordingTransport([jsonResponse(202, { event_id: "2b1f6c3d-8a4e-4c7a-9d2f-0a3b4c5d6e70", created: false })]);
  const accepted = await client(transport.fetchImpl).uploadInboundEvent(inbound);
  assert.deepEqual(accepted, { eventId: "2b1f6c3d-8a4e-4c7a-9d2f-0a3b4c5d6e70", created: false });
  assert.equal(transport.calls[0].url, "https://relay.example/v1/sealed/inbound-events");
  assert.equal(transport.calls[0].headers["content-type"], SEALED_CONTENT_TYPE);
  assert.deepEqual(transport.calls[0].body, inbound);
});

test("local bounded validation refuses non-envelope bodies before any transport call", async () => {
  const transport = recordingTransport([]);
  const sealed = client(transport.fetchImpl);
  await assert.rejects(sealed.submitOutbound(Uint8Array.of(1, 2, 3)), /ZTSE draft-01: envelope size/);
  await assert.rejects(sealed.submitOutbound("not-bytes"), /must be raw Uint8Array/);
  assert.equal(transport.calls.length, 0);
});

test("kind mismatch is refused locally: inbound envelopes never take the outbound route", async () => {
  const transport = recordingTransport([]);
  await assert.rejects(client(transport.fetchImpl).submitOutbound(inbound), /kind 2 does not belong on/);
  await assert.rejects(client(transport.fetchImpl).uploadInboundEvent(outbound), /kind 1 does not belong on/);
  assert.equal(transport.calls.length, 0);
});

test("constructor refuses origins that smuggle paths, queries or credentials", () => {
  const make = (origin, bearer = "t") => () => new SealedMessagePlaneClient({ origin, bearer, fetchImpl: async () => jsonResponse(202, {}) });
  assert.throws(make("https://relay.example/v1/alpha"), /must not carry a path/);
  assert.throws(make("https://relay.example?x=1"), /must not carry a query/);
  const credentialed = ["https://", "user", ":pass@", "relay.example"].join("");
  assert.throws(make(credentialed), /must not carry credentials/);
  assert.throws(make("ftp://relay.example"), /protocol/);
  assert.throws(make("https://relay.example", "has space"), /printable ASCII/);
  assert.throws(make("https://relay.example", ""), /bearer token/);
  assert.doesNotThrow(make("https://relay.example/"));
});

const TAXONOMY = [
  ["invalid_request", 400, false], ["future_manifest", 400, false], ["stale_event", 400, false],
  ["unauthorized", 401, false],
  ["forbidden", 403, false], ["stale_manifest", 403, false], ["re_enrollment_required", 403, false],
  ["idempotency_conflict", 409, false], ["event_id_conflict", 409, false], ["sequence_conflict", 409, false],
  ["unsupported_media_type", 415, false],
  ["rate_limited", 429, true], ["queue_full", 429, true], ["quota_exceeded", 429, true],
  ["billing_pending", 503, true], ["unavailable", 503, true],
];

for (const [code, status, retryable] of TAXONOMY) {
  test(`taxonomy: ${code} on ${status} maps to a ${retryable ? "retryable" : "terminal"} SealedApiError`, async () => {
    const transport = recordingTransport([jsonResponse(status, { code })]);
    await assert.rejects(client(transport.fetchImpl).submitOutbound(outbound), (error) => {
      assert.ok(error instanceof SealedApiError);
      assert.equal(error.code, code);
      assert.equal(error.status, status);
      assert.equal(error.retryable, retryable);
      assert.equal(isRetryableSealedCode(code), retryable);
      return true;
    });
  });
}

test("a taxonomy code arriving on the wrong HTTP status is an unexpected response", async () => {
  const transport = recordingTransport([jsonResponse(500, { code: "forbidden" })]);
  await assert.rejects(client(transport.fetchImpl).submitOutbound(outbound), (error) => {
    assert.ok(error instanceof SealedApiError);
    assert.equal(error.code, "unexpected_response");
    assert.equal(error.retryable, false);
    return true;
  });
});

test("off-taxonomy statuses and malformed bodies are unexpected responses", async () => {
  const sealed404 = client(recordingTransport([jsonResponse(404, { code: "invalid_request" })]).fetchImpl);
  const sealed500 = client(recordingTransport([jsonResponse(500, { error: "boom" })]).fetchImpl);
  const sealedBody = client(recordingTransport([{ status: 202, json: async () => { throw new Error("no"); } }]).fetchImpl);
  await assert.rejects(sealed404.submitOutbound(outbound), (e) => e.code === "unexpected_response");
  await assert.rejects(sealed500.submitOutbound(outbound), (e) => e.code === "unexpected_response");
  await assert.rejects(sealedBody.submitOutbound(outbound), (e) => e.code === "unexpected_response");
});

test("202 shape violations are refused: extra fields, missing fields, non-UUID identities", async () => {
  const cases = [
    { message_id: "not-a-uuid", created: true },
    { message_id: "1f0e5b0a-9c2d-4b6a-8e3f-7a1c2d4e5f60", created: true, extra: 1 },
    { created: true },
    { message_id: "1f0e5b0a-9c2d-4b6a-8e3f-7a1c2d4e5f60", created: "yes" },
  ];
  for (const body of cases) {
    const transport = recordingTransport([jsonResponse(202, body)]);
    await assert.rejects(client(transport.fetchImpl).submitOutbound(outbound), (e) => e instanceof SealedApiError && e.code === "unexpected_response");
  }
});

test("error body shape violations are refused: extra fields and unknown codes", async () => {
  for (const body of [{ code: "forbidden", detail: "x" }, { code: "new_code" }, {}]) {
    const transport = recordingTransport([jsonResponse(403, body)]);
    await assert.rejects(client(transport.fetchImpl).submitOutbound(outbound), (e) => e instanceof SealedApiError && e.code === "unexpected_response");
  }
});

test("withRetry resends byte-identical bytes on retryable failures and succeeds", async () => {
  const transport = recordingTransport([
    jsonResponse(429, { code: "rate_limited" }),
    jsonResponse(503, { code: "unavailable" }),
    jsonResponse(202, { message_id: "1f0e5b0a-9c2d-4b6a-8e3f-7a1c2d4e5f60", created: true }),
  ]);
  const sleeps = [];
  const sealed = client(transport.fetchImpl);
  const accepted = await sealed.withRetry(
    (envelope) => sealed.submitOutbound(envelope),
    outbound,
    { maxAttempts: 3, sleepMs: () => 0, sleep: async (ms) => sleeps.push(ms) },
  );
  assert.equal(accepted.created, true);
  assert.equal(transport.calls.length, 3);
  for (const call of transport.calls) {
    assert.deepEqual(call.body, outbound);
    assert.equal(call.headers["content-type"], SEALED_CONTENT_TYPE);
  }
  assert.deepEqual(sleeps, [0, 0]);
});

test("withRetry stops immediately on terminal failures", async () => {
  const transport = recordingTransport([jsonResponse(403, { code: "stale_manifest" })]);
  const sealed = client(transport.fetchImpl);
  await assert.rejects(
    sealed.withRetry((envelope) => sealed.submitOutbound(envelope), outbound, { maxAttempts: 5, sleepMs: () => 0, sleep: async () => {} }),
    (e) => e.code === "stale_manifest" && e.retryable === false,
  );
  assert.equal(transport.calls.length, 1);
});

test("withRetry exhausts attempts on persistent unavailability and throws the last error", async () => {
  const transport = recordingTransport([
    jsonResponse(503, { code: "billing_pending" }),
    jsonResponse(503, { code: "billing_pending" }),
  ]);
  const sealed = client(transport.fetchImpl);
  await assert.rejects(
    sealed.withRetry((envelope) => sealed.submitOutbound(envelope), outbound, { maxAttempts: 2, sleepMs: () => 0, sleep: async () => {} }),
    (e) => e.code === "billing_pending" && e.retryable === true,
  );
  assert.equal(transport.calls.length, 2);
});

test("withRetry refuses a mutated envelope instead of silently sending different bytes", async () => {
  const transport = recordingTransport([jsonResponse(429, { code: "queue_full" })]);
  const sealed = client(transport.fetchImpl);
  const envelope = Uint8Array.from(outbound);
  const attempt = await sealed.withRetry(
    (bytes) => sealed.submitOutbound(bytes),
    envelope,
    {
      maxAttempts: 3,
      sleepMs: () => 0,
      sleep: async () => {
        envelope[envelope.length - 1] ^= 0xff;
      },
    },
  ).then(
    () => assert.fail("expected envelope_mutated"),
    (error) => error,
  );
  assert.ok(attempt instanceof SealedApiError);
  assert.equal(attempt.code, "envelope_mutated");
  assert.equal(attempt.retryable, false);
  assert.equal(transport.calls.length, 1);
});

test("a transport returning a malformed response is classified, not crashed on", async () => {
  const transport = recordingTransport([undefined]);
  await assert.rejects(client(transport.fetchImpl).submitOutbound(outbound), (error) => {
    assert.ok(error instanceof SealedApiError);
    assert.equal(error.code, "unexpected_response");
    assert.equal(error.retryable, false);
    return true;
  });
});
