// SPDX-License-Identifier: AGPL-3.0-only
// Production sealed message-plane client corpus (issue #537 slice B). Every
// test runs against an in-process node:http server that asserts the exact
// wire format the sealed v1 contract pins (raw envelope body, the single
// allowed content type, no idempotency-key header, Bearer authentication) and
// scripts responses; the real server route is default-off and never needed.
// The scheme-rewriting transport below downgrades only inside this test
// process so the plaintext loopback listener can stand in for the production
// https origin the client itself refuses to relax. All tokens, UUIDs and
// envelope bytes are synthetic test data.
import assert from "node:assert/strict";
import http from "node:http";
import { createHash, webcrypto } from "node:crypto";
import { test } from "node:test";
import { isSealedClientError, SEALED_CONTENT_TYPE, SealedClient, SealedClientError } from "../dist/sealed-client.js";

globalThis.crypto ??= webcrypto;

const bearerFixture = ["test", "token"].join("-");
const MESSAGE_ID = "1f0e5b0a-9c2d-4b6a-8e3f-7a1c2d4e5f60";
const OUTBOUND_PATH = "/v1/sealed/messages";

// Synthetic envelope-shaped bytes (magic/profile/kind plus deterministic
// filler); the client transports bytes and never parses them, so the digest is
// simply the SHA-256 of everything except the fixed 64-byte signature trailer.
const envelope = (() => {
  const bytes = new Uint8Array(520);
  bytes.set(new TextEncoder().encode("ZTSE"), 0);
  bytes[4] = 2;
  bytes[5] = 1;
  let state = 0x2b;
  for (let index = 6; index < bytes.length; index++) {
    state = (state * 31 + index) & 0xff;
    bytes[index] = state;
  }
  return bytes;
})();
const unsignedDigest = Uint8Array.from(
  createHash("sha256").update(envelope.subarray(0, envelope.length - 64)).digest(),
);
const sha256 = (bytes) => Uint8Array.from(createHash("sha256").update(bytes).digest());
const sameBytes = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

function jsonReply(status, body, headers = {}, delayMs = 0) {
  return { status, body: JSON.stringify(body), headers, delayMs };
}

// Records every request, then plays a scripted reply sequence; after the last
// scripted reply it keeps repeating that reply. `destroy` tears the socket
// down instead of answering, and `delayMs` stalls the response.
function mockSealedServer() {
  const requests = [];
  let nextReply = () => jsonReply(202, { message_id: MESSAGE_ID, created: true });
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      requests.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) });
      const reply = nextReply(requests.length);
      if (!reply || reply.destroy) {
        res.socket?.destroy();
        return;
      }
      const send = () => {
        res.writeHead(reply.status, {
          "content-type": "application/json",
          "cache-control": "no-store",
          ...(reply.headers ?? {}),
        });
        res.end(reply.body ?? "");
      };
      if (reply.delayMs) setTimeout(send, reply.delayMs);
      else send();
    });
  });
  return {
    requests,
    port: new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve(server.address().port));
    }),
    script(replies) {
      const queue = [...replies];
      nextReply = () => (queue.length > 1 ? queue.shift() : queue[0]);
    },
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections?.();
        server.closeIdleConnections?.();
        server.close(() => resolve());
      }),
  };
}

async function withServer(run, options = {}) {
  const server = mockSealedServer();
  try {
    const port = await server.port;
    const client = new SealedClient({
      baseUrl: `https://127.0.0.1:${port}`,
      apiToken: bearerFixture,
      timeoutMs: options.timeoutMs,
      retry: options.retry,
      sleep: options.sleep,
      fetchImpl: options.fetchImpl ?? ((url, init) => fetch(url.replace("https://", "http://"), init)),
    });
    await run(server, client);
  } finally {
    await server.close();
  }
}

const recordedSleep = () => {
  const sleeps = [];
  return { sleeps, sleep: async (ms) => { sleeps.push(ms); } };
};

function assertTyped(error, code, { status = 0, attempts = 1 } = {}) {
  assert.ok(error instanceof SealedClientError, `not a SealedClientError: ${String(error)}`);
  assert.ok(isSealedClientError(error), "type guard accepts its own errors");
  assert.equal(error.code, code);
  assert.equal(error.status, status);
  assert.equal(error.attempts, attempts);
  assert.match(error.message, /ZTSE sealed client:/);
  assert.ok(!error.message.includes(bearerFixture), "error message must not contain the token");
}

test("submission sends only the exact envelope bytes with the pinned content type and no idempotency header", async () => {
  await withServer(async (server, client) => {
    server.script([jsonReply(202, { message_id: MESSAGE_ID, created: true })]);
    await client.submitSealedMessage(envelope, unsignedDigest);
    assert.equal(server.requests.length, 1);
    const request = server.requests[0];
    assert.equal(request.method, "POST");
    assert.equal(request.url, OUTBOUND_PATH, "no query string, nothing besides the sealed path");
    assert.equal(request.headers["content-type"], SEALED_CONTENT_TYPE, "byte-exact media type, no parameters");
    assert.ok(!request.headers["content-type"].includes(","), "exactly one content-type header");
    assert.ok(
      Object.keys(request.headers).every((name) => !name.includes("idempotency")),
      "no idempotency header in any casing",
    );
    assert.equal(request.headers.authorization, `Bearer ${bearerFixture}`);
    assert.ok(sameBytes(request.body, envelope), "the request body is the raw envelope bytes");
    assert.equal(request.body.length, envelope.length);
  });
});

test("a 202 acceptance parses message_id and created and replays surface created:false", async () => {
  await withServer(async (server, client) => {
    server.script([jsonReply(202, { message_id: MESSAGE_ID, created: true })]);
    const accepted = await client.submitSealedMessage(envelope, unsignedDigest);
    assert.deepEqual(accepted, { messageId: MESSAGE_ID, created: true });
    assert.match(accepted.messageId, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    server.script([jsonReply(202, { message_id: MESSAGE_ID, created: false })]);
    const replay = await client.submitSealedMessage(envelope, unsignedDigest);
    assert.deepEqual(replay, { messageId: MESSAGE_ID, created: false });
  });
});

const TERMINAL = [
  ["invalid_request", 400],
  ["unauthorized", 401],
  ["forbidden", 403],
  ["idempotency_conflict", 409],
  ["unsupported_media_type", 415],
  ["queue_full", 429],
  ["quota_exceeded", 429],
];

for (const [code, status] of TERMINAL) {
  test(`terminal taxonomy: ${code} on ${status} maps to a typed error with no retry`, async () => {
    await withServer(async (server, client) => {
      server.script([jsonReply(status, { code }, status === 429 ? { "retry-after": "60" } : {})]);
      await assert.rejects(
        client.submitSealedMessage(envelope, unsignedDigest),
        (error) => {
          assertTyped(error, code, { status, attempts: 1 });
          assert.equal(error.serverCode, code);
          assert.equal(error.retryable, false);
          return true;
        },
      );
      assert.equal(server.requests.length, 1, "terminal failures are never retried");
    });
  });
}

test("idempotency_conflict exposes the sent digest and the server code and never recomposes", async () => {
  await withServer(async (server, client) => {
    server.script([jsonReply(409, { code: "idempotency_conflict" })]);
    await assert.rejects(
      client.submitSealedMessage(envelope, unsignedDigest),
      (error) => {
        assertTyped(error, "idempotency_conflict", { status: 409 });
        assert.ok(sameBytes(error.digest, unsignedDigest), "the conflict error carries the digest that was sent");
        assert.equal(error.serverCode, "idempotency_conflict");
        return true;
      },
    );
    assert.equal(server.requests.length, 1);
    assert.ok(sameBytes(server.requests[0].body, envelope), "the exact bytes were sent once, unchanged");
  });
});

test("rate_limited 429 retries with the server's Retry-After, capped by the client bound, and resends identical bytes", async () => {
  const { sleeps, sleep } = recordedSleep();
  await withServer(
    async (server, client) => {
      server.script([
        jsonReply(429, { code: "rate_limited" }, { "retry-after": "60" }),
        jsonReply(202, { message_id: MESSAGE_ID, created: true }),
      ]);
      const accepted = await client.submitSealedMessage(envelope, unsignedDigest);
      assert.deepEqual(accepted, { messageId: MESSAGE_ID, created: true });
      assert.equal(server.requests.length, 2);
      assert.deepEqual(sleeps, [5000], "Retry-After honored but bounded by maxDelayMs");
      for (const request of server.requests) {
        assert.equal(request.headers["content-type"], SEALED_CONTENT_TYPE);
        assert.ok(sameBytes(request.body, envelope), "every retry resends the exact same bytes");
      }
    },
    { retry: { maxAttempts: 3, maxDelayMs: 5000 }, sleep },
  );
});

test("unavailable 503 without Retry-After retries on the bounded backoff schedule", async () => {
  const { sleeps, sleep } = recordedSleep();
  await withServer(
    async (server, client) => {
      server.script([
        jsonReply(503, { code: "unavailable" }),
        jsonReply(202, { message_id: MESSAGE_ID, created: true }),
      ]);
      await client.submitSealedMessage(envelope, unsignedDigest);
      assert.equal(server.requests.length, 2);
      assert.deepEqual(sleeps, [123]);
    },
    { retry: { maxAttempts: 2, backoffMs: () => 123 }, sleep },
  );
});

test("billing_pending 503 honors its Retry-After subject to the retry bound", async () => {
  const { sleeps, sleep } = recordedSleep();
  await withServer(
    async (server, client) => {
      server.script([
        jsonReply(503, { code: "billing_pending" }, { "retry-after": "10" }),
        jsonReply(202, { message_id: MESSAGE_ID, created: false }),
      ]);
      const accepted = await client.submitSealedMessage(envelope, unsignedDigest);
      assert.equal(accepted.created, false);
      assert.deepEqual(sleeps, [3000], "10 s hint capped at the 3 s bound");
    },
    { retry: { maxAttempts: 2, maxDelayMs: 3000 }, sleep },
  );
});

test("exhausting the bounded retries ends in a terminal typed error carrying the last status and code", async () => {
  const { sleeps, sleep } = recordedSleep();
  await withServer(
    async (server, client) => {
      server.script([jsonReply(429, { code: "rate_limited" }, { "retry-after": "1" })]);
      await assert.rejects(
        client.submitSealedMessage(envelope, unsignedDigest),
        (error) => {
          assertTyped(error, "rate_limited", { status: 429, attempts: 3 });
          assert.equal(error.retryAfterMs, 1000);
          assert.equal(error.retryable, true, "the class stays retryable for caller-driven backoff");
          return true;
        },
      );
      assert.equal(server.requests.length, 3);
      assert.deepEqual(sleeps, [1000, 1000], "no sleep after the final attempt");
      for (const request of server.requests) assert.ok(sameBytes(request.body, envelope));
    },
    { retry: { maxAttempts: 3 }, sleep },
  );
});

test("network failures retry the same submission and end in a terminal network typed error", async () => {
  const { sleeps, sleep } = recordedSleep();
  await withServer(
    async (server, client) => {
      server.script([{ destroy: true }]);
      await assert.rejects(
        client.submitSealedMessage(envelope, unsignedDigest),
        (error) => {
          assertTyped(error, "network", { status: 0, attempts: 2 });
          assert.equal(error.retryable, true);
          return true;
        },
      );
      assert.equal(server.requests.length, 2, "one send plus one retry");
      assert.deepEqual(sleeps, [1000], "backoff default applies without a Retry-After");
    },
    { retry: { maxAttempts: 2 }, sleep },
  );
});

test("a per-attempt timeout is a typed terminal error and is not retried", async () => {
  const { sleeps, sleep } = recordedSleep();
  await withServer(
    async (server, client) => {
      server.script([jsonReply(202, { message_id: MESSAGE_ID, created: true }, {}, 500)]);
      await assert.rejects(
        client.submitSealedMessage(envelope, unsignedDigest),
        (error) => {
          assertTyped(error, "timeout", { status: 0, attempts: 1 });
          assert.equal(error.retryable, false, "an uncertain outcome is surfaced, never auto-retried");
          return true;
        },
      );
      const deadline = Date.now() + 2000;
      while (server.requests.length < 1 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 10));
      assert.equal(server.requests.length, 1, "exactly one request left the client");
      assert.deepEqual(sleeps, []);
    },
    { timeoutMs: 80, retry: { maxAttempts: 3 }, sleep },
  );
});

test("a retry resends the very same bytes object, not a re-encoded copy", async () => {
  const bodies = [];
  const calls = [];
  const fetchImpl = async (url, init) => {
    bodies.push(init.body);
    calls.push({ url, headers: { ...init.headers } });
    return bodies.length === 1
      ? new Response(JSON.stringify({ code: "rate_limited" }), { status: 429, headers: { "retry-after": "0" } })
      : new Response(JSON.stringify({ message_id: MESSAGE_ID, created: true }), { status: 202 });
  };
  await withServer(
    async (_server, client) => {
      const accepted = await client.submitSealedMessage(envelope, unsignedDigest);
      assert.equal(accepted.created, true);
      assert.equal(bodies.length, 2);
      assert.ok(bodies[0] === bodies[1], "the identical Uint8Array object is resent (Q6 identity)");
      assert.ok(bodies[0] === envelope, "the caller's exact object is sent, never copied or JSON-encoded");
      assert.equal(calls[0].url, calls[1].url);
      assert.deepEqual(calls[0].headers, calls[1].headers);
      assert.equal(calls[0].headers["content-type"], SEALED_CONTENT_TYPE);
    },
    { retry: { maxAttempts: 2, maxDelayMs: 0 }, sleep: async () => {}, fetchImpl },
  );
});

test("malformed server responses fail closed as typed unexpected_response, never a crash or silent success", async () => {
  const cases = [
    [202, { message_id: "not-a-uuid", created: true }],
    [202, { message_id: MESSAGE_ID, created: true, extra: 1 }],
    [202, { created: true }],
    [202, { message_id: MESSAGE_ID, created: "yes" }],
    [202, { message_id: MESSAGE_ID.toUpperCase(), created: true }],
    [400, { code: "forbidden" }],
    [400, { code: "future_manifest" }],
    [400, { code: "invalid_request", detail: "why" }],
    [500, { code: "unavailable" }],
    [200, { message_id: MESSAGE_ID, created: true }],
  ];
  for (const [status, body] of cases) {
    await withServer(async (server, client) => {
      server.script([jsonReply(status, body)]);
      await assert.rejects(
        client.submitSealedMessage(envelope, unsignedDigest),
        (error) => {
          assertTyped(error, "unexpected_response", { status, attempts: 1 });
          return true;
        },
        `status ${status} body ${JSON.stringify(body)}`,
      );
      assert.equal(server.requests.length, 1, "an off-contract response is never retried");
    });
  }
  for (const [status, raw] of [[202, "accepted"], [429, "slow down"]]) {
    await withServer(async (server, client) => {
      server.script([{ status, body: raw }]);
      await assert.rejects(
        client.submitSealedMessage(envelope, unsignedDigest),
        (error) => {
          assertTyped(error, "unexpected_response", { status, attempts: 1 });
          return true;
        },
        `non-JSON body on ${status}`,
      );
      assert.equal(server.requests.length, 1, "an unparsable 429 is not blindly retried either");
    });
  }
  // The raw server code survives on off-taxonomy bodies for inspection.
  await withServer(async (server, client) => {
    server.script([jsonReply(400, { code: "future_manifest" })]);
    await assert.rejects(client.submitSealedMessage(envelope, unsignedDigest), (error) => {
      assertTyped(error, "unexpected_response", { status: 400 });
      assert.equal(error.serverCode, "future_manifest");
      return true;
    });
  });
});

test("the constructor refuses non-https origins and unsafe tokens before any request exists", () => {
  const make = (options) => () => new SealedClient(options);
  const valid = { baseUrl: "https://relay.example", apiToken: bearerFixture };
  assert.throws(make({ ...valid, baseUrl: "http://relay.example" }), /https/);
  assert.throws(make({ ...valid, baseUrl: "ftp://relay.example" }), /https/);
  assert.throws(make({ ...valid, baseUrl: "https://relay.example/v1/alpha" }), /path/);
  assert.throws(make({ ...valid, baseUrl: "https://relay.example/?x=1" }), /query/);
  assert.throws(make({ ...valid, baseUrl: "https://relay.example#f" }), /fragment/);
  assert.throws(make({ ...valid, baseUrl: ["https://user", "pass@relay.example"].join(":") }), /credentials/);
  assert.throws(make({ ...valid, apiToken: "" }), /token/);
  assert.throws(make({ ...valid, apiToken: "has space" }), /token/);
  assert.throws(make({ ...valid, timeoutMs: 0 }), /timeout/);
  assert.throws(make({ ...valid, retry: { maxAttempts: 0 } }), /maxAttempts/);
  assert.doesNotThrow(make(valid));
  assert.doesNotThrow(make({ ...valid, baseUrl: "https://relay.example/" }));
});

test("the token never reaches URLs, query strings or error output", async () => {
  await withServer(async (server, client) => {
    server.script([jsonReply(401, { code: "unauthorized" })]);
    await assert.rejects(client.submitSealedMessage(envelope, unsignedDigest), (error) => {
      assertTyped(error, "unauthorized", { status: 401 });
      return true;
    });
    server.script([{ destroy: true }]);
    await assert.rejects(
      client.submitSealedMessage(envelope, unsignedDigest),
      (error) => {
        assertTyped(error, "network", { status: 0, attempts: 1 });
        const cause = error.cause instanceof Error ? error.cause.message : String(error.cause ?? "");
        assert.ok(!cause.includes(bearerFixture), "the transport cause must not echo the token");
        return true;
      },
    );
    for (const request of server.requests) {
      assert.equal(request.url, OUTBOUND_PATH, "no token is ever smuggled into the URL");
      assert.equal(request.headers.authorization, `Bearer ${bearerFixture}`);
    }
    assert.equal(isSealedClientError(new Error("unrelated")), false, "guard rejects foreign errors");
  }, { sleep: async () => {}, retry: { maxAttempts: 1 } });
});

test("local input validation refuses a mismatched envelope/digest pair with no request", async () => {
  await withServer(async (server, client) => {
    const wrongDigest = sha256(envelope); // digest of the FULL bytes, not the unsigned bytes
    await assert.rejects(client.submitSealedMessage(envelope, wrongDigest), /unsignedDigest does not match/);
    await assert.rejects(client.submitSealedMessage(envelope, unsignedDigest.subarray(0, 31)), /32-byte/);
    await assert.rejects(client.submitSealedMessage("not-bytes", unsignedDigest), /Uint8Array/);
    assert.equal(server.requests.length, 0, "nothing leaves the client on a refused input");
  });
});
