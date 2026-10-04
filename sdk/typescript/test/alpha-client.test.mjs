import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";
import {
  AlphaApiError,
  AlphaClient,
  AlphaOutcomeUnknownError,
  requiresReconciliation,
} from "../dist/index.js";

const MESSAGE = "7d3f1a52-0c1e-4b6a-9a77-3f2f7f0b1c11";
const DEVICE = "0a8b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const CLIENT_ID = "11111111-2222-4333-8444-555555555555";
const REQUEST = {
  clientMessageId: CLIENT_ID,
  deviceId: DEVICE,
  recipientE164: "+15550100001",
  testCaseId: "smoke-1",
  expiresAtMs: 1_900_000_000_000,
};

async function stub(handler, timeoutMs = 2000) {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const rec = {
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString(),
      };
      seen.push(rec);
      handler(rec, res);
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  const client = new AlphaClient({ baseUrl: `http://127.0.0.1:${port}`, apiKey: "test-token", timeoutMs });
  return {
    client,
    seen,
    close: () => {
      server.closeAllConnections();
      return new Promise((r) => server.close(r));
    },
  };
}

const json = (res, status, body, headers = {}) => {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
};

test("submit sends bearer, explicit Idempotency-Key and snake_case body", async () => {
  const s = await stub((_, res) => json(res, 202, { message_id: MESSAGE, created: true }));
  try {
    const out = await s.client.submit(REQUEST, "key-1.a_b");
    assert.deepEqual(out, { messageId: MESSAGE, created: true });
    const r = s.seen[0];
    assert.equal(r.method, "POST");
    assert.equal(r.url, "/v1/alpha/messages");
    assert.equal(r.headers.authorization, "Bearer test-token");
    assert.equal(r.headers["idempotency-key"], "key-1.a_b");
    assert.deepEqual(JSON.parse(r.body), {
      client_message_id: CLIENT_ID,
      device_id: DEVICE,
      recipient_e164: "+15550100001",
      test_case_id: "smoke-1",
      expires_at_ms: 1_900_000_000_000,
    });
  } finally {
    await s.close();
  }
});

test("submit validates the idempotency key and inputs before any request", async () => {
  const s = await stub((_, res) => json(res, 202, { message_id: MESSAGE, created: true }));
  try {
    for (const bad of ["", "has space", "x".repeat(129), "café", undefined]) {
      await assert.rejects(s.client.submit(REQUEST, bad), TypeError);
    }
    await assert.rejects(s.client.submit({ ...REQUEST, recipientE164: "5550100001" }, "k"), TypeError);
    await assert.rejects(s.client.submit({ ...REQUEST, testCaseId: "no spaces" }, "k"), TypeError);
    await assert.rejects(s.client.submit({ ...REQUEST, deviceId: "nope" }, "k"), TypeError);
    assert.equal(s.seen.length, 0);
  } finally {
    await s.close();
  }
});

test("idempotent replay surfaces created:false", async () => {
  const s = await stub((_, res) => json(res, 202, { message_id: MESSAGE, created: false }));
  try {
    assert.equal((await s.client.submit(REQUEST, "k")).created, false);
  } finally {
    await s.close();
  }
});

test("API errors expose status, code and Retry-After and are never retried", async () => {
  const s = await stub((_, res) => json(res, 429, { code: "rate_limited" }, { "retry-after": "60" }));
  try {
    await assert.rejects(s.client.submit(REQUEST, "k"), (e) => {
      assert.ok(e instanceof AlphaApiError);
      assert.equal(e.status, 429);
      assert.equal(e.code, "rate_limited");
      assert.equal(e.retryAfterSeconds, 60);
      return true;
    });
    assert.equal(s.seen.length, 1);
  } finally {
    await s.close();
  }
});

test("bare 503 without a JSON body is an API error with no code", async () => {
  const s = await stub((_, res) => {
    res.writeHead(503, { "retry-after": "1" });
    res.end();
  });
  try {
    await assert.rejects(
      s.client.getStatus(MESSAGE),
      (e) => e instanceof AlphaApiError && e.status === 503 && e.code === undefined && e.retryAfterSeconds === 1,
    );
  } finally {
    await s.close();
  }
});

for (const [label, respond] of [
  ["408 deadline", (res) => { res.writeHead(408); res.end(); }],
  ["bare 502 from a proxy", (res) => { res.writeHead(502); res.end(); }],
  ["bare 503 admission refusal", (res) => { res.writeHead(503, { "retry-after": "1" }); res.end(); }],
  ["500 without a JSON error body", (res) => { res.writeHead(500); res.end("oops"); }],
]) {
  test(`submit ending in ${label} is an unknown outcome and is not retried`, async () => {
    const s = await stub((_, res) => respond(res));
    try {
      await assert.rejects(
        s.client.submit(REQUEST, "k"),
        (e) => e instanceof AlphaOutcomeUnknownError && e.operation === "submit",
      );
      assert.equal(s.seen.length, 1);
    } finally {
      await s.close();
    }
  });
}

test("submit 503 carrying the server's JSON code is a definitive refusal", async () => {
  const s = await stub((_, res) => json(res, 503, { code: "billing_pending" }, { "retry-after": "10" }));
  try {
    await assert.rejects(
      s.client.submit(REQUEST, "k"),
      (e) => e instanceof AlphaApiError && e.status === 503 && e.code === "billing_pending",
    );
  } finally {
    await s.close();
  }
});

test("transport failure on submit is an unknown outcome and is not retried", async () => {
  const s = await stub((_, res) => res.socket.destroy());
  try {
    await assert.rejects(
      s.client.submit(REQUEST, "k"),
      (e) => e instanceof AlphaOutcomeUnknownError && e.operation === "submit",
    );
    assert.equal(s.seen.length, 1);
  } finally {
    await s.close();
  }
});

test("timeout is an unknown outcome", async () => {
  const s = await stub(() => {}, 50);
  try {
    await assert.rejects(s.client.submit(REQUEST, "k"), AlphaOutcomeUnknownError);
  } finally {
    await s.close();
  }
});

test("getStatus parses the snapshot and flags unknown for reconciliation", async () => {
  const s = await stub((_, res) =>
    json(res, 200, {
      message_id: MESSAGE,
      device_id: DEVICE,
      state: "unknown",
      state_version: 4,
      created_at_ms: 1,
      updated_at_ms: 2,
    }),
  );
  try {
    const st = await s.client.getStatus(MESSAGE);
    assert.equal(s.seen[0].method, "GET");
    assert.equal(s.seen[0].url, `/v1/alpha/messages/${MESSAGE}`);
    assert.deepEqual(st, {
      messageId: MESSAGE,
      deviceId: DEVICE,
      state: "unknown",
      stateVersion: 4,
      createdAtMs: 1,
      updatedAtMs: 2,
    });
    assert.equal(requiresReconciliation(st.state), true);
    assert.equal(requiresReconciliation("delivered"), false);
  } finally {
    await s.close();
  }
});

test("cancel resolves on 204 and maps 409 to a conflict error", async () => {
  let n = 0;
  const s = await stub((_, res) => {
    if (n++ === 0) {
      res.writeHead(204);
      res.end();
    } else {
      json(res, 409, { code: "conflict" });
    }
  });
  try {
    await s.client.cancel(MESSAGE);
    assert.equal(s.seen[0].method, "POST");
    assert.equal(s.seen[0].url, `/v1/alpha/messages/${MESSAGE}/cancel`);
    await assert.rejects(s.client.cancel(MESSAGE), (e) => e instanceof AlphaApiError && e.code === "conflict");
  } finally {
    await s.close();
  }
});

test("malformed success body is an unknown outcome, not a success", async () => {
  const s = await stub((_, res) => json(res, 202, { nope: true }));
  try {
    await assert.rejects(s.client.submit(REQUEST, "k"), AlphaOutcomeUnknownError);
  } finally {
    await s.close();
  }
});
