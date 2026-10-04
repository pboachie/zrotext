// SPDX-License-Identifier: AGPL-3.0-only
import test, { mock } from "node:test";
import assert from "node:assert/strict";
import { OriginalReplyClient } from "../dist/original-reply-client.js";
import { originalReplyFixture } from "./original-reply-fixture.mjs";
import { readFile } from "node:fs/promises";
import { workflowActionDigest } from "../dist/workflow-decisions.js";
import { createHash } from "node:crypto";
const b64 = b => Buffer.from(b).toString("base64"), hex = b => Buffer.from(b).toString("hex");
const uuid = b => hex(b).replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
function proof(f) { return { account_id: uuid(f.scope.account), interval_id: uuid(f.scope.interval), device_id: uuid(f.scope.device), line_id: uuid(f.scope.line),
  connector_id: uuid(f.scope.connector), read_grant_id: uuid(f.scope.readGrant), reader_id: hex(f.scope.reader), root_generation: 1, authority_revision: 1,
  expires_at_ms: 90000, observed_at_ms: 2000, current_manifest_version: 7, current_manifest_digest: hex(f.manifest.digest),
  manifest_chain: [{ version: 7, accepted_at_ms: 2000, manifest_b64: b64(f.manifest.bytes) }] }; }
function readResult(f) { return { event_id: uuid(f.event), accepted_at_ms: 2000, envelope_b64: b64(f.envelope), historical_manifest_version: 7,
  statement_b64: b64(f.statement), approval_signature_b64: b64(f.approval), installation_signature_b64: b64(f.installation), activation_manifest_version: 7, proof: proof(f) }; }
function options(f, fetch) { return { origin: "https://customer.invalid", credential: "ztr_" + Buffer.alloc(32, 7).toString("base64url"), scope: f.scope,
  privateKey: f.privateKey, acceptedHistory: [f.manifest], clock: () => 2000n, fetch }; }
const response = (kind, result) => new Response(JSON.stringify({ kind, result }), { headers: { "content-type": "application/json" } });
test("verified original read binds its actual ciphertext and final current authority", async () => {
  const f = await originalReplyFixture(), requests = [];
  const client = new OriginalReplyClient(options(f, async (_url, init) => {
    const request = JSON.parse(init.body); requests.push(request);
    return response(request.method, request.method === "read" ? readResult(f) : { ...proof(f), expires_at_ms: 80000 });
  }));
  const result = await client.readVerified(f.event);
  assert.equal(result.plaintext, "synthetic original reply");
  assert.equal(result.event_id, uuid(f.event));
  assert.equal(result.event_envelope_digest, createHash("sha256").update(f.envelope).digest("hex"));
  assert.equal(result.accepted_manifest_version, 7);
  assert.equal(result.authority.expiresMs, 80000n);
  assert.equal(Object.isFrozen(result), true);
  assert.deepEqual(requests.map(request => request.method), ["read", "current"]);
});
test("verified original read publishes no source identity when final authority is revoked", async () => {
  const f = await originalReplyFixture(); let requests = 0;
  const client = new OriginalReplyClient(options(f, async () => ++requests === 1 ? response("read", readResult(f)) : new Response("", { status: 403 })));
  await assert.rejects(client.readVerified(f.event), /Original reply unavailable/);
  assert.equal(requests, 2);
});
test("original client uses separate bearer and current proof after real role3 opening", async () => {
  const f = await originalReplyFixture(), calls = [];
  const client = new OriginalReplyClient(options(f, async (url, init) => {
    assert.equal(url, "https://customer.invalid/v1/reply-events"); assert.equal(init.method, "POST");
    assert.equal(init.redirect, "error"); assert.equal(init.credentials, "omit"); assert.equal(init.cache, "no-store");
    assert.deepEqual(Object.keys(init.headers).sort(), ["authorization", "content-type"]);
    assert.match(init.headers.authorization, /^Bearer ztr_/); const request = JSON.parse(init.body); calls.push(request);
    return response(request.method, request.method === "read" ? readResult(f) : proof(f));
  }));
  assert.equal(await client.read(f.event), "synthetic original reply");
  assert.deepEqual(calls, [{ v: 1, method: "read", event_id: uuid(f.event), accepted_manifest_version: 7 }, { v: 1, method: "current", accepted_manifest_version: 7 }]);
});
test("original client refuses scope substitution, unknown fields and revocation without retry", async () => {
  for (const mutation of [p => ({ ...p, account_id: "14141414-1414-1414-1414-141414141414" }), p => ({ ...p, reader: "claimed" }), p => ({ ...p, authority_revision: 2 })]) {
    const f = await originalReplyFixture(); let calls = 0;
    const client = new OriginalReplyClient(options(f, async () => { calls++; return response("current", mutation(proof(f))); }));
    await assert.rejects(client.current(), /Original reply unavailable/); assert.equal(calls, 1);
  }
  const f = await originalReplyFixture(); let calls = 0;
  const client = new OriginalReplyClient(options(f, async () => ++calls === 1 ? response("read", readResult(f)) : new Response("", { status: 403 })));
  await assert.rejects(client.read(f.event), /Original reply unavailable/); assert.equal(calls, 2);
});
test("original client refuses a response-created past manifest and oversized body", async () => {
  const f = await originalReplyFixture(), result = readResult(f); result.historical_manifest_version = 6;
  const client = new OriginalReplyClient(options(f, async () => response("read", result)));
  await assert.rejects(client.read(f.event), /Original reply unavailable/);
  const oversized = new OriginalReplyClient(options(f, async () => new Response(" ".repeat(524289), { headers: { "content-type": "application/json" } })));
  await assert.rejects(oversized.current(), /Original reply unavailable/);
});
test("original client refuses local clock rollback before publishing a new current proof", async () => {
  const f = await originalReplyFixture(); let now = 2000n;
  const client = new OriginalReplyClient({ ...options(f, async () => response("current", proof(f))), clock: () => now });
  await client.current(); now = 1999n;
  await assert.rejects(client.current(), /Original reply unavailable/);
});
test("original client reads cached accepted past events without regressing its newer highwater", async () => {
  const f = await originalReplyFixture(), methods = [];
  const nextProof = chain => ({ ...proof(f), current_manifest_version: 8, current_manifest_digest: hex(f.successor.digest), manifest_chain: chain });
  const oldEntry = proof(f).manifest_chain[0], nextEntry = { version: 8, accepted_at_ms: 2000, manifest_b64: b64(f.successor.bytes) };
  const client = new OriginalReplyClient({ ...options(f, async (_url, init) => {
    const request = JSON.parse(init.body); methods.push(request);
    if (request.method === "read") return response("read", { ...readResult(f), proof: nextProof([oldEntry, nextEntry]) });
    return response("current", nextProof([nextEntry]));
  }), acceptedHistory: [f.manifest, f.successor] });
  assert.equal(await client.read(f.event, 7n), "synthetic original reply");
  assert.equal(methods[0].accepted_manifest_version, 7); assert.equal(methods[1].accepted_manifest_version, 8);
  await assert.rejects(client.read(f.event, 6n), /Original reply unavailable/); assert.equal(methods.length, 2);
});
test("original client verifies approval time separately from a capture after the challenge expired", async () => {
  const f = await originalReplyFixture({ observedMs: 6000n });
  const currentProof = { ...proof(f), observed_at_ms: 6000 };
  const client = new OriginalReplyClient({ ...options(f, async (_url, init) => {
    const method = JSON.parse(init.body).method;
    return response(method, method === "read" ? { ...readResult(f), accepted_at_ms: 2000, proof: currentProof } : currentProof);
  }), clock: () => 6000n });
  assert.equal(await client.read(f.event), "synthetic original reply");
  const incorrectReceiptTime = new OriginalReplyClient({ ...options(f, async () => response("read", { ...readResult(f), accepted_at_ms: 6000, proof: currentProof })), clock: () => 6000n });
  await assert.rejects(incorrectReceiptTime.read(f.event), /Original reply unavailable/);
});

test("original client keeps metadata availability separate from qualification and rejects unknown fields", async () => {
  const f = await originalReplyFixture(), event = { event_id: uuid(f.event), accepted_at_ms: 2000, observed_at_ms: 2000,
    historical_manifest_version: 7, activation_manifest_version: 7, disposition: "unassociated", active_request_ids: [] };
  const client = new OriginalReplyClient(options(f, async () => response("page", { events: [event], next: null, proof: proof(f) })));
  assert.deepEqual((await client.page()).events, [event]);
  for (const extra of [{ classification: "STOP" }, { message_id: uuid(f.event) }, { content: "claimed" }]) {
    const invalid = new OriginalReplyClient(options(f, async () => response("page", { events: [{ ...event, ...extra }], next: null, proof: proof(f) })));
    await assert.rejects(invalid.page(), /Original reply unavailable/);
  }
});

test("original client owner review uses no output capability and never retries lost consumption", async () => {
  const f = await originalReplyFixture(), request_id = "16161616-1616-1616-1616-161616161616";
  const input = { request_id, event_id: uuid(f.event), active_request_id: null, descriptor: null }; let calls = 0;
  const client = new OriginalReplyClient(options(f, async (_url, init) => {
    calls++; assert.equal(init.headers["x-zrotext-output-authorization"], undefined);
    const r = JSON.parse(init.body); assert.deepEqual(r.params, input); throw new Error("synthetic uncertain transport");
  }));
  await assert.rejects(client.consume(input)); assert.equal(calls, 1);
  await assert.rejects(client.consume({ ...input, consumer_id: "forged" })); assert.equal(calls, 1);
});

test("original client proposals use an independent trusted capability and exact full action binding", async () => {
  const f = await originalReplyFixture(), vector = JSON.parse(await readFile(new URL("../../../protocol/v1/vectors/workflow-action-01.json", import.meta.url)));
  const descriptor = { ...vector.action, account_id: uuid(f.scope.account), line_id: uuid(f.scope.line),
    action_id: '21212121-2121-2121-2121-212121212121', recipient_id: '22222222-2222-2222-2222-222222222222',
    purpose_id: '00000000-0000-0000-0000-000000000001', content_ref: '23232323-2323-2323-2323-232323232323',
    routine_id: '24242424-2424-2424-2424-242424242424' };
  const input = { request_id: "17171717-1717-1717-1717-171717171717", event_id: uuid(f.event),
    active_request_id: "18181818-1818-1818-1818-181818181818", descriptor };
  const key = { account_id: descriptor.account_id, action_id: descriptor.action_id, revision: descriptor.revision, binding_digest: await workflowActionDigest(descriptor) };
  const output = "ztw_" + Buffer.alloc(32, 11).toString("base64url"); let calls = 0;
  const result = { event_id: input.event_id, consumption_id: input.request_id, disposition: "proposal", active_request_id: input.active_request_id, action: key };
  const transport = async (_url, init) => {
    calls++; assert.equal(init.headers["x-zrotext-output-authorization"], "Bearer " + output);
    assert.match(init.headers.authorization, /^Bearer ztr_/); assert.equal(init.body.includes(output), false);
    return response("consume", result);
  };
  const noGrant = new OriginalReplyClient(options(f, transport)); await assert.rejects(noGrant.consume(input)); assert.equal(calls, 0);
  const client = new OriginalReplyClient({ ...options(f, transport), outputCredential: async () => output });
  assert.deepEqual((await client.consume(input)).action, key);
  const wrong = new OriginalReplyClient({ ...options(f, async () => response("consume", { ...result, action: { ...key, binding_digest: "00".repeat(32) } })), outputCredential: async () => output });
  await assert.rejects(wrong.consume(input), /Original reply unavailable/);
});

test("original client cannot publish a proof whose deadline passes during real signature verification", async () => {
  const f = await originalReplyFixture(); let now = 2000n;
  const originalVerify = crypto.subtle.verify.bind(crypto.subtle);
  const gate = mock.method(crypto.subtle, "verify", async (...args) => {
    const valid = await originalVerify(...args); now = 2100n; return valid;
  });
  try {
    const client = new OriginalReplyClient({ ...options(f, async () => response("current", { ...proof(f), expires_at_ms: 2100 })), clock: () => now });
    await assert.rejects(client.current(), /Original reply unavailable/);
    assert.ok(gate.mock.callCount() > 0);
  } finally { gate.mock.restore(); }
});

test("original client refuses a delayed old proof after a parallel proof advances accepted highwater", async () => {
  const f = await originalReplyFixture(); let firstCall = true, release, entered;
  const delayed = new Promise(resolve => { release = resolve; }), suspended = new Promise(resolve => { entered = resolve; });
  const originalVerify = crypto.subtle.verify.bind(crypto.subtle);
  const gate = mock.method(crypto.subtle, "verify", async (...args) => {
    if (firstCall) { firstCall = false; entered(); await delayed; }
    return originalVerify(...args);
  });
  let calls = 0;
  const successorProof = { ...proof(f), current_manifest_version: 8, current_manifest_digest: hex(f.successor.digest),
    manifest_chain: [...proof(f).manifest_chain, { version: 8, accepted_at_ms: 2000, manifest_b64: b64(f.successor.bytes) }] };
  try {
    const client = new OriginalReplyClient(options(f, async () => {
      calls++; return response("current", calls === 1 ? proof(f) : calls === 2 ? successorProof : { ...successorProof, manifest_chain: [successorProof.manifest_chain[1]] });
    }));
    const old = client.current(); await suspended;
    assert.equal((await client.current()).manifest.version, 8n);
    release(); await assert.rejects(old, /Original reply unavailable/);
    assert.equal((await client.current()).manifest.version, 8n);
  } finally { release(); gate.mock.restore(); }
});


test("original client bounds independently registered request availability to eight IDs", async () => {
  const f = await originalReplyFixture();
  const ids = Array.from({ length: 9 }, (_, i) => `31313131-3131-3131-3131-${String(i + 1).padStart(12, "0")}`);
  const event = { event_id: uuid(f.event), accepted_at_ms: 2000, observed_at_ms: 2000,
    historical_manifest_version: 7, activation_manifest_version: 7, disposition: "request_available", active_request_ids: ids.slice(0, 8) };
  const accepted = new OriginalReplyClient(options(f, async () => response("page", { events: [event], next: null, proof: proof(f) })));
  assert.deepEqual((await accepted.page()).events[0].active_request_ids, ids.slice(0, 8));
  const refused = new OriginalReplyClient(options(f, async () => response("page", { events: [{ ...event, active_request_ids: ids }], next: null, proof: proof(f) })));
  await assert.rejects(refused.page(), /Original reply unavailable/);
});
