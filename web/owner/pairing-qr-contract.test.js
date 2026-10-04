// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const pairingCode = require("./pairing-code.js");
const decodeProposal = text => pairingCode.decode(text, "https://gateway.example.invalid");

const sample = () => ({ type: "zrotext-pairing", v: 1, origin: "https://gateway.example.invalid", pairing_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", token: "ztp_" + "A".repeat(43) });

test("pairing QR transports only existing pairing inputs with no recovery authority", () => {
  const payload = sample();
  assert.deepEqual(decodeProposal(JSON.stringify(payload)), payload);
  assert.equal(new Set(Object.keys(payload)).size, 5);
  assert.equal(Buffer.byteLength(JSON.stringify(payload), "utf8") <= 512, true);
});

const changes = {
  "insecure server": { origin: "http://gateway.example.invalid" },
  "userinfo": { origin: "https://owner@gateway.example.invalid" },
  "server path": { origin: "https://gateway.example.invalid/owner" },
  "server query": { origin: "https://gateway.example.invalid?token=value" },
  "server fragment": { origin: "https://gateway.example.invalid#pair" },
  "noncanonical trailing slash": { origin: "https://gateway.example.invalid/" },
  "origin surrounding whitespace": { origin: " https://gateway.example.invalid" },
  "unsupported version": { v: 2 },
  "string version": { v: "1" },
  "wrong kind": { type: "recovery" },
  "malformed pairing ID": { pairing_id: "not-an-id" },
  "short token": { token: "ztp_" + "A".repeat(42) },
  "token with newline": { token: "ztp_" + "A".repeat(42) + "\n" },
  "noncanonical base64url token": { token: "ztp_" + "A".repeat(42) + "B" },
  "extra account authority": { account_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
  "extra recovery field": { recovery: "synthetic" },
  "null origin": { origin: null },
  "oversized field": { token: "A".repeat(600) },
};
for (const [name, change] of Object.entries(changes)) {
  test(`pairing QR rejects ${name} before network or navigation`, () => {
    assert.throws(() => decodeProposal(JSON.stringify({ ...sample(), ...change })), /Pairing code is not valid/);
  });
}
test("pairing QR rejects duplicate keys and noncanonical serialization", () => {
  const encoded = JSON.stringify(sample());
  assert.throws(() => decodeProposal(encoded.replace('"v":1', '"v":2,"v":1')), /Pairing code is not valid/);
  assert.throws(() => decodeProposal(" " + encoded), /Pairing code is not valid/);
  assert.throws(() => decodeProposal(encoded.replace('"v":1', '"v":1.0')), /Pairing code is not valid/);
});
test("pairing QR rejects direct URLs and arbitrary JSON containers", () => {
  for (const text of ["https://gateway.example.invalid", "null", "[]", "true", "{}", ""]) {
    assert.throws(() => decodeProposal(text), /Pairing code is not valid/);
  }
});

test("pairing QR binds a scan to the independently selected server", () => {
  const payload = sample();
  const text = pairingCode.encode(payload.origin, payload.pairing_id, payload.token);
  assert.deepEqual(pairingCode.decode(text, payload.origin), payload);
  assert.throws(() => pairingCode.decode(text, "https://other.example.invalid"), /different server/);
  assert.throws(() => pairingCode.decode(text, payload.origin + "/"), /Pairing code is not valid/);
});

test("pairing QR requires an independently established origin for every decode", () => {
  const payload = sample();
  const text = pairingCode.encodePairingPayload(payload.origin, payload.pairing_id, payload.token);
  for (const missing of [undefined, null, ""]) {
    assert.throws(() => pairingCode.decodePairingPayload(text, missing), /Pairing code is not valid/);
  }
  assert.deepEqual(pairingCode.decodePairingPayload(text, payload.origin), payload);
});

test("pairing QR rejects reordered, missing, nested and escaped fields", () => {
  const payload = sample();
  assert.throws(() => decodeProposal(JSON.stringify({ v: payload.v, ...payload })), /Pairing code is not valid/);
  delete payload.token;
  assert.throws(() => decodeProposal(JSON.stringify(payload)), /Pairing code is not valid/);
  assert.throws(() => decodeProposal(JSON.stringify({ ...sample(), token: { value: "synthetic" } })), /Pairing code is not valid/);
  assert.throws(() => decodeProposal(JSON.stringify(sample()).replace('"v":1', '"\\u0076":1')), /Pairing code is not valid/);
});

test("pairing QR failure messages never reflect scanned secrets", () => {
  const text = JSON.stringify({ ...sample(), recovery: "PRIVATE_RECOVERY_CANARY" });
  try { decodeProposal(text); assert.fail("unexpected acceptance"); }
  catch (error) { assert.equal(error.message.includes("PRIVATE_RECOVERY_CANARY"), false); }
});

test("local QR rendering preserves a four-module quiet zone without DOM payload attributes", () => {
  const paints = [];
  const context = { fillStyle: "", fillRect(x, y, width, height) { paints.push({ x, y, width, height, color: this.fillStyle }); }, clearRect() {} };
  const canvas = { width: 0, height: 0, getContext: () => context,
    setAttribute() { assert.fail("encoded data must not be written to attributes"); } };
  const payload = sample();
  pairingCode.render(canvas, pairingCode.encode(payload.origin, payload.pairing_id, payload.token));
  assert.equal(canvas.width, canvas.height);
  assert.equal(paints[0].color, "#ffffff");
  assert.equal(paints[0].width, canvas.width);
  assert.equal(paints[0].height, canvas.height);
  const modules = paints.slice(1);
  assert.equal(modules.length > 0, true);
  for (const paint of modules) {
    assert.equal(paint.color, "#000000");
    assert.equal(paint.width, 4);
    assert.equal(paint.height, 4);
    assert.equal(paint.x >= 16 && paint.y >= 16, true);
    assert.equal(paint.x + 4 <= canvas.width - 16 && paint.y + 4 <= canvas.height - 16, true);
  }
});

test("clearing a QR discards its backing bitmap and tolerates unsupported canvases", () => {
  let cleared = false;
  const canvas = { width: 260, height: 260, getContext: () => ({ clearRect() { cleared = true; } }) };
  pairingCode.clear(canvas);
  assert.equal(cleared, true);
  assert.equal(canvas.width, 1);
  assert.equal(canvas.height, 1);
  assert.doesNotThrow(() => pairingCode.clear(null));
  assert.doesNotThrow(() => pairingCode.clear({}));
});
