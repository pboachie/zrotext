// SPDX-License-Identifier: AGPL-3.0-only
// Vector tests for the bounded segment estimate and template contract.
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { estimateSegments, MAX_PARTS } from "../dist/sms-segments.js";
import {
  templateDigest,
  validateTemplate,
  validateValues,
  templateLimits,
} from "../dist/template-contract.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(
    path.join(here, "../../../protocol/v1/vectors/sms-segment-estimate-01.json"),
    "utf8",
  ),
);

test("every shared vector matches the estimator", () => {
  for (const vector of vectors.cases) {
    if (vector.error) {
      assert.throws(() => estimateSegments(vector.text), new RegExp(vector.error), vector.name);
    } else {
      assert.deepEqual(estimateSegments(vector.text), vector.estimate, vector.name);
    }
  }
});

test("extension characters cost two septets and switch nothing", () => {
  assert.equal(estimateSegments("a^b").length, 4);
  assert.equal(estimateSegments("a^b").encoding, "gsm");
  const allEscapes = "\f^{}\\[~]|€";
  assert.equal(estimateSegments(allEscapes).length, 20);
});

test("one non-gsm character switches the whole message to ucs2", () => {
  const estimate = estimateSegments("abc喵def");
  assert.equal(estimate.encoding, "ucs2");
  assert.equal(estimate.length, 7);
});

test("astral characters count two ucs2 code units", () => {
  assert.equal(estimateSegments("👍").length, 2);
});

test("multipart thresholds use the concatenated sizes", () => {
  assert.equal(estimateSegments("a".repeat(160)).parts, 1);
  assert.equal(estimateSegments("a".repeat(161)).parts, 2);
  assert.equal(estimateSegments("a".repeat(306)).parts, 2);
  assert.equal(estimateSegments("a".repeat(307)).parts, 3);
  assert.equal(estimateSegments("喵".repeat(70)).parts, 1);
  assert.equal(estimateSegments("喵".repeat(71)).parts, 2);
  assert.equal(estimateSegments("喵".repeat(134)).parts, 2);
  assert.equal(estimateSegments("喵".repeat(135)).parts, 3);
});

test("the six-part cap matches the device gate", () => {
  assert.equal(estimateSegments("a".repeat(918)).parts, MAX_PARTS);
  assert.throws(() => estimateSegments("a".repeat(919)), /too long/);
  assert.throws(() => estimateSegments("喵".repeat(403)), /too long/);
});

test("mutation: dropping the escape doubling changes a vector", () => {
  // If "^" counted as one septet, "a"*158+"^" would be 159, not 160; the
  // boundary vector above pins the doubled cost.
  assert.equal(estimateSegments("a".repeat(158) + "^").length, 160);
  assert.equal(estimateSegments("a".repeat(158) + "^").parts, 1);
});

test("template contract: valid template and values pass", () => {
  assert.doesNotThrow(() => validateTemplate("hello {{name}}, bye"));
  assert.doesNotThrow(() => validateValues({ name: "me" }));
});

test("template contract: malformed tokens and stray braces are rejected", () => {
  assert.throws(() => validateTemplate("hello {{name}"), /complete variable/);
  assert.throws(() => validateTemplate("hello {name}}"), /complete variable/);
  assert.throws(() => validateTemplate("hello }}"), /complete variable/);
  assert.throws(() => validateTemplate("hello {{1bad}}"), /complete variable/);
  assert.throws(() => validateTemplate("x".repeat(templateLimits.template + 1)), /allowed limit/);
  assert.throws(() => validateTemplate("a\ud800b"), /incomplete Unicode/);
});

test("template contract: invalid personalization data is rejected", () => {
  assert.throws(() => validateValues(null), /Invalid substitutions/);
  assert.throws(() => validateValues([["a", "b"]]), /Invalid substitutions/);
  assert.throws(() => validateValues({ "bad-key": "x" }), /identifier/);
  const reservedKey = { ok: "y" };
  // A real own __proto__ property (assignment would hit the setter).
  Object.defineProperty(reservedKey, "__proto__", {
    value: "x", enumerable: true, writable: true, configurable: true,
  });
  assert.throws(() => validateValues(reservedKey), /identifier/);
  const tooMany = {};
  for (let i = 0; i < templateLimits.entries + 1; i += 1) tooMany[`k${i}`] = "v";
  assert.throws(() => validateValues(tooMany), /Too many/);
  assert.throws(() => validateValues({ v: "x".repeat(templateLimits.value + 1) }), /allowed limit/);
  const nested = {};
  Object.defineProperty(nested, "ok", { get() { return "x"; } });
  assert.throws(() => validateValues(nested), /plain text values/);
});

test("template digest is content-addressed and order-insensitive", async () => {
  const a = await templateDigest("hi {{name}}", { name: "x", city: "y" });
  const b = await templateDigest("hi {{name}}", { city: "y", name: "x" });
  const changedTemplate = await templateDigest("hi {{nick}}", { name: "x", city: "y" });
  const changedValue = await templateDigest("hi {{name}}", { name: "z", city: "y" });
  assert.equal(a, b);
  assert.notEqual(a, changedTemplate);
  assert.notEqual(a, changedValue);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test("template digest: invalid inputs never produce a digest", async () => {
  await assert.rejects(() => templateDigest("}}", {}), /complete variable/);
  await assert.rejects(() => templateDigest("ok", { "bad key": "v" }), /identifier/);
});
