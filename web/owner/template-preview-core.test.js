// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const assert = require("node:assert/strict");
const test = require("node:test");
const { readFileSync } = require("node:fs");
const { limits, parseValues, render, estimateSegments } = require("./template-preview-core.js");

test("variables render exact literal values, spaces, Unicode and repeated occurrences", () => {
  const values = parseValues("name= Alex 😀 \r\ntext={{name}}=<script>\r\nempty=");
  assert.equal(Object.getPrototypeOf(values), null);
  assert.equal(render("Hi {{name}}\n{{text}} {{name}}{{empty}}", values),
    "Hi  Alex 😀 \n{{name}}=<script>  Alex 😀 ");
  assert.equal(render("", parseValues("")), "");
});

test("missing, malformed, nested and expression variables fail closed", () => {
  for (const template of ["{{missing}}", "{name}", "{{name", "name}}", "{{{name}}}",
    "{{ name }}", "{{name.x}}", "{{name[0]}}", "{{name()}}", "{{x || name}}", "{{}}", "{{0x}}",
    "{{" + "x".repeat(33) + "}}", "{{{{name}}}}", "}", "{"]) {
    assert.throws(() => render(template, parseValues("name=Alex")));
  }
});

test("dictionary lookup never follows prototypes or invokes getters", () => {
  assert.throws(() => render("{{name}}", Object.create({ name: "inherited" })));
  for (const key of ["__proto__", "prototype", "constructor"]) {
    assert.throws(() => parseValues(`${key}=value`));
    const values = Object.create(null);
    values[key] = "value";
    assert.throws(() => render(`{{${key}}}`, values));
  }
  let read = false;
  const values = {};
  Object.defineProperty(values, "name", { get() { read = true; return "value"; } });
  assert.throws(() => render("{{name}}", values));
  assert.equal(read, false);
  assert.throws(() => render("x", { [Symbol("name")]: "value" }));
  for (const bad of [null, [], "text", { name: {} }, { name: 7 }]) assert.throws(() => render("x", bad));
});

test("entry parser rejects duplicates, invalid keys, CR values and oversized input", () => {
  for (const values of ["name=a\nname=b", "name", "=value", " name=value", "a.b=value", "name=a\rb"]) {
    assert.throws(() => parseValues(values));
  }
  assert.equal(parseValues("name=a=b").name, "a=b");
  assert.throws(() => parseValues("a=" + "x".repeat(limits.value + 1)));
  assert.throws(() => parseValues("x".repeat(limits.substitutions + 1)));
  assert.throws(() => parseValues(Array.from({ length: limits.entries + 1 }, (_, i) => `k${i}=x`).join("\n")));
  assert.equal(Object.keys(parseValues(Array.from({ length: limits.entries }, (_, i) => `k${i}=x`).join("\n"))).length, limits.entries);
});

test("bounds are checked before output expansion and at exact boundaries", () => {
  assert.equal(render("x".repeat(limits.template), {}), "x".repeat(limits.template));
  assert.throws(() => render("x".repeat(limits.template + 1), {}));
  const values = parseValues("x=" + "a".repeat(limits.value));
  assert.equal(render("{{x}}".repeat(16), values).length, limits.output);
  assert.throws(() => render("{{x}}".repeat(17), values));
  const many = Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`k${i}`, "a".repeat(512)]));
  assert.throws(() => render("{{k0}}", many));
});

test("unpaired surrogates are refused in every input, valid pairs stay exact", () => {
  for (const bad of ["\uD800", "\uDC00", "x\uD800x", "\uD800\uD800"]) {
    assert.throws(() => render(bad, {}));
    assert.throws(() => parseValues("name=" + bad));
    assert.throws(() => render("{{name}}", { name: bad }));
  }
  assert.equal(render("😀{{name}}", { name: "😀" }), "😀😀");
});

test("segment estimates match the shared protocol vectors", () => {
  const vectors = JSON.parse(readFileSync(
    require("node:path").join(__dirname, "../../protocol/v1/vectors/sms-segment-estimate-01.json"),
    "utf8",
  ));
  for (const vector of vectors.cases) {
    if (vector.error) {
      assert.throws(() => estimateSegments(vector.text), undefined, vector.name);
    } else {
      const got = estimateSegments(vector.text);
      assert.equal(got.encoding, vector.estimate.encoding, vector.name);
      assert.equal(got.parts, vector.estimate.parts, vector.name);
      assert.equal(got.perPart, vector.estimate.perPart, vector.name);
      assert.equal(got.length, vector.estimate.length, vector.name);
      assert.equal(got.empty, vector.estimate.empty, vector.name);
    }
  }
});

test("gsm extension characters cost two septets and never switch encoding", () => {
  assert.deepEqual(
    { ...estimateSegments("a^b") },
    { encoding: "gsm", parts: 1, perPart: 160, length: 4, empty: false },
  );
  const escapes = "\f^{}\\[~]|€";
  assert.equal(estimateSegments(escapes).length, 20);
  assert.equal(estimateSegments(escapes).encoding, "gsm");
});

test("one non-gsm character switches the whole text to ucs2", () => {
  const got = estimateSegments("abc喵def");
  assert.equal(got.encoding, "ucs2");
  assert.equal(got.length, 7);
  assert.equal(estimateSegments("👍").length, 2);
});

test("the six-part cap matches the device-side gate", () => {
  assert.equal(estimateSegments("a".repeat(918)).parts, 6);
  assert.throws(() => estimateSegments("a".repeat(919)), /six-part/);
  assert.throws(() => estimateSegments("喵".repeat(403)), /six-part/);
});
