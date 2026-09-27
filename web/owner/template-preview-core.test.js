// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
const assert = require("node:assert/strict");
const test = require("node:test");
const { limits, parseValues, render } = require("./template-preview-core.js");

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
