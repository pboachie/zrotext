// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

(function (root) {
  const limits = Object.freeze({ template: 4096, substitutions: 4096, entries: 32, value: 512, output: 8192 });
  const identifier = /^[A-Za-z_][A-Za-z0-9_]{0,31}$/;
  const reserved = new Set(["__proto__", "prototype", "constructor"]);
  function validKey(key) { return identifier.test(key) && !reserved.has(key); }

  function boundedText(text, maximum) {
    if (typeof text !== "string" || text.length > maximum) throw new Error("Text exceeds the allowed limit.");
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code >= 0xD800 && code <= 0xDBFF) {
        const next = text.charCodeAt(++i);
        if (!(next >= 0xDC00 && next <= 0xDFFF)) throw new Error("Text contains an incomplete Unicode character.");
      } else if (code >= 0xDC00 && code <= 0xDFFF) {
        throw new Error("Text contains an incomplete Unicode character.");
      }
    }
  }

  function parseValues(text) {
    boundedText(text, limits.substitutions);
    const values = Object.create(null);
    let count = 0;
    for (const line of text.split(/\r?\n/)) {
      if (line === "") continue;
      const equals = line.indexOf("=");
      const key = line.slice(0, equals);
      if (equals < 1 || !validKey(key)) throw new Error("Use one identifier=value entry per line.");
      if (Object.hasOwn(values, key)) throw new Error("Each identifier may appear only once.");
      if (++count > limits.entries) throw new Error("Too many substitution entries.");
      const value = line.slice(equals + 1);
      boundedText(value, limits.value);
      if (value.includes("\r")) throw new Error("Substitution values must fit on one line.");
      values[key] = value;
    }
    return values;
  }

  function render(template, values) {
    boundedText(template, limits.template);
    if (!values || typeof values !== "object" || Array.isArray(values)) throw new Error("Invalid substitutions.");
    const keys = Reflect.ownKeys(values);
    if (keys.length > limits.entries) throw new Error("Too many substitution entries.");
    const safe = Object.create(null);
    let total = 0;
    for (const key of keys) {
      if (typeof key !== "string" || !validKey(key)) throw new Error("Invalid substitution identifier.");
      const descriptor = Object.getOwnPropertyDescriptor(values, key);
      if (!descriptor || !Object.hasOwn(descriptor, "value")) throw new Error("Substitutions must be plain text values.");
      boundedText(descriptor.value, limits.value);
      total += key.length + 1 + descriptor.value.length + (total ? 1 : 0);
      if (total > limits.substitutions) throw new Error("Text exceeds the allowed limit.");
      safe[key] = descriptor.value;
    }
    let output = "";
    const token = /\{\{([A-Za-z_][A-Za-z0-9_]{0,31})\}\}/y;
    for (let index = 0; index < template.length;) {
      let piece;
      if (template[index] === "{") {
        token.lastIndex = index;
        const match = token.exec(template);
        if (!match || !validKey(match[1])) throw new Error("Use only {{identifier}} variables; braces must form a complete variable.");
        if (!Object.hasOwn(safe, match[1])) throw new Error("A template variable has no value.");
        piece = safe[match[1]];
        index = token.lastIndex;
      } else {
        if (template[index] === "}") throw new Error("Use only {{identifier}} variables; braces must form a complete variable.");
        piece = template[index++];
      }
      if (output.length + piece.length > limits.output) throw new Error("Rendered text exceeds the output limit.");
      output += piece;
    }
    return output;
  }
  const api = Object.freeze({ limits, parseValues, render });
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.ZtTemplatePreview = api;
})(globalThis);
