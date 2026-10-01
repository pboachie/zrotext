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

  // Bounded SMS segment estimate per protocol/v1/sms-segment-estimate.md.
  // Composition aid only: no carrier or billing claim, and the device
  // re-checks the real bounds with divideMessage before dispatch.
  const gsmDefaultChars =
    "@\u00a3$\u00a5\u00e8\u00e9\u00f9\u00ec\u00f2\u00c7\n\u00d8\u00f8\r\u00c5\u00e5" +
    "\u0394_\u03a6\u0393\u039b\u03a9\u03a0\u03a8\u03a3\u0398\u039e\u00c6\u00e6\u00df" +
    "\u00c9 !\"#\u00a4%&'()*+,-./0123456789:;<=>?\u00a1" +
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ\u00c4\u00d6\u00d1\u00dc\u00a7\u00bf" +
    "abcdefghijklmnopqrstuvwxyz\u00e4\u00f6\u00f1\u00fc\u00e0";
  const gsmExtensionChars = "\u000c^{}\\[~]|\u20ac";
  const gsmDefault = new Set(gsmDefaultChars);
  const gsmExtension = new Set(gsmExtensionChars);
  const MAX_PARTS = 6;

  function estimateSegments(text) {
    if (typeof text !== "string") throw new Error("Rendered text must be a string.");
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i);
      if (code >= 0xD800 && code <= 0xDBFF) {
        const next = text.charCodeAt(++i);
        if (!(next >= 0xDC00 && next <= 0xDFFF)) throw new Error("Text contains an incomplete Unicode character.");
      } else if (code >= 0xDC00 && code <= 0xDFFF) {
        throw new Error("Text contains an incomplete Unicode character.");
      } else if (code < 0x20 && code !== 0x0a && code !== 0x0d && code !== 0x0c) {
        throw new Error("Control characters cannot be sent as SMS text.");
      }
    }
    let gsm = true;
    for (const ch of text) {
      if (!gsmDefault.has(ch) && !gsmExtension.has(ch)) { gsm = false; break; }
    }
    if (gsm) {
      let septets = 0;
      for (const ch of text) septets += gsmExtension.has(ch) ? 2 : 1;
      const single = septets <= 160;
      const perPart = single ? 160 : 153;
      const parts = single ? 1 : Math.ceil(septets / perPart);
      if (parts > MAX_PARTS) throw new Error("The text exceeds the six-part segment limit.");
      return { encoding: "gsm", parts, perPart, length: septets, empty: text.length === 0 };
    }
    const single = text.length <= 70;
    const perPart = single ? 70 : 67;
    const parts = single ? 1 : Math.ceil(text.length / perPart);
    if (parts > MAX_PARTS) throw new Error("The text exceeds the six-part segment limit.");
    return { encoding: "ucs2", parts, perPart, length: text.length, empty: text.length === 0 };
  }

  const api = Object.freeze({ limits, parseValues, render, estimateSegments });
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.ZtTemplatePreview = api;
})(globalThis);
