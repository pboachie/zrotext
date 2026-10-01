// SPDX-License-Identifier: AGPL-3.0-only
// Bounded template contract shared by the browser preview and future saved
// templates: content is text only, identifiers are plain, and every save is
// content-addressed so a changed template is detectable by its digest.
// The relay never stores or evaluates template plaintext; this module runs
// where the plaintext already lives (the owner's browser).

export const templateLimits = Object.freeze({
  template: 4096,
  substitutions: 4096,
  entries: 32,
  value: 512,
  output: 8192,
});

const identifier = /^[A-Za-z_][A-Za-z0-9_]{0,31}$/;
const reserved = new Set(["__proto__", "prototype", "constructor"]);

function validKey(key: string): boolean {
  return identifier.test(key) && !reserved.has(key);
}

/** Reject oversized text and any lone surrogate (same rule as the preview). */
export function boundedText(text: string, maximum: number): void {
  if (typeof text !== "string" || text.length > maximum) {
    throw new Error("Text exceeds the allowed limit.");
  }
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new Error("Text contains an incomplete Unicode character.");
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error("Text contains an incomplete Unicode character.");
    }
  }
}

/**
 * Validate a template against the bounded contract. Throws on oversize
 * text, lone surrogates, malformed {{identifier}} tokens, stray braces, or
 * a template that could not render at all.
 */
export function validateTemplate(template: string): void {
  boundedText(template, templateLimits.template);
  for (let index = 0; index < template.length; ) {
    if (template[index] === "{") {
      const rest = template.slice(index);
      const match = /^\{\{([A-Za-z_][A-Za-z0-9_]{0,31})\}\}/.exec(rest);
      if (!match || !validKey(match[1])) {
        throw new Error(
          "Use only {{identifier}} variables; braces must form a complete variable.",
        );
      }
      index += match[0].length;
    } else {
      if (template[index] === "}") {
        throw new Error(
          "Use only {{identifier}} variables; braces must form a complete variable.",
        );
      }
      index += 1;
    }
  }
}

/**
 * Validate personalization values: plain string keys and values only,
 * bounded per entry and in total, no reserved or malformed identifiers.
 */
export function validateValues(values: Record<string, string>): void {
  if (!values || typeof values !== "object" || Array.isArray(values)) {
    throw new Error("Invalid substitutions.");
  }
  const keys = Reflect.ownKeys(values);
  if (keys.length > templateLimits.entries) {
    throw new Error("Too many substitution entries.");
  }
  let total = 0;
  for (const key of keys) {
    if (typeof key !== "string" || !validKey(key)) {
      throw new Error("Invalid substitution identifier.");
    }
    const descriptor = Object.getOwnPropertyDescriptor(values, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) {
      throw new Error("Substitutions must be plain text values.");
    }
    boundedText(descriptor.value, templateLimits.value);
    total += key.length + 1 + descriptor.value.length + (total ? 1 : 0);
    if (total > templateLimits.substitutions) {
      throw new Error("Text exceeds the allowed limit.");
    }
  }
}

/** The canonical bytes a template's version digest is taken over. */
export function canonicalTemplateBytes(
  template: string,
  values: Record<string, string>,
): Uint8Array {
  validateTemplate(template);
  validateValues(values);
  const keys = Reflect.ownKeys(values)
    .filter((key): key is string => typeof key === "string")
    .sort();
  const canonical = JSON.stringify({
    v: 1,
    template,
    values: Object.fromEntries(keys.map((key) => [key, values[key]])),
  });
  return new TextEncoder().encode(canonical);
}

/**
 * Content digest of a template plus its personalization contract: the
 * SHA-256 of the canonical UTF-8 bytes. Saving the same content again
 * yields the same digest; any change yields a different one, which is how
 * a changed template is detected as a new version.
 */
export async function templateDigest(
  template: string,
  values: Record<string, string>,
): Promise<string> {
  const bytes = canonicalTemplateBytes(template, values);
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    bytes as unknown as ArrayBuffer,
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
