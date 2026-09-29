// Cross-client ZT-009 Q9 vector for the strict body-text receive rules.
// Consumes the same public fixture as crates/server/tests/zt_body_text_vectors.rs,
// the Android corpus and the Python suite; every client must reach identical
// verdicts for the shared bytes. Test-only material.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { decodeBodyText } from "../dist/draft01.js";

const vector = JSON.parse(readFileSync(
  new URL("../../../protocol/v1/vectors/ztse-body-text-01.json", import.meta.url),
  "utf8",
));
const bytes = (hex) => new Uint8Array(Buffer.from(hex, "hex"));

test("shared body-text corpus matches the TypeScript receive rules", () => {
  assert.equal(vector.status, "UNAPPROVED_TEST_ONLY");
  assert.equal(vector.maxBodyTextBytes, 32768);
  for (const entry of vector.textCases) {
    const raw = bytes(entry.hex);
    if (entry.verdict === "accept") {
      const text = decodeBodyText(raw);
      if (entry.text !== undefined) assert.equal(text, entry.text, entry.name);
      if (entry.textLength !== undefined) assert.equal(text.length, entry.textLength, entry.name);
    } else if (entry.verdict === "reject") {
      // Length, NUL and BOM fail the rule check; invalid UTF-8 throws from the
      // fatal decoder. Both must surface as exceptions, never as text.
      assert.throws(() => decodeBodyText(raw), (error) => error instanceof Error, entry.name);
    } else {
      assert.fail(`unknown fixture verdict for ${entry.name}`);
    }
  }
});
