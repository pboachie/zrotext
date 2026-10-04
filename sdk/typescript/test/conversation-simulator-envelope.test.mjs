// SPDX-License-Identifier: AGPL-3.0-only
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const tool = fileURLToPath(new URL("./conversation-simulator-envelope.mjs", import.meta.url));
const capture = (n = 1) => ({ body: "Synthetic bounded capture", capture: `${n.toString(16).padStart(8,"0")}-1111-2222-3333-444444444444`, observed: 1, sequence: n });
function refused(captures, expected = "fixture batch capture identity") {
  const result = spawnSync(process.execPath, [tool], { input: JSON.stringify({ op: "batch", captures }), encoding: "utf8", timeout: 5000 });
  assert.equal(result.error, undefined);
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, "");
  assert.ok(result.stderr.includes(expected));
}
test("fixture batch refuses missing empty and over-capacity requests before using any keys", () => {
  for (const values of [undefined, {}, [], Array.from({ length: 129 }, (_, i) => capture(i + 1))]) refused(values, "fixture batch bound");
});
test("fixture batch refuses duplicate event or sequence identities", () => {
  refused([capture(), capture()]);
  refused([capture(), { ...capture(2), sequence: 1 }]);
});
test("fixture batch refuses noncanonical capture identity and invalid receipt time or sequence", () => {
  for (const value of [{ capture: "invalid" }, { capture: "00000000-0000-0000-0000-000000000000" },
    { observed: 0 }, { observed: 1.5 }, { sequence: 0 }, { sequence: Number.MAX_SAFE_INTEGER + 1 }]) refused([{ ...capture(), ...value }]);
});
test("fixture batch refuses malformed or oversized body and per-item scope/key overrides", () => {
  for (const body of ["", "\0", "\uFEFFSynthetic", "x".repeat(32769)]) refused([{ ...capture(), body }]);
  refused([{ ...capture(), ready: {} }]);
  refused([{ ...capture(), device: "unselected" }]);
});
