// SPDX-License-Identifier: AGPL-3.0-only
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { encodeFixtureConfirmation } from "./conversation-simulator-send.mjs";
test("browser confirmation matches canonical Rust vector and exact body digest",async()=>{
  const value=JSON.parse(await readFile(new URL("../../../protocol/v1/vectors/conversation-send.json",import.meta.url),"utf8"));
  assert.equal(encodeFixtureConfirmation(value.confirmation).toString("hex"),value.canonical_hex);
  assert.equal(createHash("sha256").update(value.body,"utf8").digest("base64"),value.confirmation.bodyDigest);
  const altered={...value.confirmation,peer:"+13"};assert.notEqual(encodeFixtureConfirmation(altered).toString("hex"),value.canonical_hex);
  assert.throws(()=>encodeFixtureConfirmation({...value.confirmation,peer:"+1 2"}));
});
