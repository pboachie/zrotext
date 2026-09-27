import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { enrollRootPin02, verifyManifest02, advanceManifestTrust02,
  verifyRootTransition02 } from "../dist/draft02-manifest.js";

const vector = JSON.parse(await readFile(new URL("./vectors/draft02-rotation.json", import.meta.url)));
const bytes = (value) => Uint8Array.from(Buffer.from(value, "base64"));
const pin = () => bytes(vector.old_root_pin_b64);
const fingerprint = () => bytes(vector.old_root_fingerprint_b64);
const manifest = () => bytes(vector.old_manifest_b64);
const transition = () => bytes(vector.transition_b64);
const now = new DataView(transition().buffer).getBigUint64(199, false);

test("root enrollment compares the fingerprint supplied at invocation", async () => {
  const compared = new Uint8Array(32);
  const pending = enrollRootPin02(pin(), compared);
  compared.set(fingerprint());
  await assert.rejects(pending, /root pin comparison/);
});

test("root enrollment is unaffected by later changes to its input buffers", async () => {
  const input = pin();
  const compared = fingerprint();
  const original = await enrollRootPin02(input, compared);
  const pending = enrollRootPin02(input, compared);
  input.fill(0);
  compared.fill(0);
  assert.deepEqual(await pending, original);
});

test("manifest verification is unaffected by later changes to its bytes or trust state", async () => {
  const trusted = await enrollRootPin02(pin(), fingerprint());
  const original = structuredClone(trusted);
  const input = manifest();
  const pending = verifyManifest02(input, trusted, now);
  input.fill(0);
  trusted.accountId.fill(0);
  trusted.rootPoint.fill(0);
  trusted.digest.fill(9);
  trusted.anchorDigest.fill(9);
  trusted.generation = 99n;
  trusted.version = 99n;
  const accepted = await pending;
  const advanced = advanceManifestTrust02(original, accepted);
  assert.equal(advanced.generation, 1n);
  assert.equal(advanced.version, 1n);
  assert.deepEqual(advanced.digest, bytes(vector.old_semantic_manifest_digest_b64));
});

test("transition verification is unaffected by later changes to its inputs", async () => {
  const enrolled = await enrollRootPin02(pin(), fingerprint());
  const trusted = advanceManifestTrust02(enrolled, await verifyManifest02(manifest(), enrolled, now));
  const input = transition();
  const compared = bytes(vector.new_root_point_b64);
  const pending = verifyRootTransition02(input, trusted, now, compared);
  input.fill(0);
  compared.fill(0);
  trusted.accountId.fill(0);
  trusted.rootPoint.fill(0);
  trusted.digest.fill(0);
  trusted.generation = 99n;
  trusted.version = 0n;
  const accepted = await pending;
  assert.equal(accepted.generation, 2n);
  assert.deepEqual(accepted.rootPoint, bytes(vector.new_root_point_b64));
  assert.deepEqual(accepted.anchorDigest, bytes(vector.transition_anchor_digest_b64));
});
