import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import "fake-indexeddb/auto";
import { Draft02TrustStore } from "../dist/draft02-trust-store.js";

const rotation = JSON.parse(await readFile(new URL("./vectors/draft02-rotation.json", import.meta.url)));
const bytes = (value) => Uint8Array.from(Buffer.from(value, "base64"));
const transitionBytes = () => bytes(rotation.transition_b64);
const issued = new DataView(transitionBytes().buffer).getBigUint64(199, false);
const expires = new DataView(transitionBytes().buffer).getBigUint64(207, false);
const pin = () => bytes(rotation.old_root_pin_b64);
const fingerprint = () => bytes(rotation.old_root_fingerprint_b64);
const newRoot = () => bytes(rotation.new_root_point_b64);
const manifest = () => bytes(rotation.old_manifest_b64);

async function enrolled() {
  const store = await Draft02TrustStore.open(`input-snapshot-${randomUUID()}`);
  await store.enroll(pin(), fingerprint(), issued);
  return store;
}
async function accepted() {
  const store = await enrolled();
  await store.acceptManifest(manifest(), issued);
  return store;
}

test("transition time ratchet uses the same captured bytes as signature verification", async () => {
  const store = await accepted();
  const input = transitionBytes();
  const originalVerify = crypto.subtle.verify;
  let mutated = false;
  try {
    crypto.subtle.verify = async function (...args) {
      const valid = await originalVerify.apply(this, args);
      if (!mutated) {
        new DataView(input.buffer).setBigUint64(199, expires - 1n, false);
        mutated = true;
      }
      return valid;
    };
    const result = await store.acceptTransition(input, newRoot(), expires - 1n);
    assert.ok(mutated);
    assert.equal(result.lastTrustedTimeMs, issued + 300000n);
    assert.deepEqual(await store.read(), result);
  } finally { crypto.subtle.verify = originalVerify; store.close(); }
});

test("manifest and transition input buffers are captured before the storage read", async () => {
  const store = await enrolled();
  try {
    const input = manifest();
    const pendingManifest = store.acceptManifest(input, issued);
    input.fill(0);
    assert.equal((await pendingManifest).version, 1n);
    const transition = transitionBytes();
    const compared = newRoot();
    const pendingTransition = store.acceptTransition(transition, compared, issued + 1n);
    transition.fill(0);
    compared.fill(0);
    assert.equal((await pendingTransition).trust.generation, 2n);
    assert.deepEqual((await store.read()).trust.rootPoint, newRoot());
  } finally { store.close(); }
});

for (const method of ["resetTrustedTime", "reenroll"]) {
  test(`${method} cannot change its expected predecessor while storage is pending`, async () => {
    const store = await accepted();
    try {
      const stale = await store.read();
      await store.acceptTransition(transitionBytes(), newRoot(), issued + 1n);
      const current = await store.read();
      const pending = method === "resetTrustedTime"
        ? store.resetTrustedTime(stale, issued + 2n)
        : store.reenroll(stale, pin(), fingerprint(), issued + 2n);
      Object.assign(stale.trust, current.trust);
      stale.lastTrustedTimeMs = current.lastTrustedTimeMs;
      await assert.rejects(pending, /stale or corrupt state/);
      assert.deepEqual(await store.read(), current);
    } finally { store.close(); }
  });
}

test("successful time reset returns the same captured trust that storage commits", async () => {
  const store = await accepted();
  try {
    const expected = await store.read();
    const original = structuredClone(expected);
    const pending = store.resetTrustedTime(expected, issued + 1n);
    expected.trust.generation = 7n;
    expected.trust.rootPoint.fill(0);
    const result = await pending;
    assert.deepEqual(result.trust, original.trust);
    assert.deepEqual(result, await store.read());
  } finally { store.close(); }
});

for (const method of ["enroll", "reenroll"]) {
  test(`${method} captures the independently compared fingerprint before verification yields`, async () => {
    const store = method === "reenroll" ? await accepted()
      : await Draft02TrustStore.open(`input-snapshot-${randomUUID()}`);
    try {
      const before = await store.read();
      const wrongFingerprint = new Uint8Array(32);
      const pending = method === "reenroll"
        ? store.reenroll(before, pin(), wrongFingerprint, issued)
        : store.enroll(pin(), wrongFingerprint, issued);
      wrongFingerprint.set(fingerprint());
      await assert.rejects(pending, /root pin comparison/);
      assert.deepEqual(await store.read(), before);
    } finally { store.close(); }
  });
}
