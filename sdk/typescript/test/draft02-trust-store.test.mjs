import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import "fake-indexeddb/auto";
import { Draft02TrustStore } from "../dist/draft02-trust-store.js";

const vector = JSON.parse(await readFile(new URL("./vectors/draft02-genesis.json", import.meta.url)));
const rotation = JSON.parse(await readFile(new URL("./vectors/draft02-rotation.json", import.meta.url)));
const bytes = (value) => Uint8Array.from(Buffer.from(value, "base64"));
const rootPin = bytes(vector.root_pin_b64);
const fingerprint = bytes(vector.root_fingerprint_b64);
const manifest = bytes(vector.manifest_b64);
const now = BigInt(vector.now_ms);

test("root enrollment and manifest high-water survive a second client connection", async () => {
  const name = `ztse-draft02-${randomUUID()}`;
  const first = await Draft02TrustStore.open(name);
  const second = await Draft02TrustStore.open(name);
  try {
    await first.enroll(rootPin, fingerprint, now);
    await assert.rejects(second.enroll(rootPin, fingerprint, now), /stale or corrupt state/);
    const read = await second.read();
    assert.equal(read.trust.version, 0n);
    read.trust.accountId.fill(0);
    assert.equal((await second.read()).trust.accountId[0], 1);

    const accepted = await first.acceptManifest(manifest, now + 1n);
    assert.equal(accepted.version, 1n);
    const persisted = await second.read();
    assert.equal(persisted.trust.version, 1n);
    assert.deepEqual(persisted.trust.digest, bytes(vector.semantic_manifest_digest_b64));
    assert.equal(persisted.lastTrustedTimeMs, now + 1n);
    await second.acceptManifest(manifest, now + 2n); // Identical semantic replay is safe.
    assert.equal((await first.read()).lastTrustedTimeMs, now + 2n);
    await assert.rejects(first.acceptManifest(manifest, now + 1n), /clock moved backwards/);
  } finally {
    first.close();
    second.close();
  }
});

test("failed verification leaves the durable high-water unchanged", async () => {
  const store = await Draft02TrustStore.open(`ztse-draft02-${randomUUID()}`);
  try {
    await store.enroll(rootPin, fingerprint, now);
    const changed = Uint8Array.from(manifest);
    changed[5] ^= 1;
    await assert.rejects(store.acceptManifest(changed, now + 1n), /pin mismatch/);
    const state = await store.read();
    assert.equal(state.trust.version, 0n);
    assert.equal(state.lastTrustedTimeMs, now);
  } finally { store.close(); }
});

test("two tabs cannot both commit from the same manifest predecessor", { timeout: 5000 }, async () => {
  const name = `ztse-draft02-${randomUUID()}`;
  const first = await Draft02TrustStore.open(name);
  const second = await Draft02TrustStore.open(name);
  const originalVerify = crypto.subtle.verify;
  try {
    await first.enroll(rootPin, fingerprint, now);
    let arrivals = 0;
    let release;
    const barrier = new Promise((resolve) => { release = resolve; });
    crypto.subtle.verify = async function (...args) {
      const valid = await originalVerify.apply(this, args);
      if (++arrivals === 2) release();
      await barrier; // Both callers have read the same predecessor before either writes.
      return valid;
    };
    const outcomes = await Promise.allSettled([
      first.acceptManifest(manifest, now + 1n),
      second.acceptManifest(manifest, now + 1n),
    ]);
    assert.equal(outcomes.filter((outcome) => outcome.status === "fulfilled").length, 1);
    assert.match(outcomes.find((outcome) => outcome.status === "rejected").reason.message,
      /stale or corrupt state/);
    assert.equal((await first.read()).trust.version, 1n);
  } finally {
    crypto.subtle.verify = originalVerify;
    first.close();
    second.close();
  }
});

test("dual-signed rotation commits before the next generation can advance", async () => {
  const name = `ztse-draft02-${randomUUID()}`;
  const first = await Draft02TrustStore.open(name);
  try {
    await first.enroll(bytes(rotation.old_root_pin_b64), bytes(rotation.old_root_fingerprint_b64), now);
    await first.acceptManifest(bytes(rotation.old_manifest_b64), now + 1n);
    const wrongPoint = Uint8Array.from(bytes(rotation.new_root_point_b64));
    wrongPoint[10] ^= 1;
    await assert.rejects(first.acceptTransition(bytes(rotation.transition_b64), wrongPoint, now + 2n),
      /transition pin\/chain/);
    assert.equal((await first.read()).trust.generation, 1n);
    const transitioned = await first.acceptTransition(bytes(rotation.transition_b64),
      bytes(rotation.new_root_point_b64), now + 2n);
    assert.equal(transitioned.trust.generation, 2n);
    assert.equal(transitioned.trust.version, 0n);
    assert.deepEqual(transitioned.trust.anchorDigest, bytes(rotation.transition_anchor_digest_b64));
  } finally { first.close(); }

  const restarted = await Draft02TrustStore.open(name);
  try {
    await restarted.acceptManifest(bytes(rotation.new_manifest_b64), now + 3n);
    const state = await restarted.read();
    assert.equal(state.trust.generation, 2n);
    assert.equal(state.trust.version, 1n);
    assert.deepEqual(state.trust.digest, bytes(rotation.new_semantic_manifest_digest_b64));
    await assert.rejects(restarted.acceptManifest(bytes(rotation.old_manifest_b64), now + 4n), /pin mismatch/);
  } finally { restarted.close(); }
});

test("corrupt or replaced storage fails closed and cannot be silently reenrolled", async () => {
  const name = `ztse-draft02-${randomUUID()}`;
  const store = await Draft02TrustStore.open(name);
  try {
    await store.enroll(rootPin, fingerprint, now);
    await new Promise((resolve, reject) => {
      const raw = indexedDB.open(name, 1);
      raw.onsuccess = () => {
        const db = raw.result;
        const tx = db.transaction("owner-root-high-water", "readwrite");
        tx.objectStore("owner-root-high-water").put({ schema: 99 }, "state");
        tx.oncomplete = () => { db.close(); resolve(); };
        tx.onabort = () => { db.close(); reject(tx.error); };
      };
      raw.onerror = () => reject(raw.error);
    });
    await assert.rejects(store.read(), /corrupt stored state/);
    await assert.rejects(store.enroll(rootPin, fingerprint, now + 1n), /stale or corrupt state/);
  } finally { store.close(); }
});
