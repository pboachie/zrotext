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
    assert.equal(state.lastTrustedTimeMs, 0n);
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

    // The documented recovery deletes only an undecodable row, then enrollment is explicit.
    assert.equal(await store.clearCorruptState(), true);
    assert.equal(await store.read(), null);
    assert.equal(await store.clearCorruptState(), false);
    await store.enroll(rootPin, fingerprint, now + 1n);
    await assert.rejects(store.clearCorruptState(), /stored state is valid; use reenroll/);
    assert.equal((await store.read()).trust.generation, 1n);
  } finally { store.close(); }
});

const skew = 300_000n; // DRAFT02_CLOCK_SKEW_MS
const issued = new DataView(manifest.buffer, manifest.byteOffset).getBigUint64(37, false);

async function writeRawState(name, patch) {
  await new Promise((resolve, reject) => {
    const raw = indexedDB.open(name, 1);
    raw.onsuccess = () => {
      const db = raw.result;
      const tx = db.transaction("owner-root-high-water", "readwrite");
      const store = tx.objectStore("owner-root-high-water");
      const get = store.get("state");
      get.onsuccess = () => store.put({ ...get.result, ...patch }, "state");
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onabort = () => { db.close(); reject(tx.error); };
    };
    raw.onerror = () => reject(raw.error);
  });
}

test("small backward clock steps are tolerated without moving the high-water back", async () => {
  const store = await Draft02TrustStore.open(`ztse-draft02-${randomUUID()}`);
  try {
    const enrolled = await store.enroll(rootPin, fingerprint, now);
    assert.equal(enrolled.lastTrustedTimeMs, 0n); // Enrollment carries no signed time.
    await store.acceptManifest(manifest, now + 250_000n);
    assert.equal((await store.read()).lastTrustedTimeMs, now + 250_000n);
    // An NTP correction a few seconds (up to the skew) backwards still verifies.
    await store.acceptManifest(manifest, now + 245_000n);
    await store.acceptManifest(manifest, now + 250_000n - skew);
    assert.equal((await store.read()).lastTrustedTimeMs, now + 250_000n);
    // A step larger than the skew is still refused.
    await assert.rejects(store.acceptManifest(manifest, now + 250_000n - skew - 1n), /clock moved backwards/);
    assert.equal((await store.read()).lastTrustedTimeMs, now + 250_000n);
  } finally { store.close(); }
});

test("a far-ahead clock reading cannot ratchet the store past signed evidence", async () => {
  const store = await Draft02TrustStore.open(`ztse-draft02-${randomUUID()}`);
  try {
    await store.enroll(rootPin, fingerprint, now);
    // A reading years ahead fails verification and persists nothing.
    await assert.rejects(store.acceptManifest(manifest, now + 10n ** 12n), /stale or future signed object/);
    assert.equal((await store.read()).lastTrustedTimeMs, 0n);
    // A reading near the end of the signed window is capped at issuedMs + skew.
    await store.acceptManifest(manifest, issued + 3_000_000n);
    assert.equal((await store.read()).lastTrustedTimeMs, issued + skew);
    // A corrected clock back at the real time is still accepted.
    await store.acceptManifest(manifest, now + 1n);
    assert.equal((await store.read()).trust.version, 1n);
  } finally { store.close(); }
});

test("a far-future stored high-water recovers only through an explicit compare-and-swap reset", async () => {
  const name = `ztse-draft02-${randomUUID()}`;
  const store = await Draft02TrustStore.open(name);
  try {
    await store.enroll(rootPin, fingerprint, now);
    await store.acceptManifest(manifest, now + 1n);
    // Simulate a high-water saved from a bad clock (for example by an earlier release).
    const farFuture = now + 50n * 365n * 86_400_000n;
    await writeRawState(name, { lastTrustedTimeMs: farFuture.toString() });
    await assert.rejects(store.acceptManifest(manifest, now + 2n), /clock moved backwards/);

    const current = await store.read();
    assert.equal(current.lastTrustedTimeMs, farFuture);
    const stale = { ...current, lastTrustedTimeMs: now };
    await assert.rejects(store.resetTrustedTime(stale, now + 2n), /stale or corrupt state/);
    const reset = await store.resetTrustedTime(current, now + 2n);
    assert.equal(reset.lastTrustedTimeMs, now + 2n);
    assert.equal(reset.trust.version, 1n); // The version/digest ratchet is kept.
    await store.acceptManifest(manifest, now + 3n);
    assert.equal((await store.read()).lastTrustedTimeMs, now + 3n);
    // Replaying the old snapshot cannot reset again.
    await assert.rejects(store.resetTrustedTime(current, now), /stale or corrupt state/);
  } finally { store.close(); }
});

test("reenroll replaces the root only against the current snapshot", async () => {
  const name = `ztse-draft02-${randomUUID()}`;
  const store = await Draft02TrustStore.open(name);
  try {
    await store.enroll(rootPin, fingerprint, now);
    await store.acceptManifest(manifest, now + 1n);
    const before = await store.read();
    await assert.rejects(store.reenroll(null, rootPin, fingerprint, now + 2n), /requires the current snapshot/);
    const wrong = Uint8Array.from(fingerprint);
    wrong[0] ^= 1;
    await assert.rejects(store.reenroll(before, rootPin, wrong, now + 2n), /root pin comparison/);
    await assert.rejects(store.reenroll({ ...before, lastTrustedTimeMs: 7n }, rootPin, fingerprint, now + 2n),
      /stale or corrupt state/);
    assert.equal((await store.read()).trust.version, 1n);

    const replaced = await store.reenroll(before, bytes(rotation.old_root_pin_b64),
      bytes(rotation.old_root_fingerprint_b64), now + 2n);
    assert.equal(replaced.trust.version, 0n);
    assert.equal(replaced.lastTrustedTimeMs, 0n);
    await store.acceptManifest(bytes(rotation.old_manifest_b64), now + 3n);
    assert.equal((await store.read()).trust.version, 1n);
  } finally { store.close(); }
});

test("an open store closes for another connection's version upgrade instead of blocking it",
  { timeout: 5000 }, async () => {
    const name = `ztse-draft02-${randomUUID()}`;
    const store = await Draft02TrustStore.open(name);
    await store.enroll(rootPin, fingerprint, now);
    let upgraded;
    try {
      upgraded = await new Promise((resolve, reject) => {
        const request = indexedDB.open(name, 2);
        request.onblocked = () => reject(new Error("upgrade blocked"));
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      assert.equal(upgraded.version, 2);
      await assert.rejects(store.read(), /clos|InvalidStateError/i);
    } finally {
      store.close(); // Lets a blocked upgrade finish so a failing run still exits.
      upgraded?.close();
    }
  });
