/** Experimental profile-02 trust persistence. No production sealed route uses this. */

import {
  advanceManifestTrust02, DRAFT02_CLOCK_SKEW_MS, enrollRootPin02, verifyManifest02, verifyRootTransition02,
  type Manifest02, type ManifestTrust02,
} from "./draft02-manifest.js";

const storeName = "owner-root-high-water";
const stateKey = "state";
const maxSigned = (1n << 63n) - 1n;

type StoredTrust = {
  schema: 1;
  accountId: Uint8Array;
  generation: string;
  rootPoint: Uint8Array;
  version: string;
  digest: Uint8Array;
  anchorDigest: Uint8Array;
  lastTrustedTimeMs: string;
};

export type Draft02TrustSnapshot = Readonly<{
  trust: ManifestTrust02;
  lastTrustedTimeMs: bigint;
}>;

function fail(reason: string): never {
  throw new Error(`ZTSE draft-02 trust store: ${reason}`);
}

function copy(bytes: Uint8Array, length: number): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) fail("corrupt stored bytes");
  return Uint8Array.from(bytes);
}

/** Caller input copied before the first await; the verifiers check its size. */
function input(bytes: Uint8Array, what: string): Uint8Array {
  if (!(bytes instanceof Uint8Array)) fail(`${what} must be a Uint8Array`);
  return Uint8Array.from(bytes);
}

/** A caller-owned snapshot copied (and validated) before the first await. */
function captured(snapshot: Draft02TrustSnapshot): Draft02TrustSnapshot {
  try { return decode(encode(snapshot)); }
  catch { return fail("malformed expected snapshot"); }
}

function integer(value: unknown): bigint {
  if (typeof value !== "string" || value.length < 1 || value.length > 19) fail("corrupt stored integer");
  let result = 0n;
  for (const char of value) {
    const digit = char.charCodeAt(0) - 48;
    if (digit < 0 || digit > 9) fail("corrupt stored integer");
    result = result * 10n + BigInt(digit);
    if (result > maxSigned) fail("stored integer out of range");
  }
  if (result.toString() !== value) fail("noncanonical stored integer");
  return result;
}

function decode(value: unknown): Draft02TrustSnapshot {
  if (typeof value !== "object" || value === null) fail("corrupt stored state");
  const row = value as Partial<StoredTrust>;
  if (row.schema !== 1) fail("unknown stored schema");
  const trust: ManifestTrust02 = {
    accountId: copy(row.accountId as Uint8Array, 16),
    generation: integer(row.generation),
    rootPoint: copy(row.rootPoint as Uint8Array, 65),
    version: integer(row.version),
    digest: copy(row.digest as Uint8Array, 32),
    anchorDigest: copy(row.anchorDigest as Uint8Array, 32),
  };
  if (trust.generation === 0n || trust.rootPoint[0] !== 4 ||
      trust.accountId.every((byte) => byte === 0)) fail("corrupt stored identity");
  return { trust, lastTrustedTimeMs: integer(row.lastTrustedTimeMs) };
}

function encode(snapshot: Draft02TrustSnapshot): StoredTrust {
  const { trust, lastTrustedTimeMs } = snapshot;
  if (lastTrustedTimeMs < 0n || lastTrustedTimeMs > maxSigned) fail("trusted time out of range");
  return {
    schema: 1,
    accountId: copy(trust.accountId, 16),
    generation: trust.generation.toString(),
    rootPoint: copy(trust.rootPoint, 65),
    version: trust.version.toString(),
    digest: copy(trust.digest, 32),
    anchorDigest: copy(trust.anchorDigest, 32),
    lastTrustedTimeMs: lastTrustedTimeMs.toString(),
  };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

function sameSnapshot(a: Draft02TrustSnapshot, b: Draft02TrustSnapshot): boolean {
  return a.lastTrustedTimeMs === b.lastTrustedTimeMs &&
    a.trust.generation === b.trust.generation && a.trust.version === b.trust.version &&
    sameBytes(a.trust.accountId, b.trust.accountId) &&
    sameBytes(a.trust.rootPoint, b.trust.rootPoint) &&
    sameBytes(a.trust.digest, b.trust.digest) &&
    sameBytes(a.trust.anchorDigest, b.trust.anchorDigest);
}

function checkedTime(nowMs: bigint, previous?: bigint): void {
  if (typeof nowMs !== "bigint" || nowMs < 0n || nowMs > maxSigned) fail("trusted time out of range");
  // A backward step within the profile's clock skew (NTP slew or correction) is tolerated;
  // the high-water itself never moves backwards.
  if (previous !== undefined && nowMs < previous - DRAFT02_CLOCK_SKEW_MS) fail("clock moved backwards");
}

/**
 * The ratchet advances only as far as owner-signed evidence supports: a local clock
 * reading past `issuedMs + skew` of the object just verified is not persisted, so one
 * bad reading cannot push the high-water beyond what a later correct clock can meet.
 */
function ratchet(previous: bigint, nowMs: bigint, signedIssuedMs: bigint): bigint {
  const bounded = nowMs < signedIssuedMs + DRAFT02_CLOCK_SKEW_MS ? nowMs : signedIssuedMs + DRAFT02_CLOCK_SKEW_MS;
  return bounded > previous ? bounded : previous;
}

function transitionIssuedMs(bytes: Uint8Array): bigint {
  // Only called after verifyRootTransition02 accepted this exact 343-byte body.
  return new DataView(Uint8Array.from(bytes).buffer).getBigUint64(199, false);
}

function open(name: string): Promise<IDBDatabase> {
  if (!name || name.length > 128) fail("database name");
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(storeName)) request.result.createObjectStore(storeName);
    };
    request.onsuccess = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(storeName)) {
        db.close();
        reject(new Error("ZTSE draft-02 trust store: missing object store"));
        return;
      }
      // Another tab or a newer schema asked to upgrade: step aside instead of blocking it.
      // Later calls on this instance fail; the caller reopens.
      db.onversionchange = () => db.close();
      resolve(db);
    };
    request.onerror = () => reject(request.error ?? new Error("IndexedDB open failed"));
    request.onblocked = () => reject(new Error("ZTSE draft-02 trust store: database upgrade blocked"));
  });
}

export class Draft02TrustStore {
  private constructor(private readonly db: IDBDatabase) {}

  static async open(name = "ztse-draft02-trust-v1"): Promise<Draft02TrustStore> {
    return new Draft02TrustStore(await open(name));
  }

  close(): void { this.db.close(); }

  async read(): Promise<Draft02TrustSnapshot | null> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, "readonly");
      const request = tx.objectStore(storeName).get(stateKey);
      let snapshot: Draft02TrustSnapshot | null = null;
      request.onsuccess = () => {
        try { snapshot = request.result === undefined ? null : decode(request.result); }
        catch { tx.abort(); }
      };
      tx.oncomplete = () => resolve(snapshot);
      tx.onabort = () => reject(tx.error ?? new Error("ZTSE draft-02 trust store: corrupt stored state"));
      tx.onerror = () => reject(tx.error ?? new Error("IndexedDB read failed"));
    });
  }

  /**
   * Caller must compare the fingerprint through a channel independent of the relay.
   * Enrollment carries no owner-signed time, so the time high-water starts at zero and
   * first advances on an accepted manifest; `nowMs` is only range-checked.
   */
  async enroll(rootPin: Uint8Array, comparedFingerprint: Uint8Array, nowMs: bigint): Promise<Draft02TrustSnapshot> {
    checkedTime(nowMs);
    const pin = input(rootPin, "root pin");
    const fingerprint = input(comparedFingerprint, "compared fingerprint");
    const trust = await enrollRootPin02(pin, fingerprint);
    const next = { trust, lastTrustedTimeMs: 0n };
    await this.write(null, next);
    return decode(encode(next));
  }

  /**
   * Explicit recovery: replace the enrolled root, discarding the stored version and time
   * high-water. `expected` must equal the current stored snapshot (compare-and-swap), so a
   * caller cannot discard anti-rollback state it has not read. The new fingerprint must be
   * compared through a channel independent of the relay, exactly as for `enroll`.
   */
  async reenroll(expected: Draft02TrustSnapshot, rootPin: Uint8Array, comparedFingerprint: Uint8Array,
    nowMs: bigint): Promise<Draft02TrustSnapshot> {
    if (!expected) fail("reenroll requires the current snapshot");
    checkedTime(nowMs);
    const before = captured(expected);
    const pin = input(rootPin, "root pin");
    const fingerprint = input(comparedFingerprint, "compared fingerprint");
    const trust = await enrollRootPin02(pin, fingerprint);
    const next = { trust, lastTrustedTimeMs: 0n };
    await this.write(before, next);
    return decode(encode(next));
  }

  /**
   * Explicit recovery from a bad clock: keep the root, generation, version and digest
   * ratchet, but set the time high-water to `nowMs`, which may be earlier. `expected` must
   * equal the current stored snapshot (compare-and-swap). Call only when the caller has
   * independent reason to trust `nowMs`; the version ratchet still refuses older manifests.
   */
  async resetTrustedTime(expected: Draft02TrustSnapshot, nowMs: bigint): Promise<Draft02TrustSnapshot> {
    if (!expected) fail("resetTrustedTime requires the current snapshot");
    checkedTime(nowMs);
    const before = captured(expected);
    const next = { trust: before.trust, lastTrustedTimeMs: nowMs };
    await this.write(before, next);
    return decode(encode(next));
  }

  /**
   * Explicit recovery from a row that `read()` rejects as corrupt or of an unknown schema.
   * Deletes the row only if it does not decode; a valid enrollment is never removed here.
   * Returns false when nothing is stored. Afterwards the caller must `enroll` again.
   */
  clearCorruptState(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, "readwrite");
      const request = tx.objectStore(storeName).get(stateKey);
      let cleared = false;
      let valid = false;
      request.onsuccess = () => {
        if (request.result === undefined) return;
        try {
          decode(request.result);
          valid = true;
          tx.abort();
        } catch {
          tx.objectStore(storeName).delete(stateKey);
          cleared = true;
        }
      };
      tx.oncomplete = () => resolve(cleared);
      tx.onabort = () => reject(new Error(valid ? "ZTSE draft-02 trust store: stored state is valid; use reenroll" :
        "ZTSE draft-02 trust store: clear aborted"));
      tx.onerror = () => reject(tx.error ?? new Error("IndexedDB clear failed"));
    });
  }

  /**
   * The manifest is checked outside the transaction, then installed by atomic CAS.
   * The persisted time is at most the manifest's signed `issuedMs` plus clock skew.
   */
  async acceptManifest(bytes: Uint8Array, nowMs: bigint): Promise<Manifest02> {
    const signed = input(bytes, "manifest");
    const before = await this.read();
    if (!before) fail("owner root is not enrolled");
    checkedTime(nowMs, before.lastTrustedTimeMs);
    const manifest = await verifyManifest02(signed, before.trust, nowMs);
    const next = {
      trust: advanceManifestTrust02(before.trust, manifest),
      lastTrustedTimeMs: ratchet(before.lastTrustedTimeMs, nowMs, manifest.issuedMs),
    };
    await this.write(before, next);
    return manifest;
  }

  /** Restore historical acceptance without lowering high-water: prove a complete signed successor
   * chain ending at the exact CURRENT persisted digest. Expired ancestors are verified at their signed
   * issue times; the requested ancestor is verified at authenticated receipt time. Root transitions
   * and incomplete/oversized chains are refused. This operation never writes or enrolls a root.
   */
  async verifyHistory(chain: readonly Uint8Array[], observedMs: bigint): Promise<Manifest02> {
    checkedTime(observedMs);
    if (chain.length < 1 || chain.length > 64) fail("history chain bound");
    const signed = chain.map(bytes => input(bytes, "history manifest"));
    if (signed.some(bytes => bytes.length < 215 || bytes.length > 11223)) fail("history manifest bound");
    const before = await this.read();
    if (!before || before.trust.version === 0n) fail("history requires accepted high-water");
    const first = signed[0];
    const version = new DataView(first.buffer, first.byteOffset, first.byteLength).getBigUint64(29);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(first.subarray(0, -64)).buffer));
    // This temporary self-digest permits signature parsing only. It is accepted solely after the
    // contiguous chain reaches the already trusted current digest, below.
    let pin: ManifestTrust02 = { ...before.trust, version, digest };
    const historical = await verifyManifest02(first, pin, observedMs);
    pin = advanceManifestTrust02(pin, historical);
    for (const bytes of signed.slice(1)) {
      const issuedMs = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(37);
      const next = await verifyManifest02(bytes, pin, issuedMs);
      if (next.version !== pin.version + 1n) fail("history chain duplicate");
      pin = advanceManifestTrust02(pin, next);
    }
    if (pin.version !== before.trust.version || !sameBytes(pin.digest, before.trust.digest)) fail("history does not reach high-water");
    const after = await this.read();
    if (!after || !sameSnapshot(before, after)) fail("history high-water changed");
    return historical;
  }

  /** The expected new root must be pinned by the owner independently of the relay. */
  async acceptTransition(bytes: Uint8Array, expectedNewRoot: Uint8Array, nowMs: bigint): Promise<Draft02TrustSnapshot> {
    // Verification and the time cap must read the same bytes, whatever the caller does
    // with its buffers while this call is pending.
    const signed = input(bytes, "transition");
    const newRoot = input(expectedNewRoot, "expected new root");
    const before = await this.read();
    if (!before) fail("owner root is not enrolled");
    checkedTime(nowMs, before.lastTrustedTimeMs);
    const trust = await verifyRootTransition02(signed, before.trust, nowMs, newRoot);
    const next = {
      trust,
      lastTrustedTimeMs: ratchet(before.lastTrustedTimeMs, nowMs, transitionIssuedMs(signed)),
    };
    await this.write(before, next);
    return decode(encode(next));
  }

  private write(before: Draft02TrustSnapshot | null, after: Draft02TrustSnapshot): Promise<void> {
    const expected = before === null ? null : captured(before);
    const row = encode(after);
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, "readwrite");
      const request = tx.objectStore(storeName).get(stateKey);
      let denied = false;
      request.onsuccess = () => {
        try {
          const current = request.result === undefined ? null : decode(request.result);
          if (current === null ? expected !== null : expected === null || !sameSnapshot(current, expected)) {
            denied = true;
            tx.abort();
            return;
          }
          tx.objectStore(storeName).put(row, stateKey);
        } catch {
          denied = true;
          tx.abort();
        }
      };
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(new Error(denied ? "ZTSE draft-02 trust store: stale or corrupt state" :
        "ZTSE draft-02 trust store: write aborted"));
      tx.onerror = () => reject(tx.error ?? new Error("IndexedDB write failed"));
    });
  }
}
