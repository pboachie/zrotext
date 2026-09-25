/** Experimental profile-02 trust persistence. No production sealed route uses this. */

import {
  advanceManifestTrust02, enrollRootPin02, verifyManifest02, verifyRootTransition02,
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
  if (nowMs < 0n || nowMs > maxSigned) fail("trusted time out of range");
  if (previous !== undefined && nowMs < previous) fail("clock moved backwards");
}

function open(name: string): Promise<IDBDatabase> {
  if (!name || name.length > 128) fail("database name");
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(storeName)) request.result.createObjectStore(storeName);
    };
    request.onsuccess = () => {
      if (!request.result.objectStoreNames.contains(storeName)) {
        request.result.close();
        reject(new Error("ZTSE draft-02 trust store: missing object store"));
      } else resolve(request.result);
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

  /** Caller must compare the fingerprint through a channel independent of the relay. */
  async enroll(rootPin: Uint8Array, comparedFingerprint: Uint8Array, nowMs: bigint): Promise<Draft02TrustSnapshot> {
    checkedTime(nowMs);
    const trust = await enrollRootPin02(rootPin, comparedFingerprint);
    const next = { trust, lastTrustedTimeMs: nowMs };
    await this.write(null, next);
    return decode(encode(next));
  }

  /** The manifest is checked outside the transaction, then installed by atomic CAS. */
  async acceptManifest(bytes: Uint8Array, nowMs: bigint): Promise<Manifest02> {
    const before = await this.read();
    if (!before) fail("owner root is not enrolled");
    checkedTime(nowMs, before.lastTrustedTimeMs);
    const manifest = await verifyManifest02(bytes, before.trust, nowMs);
    const next = {
      trust: advanceManifestTrust02(before.trust, manifest),
      lastTrustedTimeMs: nowMs,
    };
    await this.write(before, next);
    return manifest;
  }

  /** The expected new root must be pinned by the owner independently of the relay. */
  async acceptTransition(bytes: Uint8Array, expectedNewRoot: Uint8Array, nowMs: bigint): Promise<Draft02TrustSnapshot> {
    const before = await this.read();
    if (!before) fail("owner root is not enrolled");
    checkedTime(nowMs, before.lastTrustedTimeMs);
    const next = {
      trust: await verifyRootTransition02(bytes, before.trust, nowMs, expectedNewRoot),
      lastTrustedTimeMs: nowMs,
    };
    await this.write(before, next);
    return decode(encode(next));
  }

  private write(before: Draft02TrustSnapshot | null, after: Draft02TrustSnapshot): Promise<void> {
    const row = encode(after);
    return new Promise((resolve, reject) => {
      const tx = this.db.transaction(storeName, "readwrite");
      const request = tx.objectStore(storeName).get(stateKey);
      let denied = false;
      request.onsuccess = () => {
        try {
          const current = request.result === undefined ? null : decode(request.result);
          if (current === null ? before !== null : before === null || !sameSnapshot(current, before)) {
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
