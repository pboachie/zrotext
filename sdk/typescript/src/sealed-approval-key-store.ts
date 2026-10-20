/* SPDX-License-Identifier: AGPL-3.0-only */
/** Browser-local custody only. Stored keys never establish current owner authority. */
export interface SealedApprovalScope {
  readonly origin: string;
  readonly accountId: string;
  readonly originalUserId: string;
  readonly deviceId: string;
  readonly lineId: string;
  readonly rootFingerprint: string;
}
export interface SealedApprovalMetadata {
  readonly scope: Readonly<SealedApprovalScope>;
  readonly publicPoint: string;
  readonly fingerprint: string;
}
export interface SealedApprovalLease extends SealedApprovalMetadata {
  close(): void;
  /** Trusted application callback; authenticate the current ceremony separately. */
  withKey<T>(scope: SealedApprovalScope, fingerprint: string, run: (key: CryptoKey) => Promise<T>): Promise<T>;
}
interface StoredKey {
  schema: 1; scope: SealedApprovalScope; publicPoint: string; fingerprint: string; privateKey: CryptoKey;
}
const STORE = 'sealed-line-approval-v1', CAPACITY = 128;
const fields = ['origin', 'accountId', 'originalUserId', 'deviceId', 'lineId', 'rootFingerprint'] as const;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const hex = (value: Uint8Array) => Array.from(value, v => v.toString(16).padStart(2, '0')).join('');
function refuse(): never { throw Error('Sealed approval custody unavailable; reconcile the original key'); }
function data(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) refuse();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== keys.length || keys.some(k => !descriptors[k] || !('value' in descriptors[k]))) refuse();
  return Object.fromEntries(keys.map(k => [k, descriptors[k].value]));
}
function scopeSnapshot(value: SealedApprovalScope): Readonly<SealedApprovalScope> {
  const s = data(value, fields);
  if (fields.some(k => typeof s[k] !== 'string')) refuse();
  for (const k of ['accountId', 'originalUserId', 'deviceId', 'lineId']) {
    if (!uuidPattern.test(s[k] as string) || (s[k] as string).replaceAll('-', '') === '0'.repeat(32)) refuse();
  }
  let origin: URL;
  try { origin = new URL(s.origin as string); } catch { refuse(); }
  if (origin.protocol !== 'https:' || origin.origin !== s.origin || !/^[0-9a-f]{64}$/.test(s.rootFingerprint as string)
      || s.rootFingerprint === '0'.repeat(64)) refuse();
  return Object.freeze(s) as unknown as Readonly<SealedApprovalScope>;
}
const scopeKey = (scope: SealedApprovalScope) => JSON.stringify(fields.map(k => scope[k]));
function fingerprint(value: string): string {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value) || value === '0'.repeat(64)) refuse();
  return value;
}
function point(value: string): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !/^04[0-9a-f]{128}$/.test(value)) refuse();
  return Uint8Array.from(value.match(/../g)!, v => parseInt(v, 16));
}
function keyMetadata(key: CryptoKey): void {
  // Invoke native getters: own properties cannot disguise an extractable/other-purpose key.
  const get = (name: string) => Object.getOwnPropertyDescriptor(CryptoKey.prototype, name)!.get!.call(key);
  try {
    const algorithm = get('algorithm'), usages = get('usages');
    if (get('type') !== 'private' || get('extractable') !== false || algorithm.name !== 'ECDSA'
        || algorithm.namedCurve !== 'P-256' || usages.length !== 1 || usages[0] !== 'sign') refuse();
  } catch { refuse(); }
}

export class SealedApprovalKeyStore {
  #db: IDBDatabase;
  #origin: () => string;
  #signal?: AbortSignal;
  #closed = false;
  #busy = false;
  #transactions = new Set<IDBTransaction>();
  #leases = new Set<() => void>();
  #abort: () => void;
  private constructor(db: IDBDatabase, origin: () => string, signal?: AbortSignal) {
    this.#db = db; this.#origin = origin; this.#signal = signal;
    this.#abort = () => this.close();
    signal?.addEventListener('abort', this.#abort, { once: true });
    db.onversionchange = this.#abort;
  }
  /** name/currentOrigin are trusted embedding dependencies, not server-provided values. */
  static async open(options: { name?: string; currentOrigin?: () => string; signal?: AbortSignal } = {}): Promise<SealedApprovalKeyStore> {
    const origin = options.currentOrigin ?? (() => globalThis.location.origin), signal = options.signal;
    if (signal?.aborted) refuse();
    const name = options.name ?? 'zrotext-sealed-line-approval';
    if (typeof name !== 'string' || name.length < 1 || name.length > 128) refuse();
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open(name, 1);
      let refused = false;
      const abort = () => { refused = true; reject(Error('Sealed approval storage open refused')); };
      signal?.addEventListener('abort', abort, { once: true });
      request.onblocked = abort;
      request.onupgradeneeded = () => {
        if (refused || signal?.aborted) { request.transaction?.abort(); return; }
        request.result.createObjectStore(STORE);
      };
      request.onerror = () => { signal?.removeEventListener('abort', abort); abort(); };
      request.onsuccess = () => {
        signal?.removeEventListener('abort', abort);
        if (refused || signal?.aborted || request.result.objectStoreNames.length !== 1 || !request.result.objectStoreNames.contains(STORE)) {
          request.result.close(); abort(); return;
        }
        resolve(request.result);
      };
    });
    if (signal?.aborted) { db.close(); refuse(); }
    return new SealedApprovalKeyStore(db, origin, signal);
  }
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#signal?.removeEventListener('abort', this.#abort);
    for (const tx of this.#transactions) try { tx.abort(); } catch { /* Already completed. */ }
    for (const close of this.#leases) close();
    this.#leases.clear(); this.#db.close();
  }
  #guard(scope: SealedApprovalScope): void {
    if (this.#closed || this.#signal?.aborted || this.#origin() !== scope.origin) refuse();
  }
  async #operation<T>(scope: SealedApprovalScope, run: () => Promise<T>): Promise<T> {
    if (this.#busy) refuse();
    this.#guard(scope); this.#busy = true;
    try { const result = await run(); this.#guard(scope); return result; }
    finally { this.#busy = false; }
  }
  #transaction<T>(scope: SealedApprovalScope, mode: IDBTransactionMode, run: (store: IDBObjectStore, result: (value: T) => void, abort: () => void) => void): Promise<T> {
    this.#guard(scope);
    return new Promise((resolve, reject) => {
      const tx = this.#db.transaction(STORE, mode);
      this.#transactions.add(tx);
      let result: T, assigned = false;
      const done = () => this.#transactions.delete(tx);
      tx.oncomplete = () => {
        done();
        try { this.#guard(scope); if (!assigned) refuse(); resolve(result); } catch { reject(Error('Sealed approval storage outcome unavailable')); }
      };
      tx.onabort = () => { done(); reject(Error('Sealed approval storage transaction refused')); };
      const abort = () => { try { tx.abort(); } catch { /* No result is published. */ } };
      try { run(tx.objectStore(STORE), value => { result = value; assigned = true; }, abort); } catch { abort(); }
    });
  }
  async #read(scope: SealedApprovalScope): Promise<StoredKey | null> {
    const raw = await this.#transaction<unknown>(scope, 'readonly', (store, result) => {
      const request = store.get(scopeKey(scope)); request.onsuccess = () => result(request.result);
    });
    if (raw === undefined) return null;
    const record = data(raw, ['schema', 'scope', 'publicPoint', 'fingerprint', 'privateKey']);
    if (record.schema !== 1 || scopeKey(scopeSnapshot(record.scope as SealedApprovalScope)) !== scopeKey(scope)) refuse();
    fingerprint(record.fingerprint as string); point(record.publicPoint as string); keyMetadata(record.privateKey as CryptoKey);
    return record as unknown as StoredKey;
  }
  async #verify(scope: SealedApprovalScope, record: StoredKey): Promise<void> {
    const bytes = point(record.publicPoint);
    if (hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))) !== record.fingerprint) refuse();
    this.#guard(scope);
    const publicKey = await crypto.subtle.importKey('raw', bytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    this.#guard(scope);
    const domain = new TextEncoder().encode('ZTSE/browser/sealed-approval-possession/v1\0');
    const probe = new Uint8Array(domain.length + 32); probe.set(domain); crypto.getRandomValues(probe.subarray(domain.length));
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, record.privateKey, probe);
    this.#guard(scope);
    const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, probe);
    this.#guard(scope); if (!valid) refuse();
  }
  #metadata(scope: SealedApprovalScope, record: StoredKey): SealedApprovalMetadata {
    return Object.freeze({ scope, publicPoint: record.publicPoint, fingerprint: record.fingerprint });
  }
  /** Reconcile local public metadata only; independently compare the original registration before use. */
  async metadata(input: SealedApprovalScope): Promise<SealedApprovalMetadata | null> {
    const scope = scopeSnapshot(input);
    return this.#operation(scope, async () => {
      const record = await this.#read(scope); if (!record) return null;
      await this.#verify(scope, record); return this.#metadata(scope, record);
    });
  }
  /** Explicit NEW registration only. Existing/missing registered keys require recovery, never replacement. */
  async create(input: SealedApprovalScope, consent: { retain: true; newRegistration: true }): Promise<SealedApprovalMetadata> {
    const scope = scopeSnapshot(input), decision = data(consent, ['retain', 'newRegistration']);
    if (decision.retain !== true || decision.newRegistration !== true) refuse();
    return this.#operation(scope, async () => {
      const candidate = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
      this.#guard(scope); keyMetadata(candidate.privateKey);
      const bytes = new Uint8Array(await crypto.subtle.exportKey('raw', candidate.publicKey));
      this.#guard(scope);
      const record: StoredKey = { schema: 1, scope, publicPoint: hex(bytes), fingerprint: hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))), privateKey: candidate.privateKey };
      this.#guard(scope);
      await this.#transaction(scope, 'readwrite', (store, result, abort) => {
        const count = store.count();
        count.onsuccess = () => {
          if (count.result >= CAPACITY) { abort(); return; }
          const existing = store.get(scopeKey(scope));
          existing.onsuccess = () => {
            if (existing.result !== undefined) { abort(); return; }
            const add = store.add(record, scopeKey(scope)); add.onsuccess = () => result(undefined);
          };
        };
      });
      // Request success is insufficient: #transaction resolves only on committed completion.
      const persisted = await this.#read(scope);
      if (!persisted || persisted.fingerprint !== record.fingerprint || persisted.publicPoint !== record.publicPoint) refuse();
      await this.#verify(scope, persisted); return this.#metadata(scope, persisted);
    });
  }
  /** expectedFingerprint MUST come from the independently verified original sealed registration. */
  async load(input: SealedApprovalScope, expectedFingerprint: string): Promise<SealedApprovalLease> {
    const scope = scopeSnapshot(input), expected = fingerprint(expectedFingerprint);
    return this.#operation(scope, async () => {
      const record = await this.#read(scope);
      if (!record || record.fingerprint !== expected) refuse();
      await this.#verify(scope, record);
      let held: CryptoKey | null = record.privateKey, busy = false;
      const close = () => { held = null; this.#leases.delete(close); };
      this.#leases.add(close);
      return Object.freeze({ ...this.#metadata(scope, record), close,
        withKey: async <T>(selected: SealedApprovalScope, selectedFingerprint: string, run: (key: CryptoKey) => Promise<T>): Promise<T> => {
          if (busy || !held || typeof run !== 'function') refuse();
          busy = true;
          try {
            this.#guard(scope);
            if (scopeKey(scopeSnapshot(selected)) !== scopeKey(scope) || fingerprint(selectedFingerprint) !== expected) refuse();
            const value = await run(held);
            this.#guard(scope); if (!held) refuse(); return value;
          } catch (error) { close(); throw error; }
          finally { busy = false; }
        }
      });
    });
  }
}
