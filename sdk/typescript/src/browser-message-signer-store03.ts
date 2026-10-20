/* SPDX-License-Identifier: AGPL-3.0-only */
/** Purpose-separated browser role05 custody only. No root/SEALED key import, enrollment, current permission or sending is performed. */
export interface BrowserMessageSigner03Scope {
  readonly origin: string;
  readonly accountId: string;
  readonly originalUserId: string;
  readonly deviceId: string;
  readonly lineId: string;
  readonly rootFingerprint: string;
}
export interface BrowserMessageSigner03Metadata {
  readonly purpose: typeof PURPOSE;
  readonly scope: Readonly<BrowserMessageSigner03Scope>;
  readonly publicPoint: string;
  readonly keyId: string;
}
export interface BrowserMessageSigner03Lease extends BrowserMessageSigner03Metadata {
  close(): void;
  /** Trusted application callback; authenticate the current ceremony separately. */
  withKey<T>(scope: BrowserMessageSigner03Scope, keyId: string, run: (key: CryptoKey) => Promise<T>): Promise<T>;
}
interface StoredKey {
  schema: 1; purpose: typeof PURPOSE; scope: BrowserMessageSigner03Scope; publicPoint: string; keyId: string; privateKey: CryptoKey;
}
const PURPOSE = 'conversation-signing03' as const;
const STORE = 'browser-message-signing03-v1', CAPACITY = 128;
async function messageKeyId(point: Uint8Array<ArrayBuffer>): Promise<Uint8Array> {
  const domain = new TextEncoder().encode('ZTSE/key/v1\0');
  const transcript = new Uint8Array(domain.length + 2 + point.length);
  transcript.set(domain); transcript.set([1, 1], domain.length); transcript.set(point, domain.length + 2);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', transcript));
}
const fields = ['origin', 'accountId', 'originalUserId', 'deviceId', 'lineId', 'rootFingerprint'] as const;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const hex = (value: Uint8Array) => Array.from(value, v => v.toString(16).padStart(2, '0')).join('');
function refuse(): never { throw Error('Browser message signer03 custody unavailable; reconcile the original key'); }
function data(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) refuse();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== keys.length || keys.some(k => !descriptors[k] || !('value' in descriptors[k]))) refuse();
  return Object.fromEntries(keys.map(k => [k, descriptors[k].value]));
}
function scopeSnapshot(value: BrowserMessageSigner03Scope): Readonly<BrowserMessageSigner03Scope> {
  const s = data(value, fields);
  if (fields.some(k => typeof s[k] !== 'string')) refuse();
  for (const k of ['accountId', 'originalUserId', 'deviceId', 'lineId']) {
    if (!uuidPattern.test(s[k] as string) || (s[k] as string).replaceAll('-', '') === '0'.repeat(32)) refuse();
  }
  let origin: URL;
  try { origin = new URL(s.origin as string); } catch { refuse(); }
  if (origin.protocol !== 'https:' || origin.origin !== s.origin || !/^[0-9a-f]{64}$/.test(s.rootFingerprint as string)
      || s.rootFingerprint === '0'.repeat(64)) refuse();
  return Object.freeze(s) as unknown as Readonly<BrowserMessageSigner03Scope>;
}
const scopeKey = (scope: BrowserMessageSigner03Scope) => JSON.stringify(fields.map(k => scope[k]));
function keyId(value: string): string {
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

export class BrowserMessageSigner03KeyStore {
  #db: IDBDatabase;
  #origin: () => string;
  #signal?: AbortSignal;
  #closed = false;
  #busy = false;
  #transactions = new Set<IDBTransaction>();
  #leases = new Set<() => void>();
  #pending = new Set<() => void>();
  #abort: () => void;
  private constructor(db: IDBDatabase, origin: () => string, signal?: AbortSignal) {
    this.#db = db; this.#origin = origin; this.#signal = signal;
    this.#abort = () => this.close();
    signal?.addEventListener('abort', this.#abort, { once: true });
    db.onversionchange = this.#abort;
  }
  /** name/currentOrigin are trusted embedding dependencies, not server-provided values. */
  static async open(options: { name?: string; currentOrigin?: () => string; signal?: AbortSignal } = {}): Promise<BrowserMessageSigner03KeyStore> {
    const origin = options.currentOrigin ?? (() => globalThis.location.origin), signal = options.signal;
    if (signal?.aborted) refuse();
    const name = options.name ?? 'zrotext-browser-message-signing03';
    if (typeof name !== 'string' || name.length < 1 || name.length > 128) refuse();
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open(name, 1);
      let refused = false;
      const abort = () => { refused = true; clearTimeout(timer); signal?.removeEventListener('abort', abort); reject(Error('Browser message signer03 storage open refused')); };
      const timer = setTimeout(abort, 5000);
      signal?.addEventListener('abort', abort, { once: true });
      request.onblocked = abort;
      request.onupgradeneeded = () => {
        if (refused || signal?.aborted) { request.transaction?.abort(); return; }
        request.result.createObjectStore(STORE);
      };
      request.onerror = () => { signal?.removeEventListener('abort', abort); abort(); };
      request.onsuccess = () => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', abort);
        if (refused || signal?.aborted || request.result.objectStoreNames.length !== 1 || !request.result.objectStoreNames.contains(STORE)) {
          request.result.close(); abort(); return;
        }
        resolve(request.result);
      };
    });
    if (signal?.aborted) { db.close(); refuse(); }
    return new BrowserMessageSigner03KeyStore(db, origin, signal);
  }
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#signal?.removeEventListener('abort', this.#abort);
    for (const cancel of this.#pending) cancel();
    this.#pending.clear();
    for (const tx of this.#transactions) try { tx.abort(); } catch { /* Already completed. */ }
    for (const close of this.#leases) close();
    this.#leases.clear(); this.#db.close();
  }
  #guard(scope: BrowserMessageSigner03Scope): void {
    if (this.#closed || this.#signal?.aborted || this.#origin() !== scope.origin) refuse();
  }
  #bounded<T>(scope: BrowserMessageSigner03Scope, run: () => Promise<T>): Promise<T> {
    this.#guard(scope);
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = () => { settled = true; clearTimeout(timer); this.#pending.delete(cancel); };
      const cancel = () => { if (!settled) { finish(); reject(Error('Browser message signer03 operation withdrawn')); } };
      const timer = setTimeout(() => { this.close(); cancel(); }, 5000);
      this.#pending.add(cancel);
      // Both handlers remain attached after withdrawal, including a late rejection.
      Promise.resolve().then(() => { this.#guard(scope); return run(); }).then(value => {
        if (settled) return;
        try { this.#guard(scope); finish(); resolve(value); } catch { cancel(); }
      }, error => { if (!settled) { finish(); reject(error); } });
    });
  }
  async #operation<T>(scope: BrowserMessageSigner03Scope, run: () => Promise<T>): Promise<T> {
    if (this.#busy) refuse();
    this.#guard(scope); this.#busy = true;
    try { return await this.#bounded(scope, run); }
    finally { this.#busy = false; }
  }
  #transaction<T>(scope: BrowserMessageSigner03Scope, mode: IDBTransactionMode, run: (store: IDBObjectStore, result: (value: T) => void, abort: () => void) => void): Promise<T> {
    this.#guard(scope);
    return new Promise((resolve, reject) => {
      const tx = this.#db.transaction(STORE, mode);
      this.#transactions.add(tx);
      let result: T, assigned = false;
      const done = () => this.#transactions.delete(tx);
      tx.oncomplete = () => {
        done();
        try { this.#guard(scope); if (!assigned) refuse(); resolve(result); } catch { reject(Error('Browser message signer03 storage outcome unavailable')); }
      };
      tx.onabort = () => { done(); reject(Error('Browser message signer03 storage transaction refused')); };
      const abort = () => { try { tx.abort(); } catch { /* No result is published. */ } };
      try { run(tx.objectStore(STORE), value => { result = value; assigned = true; }, abort); } catch { abort(); }
    });
  }
  async #read(scope: BrowserMessageSigner03Scope): Promise<StoredKey | null> {
    const raw = await this.#transaction<unknown>(scope, 'readonly', (store, result) => {
      const request = store.get(scopeKey(scope)); request.onsuccess = () => result(request.result);
    });
    if (raw === undefined) return null;
    const record = data(raw, ['schema', 'purpose', 'scope', 'publicPoint', 'keyId', 'privateKey']);
    if (record.schema !== 1 || record.purpose !== PURPOSE || scopeKey(scopeSnapshot(record.scope as BrowserMessageSigner03Scope)) !== scopeKey(scope)) refuse();
    keyId(record.keyId as string); point(record.publicPoint as string); keyMetadata(record.privateKey as CryptoKey);
    return record as unknown as StoredKey;
  }
  async #verify(scope: BrowserMessageSigner03Scope, record: StoredKey): Promise<void> {
    const bytes = point(record.publicPoint);
    if (hex(await messageKeyId(bytes)) !== record.keyId) refuse();
    this.#guard(scope);
    const publicKey = await crypto.subtle.importKey('raw', bytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    this.#guard(scope);
    const domain = new TextEncoder().encode('ZTSE/browser/message-signing03-possession/v1\0');
    const probe = new Uint8Array(domain.length + 32); probe.set(domain); crypto.getRandomValues(probe.subarray(domain.length));
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, record.privateKey, probe);
    this.#guard(scope);
    const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, probe);
    this.#guard(scope); if (!valid) refuse();
  }
  #metadata(scope: BrowserMessageSigner03Scope, record: StoredKey): BrowserMessageSigner03Metadata {
    return Object.freeze({ purpose: PURPOSE, scope, publicPoint: record.publicPoint, keyId: record.keyId });
  }
  /** Reconcile local public metadata only; independently compare the root-signed role05 enrollment before use. */
  async metadata(input: BrowserMessageSigner03Scope): Promise<BrowserMessageSigner03Metadata | null> {
    const scope = scopeSnapshot(input);
    return this.#operation(scope, async () => {
      const record = await this.#read(scope); if (!record) return null;
      await this.#verify(scope, record); return this.#metadata(scope, record);
    });
  }
  /** Explicit NEW browser message enrollment only. Existing/missing enrolled keys require recovery, never replacement. */
  async create(input: BrowserMessageSigner03Scope, consent: { retain: true; newEnrollment: true }): Promise<BrowserMessageSigner03Metadata> {
    const scope = scopeSnapshot(input), decision = data(consent, ['retain', 'newEnrollment']);
    if (decision.retain !== true || decision.newEnrollment !== true) refuse();
    return this.#operation(scope, async () => {
      const candidate = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
      this.#guard(scope); keyMetadata(candidate.privateKey);
      const bytes = new Uint8Array(await crypto.subtle.exportKey('raw', candidate.publicKey));
      this.#guard(scope);
      const record: StoredKey = { schema: 1, purpose: PURPOSE, scope, publicPoint: hex(bytes), keyId: hex(await messageKeyId(bytes)), privateKey: candidate.privateKey };
      this.#guard(scope);
      await this.#transaction(scope, 'readwrite', (store, result, abort) => {
        const count = store.count();
        count.onsuccess = () => { try {
          if (count.result >= CAPACITY) { abort(); return; }
          const existing = store.get(scopeKey(scope));
          existing.onsuccess = () => { try {
            if (existing.result !== undefined) { abort(); return; }
            const add = store.add(record, scopeKey(scope)); add.onsuccess = () => result(undefined);
          } catch { abort(); } };
        } catch { abort(); } };
      });
      // Request success is insufficient: #transaction resolves only on committed completion.
      const persisted = await this.#read(scope);
      if (!persisted || persisted.keyId !== record.keyId || persisted.publicPoint !== record.publicPoint) refuse();
      await this.#verify(scope, persisted); return this.#metadata(scope, persisted);
    });
  }
  /** expectedKeyId MUST come from the independently verified root-signed role05 record; stored metadata alone is not enrollment. */
  async load(input: BrowserMessageSigner03Scope, expectedKeyId: string): Promise<BrowserMessageSigner03Lease> {
    const scope = scopeSnapshot(input), expected = keyId(expectedKeyId);
    return this.#operation(scope, async () => {
      const record = await this.#read(scope);
      if (!record || record.keyId !== expected) refuse();
      await this.#verify(scope, record);
      let held: CryptoKey | null = record.privateKey, busy = false;
      const close = () => { held = null; this.#leases.delete(close); };
      this.#leases.add(close);
      return Object.freeze({ ...this.#metadata(scope, record), close,
        withKey: async <T>(selected: BrowserMessageSigner03Scope, selectedKeyId: string, run: (key: CryptoKey) => Promise<T>): Promise<T> => {
          if (busy || !held || typeof run !== 'function') refuse();
          busy = true;
          try {
            this.#guard(scope);
            if (scopeKey(scopeSnapshot(selected)) !== scopeKey(scope) || keyId(selectedKeyId) !== expected) refuse();
            const selectedKey = held;
            const value = await this.#bounded(scope, async () => {
              if (!held) refuse();
              return run(selectedKey);
            });
            this.#guard(scope); if (!held) refuse(); return value;
          } catch (error) { close(); throw error; }
          finally { busy = false; }
        }
      });
    });
  }
}
