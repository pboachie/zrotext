// SPDX-License-Identifier: AGPL-3.0-only
/** Bounded HTTPS access to original events under a separate selected-reader credential. */
import { advanceManifestTrust02, verifiedManifestIdentity02, verifiedManifestTrust02, verifyManifest02, type Manifest02 } from "./draft02-manifest.js";
import { openOriginalReply02, type OriginalReplyAuthority, type OriginalReplyScope } from "./original-reply-reader.js";
import { verifyOriginalReplySelection02 } from "./original-reply-selection.js";
import { workflowActionDigest, type WorkflowActionDescriptor, type WorkflowActionKey } from "./workflow-decisions.js";
import { matchesSchema, workflowTools } from "./workflow-tools.js";

const MAX_RESPONSE = 524288, MAX_CHAIN = 32;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const hexPattern = /^[0-9a-f]{64}$/;
const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((v, i) => v === b[i]);
function unavailable(): never { throw Error("Original reply unavailable"); }
function object(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) unavailable();
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== fields.length || fields.some(k => !Object.hasOwn(record, k))) unavailable();
  return record;
}
function integer(value: unknown): bigint { if (!Number.isSafeInteger(value) || (value as number) <= 0) unavailable(); return BigInt(value as number); }
function uuid(value: unknown): Uint8Array {
  if (typeof value !== "string" || !uuidPattern.test(value) || value === "00000000-0000-0000-0000-000000000000") unavailable();
  return Uint8Array.from(value.replaceAll("-", "").match(/../g)!, h => parseInt(h, 16));
}
function hex(value: unknown): Uint8Array { if (typeof value !== "string" || !hexPattern.test(value)) unavailable(); return Uint8Array.from(value.match(/../g)!, h => parseInt(h, 16)); }
function base64(value: unknown, limit: number): Uint8Array {
  if (typeof value !== "string" || value.length > Math.ceil(limit / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) unavailable();
  const raw = atob(value); if (!raw.length || raw.length > limit || btoa(raw) !== value) unavailable();
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
function uuidText(bytes: Uint8Array): string {
  if (bytes.length !== 16 || !bytes.some(v => v !== 0)) unavailable();
  const value = Array.from(bytes, n => n.toString(16).padStart(2, "0")).join("");
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}
const proofFields = ["account_id", "interval_id", "device_id", "line_id", "connector_id", "read_grant_id", "reader_id", "root_generation", "authority_revision", "expires_at_ms", "observed_at_ms", "current_manifest_version", "current_manifest_digest", "manifest_chain"];
export type OriginalReplyClientOptions = Readonly<{
  origin: string; credential: string; scope: OriginalReplyScope; privateKey: CryptoKey;
  /** Independently accepted local snapshots. At most 64; the newest is the request high-water. */
  acceptedHistory: readonly Manifest02[]; clock: () => bigint;
  /** Trusted transport seam for tests; the ordinary browser/Node fetch is used by default. */
  fetch?: typeof fetch; timeoutMs?: number;
  /** Independently configured trusted-local Propose credential. Never a model parameter. */
  outputCredential?: () => Promise<string>;
}>;
export type OriginalReplyCursor = Readonly<{ accepted_at_ms: number; event_id: string }>;
export type OriginalReplyEventMetadata = Readonly<{ event_id: string; accepted_at_ms: number; observed_at_ms: number;
  historical_manifest_version: number; activation_manifest_version: number;
  disposition: "unassociated" | "owner_review" | "request_available"; active_request_ids: readonly string[] }>;
export type OriginalReplyConsumption = Readonly<{ event_id: string; consumption_id: string;
  disposition: "proposal" | "owner_review"; active_request_id: string | null; action: WorkflowActionKey | null }>;
export type OriginalReplyConsumeRequest = Readonly<{ request_id: string; event_id: string; active_request_id: string | null; descriptor: WorkflowActionDescriptor | null }>;
export class OriginalReplyClient {
  readonly #endpoint: string; readonly #credential: string; readonly #scope: OriginalReplyScope;
  readonly #privateKey: CryptoKey; readonly #clock: () => bigint; readonly #fetch: typeof fetch; readonly #timeout: number;
  readonly #outputCredential?: () => Promise<string>;
  readonly #history = new Map<bigint, Manifest02>(); #latest: Manifest02; #busy = false; #lastClock: bigint;
  constructor(options: OriginalReplyClientOptions) {
    const origin = new URL(options.origin);
    if (origin.protocol !== "https:" || origin.username || origin.password || origin.pathname !== "/" || origin.search || origin.hash ||
        !/^ztr_[A-Za-z0-9_-]{43}$/.test(options.credential)) unavailable();
    const credentialBytes = Uint8Array.from(atob(options.credential.slice(4).replaceAll("-", "+").replaceAll("_", "/") + "="), c => c.charCodeAt(0));
    if (credentialBytes.length !== 32 || btoa(String.fromCharCode(...credentialBytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "") !== options.credential.slice(4)) unavailable();
    credentialBytes.fill(0);
    if (!options.acceptedHistory.length || options.acceptedHistory.length > 64) unavailable();
    this.#scope = { ...options.scope, account: Uint8Array.from(options.scope.account), device: Uint8Array.from(options.scope.device), line: Uint8Array.from(options.scope.line),
      interval: Uint8Array.from(options.scope.interval), connector: Uint8Array.from(options.scope.connector), readGrant: Uint8Array.from(options.scope.readGrant), reader: Uint8Array.from(options.scope.reader) };
    for (const field of [this.#scope.account, this.#scope.device, this.#scope.line, this.#scope.interval, this.#scope.connector, this.#scope.readGrant]) uuidText(field);
    if (this.#scope.reader.length !== 32 || !this.#scope.reader.some(v => v !== 0)) unavailable();
    const now = options.clock(); if (now <= 0n) unavailable(); this.#lastClock = now; let previous = 0n;
    for (const manifest of options.acceptedHistory) {
      // Historic acceptance must already exist in the verifier's immutable local provenance.
      const trust = verifiedManifestTrust02(manifest, manifest.issuedMs);
      if (!same(trust.accountId, this.#scope.account) || trust.version <= previous) unavailable();
      previous = trust.version; this.#history.set(trust.version, manifest);
    }
    this.#latest = options.acceptedHistory[options.acceptedHistory.length - 1];
    verifiedManifestIdentity02(this.#latest, now);
    this.#endpoint = new URL("/v1/reply-events", origin).href; this.#credential = options.credential;
    this.#privateKey = options.privateKey; this.#clock = options.clock; this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#outputCredential = options.outputCredential;
    this.#timeout = options.timeoutMs ?? 5000;
    if (!Number.isSafeInteger(this.#timeout) || this.#timeout < 1 || this.#timeout > 10000) unavailable();
  }
  async #request(method: "current" | "read" | "page" | "consume" | "status", event?: Uint8Array, baseline: Manifest02 = this.#latest,
    additional: Record<string, unknown> = {}, outputCredential?: string): Promise<unknown> {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), this.#timeout);
    try {
      if (!Number.isSafeInteger(Number(baseline.version))) unavailable();
      const body = JSON.stringify({ v: 1, method, ...(event ? { event_id: uuidText(event) } : {}), accepted_manifest_version: Number(baseline.version), ...additional });
      if (new TextEncoder().encode(body).length > 4096) unavailable();
      const headers: Record<string, string> = { authorization: `Bearer ${this.#credential}`, "content-type": "application/json" };
      if (outputCredential) headers["x-zrotext-output-authorization"] = `Bearer ${outputCredential}`;
      const response = await this.#fetch(this.#endpoint, { method: "POST", headers,
        body, redirect: "error", credentials: "omit", cache: "no-store", signal: controller.signal });
      if (!response.ok || response.redirected || (response.url && response.url !== this.#endpoint) || !response.body ||
          response.headers.get("content-type")?.split(";")[0].trim() !== "application/json") unavailable();
      const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
      try { while (true) { const chunk = await reader.read(); if (chunk.done) break; size += chunk.value.length; if (size > MAX_RESPONSE) unavailable(); chunks.push(chunk.value); } }
      finally { await reader.cancel().catch(() => {}); }
      const bytes = new Uint8Array(size); let at = 0; for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.length; }
      const result = object(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)), ["kind", "result"]);
      if (result.kind !== method) unavailable(); return result.result;
    } catch { unavailable(); } finally { clearTimeout(timer); }
  }
  async #proof(input: unknown, baseline: Manifest02 = this.#latest): Promise<OriginalReplyAuthority> {
    const p = object(input, proofFields), now = this.#clock(), observed = integer(p.observed_at_ms), expires = integer(p.expires_at_ms);
    if (now < this.#lastClock || now < observed - 30000n || now > observed + 30000n || now >= expires) unavailable();
    for (const [field, expected] of [["account_id", this.#scope.account], ["device_id", this.#scope.device], ["line_id", this.#scope.line], ["interval_id", this.#scope.interval],
      ["connector_id", this.#scope.connector], ["read_grant_id", this.#scope.readGrant]] as const) if (!same(uuid(p[field]), expected)) unavailable();
    if (!same(hex(p.reader_id), this.#scope.reader) || integer(p.authority_revision) !== 1n) unavailable();
    if (!Array.isArray(p.manifest_chain) || p.manifest_chain.length < 1 || p.manifest_chain.length > MAX_CHAIN) unavailable();
    let previous = baseline, trust = verifiedManifestTrust02(previous, previous.issuedMs);
    const initial = verifiedManifestIdentity02(previous, previous.issuedMs), staged: Manifest02[] = [];
    for (let index = 0; index < p.manifest_chain.length; index++) {
      const entry = object(p.manifest_chain[index], ["version", "accepted_at_ms", "manifest_b64"]), version = integer(entry.version), at = integer(entry.accepted_at_ms);
      if (at > now + 30000n || (index === 0 ? version !== initial.version : version !== previous.version + 1n)) unavailable();
      const manifest = await verifyManifest02(base64(entry.manifest_b64, 9751), trust, at);
      if (manifest.version !== version) unavailable();
      if (index === 0 && !same(manifest.digest, initial.digest)) unavailable();
      const cached = this.#history.get(version);
      if (cached && !same(manifest.digest, verifiedManifestIdentity02(cached, cached.issuedMs).digest)) unavailable();
      trust = advanceManifestTrust02(trust, manifest); previous = manifest; staged.push(manifest);
    }
    // Crypto verification awaited above. Another proof may have advanced local
    // trust, or a deadline may have passed, while this proof was suspended.
    // Publish only against the actual final clock/highwater, without an await
    // between this fence and installation of the staged accepted history.
    const fresh = this.#clock();
    if (fresh < now || fresh < this.#lastClock || fresh < observed - 30000n || fresh > observed + 30000n || fresh >= expires) unavailable();
    const identity = verifiedManifestIdentity02(previous, fresh), highwater = verifiedManifestIdentity02(this.#latest, this.#latest.issuedMs);
    for (const manifest of staged) {
      const cached = this.#history.get(manifest.version);
      if (cached && !same(verifiedManifestIdentity02(manifest, manifest.issuedMs).digest, verifiedManifestIdentity02(cached, cached.issuedMs).digest)) unavailable();
    }
    if (identity.version !== integer(p.current_manifest_version) || !same(identity.digest, hex(p.current_manifest_digest)) || identity.generation !== integer(p.root_generation) ||
        identity.generation !== initial.generation || !same(identity.rootPoint, initial.rootPoint) || identity.version < highwater.version ||
        (identity.version === highwater.version && !same(identity.digest, highwater.digest)) || this.#history.size + staged.filter(m => !this.#history.has(m.version)).length > 64) unavailable();
    for (const manifest of staged) this.#history.set(manifest.version, manifest); this.#latest = previous; this.#lastClock = fresh;
    return { ...this.#scope, revision: "1", nowMs: fresh, expiresMs: expires, manifest: previous };
  }
  /** A current service check; this is not satisfied by webhook HMAC or local manifest parsing. */
  async current(): Promise<OriginalReplyAuthority> { return this.#proof(await this.#request("current")); }
  /** Bounded metadata page. Availability never qualifies a reply or supplies STOP classification. */
  async page(cursor: OriginalReplyCursor | null = null, limit = 20): Promise<Readonly<{ events: readonly OriginalReplyEventMetadata[]; next: OriginalReplyCursor | null }>> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 32) unavailable();
    const checkedCursor = cursor === null ? null : this.#cursor(cursor);
    const r = object(await this.#request("page", undefined, this.#latest, { cursor: checkedCursor, limit }), ["events", "next", "proof"]);
    await this.#proof(r.proof);
    if (!Array.isArray(r.events) || r.events.length > limit) unavailable();
    const ids = new Set<string>(), events: OriginalReplyEventMetadata[] = [];
    for (const event of r.events) {
      const e = object(event, ["event_id", "accepted_at_ms", "observed_at_ms", "historical_manifest_version", "activation_manifest_version", "disposition", "active_request_ids"]);
      uuid(e.event_id); if (ids.has(e.event_id as string)) unavailable(); ids.add(e.event_id as string);
      for (const field of ["accepted_at_ms", "observed_at_ms", "historical_manifest_version", "activation_manifest_version"]) integer(e[field]);
      if (!["unassociated", "owner_review", "request_available"].includes(e.disposition as string) || !Array.isArray(e.active_request_ids) || e.active_request_ids.length > 8) unavailable();
      const requests = new Set<string>(); for (const id of e.active_request_ids) { uuid(id); if (requests.has(id)) unavailable(); requests.add(id); }
      events.push({ event_id: e.event_id as string, accepted_at_ms: e.accepted_at_ms as number, observed_at_ms: e.observed_at_ms as number,
        historical_manifest_version: e.historical_manifest_version as number, activation_manifest_version: e.activation_manifest_version as number,
        disposition: e.disposition as OriginalReplyEventMetadata["disposition"], active_request_ids: [...requests] });
    }
    return { events, next: r.next === null ? null : this.#cursor(r.next) };
  }
  #cursor(input: unknown): OriginalReplyCursor {
    const c = object(input, ["accepted_at_ms", "event_id"]); integer(c.accepted_at_ms); uuid(c.event_id);
    return { accepted_at_ms: c.accepted_at_ms as number, event_id: c.event_id as string };
  }
  #consumption(input: unknown): OriginalReplyConsumption {
    const r = object(input, ["event_id", "consumption_id", "disposition", "active_request_id", "action"]);
    uuid(r.event_id); uuid(r.consumption_id); if (r.active_request_id !== null) uuid(r.active_request_id);
    let action: WorkflowActionKey | null = null;
    if (r.action !== null) {
      const key = object(r.action, ["account_id", "action_id", "revision", "binding_digest"]);
      if (!same(uuid(key.account_id), this.#scope.account)) unavailable(); uuid(key.action_id);
      const revision = integer(key.revision); if (revision > 128n) unavailable(); hex(key.binding_digest);
      action = { ...key } as unknown as WorkflowActionKey;
    }
    if (r.disposition === "proposal" ? !action || r.active_request_id === null : r.disposition !== "owner_review" || action !== null) unavailable();
    return { event_id: r.event_id as string, consumption_id: r.consumption_id as string, disposition: r.disposition as "proposal" | "owner_review", active_request_id: r.active_request_id as string | null, action };
  }
  /** One effect attempt only. An unknown result must recover by the same durable identity/status. */
  async consume(input: OriginalReplyConsumeRequest): Promise<OriginalReplyConsumption> {
    const p = object(input, ["request_id", "event_id", "active_request_id", "descriptor"]);
    uuid(p.request_id); uuid(p.event_id); if (p.active_request_id !== null) uuid(p.active_request_id);
    let params: OriginalReplyConsumeRequest, outputCredential: string | undefined;
    if (p.descriptor !== null) {
      const tool = workflowTools.find(t => t.name === "workflow.action.propose")!;
      if (!matchesSchema(tool.inputSchema, { request_id: p.request_id, descriptor: p.descriptor })) unavailable();
      const descriptor = { ...(p.descriptor as WorkflowActionDescriptor) };
      if (descriptor.account_id !== uuidText(this.#scope.account) || descriptor.line_id !== uuidText(this.#scope.line) || p.active_request_id === null) unavailable();
      params = { request_id: p.request_id as string, event_id: p.event_id as string, active_request_id: p.active_request_id as string, descriptor };
      outputCredential = await this.#outputCredential?.();
      if (typeof outputCredential !== "string" || !/^ztw_[A-Za-z0-9_-]{43}$/.test(outputCredential)) unavailable();
      const encoded = outputCredential.slice(4), raw = atob(encoded.replaceAll("-", "+").replaceAll("_", "/") + "=");
      if (raw.length !== 32 || btoa(raw).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "") !== encoded) unavailable();
    } else params = { request_id: p.request_id as string, event_id: p.event_id as string, active_request_id: p.active_request_id as string | null, descriptor: null };
    const digest = params.descriptor ? await workflowActionDigest(params.descriptor) : null;
    const result = this.#consumption(await this.#request("consume", undefined, this.#latest, { params }, outputCredential));
    if (result.event_id !== params.event_id || result.consumption_id !== params.request_id || result.active_request_id !== params.active_request_id) unavailable();
    if (result.action && (!params.descriptor || result.action.action_id !== params.descriptor.action_id || result.action.revision !== params.descriptor.revision || result.action.binding_digest !== digest)) unavailable();
    return result;
  }
  async status(consumptionId: string): Promise<OriginalReplyConsumption> {
    uuid(consumptionId);
    const result = this.#consumption(await this.#request("status", undefined, this.#latest, { consumption_id: consumptionId }));
    if (result.consumption_id !== consumptionId) unavailable(); return result;
  }
  /** Returns transient original plaintext only after phone selection, accepted history and final current service proof. */
  async read(event: Uint8Array, acceptedManifestVersion?: bigint): Promise<string> {
    if (this.#busy) unavailable(); this.#busy = true; const selectedEvent = Uint8Array.from(event);
    try {
      const baselineVersion = acceptedManifestVersion ?? Array.from(this.#history.keys()).find(v => this.#latest.version - v < BigInt(MAX_CHAIN));
      const baseline = baselineVersion === undefined ? undefined : this.#history.get(baselineVersion);
      if (!baseline || baseline.version > this.#latest.version || this.#latest.version - baseline.version >= BigInt(MAX_CHAIN)) unavailable();
      const r = object(await this.#request("read", selectedEvent, baseline), ["event_id", "accepted_at_ms", "envelope_b64", "historical_manifest_version", "statement_b64", "approval_signature_b64", "installation_signature_b64", "activation_manifest_version", "proof"]);
      if (!same(uuid(r.event_id), selectedEvent)) unavailable();
      const proof = await this.#proof(r.proof, baseline), historical = this.#history.get(integer(r.historical_manifest_version)), activation = this.#history.get(integer(r.activation_manifest_version));
      if (!historical || !activation) unavailable();
      const selection = await verifyOriginalReplySelection02(base64(r.statement_b64, 1536), base64(r.approval_signature_b64, 64), base64(r.installation_signature_b64, 64), activation, integer(r.accepted_at_ms), this.#scope);
      let first = true;
      return await openOriginalReply02(base64(r.envelope_b64, 34082), { scope: this.#scope, event: selectedEvent, privateKey: this.#privateKey, historical, selection,
        readCurrent: async () => { if (first) { first = false; return proof; } return this.current(); } });
    } catch { unavailable(); } finally { this.#busy = false; }
  }
}
