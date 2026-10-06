// SPDX-License-Identifier: AGPL-3.0-only
// Simulator-only send guard for agent text tools. Every check fails closed.
// Nothing here opens a network connection or sends real SMS; the transport is
// an injected function and the bundled one is a deterministic simulator.
import { createHash, createHmac, randomUUID } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';

export const SEND_SCOPE = 'messages:send';
export const DEFAULT_LIMITS = Object.freeze({ perMinute: 3, perDay: 20, newRecipientsPerDay: 3, refusalsPerMinute: 10 });
// Owner policy may lower these but never raise them.
export const HARD_LIMITS = Object.freeze({ perMinute: 10, perDay: 200, newRecipientsPerDay: 20, refusalsPerMinute: 30 });
export const MAX_GRANT_MS = 24 * 60 * 60 * 1000;
export const MAX_LEDGER_ENTRIES = 10000;
const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;
const KEY_RE = /^[A-Za-z0-9_-]{16,64}$/;
const E164_RE = /^\+[1-9][0-9]{7,14}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const TRANSPORT_REFUSALS = new Set(['recipient_suppressed', 'device_unavailable', 'quota_exhausted', 'invalid_request']);

export const recipientDigest = (salt, e164) =>
  createHmac('sha256', salt).update(`zrotext-send-recipient-v1\0${e164}`).digest('hex');
const short = hex => hex.slice(0, 12);
const sha = text => createHash('sha256').update(text).digest('hex');
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const onlyKeys = (object, keys) => Object.keys(object).every(key => keys.includes(key));

/** Validate an owner-authored policy. Returns null for anything unexpected. */
export function parsePolicy(raw, now) {
  try {
    if (!isObject(raw) || !onlyKeys(raw, ['agentId', 'deviceId', 'recipientSalt', 'grant', 'approvedRecipients', 'suppressedRecipients', 'limits'])) return null;
    const { agentId, deviceId, recipientSalt, grant } = raw;
    if (!ID_RE.test(agentId) || !ID_RE.test(deviceId) || typeof recipientSalt !== 'string' || recipientSalt.length < 32) return null;
    if (!isObject(grant) || !onlyKeys(grant, ['scopes', 'deviceId', 'agentId', 'issuedAtMs', 'expiresAtMs'])) return null;
    // Least privilege: exactly the send scope, bound to this one device and agent, short-lived.
    if (!Array.isArray(grant.scopes) || grant.scopes.length !== 1 || grant.scopes[0] !== SEND_SCOPE) return null;
    if (grant.deviceId !== deviceId || grant.agentId !== agentId) return null;
    if (!Number.isSafeInteger(grant.issuedAtMs) || !Number.isSafeInteger(grant.expiresAtMs)) return null;
    if (grant.expiresAtMs <= now || grant.expiresAtMs - grant.issuedAtMs > MAX_GRANT_MS || grant.issuedAtMs > now + MINUTE) return null;
    const lists = {};
    for (const name of ['approvedRecipients', 'suppressedRecipients']) {
      const list = raw[name] ?? [];
      if (!Array.isArray(list) || list.length > 1000 || !list.every(item => HEX64_RE.test(item))) return null;
      lists[name] = new Set(list);
    }
    const limits = { ...DEFAULT_LIMITS };
    if (raw.limits !== undefined) {
      if (!isObject(raw.limits) || !onlyKeys(raw.limits, Object.keys(DEFAULT_LIMITS))) return null;
      for (const [name, value] of Object.entries(raw.limits)) {
        if (!Number.isSafeInteger(value) || value < 1 || value > HARD_LIMITS[name]) return null;
        limits[name] = value;
      }
    }
    return { agentId, deviceId, recipientSalt, approved: lists.approvedRecipients, suppressed: lists.suppressedRecipients, limits };
  } catch { return null; }
}

/** Read the policy file fresh for every send so owner revocation applies at once. */
export function createFilePolicyLoader(path, clock = Date.now) {
  return () => {
    if (typeof path !== 'string' || path === '') return { error: 'not_configured' };
    try {
      const info = statSync(path);
      if (!info.isFile() || info.size > 262144) return { error: 'policy_invalid' };
      // A policy that other local users can rewrite is not owner authority.
      if (process.platform !== 'win32' && (info.mode & 0o022) !== 0) return { error: 'policy_invalid' };
      const policy = parsePolicy(JSON.parse(readFileSync(path, 'utf8')), clock());
      return policy ? { policy } : { error: 'policy_invalid' };
    } catch { return { error: 'policy_invalid' }; }
  };
}

export function writeJsonAtomic(path, value) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  writeFileSync(temporary, JSON.stringify(value), { mode: 0o600 });
  renameSync(temporary, path);
  try { chmodSync(path, 0o600); } catch { /* best effort on platforms without modes */ }
}

/** Idempotency, rate and unknown-state memory. Entries reserve before transport. */
export class SendLedger {
  constructor(path) {
    this.path = path;
    this.entries = new Map();
    this.suppressed = new Set();
    if (path && existsSync(path)) {
      const data = JSON.parse(readFileSync(path, 'utf8'));
      if (!isObject(data) || !Array.isArray(data.entries) || !Array.isArray(data.suppressed)) throw new Error('ledger_invalid');
      for (const entry of data.entries) {
        // A crash between reservation and result cannot prove the radio was not used.
        this.entries.set(entry.key, entry.state === 'pending' ? { ...entry, state: 'unknown', code: 'submission_unknown' } : entry);
      }
      for (const ref of data.suppressed) this.suppressed.add(ref);
    }
  }
  persist() {
    if (this.path) writeJsonAtomic(this.path, { entries: [...this.entries.values()], suppressed: [...this.suppressed] });
  }
  /** Owner-only: record the externally verified outcome of an unknown send. */
  resolve(key, outcome) {
    const entry = this.entries.get(key);
    if (!entry || entry.state !== 'unknown' || !['sent', 'not_sent'].includes(outcome)) return false;
    this.entries.set(key, { ...entry, state: outcome === 'sent' ? 'accepted' : 'refused', code: outcome === 'sent' ? 'owner_confirmed_sent' : 'owner_confirmed_not_sent', resolved: true });
    this.persist();
    return true;
  }
  hasUnknown(recipientRef) {
    for (const entry of this.entries.values()) if (entry.recipientRef === recipientRef && entry.state === 'unknown') return true;
    return false;
  }
}

/**
 * The simulator transport. It accepts every well-formed request synthetically.
 * Tests pass a script to model refusals, suppression and ambiguous failures.
 */
export function createSimulatorTransport(script = []) {
  const queue = [...script];
  return async () => {
    const next = queue.shift();
    if (next === 'throw') throw new Error('simulated disconnect');
    return next ?? { state: 'accepted', messageId: randomUUID() };
  };
}

const refuse = (code, extra = {}) => ({ synthetic: true, state: 'refused', code, ...extra });

export class SendGuard {
  constructor({ loadPolicy, ledger = new SendLedger(), transport = createSimulatorTransport(), now = Date.now, audit = () => {} }) {
    Object.assign(this, { loadPolicy, ledger, transport, now, audit });
    this.refusals = [];
  }

  emit(event, result, refs = {}) {
    // Audit lines carry fixed codes and one-way references only: never numbers, bodies or keys.
    try { this.audit({ event, state: result.state, code: result.code, t: this.now(), ...refs }); } catch { /* auditing must not change the decision */ }
    return result;
  }

  deny(code, refs, extra) {
    const t = this.now();
    this.refusals = this.refusals.filter(time => t - time < MINUTE);
    this.refusals.push(t);
    return this.emit('send', refuse(code, extra), refs);
  }

  /** The single entry point an agent can reach. Arguments are all untrusted. */
  async send(args) {
    try { return await this.sendChecked(args); } catch { return this.deny('internal_error'); }
  }

  async sendChecked(args) {
    const t = this.now();
    const { policy, error } = this.loadPolicy();
    if (!policy) return this.deny(error ?? 'policy_invalid');
    const { limits } = policy;
    this.refusals = this.refusals.filter(time => t - time < MINUTE);
    // A looping agent that keeps hitting refusals is stopped before it can probe further.
    if (this.refusals.length >= limits.refusalsPerMinute) return this.emit('send', refuse('circuit_open'));
    if (!isObject(args) || !onlyKeys(args, ['recipient', 'body', 'idempotency_key'])) return this.deny('invalid_request');
    const { recipient, body, idempotency_key: key } = args;
    if (key === undefined) return this.deny('idempotency_key_required');
    if (typeof key !== 'string' || !KEY_RE.test(key)) return this.deny('invalid_idempotency_key');
    const keyRef = { keyRef: short(sha(key)) };
    if (typeof recipient !== 'string' || !E164_RE.test(recipient)) return this.deny('invalid_request', keyRef);
    // Control characters (other than newline) and oversized bodies are never forwarded.
    if (typeof body !== 'string' || body.length < 1 || body.length > 640 || /[\u0000-\u0009\u000b-\u001f\u007f]/.test(body)) return this.deny('invalid_request', keyRef);
    const ref = recipientDigest(policy.recipientSalt, recipient);
    const refs = { ...keyRef, recipientRef: short(ref) };
    const fingerprint = sha(`${ref}\0${body}`);

    const prior = this.ledger.entries.get(key);
    if (prior) {
      if (prior.fingerprint !== fingerprint) return this.deny('idempotency_conflict', refs);
      return this.emit('replay', this.render(prior, true), refs);
    }
    if (policy.suppressed.has(ref) || this.ledger.suppressed.has(ref)) return this.deny('recipient_suppressed', refs);
    if (!policy.approved.has(ref)) {
      // Authority comes only from the owner-written policy; model output and inbound texts cannot add to it.
      return this.emit('send', { synthetic: true, state: 'awaiting_owner_approval', code: 'owner_approval_required', recipientRef: short(ref) }, refs);
    }
    if (this.ledger.hasUnknown(short(ref))) return this.deny('unknown_pending_review', refs);

    const own = [...this.ledger.entries.values()].filter(entry => entry.agentId === policy.agentId);
    if (own.filter(entry => t - entry.t < MINUTE).length >= limits.perMinute || own.filter(entry => t - entry.t < DAY).length >= limits.perDay) {
      return this.deny('rate_limited', refs);
    }
    const seenToday = new Set(own.filter(entry => t - entry.t < DAY).map(entry => entry.recipientRef));
    const everSeen = new Set(own.map(entry => entry.recipientRef));
    if (!everSeen.has(short(ref)) && seenToday.size >= limits.newRecipientsPerDay) return this.deny('rate_limited', refs);
    if (this.ledger.entries.size >= MAX_LEDGER_ENTRIES) return this.deny('ledger_full', refs);

    // Reserve durably before the one and only transport call.
    const entry = { key, fingerprint, agentId: policy.agentId, recipientRef: short(ref), t, state: 'pending', code: 'in_progress' };
    this.ledger.entries.set(key, entry);
    try { this.ledger.persist(); } catch {
      this.ledger.entries.delete(key);
      return this.deny('ledger_unavailable', refs);
    }
    let outcome;
    try {
      // The transport sees only this request, never the credential or other recipients.
      const response = await this.transport({ deviceId: policy.deviceId, agentId: policy.agentId, recipient, body, idempotencyKey: key });
      if (response?.state === 'accepted' && typeof response.messageId === 'string') outcome = { state: 'accepted', code: 'accepted_simulated', messageId: response.messageId };
      else if (response?.state === 'refused' && TRANSPORT_REFUSALS.has(response.code)) outcome = { state: 'refused', code: response.code };
      else outcome = { state: 'unknown', code: 'submission_unknown' };
    } catch { outcome = { state: 'unknown', code: 'submission_unknown' }; }
    Object.assign(entry, outcome);
    if (outcome.code === 'recipient_suppressed') this.ledger.suppressed.add(ref);
    try { this.ledger.persist(); } catch { /* the in-memory entry still blocks a resend this session */ }
    return this.emit('send', this.render(entry, false), refs);
  }

  render(entry, replay) {
    const pending = entry.state === 'pending';
    const base = { synthetic: true, state: pending ? 'unknown' : entry.state, code: pending ? 'in_progress' : entry.code };
    if (replay) base.replay = true;
    if (entry.state === 'accepted' && entry.messageId) base.messageId = entry.messageId;
    return base;
  }

  status(args) {
    if (!isObject(args) || !onlyKeys(args, ['idempotency_key']) || typeof args.idempotency_key !== 'string' || !KEY_RE.test(args.idempotency_key)) {
      return refuse('invalid_request');
    }
    const entry = this.ledger.entries.get(args.idempotency_key);
    // Unknown stays unknown: only the owner can resolve it after checking the phone.
    return entry ? this.render(entry, true) : refuse('not_found');
  }

  readiness() {
    const { policy, error } = this.loadPolicy();
    return policy
      ? { synthetic: true, realSms: false, configured: true, limits: policy.limits }
      : { synthetic: true, realSms: false, configured: false, code: error };
  }
}
