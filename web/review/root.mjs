// SPDX-License-Identifier: AGPL-3.0-only
import { createReviewFlight } from './single-flight.mjs';
import { artifactRequest, base64, closed, decimal, decode, inspectChallenge, inspectReceipt, readArtifacts, uuid, verifySignatures } from './root-material.mjs';

const prefix = '/v1/review/';
const operationFields = ['version', 'request_id', 'preparation_id', 'generation', 'state', 'create_deadline_ms', 'delivery_deadline_ms', 'server_now_ms'];
const states = new Set(['prepared', 'confirmed', 'busy_unknown', 'cancelled_no_effect', 'rejected_no_effect', 'committed_known', 'unavailable']);
const contextFields = ['version', 'request_id', 'realm', 'database_commitment_b64', 'config_digest_b64', 'config_revision', 'origin', 'account', 'owner_user', 'review_owner_session', 'broker_principal', 'credential_id', 'credential_revision', 'broker_session', 'auth_event', 'issued_ms', 'absolute_expiry_ms', 'idle_deadline_ms', 'server_now_ms', 'capabilities', 'root_state', 'locator_retained'];
const sessionFields = ['realm', 'database_commitment_b64', 'config_digest_b64', 'config_revision', 'origin', 'account', 'owner_user', 'review_owner_session', 'broker_principal', 'credential_id', 'credential_revision', 'broker_session', 'auth_event', 'issued_ms', 'absolute_expiry_ms'];
export function cookie(raw, name) {
  if (typeof raw !== 'string' || raw.length > 8192 || /[^\x20-\x7e]/.test(raw)) throw Error('Review cookies unavailable.');
  const matches = raw.split(';').map((v) => v.trim()).filter((v) => v.split('=', 1)[0] === name);
  if (matches.length !== 1) throw Error('Review cookie missing or ambiguous.');
  const value = matches[0].slice(name.length + 1);
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw Error('Review CSRF cookie refused.');
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/') + '=';
  const bytes = decode(normalized, 32, true);
  if (!bytes.some((b) => b !== 0)) throw Error('Review CSRF cookie refused.');
  return value;
}
function operation(value, identity) {
  closed(value, operationFields);
  if (value.version !== 1 || value.request_id !== identity.request_id || !states.has(value.state)) throw Error('Original review operation changed.');
  uuid(value.request_id);
  uuid(value.preparation_id); decimal(value.generation);
  if (identity.preparation_id && (value.preparation_id !== identity.preparation_id || value.generation !== identity.generation)) throw Error('Original review preparation changed.');
  const create = decimal(value.create_deadline_ms), delivery = decimal(value.delivery_deadline_ms);
  decimal(value.server_now_ms);
  if (delivery < create) throw Error('Review operation bounds refused.');
  return value;
}
function context(value, request, origin, prior) {
  closed(value, contextFields);
  if (value.version !== 1 || value.request_id !== request.request_id || value.origin !== origin || typeof value.locator_retained !== 'boolean') throw Error('Current review context changed.');
  for (const field of ['realm', 'account', 'owner_user', 'review_owner_session', 'broker_principal', 'credential_id', 'broker_session', 'auth_event']) uuid(value[field]);
  for (const field of ['database_commitment_b64', 'config_digest_b64']) { if (!decode(value[field], 32, true).some((b) => b !== 0)) throw Error('Review deployment identity refused.'); }
  for (const field of ['config_revision', 'credential_revision']) decimal(value[field]);
  const issued = decimal(value.issued_ms), expiry = decimal(value.absolute_expiry_ms), idle = decimal(value.idle_deadline_ms), now = decimal(value.server_now_ms);
  if (issued > now || now >= idle || idle > expiry) throw Error('Review session expired.');
  if (!Array.isArray(value.capabilities) || value.capabilities.join('\0') !== ['bootstrap_session', 'root_issue', 'root_complete', 'root_receipt', 'root_custody_export'].join('\0')) throw Error('Review capabilities changed.');
  if (!value.root_state || !['no_root_history', 'pending_enrollment', 'enrolled', 'history', 'unavailable'].includes(value.root_state.kind)) throw Error('Root history unavailable.');
  const root = value.root_state;
  if (root.kind === 'pending_enrollment') {
    closed(root, ['kind', 'challenge_id', 'root_pin_b64', 'root_fingerprint_b64', 'encrypted_backup_sha256_b64', 'public_card_sha256_b64', 'unsigned_enrollment_sha256_b64', 'custody_statement_sha256_b64', 'expires_ms']);
    uuid(root.challenge_id); decode(root.root_pin_b64, 94, true); decimal(root.expires_ms);
    for (const field of ['root_fingerprint_b64', 'encrypted_backup_sha256_b64', 'public_card_sha256_b64', 'unsigned_enrollment_sha256_b64', 'custody_statement_sha256_b64']) decode(root[field], 32, true);
  } else if (root.kind === 'enrolled') {
    closed(root, ['kind', 'root_pin_b64', 'root_fingerprint_b64', 'generation']);
    decode(root.root_pin_b64, 94, true); decode(root.root_fingerprint_b64, 32, true); decimal(root.generation);
  } else closed(root, ['kind']);
  if (prior && sessionFields.some((field) => value[field] !== prior[field])) throw Error('Review session or configuration was replaced.');
  if (prior && now < decimal(prior.server_now_ms)) throw Error('Review clock moved backwards.');
  return Object.freeze(value);
}
async function boundedJson(response, max) {
  if (!response.ok || response.redirected || response.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json' ||
      !response.headers.get('Cache-Control')?.split(',').map((v) => v.trim().toLowerCase()).includes('no-store')) throw Error('Review response refused. Check the original operation before retrying.');
  const reader = response.body?.getReader();
  if (!reader) throw Error('Bounded review response required.');
  const parts = []; let count = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      count += value.length;
      if (count > max) throw Error('Review response too large.');
      parts.push(value);
    }
    const all = new Uint8Array(count); let at = 0;
    for (const part of parts) { all.set(part, at); at += part.length; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(all));
  } finally { try { await reader.cancel(); } finally { reader.releaseLock(); } }
}

/** Browser coordination only; all authorization is checked again by the server. */
export class ReviewRootClient {
  #request; #cookies; #id; #origin; #changed; #closed = false; #browser = null; #browserRequest;
  #pending = null; #current = null; #kit = null; #challenge = null; #abort = null;
  #canLogin = false; #ownerIssued = false; #contextUsable = false;
  flight = createReviewFlight();
  constructor({ origin, fetch = (...args) => globalThis.fetch(...args), cookies = () => document.cookie, newId = () => crypto.randomUUID(), changed = () => {} }) {
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.origin !== origin || origin.length > 255) throw Error('Exact HTTPS review origin required.');
    this.#origin = origin; this.#request = fetch; this.#cookies = cookies; this.#id = newId; this.#changed = changed;
    this.#browserRequest = this.#identity();
  }
  #identity() { const request_id = this.#id(); uuid(request_id); return { version: 1, request_id }; }
  snapshot() { return { ready: this.#browser !== null && !this.#closed, canSignIn: this.#canLogin && !this.#closed, context: this.#contextUsable ? this.#current : null, pending: this.#pending ? { ...this.#pending.identity, phase: this.#pending.phase, kind: this.#pending.kind } : null, challenge: this.#challenge?.view ?? null }; }
  #active(owner = true) {
    const raw = this.#cookies();
    return { 'X-Ztrw-Broker-Csrf': cookie(raw, '__Host-ztrw-broker-csrf'), ...(owner ? { 'X-Ztrw-Owner-Csrf': cookie(raw, '__Host-ztrw-owner-csrf') } : {}) };
  }
  #prepared() {
    if (!this.#pending?.identity.preparation_id || !this.#pending.csrf) throw Error('Original preparation unavailable.');
    const name = '__Host-ztrw-c-' + this.#pending.identity.preparation_id.replaceAll('-', '');
    if (cookie(this.#cookies(), name) !== this.#pending.csrf) throw Error('Original preparation cookie changed.');
    return { 'X-Ztrw-Prepared-Csrf': this.#pending.csrf };
  }
  #ackHeaders() {
    if (!this.#pending?.csrf) throw Error('Original acknowledgement proof unavailable.');
    const name = '__Host-ztrw-c-' + this.#pending.identity.preparation_id.replaceAll('-', '');
    const present = this.#cookies().split(';').some((part) => part.trim().split('=', 1)[0] === name);
    // Only this exact already-committed delivery may use a held proof when the
    // server already retired p/c. Actual owner/broker and DB result are required.
    return { ...(present ? this.#prepared() : { 'X-Ztrw-Prepared-Csrf': this.#pending.csrf }), ...this.#active() };
  }
  async #post(path, body, headers = {}, max = 8192) {
    if (this.#closed) throw Error('Review page closed.');
    const abort = new AbortController(); this.#abort = abort;
    const timer = setTimeout(() => abort.abort(), 10000);
    try {
      const response = await this.#request(this.#origin + prefix + path, { method: 'POST', credentials: 'same-origin', mode: 'same-origin', redirect: 'error', cache: 'no-store', signal: abort.signal,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...headers }, body: JSON.stringify(body) });
      if (this.#closed || abort.signal.aborted) throw Error('Review operation unconfirmed.');
      const value = await boundedJson(response, max);
      if (this.#closed || abort.signal.aborted) throw Error('Review operation unconfirmed.');
      return value;
    } finally { clearTimeout(timer); if (this.#abort === abort) this.#abort = null; }
  }
  async #passwordPost(path, fields, headers, readPassword) {
    // Keep the password in this one request body, never in pending-operation
    // state. Remove the field on every completion, rejection or transport error.
    const body = Object.fromEntries([...Object.entries(fields), ['password', readPassword()]]);
    try {
      if (typeof body.password !== 'string' || new TextEncoder().encode(body.password).length < 1 || new TextEncoder().encode(body.password).length > 1024) throw Error('Review password required.');
      return await this.#post(path, body, headers);
    } finally { delete body.password; }
  }
  async #run(action) {
    try { return await this.flight.run(action); }
    finally { this.#changed(this.snapshot()); }
  }
  async initialize() {
    return this.#run(async () => {
      const value = await this.#post('browser/prepare', this.#browserRequest);
      closed(value, ['version', 'request_id', 'browser_context_commitment_b64', 'issued_ms', 'expires_ms', 'server_now_ms', 'outstanding', 'owner_session_issued']);
      if (value.version !== 1 || value.request_id !== this.#browserRequest.request_id || decimal(value.issued_ms) > decimal(value.server_now_ms) || decimal(value.server_now_ms) >= decimal(value.expires_ms)) throw Error('Browser confirmation refused.');
      decode(value.browser_context_commitment_b64, 32, true);
      const confirm = { ...this.#identity(), browser_context_commitment_b64: value.browser_context_commitment_b64 };
      const result = await this.#post('browser/confirm', confirm, { 'X-Ztrw-Prepared-Csrf': value.browser_context_commitment_b64 });
      closed(result, ['version', 'request_id', 'browser_context_commitment_b64', 'issued_ms', 'expires_ms', 'server_now_ms', 'outstanding', 'owner_session_issued']);
      if (result.version !== 1 || result.request_id !== confirm.request_id || result.browser_context_commitment_b64 !== value.browser_context_commitment_b64) throw Error('Browser continuity changed.');
      if (result.issued_ms !== value.issued_ms || result.expires_ms !== value.expires_ms || decimal(result.server_now_ms) < decimal(value.server_now_ms) || decimal(result.server_now_ms) >= decimal(result.expires_ms)) throw Error('Original browser lifetime changed.');
      if (typeof result.owner_session_issued !== 'boolean' || typeof value.owner_session_issued !== 'boolean' || result.owner_session_issued !== value.owner_session_issued) throw Error('Browser session history changed.');
      this.#browser = value.browser_context_commitment_b64;
      this.#ownerIssued = result.owner_session_issued;
      this.#canLogin = false;
      if (result.outstanding !== null) {
        const old = operation(result.outstanding, result.outstanding);
        this.#pending = { identity: { version: 1, request_id: old.request_id, preparation_id: old.preparation_id, generation: old.generation }, kind: 'unrecovered', phase: 'unconfirmed' };
        throw Error('An original operation is still retained. Keep the existing files and reconcile it before starting another.');
      }
      if (this.#ownerIssued) await this.#context();
      else this.#canLogin = true;
    });
  }
  async #prepare(kind, fields) {
    if (!this.#browser || this.#pending || this.#closed) throw Error('Resolve the original operation first.');
    const request = { ...this.#identity(), operation: { kind, ...fields } };
    if (kind === 'initial_bootstrap') this.#canLogin = false;
    this.#pending = { identity: { version: 1, request_id: request.request_id }, kind, phase: 'prepare_unconfirmed' };
    const value = operation(await this.#post('preparations', request, { 'X-Ztrw-Prepared-Csrf': this.#browser, ...(kind.startsWith('root_') ? this.#active() : {}) }), request);
    this.#pending.identity = { version: 1, request_id: value.request_id, preparation_id: value.preparation_id, generation: value.generation };
    this.#pending.csrf = cookie(this.#cookies(), '__Host-ztrw-c-' + value.preparation_id.replaceAll('-', ''));
    if (value.state !== 'prepared') throw Error('Preparation was not confirmed.');
    const confirmed = operation(await this.#post('preparations/confirm', this.#pending.identity, { ...this.#prepared(), ...(kind.startsWith('root_') ? this.#active() : {}) }), this.#pending.identity);
    if (confirmed.state !== 'confirmed') throw Error('Original preparation is unconfirmed.');
    this.#pending.phase = kind;
    return this.#pending.identity;
  }
  async #context() {
    this.#contextUsable = false;
    const request = this.#identity();
    const value = context(await this.#post('session/context', request, this.#active()), request, this.#origin, this.#current);
    this.#current = value; this.#contextUsable = true; this.#ownerIssued = true; return value;
  }
  async #ack() {
    const pending = this.#pending;
    pending.phase = 'ack_unconfirmed';
    const value = operation(await this.#post('session/confirm', pending.identity, this.#ackHeaders()), pending.identity);
    if (value.state !== 'committed_known') throw Error('Original delivery is unconfirmed.');
    this.#pending = null;
  }
  async #promote() {
    const identity = this.#pending.identity;
    const login = operation(await this.#post('login/status', identity, this.#prepared()), identity);
    if (login.state !== 'committed_known') throw Error('Original sign-in is still unconfirmed.');
    this.#pending.phase = 'workspace_unconfirmed';
    const workspace = operation(await this.#post('workspace/status', identity, { ...this.#prepared(), ...this.#active(false) }), identity);
    if (workspace.state !== 'committed_known') throw Error('Original workspace is still unconfirmed.');
    await this.#context(); await this.#ack();
  }
  async login(alias, password) {
    if (!/^[a-z0-9][a-z0-9_-]{0,31}$/.test(alias)) throw Error('Use the provided review sign-in name exactly.');
    if (!this.#canLogin || this.#ownerIssued) throw Error('Recover or reconcile the existing workspace before another sign-in.');
    return this.#run(async () => {
      const identity = await this.#prepare('initial_bootstrap', { alias });
      this.#pending.phase = 'login_unconfirmed';
      const result = operation(await this.#passwordPost('login/bootstrap', { ...identity, alias }, this.#prepared(), password), identity);
      if (result.state !== 'committed_known') throw Error('Original sign-in is unconfirmed.');
      await this.#promote();
    });
  }
  async refresh() { return this.#run(() => this.#context()); }
  async issue(backup, card, independent) {
    return this.#run(async () => {
      const before = await this.#context();
      if (!before.locator_retained || before.root_state.kind !== 'no_root_history') throw Error('Retain the private workspace locator and resolve any root history first.');
      const kit = await readArtifacts(backup, card, { ...independent, account: before.account, origin: this.#origin });
      await this.#context();
      const identity = await this.#prepare('root_issue', artifactRequest(kit));
      this.#kit = kit; this.#pending.phase = 'root_issue_unconfirmed';
      const view = await this.#post('root/issue', { ...identity, ...artifactRequest(kit) }, { ...this.#prepared(), ...this.#active() });
      this.#challenge = await inspectChallenge(view, identity, before, kit);
      await this.#context(); await this.#ack();
      return this.#challenge.view;
    });
  }
  async complete(publicResponse, password) {
    return this.#run(async () => {
      if (!this.#kit || !this.#challenge) throw Error('Recover the original proposal first.');
      const current = await this.#context();
      if (decimal(current.server_now_ms) >= this.#challenge.expires || current.root_state.kind !== 'pending_enrollment' || current.root_state.challenge_id !== this.#challenge.view.root_challenge_id) throw Error('The original pending enrollment changed or expired.');
      const signatures = await verifySignatures(publicResponse, this.#challenge, this.#kit);
      const { root_pin_b64: ignoredPin, ...artifacts } = artifactRequest(this.#kit);
      const fields = { ...artifacts, ...signatures, root_challenge_id: this.#challenge.view.root_challenge_id, reauth_challenge_id: this.#challenge.view.reauth_challenge_id,
        reauth_nonce_b64: this.#challenge.view.reauth_nonce_b64, unsigned_enrollment_b64: this.#challenge.view.unsigned_enrollment_b64 };
      const identity = await this.#prepare('root_complete', fields);
      this.#pending.phase = 'root_complete_unconfirmed';
      await this.#passwordPost('root/complete', { ...identity, ...fields }, { ...this.#prepared(), ...this.#active() }, password);
      await this.#readCompletion(); await this.#ack(); await this.#context();
    });
  }
  async #readCompletion() {
    const request = { ...this.#identity(), independently_compared_fingerprint_b64: base64(this.#kit.fingerprint) };
    const receipt = await this.#post('root/result', request, this.#active());
    return inspectReceipt(receipt, request, this.#current, this.#kit, this.#challenge);
  }
  async reconcile() {
    return this.#run(async () => {
      if (!this.#pending) { await this.#context(); return; }
      const pending = this.#pending;
      if (pending.phase === 'terminal_cleanup') throw Error('No effect is already confirmed. Request only the original cancellation acknowledgement to retire its cookies.');
      if (pending.phase === 'ack_unconfirmed') { await this.#ack(); await this.#context(); return; }
      if (pending.phase === 'cancel_unconfirmed') {
        if (!pending.csrf) throw Error('Original cancellation proof unavailable.');
        const result = operation(await this.#post('preparations/status', pending.identity,
          { 'X-Ztrw-Prepared-Csrf': pending.csrf, ...(pending.kind.startsWith('root_') ? this.#active() : {}) }), pending.identity);
        if (['cancelled_no_effect', 'rejected_no_effect'].includes(result.state)) { this.#finishCancellation(); return; }
        if (['prepared', 'confirmed', 'committed_known'].includes(result.state)) pending.phase = pending.cancelFrom;
        throw Error('Cancellation has not proved no effect. Check the original operation.');
      }
      if (!pending.identity.preparation_id || !pending.csrf) {
        const raw = this.#cookies(), candidates = raw.split(';').map((s) => s.trim().split('=', 1)[0]).filter((name) => /^__Host-ztrw-c-[0-9a-f]{32}$/.test(name));
        if (candidates.length !== 1) throw Error('Original preparation cookies unavailable. Keep retained files; do not create a replacement.');
        const header = cookie(raw, candidates[0]);
        const result = operation(await this.#post('preparations/status', { version: 1, request_id: pending.identity.request_id }, { 'X-Ztrw-Prepared-Csrf': header }), pending.identity);
        pending.identity = { version: 1, request_id: result.request_id, preparation_id: result.preparation_id, generation: result.generation }; pending.csrf = header;
        if (result.state !== 'committed_known') throw Error('Original operation is retained and unconfirmed. No new operation was started.');
      }
      if (pending.kind === 'initial_bootstrap') { await this.#promote(); return; }
      if (pending.kind === 'root_issue' && this.#kit) {
        const view = await this.#post('root/issue-status', pending.identity, { ...this.#prepared(), ...this.#active() });
        this.#challenge = await inspectChallenge(view, pending.identity, await this.#context(), this.#kit);
        await this.#ack(); return;
      }
      if (pending.kind === 'root_complete' && this.#kit && this.#challenge) { await this.#readCompletion(); await this.#ack(); await this.#context(); return; }
      throw Error('Original operation remains retained. Reconcile its original context before any new preparation.');
    });
  }
  async cancel() {
    return this.#run(async () => {
      if (!this.#pending) throw Error('No original operation selected.');
      if (this.#pending.phase === 'cancel_unconfirmed') throw Error('Check the original cancellation before requesting it again.');
      this.#pending.cancelFrom = this.#pending.phase;
      this.#pending.phase = 'cancel_unconfirmed';
      const value = operation(await this.#post('preparations/cancel', this.#pending.identity, { ...this.#prepared(), ...(this.#pending.kind.startsWith('root_') ? this.#active() : {}) }), this.#pending.identity);
      if (!['cancelled_no_effect', 'rejected_no_effect'].includes(value.state)) throw Error('Cancellation did not prove no effect. Keep the original context.');
      this.#finishCancellation();
    });
  }
  #finishCancellation() {
    // A positive exact server terminal result is required before checking cleanup.
    const name = '__Host-ztrw-c-' + this.#pending.identity.preparation_id.replaceAll('-', '');
    if (this.#cookies().split(';').some((v) => v.trim().split('=', 1)[0] === name)) {
      this.#pending.phase = 'terminal_cleanup';
      throw Error('No effect is confirmed; original cookie cleanup still needs the same cancellation acknowledgement.');
    }
    if (this.#pending.kind === 'initial_bootstrap' && !this.#ownerIssued && !this.#current) this.#canLogin = true;
    this.#pending = null;
  }
  close() { this.#closed = true; this.#canLogin = false; this.#contextUsable = false; this.#abort?.abort(); this.#kit = null; this.#challenge = null; this.#current = null; this.#changed(this.snapshot()); }
}

export function mountReviewPage(document, window) {
  const byId = (id) => document.getElementById(id);
  const message = (text) => { byId('status').textContent = text; };
  const clearPasswords = () => { byId('password').value = ''; byId('reauth-password').value = ''; };
  const client = new ReviewRootClient({ origin: window.location.origin, changed: render });
  let busy = false;
  function render() {
    const state = client.snapshot(), current = state.context;
    byId('login').hidden = !!current || !state.canSignIn;
    byId('workspace').hidden = !current;
    byId('issue').hidden = !current || current.root_state.kind !== 'no_root_history';
    byId('challenge').hidden = !state.challenge;
    byId('complete').hidden = !state.challenge || current?.root_state.kind === 'enrolled';
    byId('recovery').hidden = !state.pending;
    for (const form of [byId('login'), byId('issue'), byId('complete')]) form.querySelector('button[type=submit]').disabled = busy || !state.ready || !!state.pending || (form.id === 'login' && !state.canSignIn) || (form.id === 'issue' && !current?.locator_retained);
    byId('reconcile').disabled = busy; byId('cancel').disabled = busy || !state.pending?.preparation_id;
    if (current) { byId('origin').textContent = current.origin; byId('account').textContent = current.account; byId('root-state').textContent = current.root_state.kind.replaceAll('_', ' ') + (current.locator_retained ? '' : ' — retain your private locator in the app first'); }
    if (state.challenge) { byId('unsigned').value = state.challenge.unsigned_enrollment_b64; byId('expiry').textContent = 'This exact proposal expires at ' + new Date(Number(state.challenge.expires_ms)).toISOString() + '.'; }
  }
  async function act(action, success) {
    if (busy) return; busy = true; render();
    try { await action(); message(success); }
    catch (error) { message(error instanceof Error ? error.message : 'Review operation unconfirmed. Check the original operation.'); }
    finally { busy = false; clearPasswords(); render(); }
  }
  byId('login').addEventListener('submit', (event) => { event.preventDefault(); act(() => client.login(byId('alias').value, () => { const value = byId('password').value; byId('password').value = ''; return value; }), 'Signed in. Retain your private locator and create or recover your kit in the app.'); });
  byId('issue').addEventListener('submit', (event) => { event.preventDefault(); if (!byId('publish-consent').checked) return; act(() => client.issue(byId('backup').files[0], byId('card').files[0], { bundle: byId('bundle').value, fingerprint: byId('fingerprint').value }), 'Exact public proposal ready. Review and approve it in the app.'); });
  byId('complete').addEventListener('submit', (event) => { event.preventDefault(); if (!byId('complete-consent').checked) return; act(() => client.complete(byId('signatures').value, () => { const value = byId('reauth-password').value; byId('reauth-password').value = ''; return value; }), 'The original root publication is confirmed. Use the app to verify its signed custody export.'); });
  byId('reconcile').addEventListener('click', () => act(() => client.reconcile(), 'Original operation checked. No replacement was created.'));
  byId('cancel').addEventListener('click', () => act(() => client.cancel(), 'The server confirmed no effect and retired the original preparation.'));
  byId('copy-challenge').addEventListener('click', () => act(async () => { const text = client.snapshot().challenge?.unsigned_enrollment_b64; if (!text) throw Error('Original proposal unavailable.'); await window.navigator.clipboard.writeText(text); }, 'Public challenge copied. No recovery token or private key was copied.'));
  window.ZrotextReviewRoot = Object.freeze({
    requestPause(id) { const accepted = client.flight.requestPause(id); if (accepted) clearPasswords(); return accepted; },
    pauseStatus(id) { return client.flight.pauseStatus(id); },
    resume(id) { const accepted = client.flight.resume(id); if (accepted) act(() => client.refresh(), 'Review workspace refreshed.'); return accepted; },
  });
  window.addEventListener('pagehide', () => { clearPasswords(); client.close(); });
  act(() => client.initialize(), 'Ready for the provided review sign-in.');
  return client;
}
if (typeof document !== 'undefined' && typeof window !== 'undefined') mountReviewPage(document, window);
