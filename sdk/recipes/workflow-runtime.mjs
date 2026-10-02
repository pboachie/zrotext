// SPDX-License-Identifier: AGPL-3.0-only
// Customer-local orchestration. All remote authority remains in the shared service.
import { WorkflowToolClient, WorkflowToolError } from '../typescript/dist/workflow-tool-client.js';
import { canonicalWorkflowAction, workflowActionDigest } from '../typescript/dist/workflow-decisions.js';
import { ReplyEventAdapter } from '../replies/reply-events.mjs';
import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';

export class WorkflowRecipeError extends Error {
  constructor(code) { super(code); this.name = 'WorkflowRecipeError'; this.code = code; }
}
const deny = code => { throw new WorkflowRecipeError(code); };
const uuid = value => typeof value === 'string' &&
  /^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
const closed = (value, names) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));

/** Import creates no active recipe. Trusted startup configuration selects one
 * immutable source/action; workflow input cannot change recipient, keys or scope.
 * Owner approval/binding is created independently in the existing owner lane.
 * No model provider or alternate cryptography is added here. */
export class WorkflowRecipe {
  #client; #descriptor; #context; #replies; #consumer; #enabled = false;
  constructor({ origin, credential, descriptor, replyAdapter, consumerId, fetchImpl }) {
    canonicalWorkflowAction(descriptor);
    this.#descriptor = structuredClone(descriptor);
    this.#context = this.#descriptor.content_ref;
    // Trusted customer transport seam, identical to the shared client contract;
    // never supplied by callable inputs or exported workflow configuration.
    this.#client = new WorkflowToolClient({ origin, credential, fetchImpl });
    if (replyAdapter !== undefined && (!(replyAdapter instanceof ReplyEventAdapter) || !uuid(consumerId) ||
      replyAdapter.accountId !== this.#descriptor.account_id || replyAdapter.lineId !== this.#descriptor.line_id)) deny('invalid_reply_adapter');
    this.#replies = replyAdapter; this.#consumer = consumerId;
  }
  async setup() {
    const readiness = await this.#client.readiness();
    if (readiness.scope.context_id !== this.#context || readiness.scope.line_id !== this.#descriptor.line_id) deny('scope_mismatch');
    return { installed_state: this.#enabled ? 'enabled' : 'disabled', scope: readiness.scope,
      required_permissions: ['context_metadata', 'propose', 'status'],
      optional_permissions: ['send'],
      methods: readiness.methods, content_reader: 'customer_local_if_independently_configured',
      model_provider_access: 'none', owner_grant_setup: 'authenticated_operator_required',
      send_semantics: readiness.send_semantics };
  }
  /** Local owner/controller activation, never exposed in the callable input. */
  async enable() {
    const setup = await this.setup();
    for (const method of ['workflow.context.metadata', 'workflow.action.propose', 'workflow.action.status']) {
      if (!setup.methods.find(item => item.method === method)?.permission_granted) deny('missing_grant');
    }
    this.#enabled = true;
  }
  disable() { this.#enabled = false; }
  async preview(requestId) {
    if (!uuid(requestId)) deny('invalid_request');
    // Preview is read-only and never persists a proposal or prepares a message.
    const metadata = await this.#client.call('workflow.context.metadata', { request_id: requestId, context_id: this.#context });
    if (metadata.result.source_content_digest !== this.#descriptor.content_digest ||
      metadata.result.revision !== this.#descriptor.content_version) deny('source_changed');
    return { state: 'preview', context_id: this.#context, action_id: this.#descriptor.action_id,
      content_digest: metadata.result.source_content_digest, approval: false, model_provider_access: 'none' };
  }
  async call(input) {
    if (!closed(input, ['operation', 'request_id']) || !uuid(input.request_id) ||
      !['task_completion', 'owner_proposal', 'status'].includes(input.operation)) deny('invalid_request');
    if (!this.#enabled) deny('disabled');
    const id = input.request_id;
    if (input.operation === 'task_completion' || input.operation === 'owner_proposal') {
      return this.#client.call('workflow.action.propose', { request_id: id, descriptor: this.#descriptor });
    }
    return this.#client.call('workflow.action.status', {
      request_id: id, context_id: this.#context, action_id: this.#descriptor.action_id });
  }
  async prepare(input) {
    if (!input || Object.keys(input).some(name => !['request_id', 'key', 'occurrence_id'].includes(name))) deny('invalid_request');
    const { request_id, key, occurrence_id = null } = input;
    if (!this.#enabled) deny('disabled');
    if (!uuid(request_id) || !closed(key, ['account_id', 'action_id', 'revision', 'binding_digest']) ||
      key.account_id !== this.#descriptor.account_id || key.action_id !== this.#descriptor.action_id ||
      key.revision !== this.#descriptor.revision || key.binding_digest !== await workflowActionDigest(this.#descriptor)) deny('scope_mismatch');
    // The shared client validates the digest/schema; the service requires exact
    // owner approval, genuine binding and (for windows) the real occurrence.
    return this.#client.call('workflow.action.send', { request_id, key, occurrence_id });
  }
  ingestReply(raw, headers) {
    if (!this.#replies) deny('reply_unavailable');
    return this.#replies.ingest(raw, headers);
  }
  async routeReply(input) {
    if (!closed(input, ['event_id', 'request_id'])) deny('invalid_request');
    const { event_id, request_id } = input;
    if (!this.#enabled) deny('disabled');
    if (!this.#replies || !uuid(event_id) || !uuid(request_id)) deny('reply_unavailable');
    // Existing signed receiver/current-source checks and durable event action
    // reservation decide disposition. Text/verified booleans are never input.
    return this.#replies.runAction({ consumerId: this.#consumer, eventId: event_id, actionId: request_id },
      async reservation => {
        if (reservation.disposition !== 'reply_notice') return;
        await this.#client.call('workflow.action.propose', { request_id, descriptor: this.#descriptor });
      });
  }
}

export { WorkflowToolError };

/** Unstarted local automation bridge. The installation owner configures both
 * credentials; exported workflows hold only credential-store references.
 * Browser origins are refused. Bind to loopback or provide customer TLS/network
 * controls. This interface cannot activate a recipe or issue a hub grant. */
export function createWorkflowRecipeServer(recipe, localCredential) {
  if (!(recipe instanceof WorkflowRecipe) || !(localCredential instanceof Uint8Array) || localCredential.length !== 32) deny('invalid_configuration');
  const bearer = Buffer.from(Buffer.from(localCredential).toString('base64url'));
  let inFlight = 0;
  const server = createServer({ maxHeaderSize: 8192 }, async (request, response) => {
    response.setHeader('cache-control', 'no-store');
    response.setHeader('content-type', 'application/json');
    const authorization = request.headers.authorization ?? '';
    const provided = Buffer.from(authorization.startsWith('Bearer ') ? authorization.slice(7) : '');
    const authorizationCount = request.rawHeaders.filter((value, index) => index % 2 === 0 && value.toLowerCase() === 'authorization').length;
    if (Object.hasOwn(request.headers, 'origin') || request.headers.cookie || authorizationCount !== 1 || provided.length !== bearer.length || !timingSafeEqual(provided, bearer)) {
      response.statusCode = 401; response.end(JSON.stringify({ code: 'unauthorized' })); return;
    }
    if (inFlight >= 4) { response.statusCode = 429; response.end(JSON.stringify({ code: 'rate_limited' })); return; }
    inFlight++;
    try {
      if (request.url !== '/recipe') deny('invalid_request');
      if (request.method === 'GET') { response.end(JSON.stringify(await recipe.setup())); return; }
      if (request.method !== 'POST' || !/^application\/json(?:;\s*charset=utf-8)?$/i.test(request.headers['content-type'] ?? '')) deny('invalid_request');
      const parts = []; let length = 0;
      for await (const bytes of request) { length += bytes.length; if (length > 8192) deny('invalid_request'); parts.push(bytes); }
      let input;
      try { input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(parts))); }
      catch { deny('invalid_request'); }
      if (!closed(input, ['operation', 'params'])) deny('invalid_request');
      let output;
      if (input.operation === 'preview' && closed(input.params, ['request_id'])) output = await recipe.preview(input.params.request_id);
      else if (input.operation === 'prepare') output = await recipe.prepare(input.params);
      else if (input.operation === 'verified_reply') output = await recipe.routeReply(input.params);
      else if (closed(input.params, ['request_id'])) output = await recipe.call({ operation: input.operation, request_id: input.params.request_id });
      else deny('invalid_request');
      response.end(JSON.stringify(output));
    } catch (error) {
      const code = error instanceof WorkflowToolError || error instanceof WorkflowRecipeError ? error.code : 'unavailable';
      const state = error instanceof WorkflowToolError ? error.state : 'refused';
      response.statusCode = code === 'invalid_request' ? 400 : 503;
      response.end(JSON.stringify({ code, state }));
    } finally { inFlight--; }
  });
  server.requestTimeout = 5000; server.headersTimeout = 5000;
  server.on('close', () => bearer.fill(0));
  return server;
}
