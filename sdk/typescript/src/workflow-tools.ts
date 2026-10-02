// SPDX-License-Identifier: AGPL-3.0-only
/** Shared function/MCP vocabulary. Schemas describe requests, never permissions. */
import { canonicalWorkflowAction } from './workflow-decisions.js';

export type Schema = Readonly<{ type?: string; properties?: Readonly<Record<string, Schema>>;
  required?: readonly string[]; additionalProperties?: false; enum?: readonly unknown[];
  minimum?: number; maximum?: number; minLength?: number; maxLength?: number; pattern?: string;
  anyOf?: readonly Schema[] }>;
const object = (properties: Record<string, Schema>, required = Object.keys(properties)): Schema =>
  ({ type: 'object', properties, required, additionalProperties: false });
const integer = (minimum = 0, maximum = Number.MAX_SAFE_INTEGER): Schema => ({ type: 'integer', minimum, maximum });
const text = (minLength = 1, maxLength = 128): Schema => ({ type: 'string', minLength, maxLength });
const uuid: Schema = { ...text(36, 36), pattern: '^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' };
const digest: Schema = { ...text(64, 64), pattern: '^[0-9a-f]{64}$' };
const nullable = (schema: Schema): Schema => ({ anyOf: [schema, { type: 'null' }] });
const key = object({ account_id: uuid, action_id: uuid, revision: integer(1, 128), binding_digest: digest });
const descriptor = object({ account_id: uuid, action_id: uuid, revision: integer(1, 128), line_id: uuid,
  recipient_id: uuid, purpose_id: uuid, content_ref: uuid, content_digest: digest, content_version: integer(1),
  not_before: integer(), expires_at: integer(1), timezone: text(), window_id: text(), routine_id: uuid,
  authority_generation: integer(1), commitment: { enum: ['informational', 'sensitive'] } });
const policy = object({ timezone: nullable({ ...text(), pattern: '^[!-~]+$' }),
  first_local_date: { ...text(10, 10), pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' }, opens_minute: integer(0, 1439),
  closes_minute: integer(0, 1439), repeat_every_days: nullable(integer(1, 365)), max_occurrences: integer(1, 100),
  pacing_seconds: integer(60, 86400) });
const context = object({ request_id: uuid, context_id: uuid });
const definitions = [
  ['workflow.contact.read', 'Read the current permitted contact purpose and opaque peer binding.', context, true],
  ['workflow.context.metadata', 'Read scoped metadata and the encrypted source digest, not plaintext.', context, true],
  ['workflow.context.content', 'Read the independent selected-reader encrypted projection.', context, true],
  ['workflow.action.propose', 'Persist an exact proposal; this does not approve or dispatch it.', object({ request_id: uuid, descriptor }), false],
  ['workflow.action.status', 'Read current durable action metadata; historical state is not a send permit.', object({ request_id: uuid, context_id: uuid, action_id: uuid }), true],
  ['workflow.action.schedule', 'Record an approved bounded occurrence through the shared service.', object({ request_id: uuid, key, policy, series_id: uuid, ordinal: integer(0, 99) }), false],
  ['workflow.action.send', 'Prepare an independently owner-bound action; never claim carrier submission.', object({ request_id: uuid, key, occurrence_id: nullable(uuid) }, ['request_id', 'key']), false],
] as const;
export type WorkflowMethod = typeof definitions[number][0];

export function matchesSchema(schema: Schema, value: unknown): boolean {
  if (schema.anyOf) return schema.anyOf.some(item => matchesSchema(item, value));
  if (schema.enum) return schema.enum.includes(value);
  switch (schema.type) {
    case 'null': return value === null;
    case 'boolean': return typeof value === 'boolean';
    case 'integer': return typeof value === 'number' && Number.isSafeInteger(value) &&
      value >= (schema.minimum ?? Number.MIN_SAFE_INTEGER) && value <= (schema.maximum ?? Number.MAX_SAFE_INTEGER);
    case 'string': return typeof value === 'string' && value.length >= (schema.minLength ?? 0) &&
      value.length <= (schema.maxLength ?? Number.MAX_SAFE_INTEGER) && (!schema.pattern || new RegExp(schema.pattern, 'u').test(value));
    case 'object': {
      if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
      const record = value as Record<string, unknown>, fields = schema.properties ?? {};
      return (schema.required ?? []).every(name => Object.hasOwn(record, name)) && Object.keys(record).every(name =>
        Object.hasOwn(fields, name) && matchesSchema(fields[name], record[name]));
    }
    default: return false;
  }
}
export function validateWorkflowRequest(method: string, params: unknown): asserts method is WorkflowMethod {
  const tool = workflowTools.find(item => item.name === method);
  if (!tool || !matchesSchema(tool.inputSchema, params)) throw new Error('invalid_request');
  const record = params as Record<string, any>;
  if (method === 'workflow.action.propose') canonicalWorkflowAction(record.descriptor);
  if (method === 'workflow.action.schedule' && (record.ordinal >= record.policy.max_occurrences ||
    record.policy.opens_minute === record.policy.closes_minute ||
    (record.policy.repeat_every_days === null && record.policy.max_occurrences !== 1))) throw new Error('invalid_request');
}

const action = object({ key, record_version: integer(1), phase: { enum: ['proposed', 'approved', 'invalidated',
  'cancelled', 'expired', 'dispatching', 'unknown', 'succeeded', 'failed'] } });
const responses: Record<string, Schema> = {
  contact: object({ contact_id: uuid, purpose: { enum: ['transactional', 'operational', 'marketing'] }, peer_digest: digest }),
  context_metadata: object({ context_id: uuid, source_content_digest: digest, revision: integer(1), kind: integer(0, 255),
    expires_at_ms: integer(1), binding_generation: integer(1), trust_generation: integer(1), manifest_version: integer(1) }),
  context_content: object({ context_id: uuid, revision: integer(1), envelope_base64url: {
    ...text(1, 131072), pattern: '^[A-Za-z0-9_-]+$' } }),
  action,
  occurrence: object({ occurrence_id: uuid, series_id: uuid, ordinal: integer(0, 99), phase: text(),
    opens_at_ms: nullable(integer()), closes_at_ms: nullable(integer()), expires_at_ms: integer(1) }),
  send: { anyOf: [object({ state: { enum: ['waiting_owner_binding', 'waiting_window'] } }),
    object({ state: { enum: ['prepared'] }, message_id: uuid, dispatch_id: uuid })] },
};
const responseKinds = ['contact', 'context_metadata', 'context_content', 'action', 'action', 'occurrence', 'send'];
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
export const workflowTools = freeze(definitions.map(([name, description, inputSchema, readOnlyHint], index) => ({
  name, description, inputSchema,
  outputSchema: object({ kind: { enum: [responseKinds[index]] }, result: responses[responseKinds[index]] }),
  annotations: { readOnlyHint, destructiveHint: name === 'workflow.action.send', idempotentHint: true, openWorldHint: false },
})));
/** Provider-neutral functions and MCP use exactly the same parameter schemas. */
export const workflowFunctions = freeze(workflowTools.map(tool => ({ name: tool.name, description: tool.description, parameters: tool.inputSchema })));
export type WorkflowResponse = Readonly<{ kind: string; result: Readonly<Record<string, unknown>> }>;
export function validateWorkflowResponse(method: WorkflowMethod, value: unknown): asserts value is WorkflowResponse {
  const kind = responseKinds[workflowTools.findIndex(tool => tool.name === method)];
  if (!matchesSchema(object({ kind: { enum: [kind] }, result: responses[kind] }), value)) throw new Error('unexpected_response');
  if (kind === 'context_content') {
    const encoded = (value as WorkflowResponse).result.envelope_base64url as string;
    if (encoded.length % 4 === 1 || btoa(atob(encoded.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - encoded.length % 4) % 4)))
      .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '') !== encoded) throw new Error('unexpected_response');
  }
}
export interface WorkflowReadiness {
  available: true;
  methods: readonly Readonly<{ method: WorkflowMethod; operation: string; read_only_hint: boolean;
    destructive_hint: boolean; idempotent_hint: true; implementation: 'library_candidate';
    transport_mounted: true; permission_granted: boolean }>[];
  scope: Readonly<{ context_id: string; device_id: string; line_id: string }>;
  send_semantics: 'owner_bound_prepared_only';
}
// Array element identity and exact seven-method inventory are checked below.
export const workflowReadinessSchema = freeze({ type: 'object', additionalProperties: false,
  required: ['available', 'methods', 'scope', 'send_semantics'], properties: {
    available: { const: true }, methods: { type: 'array', minItems: 7, maxItems: 7, items: { type: 'object',
      additionalProperties: false, required: ['method', 'operation', 'read_only_hint', 'destructive_hint', 'idempotent_hint',
        'implementation', 'transport_mounted', 'permission_granted'], properties: {
        method: { enum: workflowTools.map(tool => tool.name) }, operation: { enum: ['contact_read', 'context_metadata', 'context_content', 'propose', 'status', 'schedule', 'send'] },
        read_only_hint: { type: 'boolean' }, destructive_hint: { type: 'boolean' }, idempotent_hint: { const: true },
        implementation: { const: 'library_candidate' }, transport_mounted: { const: true }, permission_granted: { type: 'boolean' },
      } } }, scope: object({ context_id: uuid, device_id: uuid, line_id: uuid }), send_semantics: { const: 'owner_bound_prepared_only' },
  } });
export function validateWorkflowReadiness(value: unknown): asserts value is WorkflowReadiness {
  const outer = object({ available: { enum: [true] }, methods: { type: 'null' }, scope: object({ context_id: uuid, device_id: uuid, line_id: uuid }),
    send_semantics: { enum: ['owner_bound_prepared_only'] } });
  // Validate array elements against their exact operation; no permission bit is a reusable permit.
  const record = value as WorkflowReadiness;
  if (!value || typeof value !== 'object' || Array.isArray(value) || !Array.isArray(record.methods) || record.methods.length !== 7) throw new Error('unexpected_response');
  const withoutMethods = { ...record, methods: null };
  if (!matchesSchema(outer, withoutMethods)) throw new Error('unexpected_response');
  const seen = new Set<string>();
  for (const item of record.methods) {
    const tool = workflowTools.find(tool => tool.name === item.method);
    if (!tool || seen.has(item.method) || !matchesSchema(object({ method: { enum: [item.method] },
      operation: { enum: [item.method.replace('workflow.', '').replace('action.', '').replaceAll('.', '_')] },
      read_only_hint: { enum: [tool.annotations.readOnlyHint] }, destructive_hint: { enum: [tool.annotations.destructiveHint] },
      idempotent_hint: { enum: [true] }, implementation: { enum: ['library_candidate'] }, transport_mounted: { enum: [true] },
      permission_granted: { type: 'boolean' } }), item)) throw new Error('unexpected_response');
    seen.add(item.method);
  }
}
