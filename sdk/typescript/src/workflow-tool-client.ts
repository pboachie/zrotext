// SPDX-License-Identifier: AGPL-3.0-only
import { validateWorkflowReadiness, validateWorkflowRequest, validateWorkflowResponse,
  type WorkflowMethod, type WorkflowReadiness, type WorkflowResponse } from './workflow-tools.js';
import { workflowActionDigest } from './workflow-decisions.js';
export { workflowTools, workflowFunctions, workflowReadinessSchema } from './workflow-tools.js';

const PATH = '/v1/workflow/tools';
const MAX_REQUEST = 65536, MAX_RESPONSE = 131072;
const statuses: Readonly<Record<string, number>> = { invalid_request: 400, unauthorized: 401, forbidden: 403,
  not_found: 404, conflict: 409, rate_limited: 429, unavailable: 503 };
export class WorkflowToolError extends Error {
  constructor(readonly code: string, readonly state: 'refused' | 'unknown', readonly attempts: number) {
    super(`Workflow tool ${code}`);
    this.name = 'WorkflowToolError';
  }
}
export interface WorkflowToolOptions {
  origin: string;
  credential: string;
  timeoutMs?: number;
  /** Trusted transport seam. It receives the credential; never expose it as a model tool. */
  fetchImpl?: typeof fetch;
}
async function json(response: Response): Promise<unknown> {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(response.headers.get('content-type') ?? '')) {
    await response.body?.cancel().catch(() => {});
    throw new Error();
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error();
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      size += next.value.byteLength;
      if (size > MAX_RESPONSE) throw new Error();
      chunks.push(next.value);
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}
/** Actual HTTPS transport into the shared runtime. It never creates owner approval or radio work. */
export class WorkflowToolClient {
  #url: string;
  #credential: string;
  #fetch: typeof fetch;
  #timeout: number;
  constructor(options: WorkflowToolOptions) {
    try {
      const origin = new URL(options.origin);
      const encoded = options.credential.slice(4);
      if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash ||
        !/^ztw_[A-Za-z0-9_-]{43}$/u.test(options.credential) ||
        btoa(atob(encoded.replaceAll('-', '+').replaceAll('_', '/') + '=')).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '') !== encoded) throw new Error();
      const timeout = options.timeoutMs ?? 10000;
      if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 10000) throw new Error();
      this.#url = new URL(PATH, origin).href;
      this.#credential = options.credential;
      this.#fetch = options.fetchImpl ?? globalThis.fetch;
      this.#timeout = timeout;
    } catch { throw new WorkflowToolError('invalid_configuration', 'refused', 0); }
  }
  async #request(body: string | undefined, maxAttempts: number): Promise<{ value: unknown; attempts: number }> {
    if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 3) throw new WorkflowToolError('invalid_request', 'refused', 0);
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      const deadline = new Promise<never>((_, reject) => {
        timer = setTimeout(() => { controller.abort(); reject(new Error()); }, this.#timeout);
      });
      try {
        const value = await Promise.race([deadline, (async () => {
          const response = await this.#fetch(this.#url, { method: body === undefined ? 'GET' : 'POST',
            headers: { Authorization: `Bearer ${this.#credential}`, Accept: 'application/json',
              ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
            body, signal: controller.signal, redirect: 'error', credentials: 'omit', cache: 'no-store' });
          if (response.redirected || (response.url && response.url !== this.#url)) {
            await response.body?.cancel().catch(() => {});
            throw new Error();
          }
          const parsed = await json(response);
          if (response.status === 200) return parsed;
          const record = parsed as { error?: { code?: string } };
          if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || Object.keys(parsed).join(',') !== 'error' ||
            !record.error || typeof record.error !== 'object' || Array.isArray(record.error) || Object.keys(record.error).join(',') !== 'code' ||
            typeof record.error.code !== 'string' || statuses[record.error.code] !== response.status) throw new Error();
          throw new WorkflowToolError(record.error.code, record.error.code === 'unavailable' ? 'unknown' : 'refused', attempt);
        })()]);
        return { value, attempts: attempt };
      } catch (error) {
        // Only an explicit admission rate refusal may be retried automatically.
        // Network/timeouts/malformed replies may follow a committed effect; stop.
        if (error instanceof WorkflowToolError) {
          if (error.code === 'rate_limited' && attempt < maxAttempts) continue;
          throw error;
        }
        throw new WorkflowToolError('response_unknown', 'unknown', attempt);
      } finally { if (timer !== undefined) clearTimeout(timer); }
    }
    throw new WorkflowToolError('response_unknown', 'unknown', maxAttempts);
  }
  async readiness(): Promise<WorkflowReadiness> {
    const { value } = await this.#request(undefined, 1);
    try { validateWorkflowReadiness(value); return value; }
    catch { throw new WorkflowToolError('response_unknown', 'unknown', 1); }
  }
  async cancel(requestId: string, key: unknown): Promise<WorkflowResponse> {
    return this.call('workflow.action.cancel', { request_id: requestId, key });
  }
  async call(method: WorkflowMethod, params: unknown, maxAttempts = 1): Promise<WorkflowResponse> {
    let body: string;
    let snapshot: Record<string, any>;
    let proposalDigest: string | undefined;
    try {
      snapshot = structuredClone(params) as Record<string, any>;
      validateWorkflowRequest(method, snapshot);
      body = JSON.stringify({ method, params: snapshot });
      if (new TextEncoder().encode(body).byteLength > MAX_REQUEST) throw new Error();
      if (method === 'workflow.action.propose') proposalDigest = await workflowActionDigest(snapshot.descriptor);
    } catch { throw new WorkflowToolError('invalid_request', 'refused', 0); }
    const { value, attempts } = await this.#request(body, maxAttempts);
    try {
      validateWorkflowResponse(method, value);
      const result = value.result;
      if ((method === 'workflow.context.metadata' || method === 'workflow.context.content') && result.context_id !== snapshot.context_id) throw new Error();
      if (method === 'workflow.action.status' && (result.key as Record<string, unknown>).action_id !== snapshot.action_id) throw new Error();
      if (method === 'workflow.action.propose') {
        const key = result.key as Record<string, unknown>;
        for (const field of ['account_id', 'action_id', 'revision']) if (key[field] !== snapshot.descriptor[field]) throw new Error();
        if (key.binding_digest !== proposalDigest) throw new Error();
      }
      if (method === 'workflow.action.cancel') {
        const actual = result.key as Record<string, unknown>;
        for (const field of ['account_id', 'action_id', 'revision', 'binding_digest']) if (actual[field] !== snapshot.key[field]) throw new Error();
      }
      if (method === 'workflow.action.schedule' && (result.series_id !== snapshot.series_id || result.ordinal !== snapshot.ordinal)) throw new Error();
      return value;
    }
    catch { throw new WorkflowToolError('response_unknown', 'unknown', attempts); }
  }
}
