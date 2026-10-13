// SPDX-License-Identifier: AGPL-3.0-only
import { workflowTools, validateWorkflowRequest, validateWorkflowResponse } from '../../typescript/dist/workflow-tools.js';

const definitions = new Map(workflowTools.map(tool =>
  [`workflow_tools_${tool.name.slice('workflow.'.length).replaceAll('.', '_')}`, tool]));
const codes = new Set(['invalid_request', 'unauthorized', 'forbidden', 'not_found', 'conflict', 'rate_limited', 'unavailable', 'response_unknown']);
const result = (value, isError = false) => ({ content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value, isError });
const refuse = (code, dispatched = false) => result({ available: false, code,
  state: dispatched ? 'unknown' : 'refused', attempts: dispatched ? 1 : 0 }, true);

export class WebMcpRegistrationError extends Error {
  constructor(code) { super(`Scoped WebMCP registration: ${code}`); this.code = code; }
}

function catalog(manifest, allowlist) {
  if (manifest?.catalogVersion !== 1 || manifest.api !== 'zrotext' || !Array.isArray(manifest.tools) ||
      !Array.isArray(allowlist) || !allowlist.length || new Set(allowlist).size !== allowlist.length)
    throw new WebMcpRegistrationError('invalid_catalog');
  return allowlist.map(name => {
    const guarded = definitions.get(name);
    const matches = manifest.tools.filter(item => item?.name === name);
    if (!guarded || matches.length !== 1 || matches[0].kind !== 'operation' || matches[0].target !== guarded.name)
      throw new WebMcpRegistrationError('invalid_catalog');
    return { name, guarded };
  });
}

function raceAbort(action, signal) {
  return new Promise((resolve, reject) => {
    const stop = () => reject(new WebMcpRegistrationError('closed'));
    if (signal.aborted) return stop();
    signal.addEventListener('abort', stop, { once: true });
    Promise.resolve().then(() => {
      if (signal.aborted) throw new WebMcpRegistrationError('closed');
      return action();
    }).then(resolve, reject).finally(() => signal.removeEventListener('abort', stop));
  });
}

/** Explicit opt-in only. No globals are inspected and no registration occurs on import.
 * registry must implement the current document-style registerTool(tool,{signal})
 * contract, including removal when that signal aborts. All inputs are application-owned.
 * transport must enforce the existing workflow grant and response binding checks;
 * no credentials, owner session or arbitrary endpoint are accepted here. */
export async function registerWorkflowTools({ manifest, allowlist, registry, transport, signal } = {}) {
  if (registry?.kind !== 'document' || typeof registry.registerTool !== 'function')
    throw new WebMcpRegistrationError('unsupported');
  if (!signal || typeof signal.aborted !== 'boolean' || typeof signal.addEventListener !== 'function' ||
      typeof signal.removeEventListener !== 'function' || typeof transport?.isAuthorized !== 'function' ||
      typeof transport.call !== 'function') throw new WebMcpRegistrationError('invalid_configuration');
  const allowed = catalog(manifest, allowlist);
  const authorized = transport.isAuthorized.bind(transport), dispatch = transport.call.bind(transport);
  const lifetime = new AbortController();
  let closed = false;
  const close = () => { closed = true; lifetime.abort(); signal.removeEventListener('abort', close); };
  const permitted = () => {
    try { return !closed && !signal.aborted && authorized() === true; } catch { return false; }
  };
  if (!permitted()) throw new WebMcpRegistrationError('unauthorized');
  signal.addEventListener('abort', close, { once: true });
  try {
    for (const { name, guarded } of allowed) {
      if (!permitted()) throw new WebMcpRegistrationError('unauthorized');
      const tool = {
        name, description: guarded.description, inputSchema: structuredClone(guarded.inputSchema),
        annotations: { readOnlyHint: guarded.annotations.readOnlyHint, untrustedContentHint: true,
          consequentialHint: !guarded.annotations.readOnlyHint, debugging: false },
        async execute(args, options = {}) {
          if (!permitted()) { close(); return refuse('unauthorized'); }
          let snapshot;
          try {
            snapshot = structuredClone(args);
            validateWorkflowRequest(guarded.name, snapshot);
            if (new TextEncoder().encode(JSON.stringify(snapshot)).length > 65536) throw new Error();
          } catch { return refuse('invalid_request'); }
          const call = new AbortController();
          const abort = () => call.abort();
          const signals = [lifetime.signal, options.signal].filter(Boolean);
          if (signals.some(s => typeof s.addEventListener !== 'function' || typeof s.removeEventListener !== 'function'))
            return refuse('invalid_request');
          for (const s of signals) {
            if (s.aborted) abort();
            else s.addEventListener('abort', abort, { once: true });
          }
          const deadline = setTimeout(abort, 10000);
          let dispatched = false;
          try {
            const value = await raceAbort(() => {
              if (!permitted()) { close(); throw new WebMcpRegistrationError('closed'); }
              dispatched = true;
              return dispatch(guarded.name, snapshot, { signal: call.signal });
            }, call.signal);
            if (!permitted()) { close(); return refuse('response_unknown', dispatched); }
            const captured = structuredClone(value);
            validateWorkflowResponse(guarded.name, captured);
            if (new TextEncoder().encode(JSON.stringify(captured)).length > 131072) throw new Error();
            return result(captured);
          } catch (error) {
            if (!permitted()) close();
            if (dispatched && codes.has(error?.code) && ['refused', 'unknown'].includes(error.state) &&
                Number.isInteger(error.attempts) && error.attempts >= 0 && error.attempts <= 3 && !call.signal.aborted) {
              return result({ available: false, code: error.code, state: error.state, attempts: error.attempts }, true);
            }
            return refuse(dispatched ? 'response_unknown' : 'unavailable', dispatched);
          } finally {
            clearTimeout(deadline);
            for (const s of signals) s.removeEventListener('abort', abort);
          }
        },
      };
      await raceAbort(() => registry.registerTool(tool, { signal: lifetime.signal }), lifetime.signal);
    }
    if (!permitted()) throw new WebMcpRegistrationError('unauthorized');
    return Object.freeze({ registeredNames: Object.freeze(allowed.map(t => t.name)), close });
  } catch {
    close();
    throw new WebMcpRegistrationError('registration_failed');
  }
}
