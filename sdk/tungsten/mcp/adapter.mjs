// SPDX-License-Identifier: AGPL-3.0-only
import { createSession as guardedSession, tools as guardedTools } from '../../mcp/server.mjs';

// Deliberately closed mapping. Adding a generated operation cannot expand authority.
const targets = new Map([
  ['workflow.workflowReadiness', ['workflow_tools_readiness', 'zrotext_readiness']],
  ...['contact.read', 'context.metadata', 'context.content', 'action.propose',
    'action.status', 'action.schedule', 'action.send', 'action.cancel'].map(method =>
    [`workflow.${method}`, [`workflow_tools_${method.replaceAll('.', '_')}`, `workflow.${method}`]]),
]);

/** Trusted startup catalog only. Generated descriptions and schemas never
 * replace the guarded tool contract. Owner, sealed and macro tools are omitted. */
export function workflowCatalog(manifest) {
  if (manifest?.manifestVersion !== 1 || manifest.api !== 'zrotext' || !Array.isArray(manifest.tools)) {
    throw new Error('Invalid generated workflow catalog');
  }
  const seen = new Set();
  const catalog = [];
  for (const item of manifest.tools) {
    if (!item || typeof item !== 'object') throw new Error('Invalid generated workflow catalog');
    const mapping = targets.get(item.target);
    if (!mapping) continue;
    if (item.kind !== 'operation' || item.name !== mapping[0] || seen.has(item.target)) {
      throw new Error('Invalid generated workflow catalog');
    }
    seen.add(item.target);
    const guarded = guardedTools.find(tool => tool.name === mapping[1]);
    if (!guarded) throw new Error('Guarded workflow contract unavailable');
    catalog.push({ alias: mapping[0], target: mapping[1], definition: { ...structuredClone(guarded), name: mapping[0] } });
  }
  if (!catalog.length) throw new Error('Generated workflow catalog is empty');
  return catalog;
}

/** Client is a trusted operator/test seam, never accepted from MCP arguments.
 * Use configuredClient from the guarded server for production startup. */
export function createSession(manifest, { client } = {}) {
  const catalog = workflowCatalog(manifest);
  const mapping = new Map(catalog.map(tool => [tool.alias, tool.target]));
  const guarded = guardedSession({ client });
  return async request => {
    let forwarded = request;
    if (request?.method === 'tools/call') {
      const target = mapping.get(request.params?.name);
      // Unknown aliases remain unknown even if their raw name is a legacy tool.
      forwarded = { ...request, params: { ...request.params, name: target ?? '__denied_generated_tool__' } };
    }
    const response = await guarded(forwarded);
    if (request?.method === 'tools/list' && response?.result?.tools) {
      return { ...response, result: { tools: catalog.map(tool => structuredClone(tool.definition)) } };
    }
    return response;
  };
}
