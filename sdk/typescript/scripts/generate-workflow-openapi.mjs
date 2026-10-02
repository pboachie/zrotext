// SPDX-License-Identifier: AGPL-3.0-only
import { writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { workflowTools, workflowReadinessSchema } from '../dist/workflow-tool-client.js';

export function workflowOpenApi() {
  const error = { type: 'object', additionalProperties: false, required: ['error'], properties: {
    error: { type: 'object', additionalProperties: false, required: ['code'], properties: { code: {
      enum: ['invalid_request', 'unauthorized', 'forbidden', 'not_found', 'conflict', 'rate_limited', 'unavailable'],
    } } },
  } };
  const responses = { '200': { description: 'Checked service metadata; Prepared never proves carrier submission.',
    content: { 'application/json': { schema: { $ref: '#/components/schemas/WorkflowResponse' } } } } };
  for (const status of [400, 401, 403, 404, 409, 429, 503]) responses[status] = {
    description: 'Redacted failure. Unavailable can be ambiguous; do not resend automatically.',
    content: { 'application/json': { schema: { $ref: '#/components/schemas/WorkflowError' } } },
  };
  return { openapi: '3.1.0', info: { title: 'ZROtext authorized workflow tools', version: '0.0.0-draft',
    description: 'Requires the separately enabled WORKFLOW_TOOLS_ENABLED transport and a current workflow grant. Default off. Schemas and method hints confer no authority.' },
  paths: { '/v1/workflow/tools': {
    get: { operationId: 'workflowReadiness', security: [{ workflowCredential: [] }], responses: {
      ...responses, '200': { description: 'Current scope and method hints, not a reusable permission.',
        content: { 'application/json': { schema: { $ref: '#/components/schemas/WorkflowReadiness' } } } },
    } },
    post: { operationId: 'callWorkflowTool', security: [{ workflowCredential: [] }], requestBody: { required: true,
      content: { 'application/json': { schema: { $ref: '#/components/schemas/WorkflowRequest' } } } }, responses },
  } }, components: { securitySchemes: { workflowCredential: { type: 'http', scheme: 'bearer', bearerFormat: 'ztw_',
    description: 'Dedicated bounded workflow credential, never owner cookies, ordinary API keys or agent keys.' } }, schemas: {
    WorkflowReadiness: workflowReadinessSchema, WorkflowError: error,
    WorkflowRequest: { oneOf: workflowTools.map(tool => ({ type: 'object', additionalProperties: false,
      required: ['method', 'params'], properties: { method: { const: tool.name }, params: tool.inputSchema } })) },
    WorkflowResponse: { oneOf: workflowTools.map(tool => tool.outputSchema).filter((value, index, all) =>
      all.findIndex(other => JSON.stringify(other) === JSON.stringify(value)) === index) },
  } } };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await writeFile(new URL('../../../protocol/v1/openapi/workflow-tools-v1.json', import.meta.url), JSON.stringify(workflowOpenApi(), null, 2) + '\n');
}
