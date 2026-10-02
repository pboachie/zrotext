// SPDX-License-Identifier: AGPL-3.0-only
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { workflowOpenApi } from '../scripts/generate-workflow-openapi.mjs';
test('HTTP documentation is generated from the same seven schemas as callable and MCP tools', async () => {
  const saved = JSON.parse(await readFile(new URL('../../../protocol/v1/openapi/workflow-tools-v1.json', import.meta.url)));
  assert.deepEqual(saved, workflowOpenApi());
  assert.deepEqual(Object.keys(saved.paths), ['/v1/workflow/tools']);
  assert.equal(saved.components.schemas.WorkflowRequest.oneOf.length, 7);
  assert.equal(saved.components.securitySchemes.workflowCredential.bearerFormat, 'ztw_');
});
