// SPDX-License-Identifier: AGPL-3.0-only
import { writeFile } from 'node:fs/promises';
import { workflowTools, workflowReadinessSchema } from '../dist/workflow-tools.js';
await writeFile(new URL('../../python/workflow_contract.json', import.meta.url),
  JSON.stringify({ tools: workflowTools, readiness: workflowReadinessSchema }, null, 2) + '\n');
