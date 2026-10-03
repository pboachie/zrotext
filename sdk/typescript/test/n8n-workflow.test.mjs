// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { createWorkflowRecipeServer } from '../../recipes/workflow-runtime.mjs';
import { fixture, id } from '../../recipes/test-support/runtime-fixture.mjs';

const execute = promisify(execFile);
const exported = JSON.parse(await readFile(new URL('../../recipes/n8n-workflow-runtime.json', import.meta.url)));
const operationNode = workflow => workflow.nodes.find(node => node.id === 'runtime_operation');
const httpNode = workflow => workflow.nodes.find(node => node.id === 'runtime_preview');

test('disabled n8n export forwards a closed manual operation through the separate local credential', () => {
  assert.equal(exported.active, false);
  assert.deepEqual(JSON.parse(operationNode(exported).parameters.jsonOutput), {
    operation: 'preview', params: { request_id: id(1) },
  });
  assert.equal(httpNode(exported).parameters.body, '={{ JSON.stringify($json) }}');
  assert.deepEqual(exported.connections['Manual controlled test'].main[0], [
    { node: operationNode(exported).name, type: 'main', index: 0 },
  ]);
  assert.deepEqual(exported.connections[operationNode(exported).name].main[0], [
    { node: httpNode(exported).name, type: 'main', index: 0 },
  ]);
  assert.equal(exported.settings.saveDataErrorExecution, 'none');
  assert.equal(exported.settings.saveDataSuccessExecution, 'none');
  assert.equal(exported.settings.saveManualExecutions, false);
  assert.equal(exported.nodes.some(node => /webhook|schedule|agent|model/i.test(node.type)), false);
});

// Optional installed-tool compatibility check; ordinary CI always checks the
// exported shape above and discovers this test without installing n8n.
test('n8n imports and executes proposals and durable reply safety through the actual local bridge', {
  skip: process.env.ZT_N8N_CLI ? false : 'requires a disposable n8n 2.41.4 installation and Node 24',
  timeout: 1_200_000,
}, () => fixture(async f => {
  const directory = await mkdtemp(join(tmpdir(), 'zrotext-n8n-compatibility-'));
  const local = randomBytes(32);
  let bridge;
  const responses = [];
  const env = { ...process.env, N8N_USER_FOLDER: join(directory, 'instance'),
    N8N_DIAGNOSTICS_ENABLED: 'false', N8N_VERSION_NOTIFICATIONS_ENABLED: 'false',
    N8N_TEMPLATES_ENABLED: 'false', N8N_LICENSE_AUTO_RENEW_ENABLED: 'false',
    N8N_RUNNERS_ENABLED: 'false', DB_TYPE: 'sqlite', DB_SQLITE_POOL_SIZE: '3',
  };
  const cli = async (...args) => {
    try {
      return await execute(process.env.ZT_N8N_NODE ?? process.execPath,
        [process.env.ZT_N8N_CLI, ...args], { env, cwd: directory, timeout: 300_000, maxBuffer: 8 * 1024 * 1024 });
    } catch (error) {
      // Synthetic execution output stays in the disposable private test folder.
      await writeFile(join(directory, 'last-cli-error.txt'), `${error.stdout ?? ''}\n${error.stderr ?? ''}`);
      throw Object.assign(new Error(`n8n ${args[0]} failed (${error.code ?? 'timeout'})`), {
        exitCode: error.code, signal: error.signal, killed: error.killed,
      });
    }
  };
  const listen = async recipe => {
    bridge = createWorkflowRecipeServer(recipe, local);
    bridge.on('request', (_request, response) => response.on('finish', () => responses.push(response.statusCode)));
    await new Promise(done => bridge.listen(0, 'localhost', done));
    return `http://localhost:${bridge.address().port}/recipe`;
  };
  const closeBridge = async () => {
    if (!bridge) return;
    bridge.closeAllConnections();
    await new Promise(done => bridge.close(done));
    bridge = undefined;
  };
  try {
    assert.equal((await cli('--version')).stdout.trim(), '2.41.4');
    let url = await listen(f.recipe);
    const credentialFile = join(directory, 'credentials.json');
    await writeFile(credentialFile, JSON.stringify([{ id: 'zrotextLocalRecipe',
      name: 'ZROtext local recipe authority', type: 'httpHeaderAuth',
      data: { name: 'Authorization', value: `Bearer ${local.toString('base64url')}` },
    }]));
    await cli('import:credentials', `--input=${credentialFile}`);
    const run = async (operation, params, { refused = false } = {}) => {
      const workflow = structuredClone(exported);
      httpNode(workflow).parameters.url = url;
      operationNode(workflow).parameters.jsonOutput = JSON.stringify({ operation, params });
      const input = join(directory, 'workflow.json'), output = join(directory, 'export.json');
      await writeFile(input, JSON.stringify(workflow));
      await cli('import:workflow', `--input=${input}`);
      await cli('export:workflow', `--id=${workflow.id}`, `--output=${output}`);
      const [roundTrip] = JSON.parse(await readFile(output));
      assert.equal(roundTrip.active, false);
      assert.deepEqual(JSON.parse(operationNode(roundTrip).parameters.jsonOutput), { operation, params });
      assert.equal(httpNode(roundTrip).parameters.body, httpNode(workflow).parameters.body);
      // --raw still adds a CLI prefix. Parse only the execution JSON document.
      let result;
      const prior = responses.length;
      try { result = await cli('execute', `--id=${workflow.id}`, '--raw'); }
      catch (error) {
        if (!refused) throw error;
        assert.equal(error.exitCode, 1); // The expected normal n8n execution refusal.
        assert.equal(error.signal, null);
        assert.equal(error.killed, false); // A timeout or interrupted CLI is never success.
        assert.deepEqual(responses.slice(prior), [503]);
        return;
      }
      assert.deepEqual(responses.slice(prior), [refused ? 503 : 200]);
      const start = result.stdout.indexOf('{');
      assert.notEqual(start, -1);
      const data = JSON.parse(result.stdout.slice(start));
      if (refused) { assert.ok(data.data.resultData.error); return; }
      assert.equal(data.data.resultData.error, undefined);
      console.info(`n8n imported/exported/executed ${operation}`);
      return data.data.resultData.runData[httpNode(workflow).name][0].data.main[0][0].json;
    };
    assert.equal((await run('preview', { request_id: id(101) })).approval, false);
    assert.deepEqual(f.calls.map(call => call.method), ['workflow.context.metadata']);
    await run('owner_proposal', { request_id: id(102) }, { refused: true });
    assert.equal(f.calls.length, 1); // Imported workflow cannot activate its adapter.
    await f.recipe.enable();
    assert.equal((await run('task_completion', { request_id: id(103) })).result.phase, 'proposed');
    assert.equal((await run('owner_proposal', { request_id: id(104) })).result.phase, 'proposed');
    assert.equal((await run('status', { request_id: id(105) })).result.phase, 'proposed');
    assert.equal((await run('prepare', { request_id: id(106), key: f.key })).result.state, 'waiting_owner_binding');
    f.recipe.ingestReply(...f.signed());
    const reply = { event_id: id(14), request_id: id(107) };
    assert.equal((await run('verified_reply', reply)).disposition, 'reply_notice');
    const count = f.calls.length;
    await closeBridge();
    const restarted = f.restartReplies();
    await restarted.enable(); url = await listen(restarted);
    assert.equal((await run('verified_reply', reply)).execute, false);
    assert.equal(f.calls.length, count);
    restarted.ingestReply(...f.signed(id(17))); f.advance(31_000);
    assert.equal((await run('verified_reply', { event_id: id(17), request_id: id(109) })).disposition, 'owner_review');
    assert.equal(f.calls.length, count);
    restarted.ingestReply(...f.signed(id(16), 'opt_out'));
    assert.equal((await run('verified_reply', { event_id: id(16), request_id: id(108) })).disposition, 'stop');
    assert.equal(f.calls.length, count);
    f.deny();
    await assert.rejects(() => restarted.enable(), error => error.code === 'missing_grant');
    await run('owner_proposal', { request_id: id(110) }, { refused: true });
    assert.equal(f.calls.length, count);
    await closeBridge();
    await assert.rejects(() => fetch(url));
  } finally {
    await closeBridge(); local.fill(0);
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    await rm(directory, { recursive: true, force: true });
  }
}));
