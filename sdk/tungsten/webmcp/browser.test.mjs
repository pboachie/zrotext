// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { after, before, test } from 'node:test';

// Reuse the repository's exact Playwright development dependency.
const { chromium } = createRequire(new URL('../../../web/owner/package.json', import.meta.url))('playwright');
const root = new URL('../../../', import.meta.url);
let browser, server, origin;
before(async () => {
  const files = new Map([
    ['/sdk/tungsten/webmcp/index.mjs', new URL('sdk/tungsten/webmcp/index.mjs', root)],
    ['/sdk/typescript/dist/workflow-tools.js', new URL('sdk/typescript/dist/workflow-tools.js', root)],
    ['/sdk/typescript/dist/workflow-decisions.js', new URL('sdk/typescript/dist/workflow-decisions.js', root)],
  ]);
  server = createServer(async (request, response) => {
    if (request.url === '/') return response.end('<!doctype html><title>Synthetic WebMCP test</title>');
    const file = files.get(request.url);
    if (!file) return response.writeHead(404).end();
    try { response.setHeader('Content-Type', 'text/javascript'); response.end(await readFile(fileURLToPath(file))); }
    catch { response.writeHead(500).end(); }
  });
  await new Promise(resolve => server.listen(0, 'localhost', resolve));
  origin = `http://localhost:${server.address().port}`;
  browser = await chromium.launch({
    ...(process.env.ZT_WEBMCP_BROWSER ? { executablePath: process.env.ZT_WEBMCP_BROWSER } : {}),
    headless: true,
    args: ['--enable-features=WebMCP', '--enable-blink-features=WebMCP'],
  });
  console.log(`Native WebMCP browser: ${browser.version()}`);
});
after(async () => { await browser?.close(); if (server) await new Promise(resolve => server.close(resolve)); });

async function fixture(run) {
  const page = await browser.newPage();
  try {
    await page.goto(origin);
    await page.evaluate(async stringArguments => {
      if (!document.modelContext?.executeTool || !document.modelContext?.getTools)
        throw new Error('Native document.modelContext required; no polyfill or legacy fallback');
      const { registerWorkflowTools } = await import('/sdk/tungsten/webmcp/index.mjs');
      const id = '11111111-2222-4333-8444-555555555555';
      const name = 'workflow_tools_contact_read';
      const state = globalThis.fixture = { calls: 0, permission: true, signal: new AbortController(), name,
        args: { request_id: id, context_id: id },
        response: { kind: 'contact', result: { contact_id: id, purpose: 'transactional', peer_digest: 'ab'.repeat(32) } } };
      state.register = () => registerWorkflowTools({
        manifest: { catalogVersion: 1, api: 'zrotext', tools: [{ name, target: 'workflow.contact.read', kind: 'operation' }] },
        allowlist: [name], registry: { kind: 'document', registerTool: (...args) => document.modelContext.registerTool(...args) },
        signal: state.signal.signal,
        transport: { isAuthorized: () => state.permission, call: async (_method, _args, { signal }) => {
          state.calls++; state.callSignal = signal;
          if (state.delay) await new Promise(resolve => { state.release = resolve; });
          return state.response;
        } },
      });
      state.execute = async (args = state.args, options) => {
        const tool = (await document.modelContext.getTools()).find(tool => tool.name === name);
        return JSON.parse(await document.modelContext.executeTool(tool, stringArguments ? JSON.stringify(args) : args, options));
      };
    }, Number(browser.version().split('.')[0]) < 155);
    return await run(page);
  } finally { await page.close(); }
}

test('native registration requires opt in and returns structured synthetic data', () => fixture(async page => {
  const value = await page.evaluate(async () => {
    const f = fixture;
    const before = (await document.modelContext.getTools()).length;
    const scope = await f.register();
    const result = await f.execute();
    scope.close();
    return { before, result, expected: f.response, calls: f.calls, after: (await document.modelContext.getTools()).length };
  });
  assert.equal(value.before, 0); assert.equal(value.calls, 1); assert.equal(value.after, 0);
  assert.deepEqual(value.result.structuredContent, value.expected); assert.equal(value.result.isError, false);
}));

test('native registry receives no unauthorized tools and revoked execution never dispatches', () => fixture(async page => {
  const value = await page.evaluate(async () => {
    const f = fixture; f.permission = false;
    let code; try { await f.register(); } catch (error) { code = error.code; }
    const deniedCount = (await document.modelContext.getTools()).length;
    f.permission = true; await f.register(); f.permission = false;
    const result = await f.execute();
    return { code, deniedCount, result, calls: f.calls, after: (await document.modelContext.getTools()).length };
  });
  assert.equal(value.code, 'unauthorized'); assert.equal(value.deniedCount, 0); assert.equal(value.calls, 0);
  assert.equal(value.result.structuredContent.code, 'unauthorized'); assert.equal(value.after, 0);
}));

test('native invalid arguments never reach the authenticated transport', () => fixture(async page => {
  const value = await page.evaluate(async () => {
    const f = fixture; await f.register();
    let result, rejected = false;
    try { result = await f.execute({ unexpected: true }); } catch { rejected = true; }
    return { result, rejected, calls: f.calls };
  });
  assert.equal(value.calls, 0);
  assert.ok(value.rejected || value.result?.structuredContent.code === 'invalid_request');
}));

test('native revocation aborts transport and suppresses a late result', () => fixture(async page => {
  await page.evaluate(async () => {
    fixture.delay = true; await fixture.register();
    fixture.pending = fixture.execute().then(result => ({ result }), error => ({ error: error.name }));
  });
  await page.waitForFunction(() => fixture.calls === 1);
  const value = await page.evaluate(async () => {
    const f = fixture; f.permission = false; f.signal.abort();
    const outcome = await f.pending; f.release();
    return { outcome, aborted: f.callSignal.aborted, calls: f.calls, tools: (await document.modelContext.getTools()).length };
  });
  assert.equal(value.aborted, true); assert.equal(value.calls, 1); assert.equal(value.tools, 0);
  if (value.outcome.result) {
    assert.equal(value.outcome.result.structuredContent.state, 'unknown');
    assert.equal(value.outcome.result.structuredContent.attempts, 1);
    assert.equal(value.outcome.result.structuredContent.result, undefined);
  } else assert.equal(value.outcome.error, 'AbortError');
}));

test('native execution cancellation hides results and application revocation aborts transport', () => fixture(async page => {
  await page.evaluate(async () => {
    const f = fixture; f.delay = true; await f.register(); f.execution = new AbortController();
    f.pending = f.execute(f.args, { signal: f.execution.signal })
      .then(result => ({ result }), error => ({ error: error.name }));
  });
  await page.waitForFunction(() => fixture.calls === 1);
  const value = await page.evaluate(async () => {
    const f = fixture; f.execution.abort();
    const outcome = await f.pending;
    // Allow native cancellation propagation before the deliberately late response.
    await new Promise(resolve => {
      if (f.callSignal.aborted) return resolve();
      const timer = setTimeout(resolve, 2000);
      f.callSignal.addEventListener('abort', () => { clearTimeout(timer); resolve(); }, { once: true });
    });
    const nativeAborted = f.callSignal.aborted;
    // Exercise application teardown too, independently of execution cancellation.
    f.signal.abort();
    const aborted = f.callSignal.aborted;
    f.release();
    return { outcome, nativeAborted, aborted, calls: f.calls };
  });
  assert.equal(value.calls, 1); assert.equal(value.aborted, true);
  assert.equal(value.nativeAborted, true);
  if (value.outcome.result) {
    assert.equal(value.outcome.result.structuredContent.state, 'unknown');
    assert.equal(value.outcome.result.structuredContent.result, undefined);
  } else assert.equal(value.outcome.error, 'AbortError');
}));
