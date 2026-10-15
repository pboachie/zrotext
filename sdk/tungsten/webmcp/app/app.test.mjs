// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createServer, request } from 'node:https';
import { createServer as reserve } from 'node:net';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Readable } from 'node:stream';
import { createRequire } from 'node:module';
import { createWorkflowApplication } from './server.mjs';

const { chromium } = createRequire(new URL('../../../../web/owner/package.json', import.meta.url))('playwright');
const accessKey = randomBytes(32).toString('base64url'), credential = 'ztw_' + randomBytes(32).toString('base64url');
const id = '11111111-2222-4333-8444-555555555555';
const params = { request_id: id, context_id: id };
const contact = { kind: 'contact', result: { contact_id: id, purpose: 'transactional', peer_digest: 'ab'.repeat(32) } };
let directory, tls, browser, upstream, workflowOrigin, requests = [], hold = false, held = [], upstreamStatus = 200;
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const close = server => new Promise(resolve => { server.close(resolve); server.closeAllConnections?.(); });
const fetchTls = (url, init = {}) => new Promise((resolve, reject) => {
  const req = request(url, { ca: tls.cert, method: init.method, headers: init.headers, signal: init.signal }, res => {
    resolve(new Response(Readable.toWeb(res), { status: res.statusCode, headers: res.headers }));
  }); req.on('error', reject); req.end(init.body);
});

before(async () => {
  directory = await mkdtemp(join(tmpdir(), 'zrotext-webmcp-app-'));
  const key = join(directory, 'key.pem'), cert = join(directory, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
    '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], { stdio: 'ignore' });
  tls = { key: await readFile(key), cert: await readFile(cert) };
  upstream = createServer(tls, async (req, res) => {
    let raw = ''; for await (const chunk of req) raw += chunk;
    requests.push({ path: req.url, authorization: req.headers.authorization, value: JSON.parse(raw) });
    if (hold) { held.push(res); return; }
    res.writeHead(upstreamStatus, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(upstreamStatus === 200 ? contact : { error: { code: upstreamStatus === 401 ? 'unauthorized' : 'rate_limited' } }));
  });
  await listen(upstream); workflowOrigin = `https://127.0.0.1:${upstream.address().port}`;
  browser = await chromium.launch({ headless: true,
    ...(process.env.ZT_WEBMCP_BROWSER ? { executablePath: process.env.ZT_WEBMCP_BROWSER } : {}),
    args: ['--enable-features=WebMCP', '--enable-blink-features=WebMCP'] });
  console.log(`Authenticated application browser: ${browser.version()}`);
});
after(async () => { await browser?.close(); if (upstream) await close(upstream); if (directory) await rm(directory, { recursive: true, force: true }); });

async function fixture(run, sessionMs = 300000) {
  const reserved = reserve(); await listen(reserved); const port = reserved.address().port;
  await new Promise(resolve => reserved.close(resolve));
  const origin = `https://127.0.0.1:${port}`;
  const server = await createWorkflowApplication({ origin, accessKey, workflowOrigin, workflowCredential: credential,
    allowlist: ['workflow.contact.read'], sessionMs, tls, workflowFetch: fetchTls });
  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage(); requests = []; hold = false; held = []; upstreamStatus = 200;
  try {
    await page.goto(origin);
    await page.waitForFunction(() => !!document.modelContext?.getTools);
    const post = async (path, value, headers = {}) => {
      const response = await fetchTls(origin + path, { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(value) });
      return { response, value: await response.json() };
    };
    const login = async () => {
      await page.locator('#access').fill(accessKey);
      const response = page.waitForResponse(res => res.url() === origin + '/session/login');
      await page.locator('#login button').click(); const value = await (await response).json();
      await page.waitForFunction(() => !document.querySelector('#register').disabled); return value;
    };
    const register = async () => { await page.locator('#register').click(); await page.waitForFunction(async () => (await document.modelContext.getTools()).length === 1); };
    const execute = () => page.evaluate(async ({ params, strings }) => {
      const tool = (await document.modelContext.getTools())[0];
      return JSON.parse(await document.modelContext.executeTool(tool, strings ? JSON.stringify(params) : params));
    }, { params, strings: Number(browser.version().split('.')[0]) < 155 });
    await run({ page, context, origin, post, login, register, execute });
  } finally { for (const response of held) response.destroy(); await context.close(); await close(server); }
}

test('real HTTPS session and explicit native registration keep service credentials server-side', () => fixture(async ({ page, context, login, register, execute }) => {
  const traffic = []; page.on('request', req => traffic.push(req.url() + '\n' + JSON.stringify(req.headers()) + '\n' + (req.postData() ?? '')));
  assert.equal(await page.evaluate(async () => (await document.modelContext.getTools()).length), 0);
  await login(); assert.equal(await page.evaluate(async () => (await document.modelContext.getTools()).length), 0);
  const cookie = (await context.cookies()).find(item => item.name === '__Host-zt_webmcp');
  assert.equal(cookie.httpOnly, true); assert.equal(cookie.secure, true); assert.equal(cookie.sameSite, 'Strict');
  assert.equal(await page.evaluate(() => document.cookie), '');
  await register(); const result = await execute(); assert.deepEqual(result.structuredContent, contact);
  assert.equal(requests.length, 1); assert.equal(requests[0].authorization, `Bearer ${credential}`);
  assert.equal(requests[0].path, '/v1/workflow/tools'); assert.deepEqual(requests[0].value, { method: 'workflow.contact.read', params });
  assert.ok(!traffic.join('\n').includes(credential)); assert.ok(!JSON.stringify(result).includes(credential));
  await page.locator('#logout').click(); await page.waitForFunction(async () => (await document.modelContext.getTools()).length === 0);
}));

test('unauthenticated, foreign-origin, CSRF, duplicate-cookie and disallowed tools never dispatch', () => fixture(async ({ post }) => {
  assert.equal((await post('/workflow/call', { method: 'workflow.contact.read', params })).response.status, 401);
  assert.equal((await post('/session/login', { accessKey }, { Origin: 'https://foreign.example' })).response.status, 403);
  assert.equal((await post('/session/login', { accessKey: 'incorrect' })).response.status, 401);
  const signed = await post('/session/login', { accessKey });
  const cookie = signed.response.headers.get('set-cookie').split(';')[0], csrf = signed.value.csrf;
  assert.equal((await post('/workflow/call', { method: 'workflow.contact.read', params }, { Cookie: cookie })).response.status, 403);
  assert.equal((await post('/workflow/call', { method: 'workflow.contact.read', params }, { Cookie: cookie + ';' + cookie, 'X-Zrotext-Csrf': csrf })).response.status, 401);
  assert.equal((await post('/workflow/call', { method: 'workflow.action.cancel', params }, { Cookie: cookie, 'X-Zrotext-Csrf': csrf })).response.status, 403);
  assert.equal((await post('/workflow/call', { method: 'workflow.contact.read', params: { ...params, credential } }, { Cookie: cookie, 'X-Zrotext-Csrf': csrf })).value.attempts, 0);
  assert.equal(requests.length, 0);
}));

test('logout revokes cookie reuse and aborts an in-flight native call without claiming cancellation', () => fixture(async ({ page, context, origin, login, register, execute, post }) => {
  await login(); const old = (await context.cookies()).find(item => item.name === '__Host-zt_webmcp'); await register();
  hold = true; const pending = execute().then(result => ({ result }), () => ({ nativeAbort: true }));
  await page.waitForFunction(() => document.querySelector('#status').textContent.includes('registered'));
  const until = Date.now() + 5000; while (!requests.length && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(requests.length, 1);
  await page.locator('#logout').click(); const outcome = await pending;
  if (outcome.result) { assert.equal(outcome.result.structuredContent.state, 'unknown'); assert.equal(outcome.result.structuredContent.result, undefined); }
  await page.waitForFunction(async () => (await document.modelContext.getTools()).length === 0);
  const untilLogout = Date.now() + 5000;
  while ((await context.cookies(origin)).length && Date.now() < untilLogout) await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal((await post('/workflow/call', { method: 'workflow.contact.read', params }, { Cookie: `${old.name}=${old.value}`, 'X-Zrotext-Csrf': 'stale' })).response.status, 401);
  assert.equal(requests.length, 1);
}));

test('session expiry removes native registrations and expires server authority', () => fixture(async ({ page, context, login, register, post }) => {
  const session = await login(), old = (await context.cookies()).find(item => item.name === '__Host-zt_webmcp'); await register();
  await page.waitForFunction(() => document.querySelector('#status').textContent === 'Signed out. No tools registered.');
  assert.equal(await page.evaluate(async () => (await document.modelContext.getTools()).length), 0);
  assert.equal(await page.locator('#status').textContent(), 'Signed out. No tools registered.');
  assert.equal((await post('/workflow/call', { method: 'workflow.contact.read', params }, { Cookie: `${old.name}=${old.value}`, 'X-Zrotext-Csrf': session.csrf })).response.status, 401);
  assert.equal(requests.length, 0);
}, 1500));

test('HTTP origin and weak access-key configuration refuse startup', async () => {
  for (const changes of [{ origin: 'http://localhost' }, { accessKey: 'short' }, { allowlist: ['owner.approve'] }, { sessionMs: 300001 }]) {
    await assert.rejects(createWorkflowApplication({ origin: 'https://localhost', accessKey, workflowOrigin, workflowCredential: credential, tls, ...changes }));
  }
});

test('bounded sessions refuse concurrent dispatch and never retry a rate refusal', () => fixture(async ({ post }) => {
  const signed = await post('/session/login', { accessKey });
  const headers = { Cookie: signed.response.headers.get('set-cookie').split(';')[0], 'X-Zrotext-Csrf': signed.value.csrf };
  hold = true;
  const pending = post('/workflow/call', { method: 'workflow.contact.read', params }, headers);
  const until = Date.now() + 5000; while (!requests.length && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(requests.length, 1);
  assert.equal((await post('/workflow/call', { method: 'workflow.contact.read', params }, headers)).response.status, 409);
  held[0].writeHead(200, { 'Content-Type': 'application/json' }); held[0].end(JSON.stringify(contact));
  assert.deepEqual((await pending).value.result, contact);
  hold = false; upstreamStatus = 429;
  const denied = await post('/workflow/call', { method: 'workflow.contact.read', params }, headers);
  assert.deepEqual(denied.value, { available: false, code: 'rate_limited', state: 'refused', attempts: 1 });
  assert.equal(requests.length, 2);
}));

test('login rate, cross-site metadata, oversize inputs and authentication refresh fail closed', () => fixture(async ({ post }) => {
  assert.equal((await post('/session/login', { accessKey }, { 'Sec-Fetch-Site': 'cross-site' })).response.status, 403);
  assert.equal((await post('/session/login', { accessKey: 'x'.repeat(65536) })).response.status, 400);
  const first = await post('/session/login', { accessKey });
  const firstCookie = first.response.headers.get('set-cookie').split(';')[0];
  const second = await post('/session/login', { accessKey }, { Cookie: firstCookie });
  assert.equal(second.response.status, 200);
  assert.equal((await post('/workflow/call', { method: 'workflow.contact.read', params }, { Cookie: firstCookie, 'X-Zrotext-Csrf': first.value.csrf })).response.status, 401);
  let blocked = false;
  for (let attempt = 0; attempt < 21; attempt++) if ((await post('/session/login', { accessKey: 'incorrect' })).response.status === 429) blocked = true;
  assert.equal(blocked, true); assert.equal(requests.length, 0);
}));

test('a delayed old-session unauthorized response cannot close a newer authenticated session', () => fixture(async ({ page, login, register, execute }) => {
  await login(); await register();
  await page.evaluate(() => {
    const nativeFetch = globalThis.fetch;
    globalThis.fetch = (path, init) => {
      if (path !== '/workflow/call') return nativeFetch(path, init);
      // Deliberately ignore abort to exercise a late obsolete response.
      return new Promise(resolve => { globalThis.releaseOldResponse = () => resolve(new Response(JSON.stringify({ available: false, code: 'unauthorized', state: 'refused', attempts: 0 }), { status: 401, headers: { 'Content-Type': 'application/json' } })); });
    };
  });
  const pending = execute().catch(() => undefined);
  await page.waitForFunction(() => typeof releaseOldResponse === 'function');
  await login(); await page.evaluate(() => releaseOldResponse()); await pending;
  await page.waitForTimeout(50);
  assert.equal(await page.locator('#register').isEnabled(), true);
  assert.equal(await page.locator('#status').textContent(), 'Signed in. Choose Register workflow tools to continue.');
  assert.equal(requests.length, 0);
}));

test('the standalone launcher starts from private configuration and serves the authenticated app', async () => {
  const reserved = reserve(); await listen(reserved); const port = reserved.address().port;
  await new Promise(resolve => reserved.close(resolve)); const origin = `https://127.0.0.1:${port}`;
  const environment = { ...process.env, NODE_OPTIONS: '', NODE_PATH: '', ZT_WEBMCP_APP_ORIGIN: origin,
    ZT_WEBMCP_WORKFLOW_ORIGIN: workflowOrigin, ZT_WEBMCP_WORKFLOW_CREDENTIAL: credential,
    ZT_WEBMCP_ALLOWLIST: 'workflow.contact.read', ZT_WEBMCP_TLS_KEY: join(directory, 'key.pem'),
    ZT_WEBMCP_TLS_CERT: join(directory, 'cert.pem') };
  environment.ZT_WEBMCP_APP_ACCESS_KEY = accessKey;
  const child = spawn(process.execPath, [fileURLToPath(new URL('./server.mjs', import.meta.url))], {
    env: environment,
    stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
  });
  let logs = ''; child.stdout.on('data', data => { logs += data; }); child.stderr.on('data', data => { logs += data; });
  const exited = new Promise(resolve => child.once('exit', resolve));
  try {
    let response; const until = Date.now() + 5000;
    while (!response && Date.now() < until && child.exitCode === null) {
      try { response = await fetchTls(origin); } catch { await new Promise(resolve => setTimeout(resolve, 20)); }
    }
    assert.equal(response?.status, 200, 'Launcher must serve HTTPS');
    assert.match(await response.text(), /Experimental workflow tools/u);
    const refused = await fetchTls(origin + '/workflow/call', { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ method: 'workflow.contact.read', params }) });
    assert.equal(refused.status, 401);
    assert.ok(!logs.includes(accessKey) && !logs.includes(credential));
  } finally { if (child.exitCode === null) child.kill(); await exited; }
});

test('sign-in refusal is visible and upstream grant rejection closes native tools', () => fixture(async ({ page, login, register, execute }) => {
  await page.locator('#access').fill('incorrect'); await page.locator('#login button').click();
  await page.waitForFunction(() => document.querySelector('#status').textContent === 'Sign-in unavailable.');
  assert.equal(await page.locator('#access').inputValue(), ''); assert.equal(requests.length, 0);
  await login(); await register(); upstreamStatus = 401;
  const result = await execute().catch(() => undefined);
  if (result) { assert.equal(result.isError, true); assert.equal(result.structuredContent.result, undefined); }
  await page.waitForFunction(() => document.querySelector('#status').textContent === 'Signed out. No tools registered.');
  assert.equal(await page.evaluate(async () => (await document.modelContext.getTools()).length), 0);
  assert.equal(requests.length, 1);
}));
