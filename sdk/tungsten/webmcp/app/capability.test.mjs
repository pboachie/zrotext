// SPDX-License-Identifier: AGPL-3.0-only
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:net';
import { createRequire } from 'node:module';
import { createWorkflowApplication } from './server.mjs';

const engines = createRequire(new URL('../../../../web/owner/package.json', import.meta.url))('playwright');
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

test('actual browser capability matrix gates authentication without registering tools', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'zrotext-webmcp-capability-'));
  let server;
  try {
    const key = join(directory, 'key.pem'), cert = join(directory, 'cert.pem');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert,
      '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost'], { stdio: 'ignore' });
    const reserved = createServer(); await listen(reserved); const port = reserved.address().port;
    await new Promise(resolve => reserved.close(resolve));
    const origin = `https://127.0.0.1:${port}`;
    let upstreamCalls = 0;
    server = await createWorkflowApplication({ origin, accessKey: randomBytes(32).toString('base64url'),
      workflowOrigin: 'https://workflow.invalid', workflowCredential: 'ztw_' + randomBytes(32).toString('base64url'),
      allowlist: ['workflow.contact.read'], tls: { key: await readFile(key), cert: await readFile(cert) },
      workflowFetch: async () => { upstreamCalls++; throw new Error('No workflow call authorized by this test'); } });
    await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));
    const report = [];
    for (const [engine, native] of [['chromium', true], ['chromium', false], ['firefox', false], ['webkit', false]]) {
      const browser = await engines[engine].launch({ headless: true,
        ...(engine === 'chromium' ? {
          ...(process.env.ZT_WEBMCP_BROWSER ? { executablePath: process.env.ZT_WEBMCP_BROWSER } : {}),
          args: native ? ['--enable-features=WebMCP', '--enable-blink-features=WebMCP']
            : ['--disable-features=WebMCP', '--disable-blink-features=WebMCP'],
        } : {}),
      });
      try {
        const context = await browser.newContext({ ignoreHTTPSErrors: true });
        const page = await context.newPage(), requests = [], errors = [];
        page.on('request', req => { if (req.method() === 'POST') requests.push(req.url()); });
        page.on('pageerror', error => errors.push(error.message));
        await page.goto(origin);
        await page.waitForFunction(() => document.querySelector('#access').disabled ||
          (typeof document.modelContext?.registerTool === 'function' && !document.querySelector('#login button').disabled));
        assert.equal(await page.evaluate(() => typeof document.modelContext?.registerTool === 'function'), native,
          `${engine} capability changed; qualify its native registration before changing the matrix`);
        assert.equal(await page.locator('#access').isDisabled(), !native);
        assert.equal(await page.locator('#login button').isDisabled(), !native);
        assert.equal(await page.locator('#register').isDisabled(), true);
        assert.equal(await page.locator('#logout').isDisabled(), true);
        if (!native) {
          assert.match(await page.locator('#status').textContent(), /does not provide native WebMCP/);
          // Even a synthetic submit event cannot send credentials in the unsupported state.
          await page.evaluate(() => {
            document.querySelector('#access').value = 'synthetic-unused-access';
            document.querySelector('#login').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
          });
          assert.equal(await page.locator('#access').inputValue(), '');
          assert.match(await page.locator('#status').textContent(), /does not provide native WebMCP/);
        } else {
          assert.equal(await page.evaluate(async () => (await document.modelContext.getTools()).length), 0);
        }
        assert.deepEqual(requests, []); assert.deepEqual(errors, []); assert.equal(upstreamCalls, 0);
        report.push({ engine, version: browser.version(), nativeRegistration: native,
          qualification: native ? 'explicit registration available; authentication still required' : 'unsupported; authentication and registration disabled' });
        await context.close();
      } finally { await browser.close(); }
    }
    console.log('WebMCP capability matrix: ' + JSON.stringify(report));
    if (process.env.ZT_WEBMCP_BROWSER_REPORT) await writeFile(process.env.ZT_WEBMCP_BROWSER_REPORT, JSON.stringify(report));
  } finally {
    if (server) await new Promise(resolve => { server.close(resolve); server.closeAllConnections?.(); });
    await rm(directory, { recursive: true, force: true });
  }
});
