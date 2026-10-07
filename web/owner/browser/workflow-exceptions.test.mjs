// SPDX-License-Identifier: AGPL-3.0-only
// Real rendered page, HttpOnly Cookie and streams; proposed metadata HTTP is synthetic, not PG acceptance.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
const require = createRequire(new URL('../package.json', import.meta.url));
const { chromium } = require('playwright');
const origin = 'https://exceptions.invalid', A = '11111111-1111-4111-8111-111111111111', B = '22222222-2222-4222-8222-222222222222', C = '33333333-3333-4333-8333-333333333333';
const id = n => '44444444-4444-4444-8444-' + String(n).padStart(12, '0');
const row = n => ({ account_id: A, context_id: C, id: id(n), context_revision: 1, source_kind: 1, source_id: id(90), reason: 1, request_digest: '\\x' + 'ab'.repeat(32), revision: 1, state: 'pending', resolution_request_id: null, resolved_at: null, created_at: '2024-02-29T12:34:56Z' });
const envelope = (items = [], next_cursor = null) => ({ account_id: A, context_id: C, items, next_cursor });
const html = await readFile(new URL('../workflow-exceptions.html', import.meta.url)), source = await readFile(new URL('../workflow-exceptions.js', import.meta.url), 'utf8');

async function visit(browser, mode, script = source) {
  const context = await browser.newContext({ serviceWorkers: 'block' });
  await context.addCookies([{ name: '__Host-zrotext_session', value: 'synthetic-owner-a', url: origin, httpOnly: true, secure: true, sameSite: 'Strict' }, { name: '__Host-zrotext_csrf', value: 'synthetic-token', url: origin, secure: true, sameSite: 'Strict' }]);
  const requests = []; let release = null, queues = 0, sessions = 0;
  await context.route(origin + '/**', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.pathname === '/workflow-exceptions.html') return route.fulfill({ contentType: 'text/html', body: html });
    if (url.pathname === '/workflow-exceptions.js') return route.fulfill({ contentType: 'text/javascript', body: script });
    const headers = await request.allHeaders(); requests.push({ path: url.pathname, query: url.search, method: request.method(), headers });
    assert.equal(request.method(), 'GET', mode); assert.equal(headers.authorization, undefined, mode);
    assert.ok(headers.cookie.includes('__Host-zrotext_session='), mode);
    if (url.pathname === '/v1/auth/session') {
      sessions++; assert.equal(headers['x-zrotext-csrf'], undefined, mode);
      const account_id = headers.cookie.includes('synthetic-owner-b') ? B : A;
      return route.fulfill({ contentType: 'application/json', body: JSON.stringify({ account_id, user_id: id(91), session_id: mode === 'final-session' && sessions === 2 ? id(93) : id(92), role: 'owner' }) });
    }
    assert.equal(url.pathname, '/v1/owner/workflow/contexts/' + C + '/exceptions', mode);
    assert.equal(headers['x-zrotext-csrf'], 'synthetic-token', mode); queues++;
    if (['clear', 'edit', 'pagehide', 'token', 'remote-cookie', 'late-guard'].includes(mode) || mode === 'next-held' && queues === 2) await new Promise(resolve => { release = resolve; });
    if (mode === 'next-success') assert.equal(url.search, queues === 1 ? '' : '?before=44444444-4444-4444-8444-000000000020', mode);
    const items = mode === 'rows' || mode === 'clear' || mode === 'late-guard' ? [row(1)] : mode === 'next-held' || mode === 'next-success' && queues === 1 ? Array.from({ length: 20 }, (_, n) => row(n + 1)) : mode === 'next-success' ? [row(21), row(22), row(23)] : [];
    let body = JSON.stringify(envelope(items, mode === 'next-held' || mode === 'next-success' && queues === 1 ? id(20) : null));
    if (mode === 'legacy') body = JSON.stringify({ items: [], next_cursor: null });
    if (mode === 'account-envelope' || mode === 'account-guard') body = JSON.stringify({ ...envelope(), account_id: B });
    if (mode === 'duplicate' || mode === 'duplicate-guard') body = body.replace('"account_id":', '"account_id":"' + A + '","account_\\u0069d":');
    if (mode === 'cap') body = ' '.repeat(65537);
    await route.fulfill({ contentType: 'application/json', body });
  });
  const page = await context.newPage(); await page.goto(origin + '/workflow-exceptions.html');
  await page.locator('#exceptions-account').fill(A); await page.locator('#exceptions-context').fill(C); await page.locator('#exceptions-ack').check();
  return { page, context, requests, release: () => { release?.(); release = null; }, held: () => Boolean(release), queues: () => queues };
}
const closed = page => page.waitForFunction(() => document.getElementById('exceptions-status').textContent === 'Exceptions page closed. Reload for a fresh selection.');
const checked = page => page.waitForFunction(() => document.getElementById('exceptions-status').textContent.includes('checked'));
async function held(f) {
  const end = performance.now() + 10000;
  while (!f.held()) { assert.ok(performance.now() < end, 'held response did not arrive within the original bounded phase'); await new Promise(resolve => setTimeout(resolve, 0)); }
}

test('rendered isolated exceptions page binds metadata, scrubs local events and observes remote credentials', { timeout: 60000 }, async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    for (const mode of ['empty', 'rows', 'legacy', 'account-envelope', 'duplicate', 'final-session', 'cap', 'clear', 'edit', 'pagehide', 'token', 'remote-cookie', 'next-held', 'next-success']) {
      const f = await visit(browser, mode);
      try {
        await f.page.getByRole('button', { name: 'Read exceptions', exact: true }).click();
        if (['clear', 'edit', 'pagehide', 'token', 'remote-cookie'].includes(mode)) {
          await f.page.waitForFunction(() => document.getElementById('exceptions-status').textContent === 'Checking exceptions…');
          await held(f);
          assert.equal(await f.page.locator('#exceptions-rows li').count(), 0, mode);
          if (mode === 'clear') await f.page.getByRole('button', { name: 'Clear and close' }).click();
          if (mode === 'edit') await f.page.locator('#exceptions-account').fill(B);
          if (mode === 'pagehide') await f.page.evaluate(() => window.dispatchEvent(new Event('pagehide')));
          if (mode === 'token') await f.context.addCookies([{ name: '__Host-zrotext_csrf', value: 'changed-token', url: origin, secure: true, sameSite: 'Strict' }]);
          if (mode === 'remote-cookie') await f.context.addCookies([{ name: '__Host-zrotext_session', value: 'synthetic-owner-b', url: origin, httpOnly: true, secure: true, sameSite: 'Strict' }]);
          // Remote Cookie changes are not synchronous observer events: empty display comes from read start.
          if (['clear', 'edit', 'pagehide'].includes(mode)) { await closed(f.page); assert.equal(await f.page.locator('#exceptions-rows li').count(), 0, mode); }
          f.release(); await closed(f.page);
          assert.equal(await f.page.locator('#exceptions-rows li').count(), 0, mode); assert.equal(await f.page.locator('#exceptions-next').isDisabled(), true, mode);
        } else if (mode === 'next-held') {
          await checked(f.page); assert.equal(await f.page.locator('#exceptions-rows li').count(), 20);
          await f.page.getByRole('button', { name: 'Next page', exact: true }).click();
          assert.equal(await f.page.locator('#exceptions-rows li').count(), 0); assert.equal(await f.page.locator('#exceptions-next').isDisabled(), true);
          await held(f);
          assert.equal(f.requests.filter(r => r.query).at(-1).query, '?before=' + id(20)); await f.page.getByRole('button', { name: 'Clear and close' }).click(); f.release(); await closed(f.page);
        } else if (mode === 'next-success') {
          // Independent public expectations are literal values, not decoder/render/fixture output.
          const firstIds = ["44444444-4444-4444-8444-000000000001", "44444444-4444-4444-8444-000000000002", "44444444-4444-4444-8444-000000000003", "44444444-4444-4444-8444-000000000004", "44444444-4444-4444-8444-000000000005", "44444444-4444-4444-8444-000000000006", "44444444-4444-4444-8444-000000000007", "44444444-4444-4444-8444-000000000008", "44444444-4444-4444-8444-000000000009", "44444444-4444-4444-8444-000000000010", "44444444-4444-4444-8444-000000000011", "44444444-4444-4444-8444-000000000012", "44444444-4444-4444-8444-000000000013", "44444444-4444-4444-8444-000000000014", "44444444-4444-4444-8444-000000000015", "44444444-4444-4444-8444-000000000016", "44444444-4444-4444-8444-000000000017", "44444444-4444-4444-8444-000000000018", "44444444-4444-4444-8444-000000000019", "44444444-4444-4444-8444-000000000020"];
          const secondIds = ["44444444-4444-4444-8444-000000000021", "44444444-4444-4444-8444-000000000022", "44444444-4444-4444-8444-000000000023"];
          const secondTexts = ["44444444-4444-4444-8444-000000000021 · pending · source 1/44444444-4444-4444-8444-000000000090 · reason 1 · context revision 1 · created 2024-02-29T12:34:56Z", "44444444-4444-4444-8444-000000000022 · pending · source 1/44444444-4444-4444-8444-000000000090 · reason 1 · context revision 1 · created 2024-02-29T12:34:56Z", "44444444-4444-4444-8444-000000000023 · pending · source 1/44444444-4444-4444-8444-000000000090 · reason 1 · context revision 1 · created 2024-02-29T12:34:56Z"];
          await f.page.waitForFunction(() => document.getElementById('exceptions-status').textContent === 'Exceptions checked at this read. Permissions can change.' && !document.getElementById('exceptions-next').disabled);
          assert.deepEqual(await f.page.locator('#exceptions-rows li').evaluateAll(items => items.map(item => item.textContent.split(' · ')[0])), firstIds, mode);
          await f.page.getByRole('button', { name: 'Next page', exact: true }).click();
          // Observe completed replacement, not the first page's already-checked status.
          await f.page.waitForFunction(expected => document.getElementById('exceptions-status').textContent === 'Exceptions checked at this read. Permissions can change.' && Array.from(document.querySelectorAll('#exceptions-rows li'), item => item.textContent.split(' · ')[0]).join(',') === expected.join(','), secondIds);
          const actualTexts = await f.page.locator('#exceptions-rows li').allTextContents();
          assert.deepEqual(actualTexts, secondTexts, mode);
          assert.ok(firstIds.every(oldId => actualTexts.every(text => !text.startsWith(oldId + ' · '))), mode);
          assert.equal(await f.page.locator('#exceptions-next').isDisabled(), true, mode);
          assert.equal(f.queues(), 2, mode);
          const queueRequests = f.requests.filter(request => request.path.endsWith('/exceptions'));
          assert.deepEqual(queueRequests.map(request => request.query), ['', '?before=44444444-4444-4444-8444-000000000020'], mode);
          assert.ok(queueRequests.every(request => request.method === 'GET' && request.headers['x-zrotext-csrf'] === 'synthetic-token'), mode);
          const sessionRequests = f.requests.filter(request => request.path === '/v1/auth/session');
          assert.equal(sessionRequests.length, 4, mode);
          assert.ok(sessionRequests.every(request => request.method === 'GET' && request.headers['x-zrotext-csrf'] === undefined), mode);
        } else if (['empty', 'rows'].includes(mode)) {
          await checked(f.page); assert.equal(await f.page.locator('#exceptions-rows li').count(), mode === 'rows' ? 1 : 0, mode); assert.equal(await f.page.locator('#exceptions-next').isDisabled(), true, mode);
        } else { await closed(f.page); assert.equal(await f.page.locator('#exceptions-rows li').count(), 0, mode); }
        assert.ok(f.requests.every(r => r.method === 'GET'), mode);
      } finally { f.release(); await f.context.close(); }
    }
  } finally { await browser.close(); }
});

test('account guard removal fails the independent empty-B refusal control and restored source passes', async () => {
  const browser = await chromium.launch({ headless: true });
  async function refusal(script) {
    const f = await visit(browser, 'account-guard', script);
    try { await f.page.getByRole('button', { name: 'Read exceptions', exact: true }).click(); await f.page.waitForFunction(() => !document.getElementById('exceptions-status').textContent.startsWith('Checking')); assert.equal(await f.page.locator('#exceptions-status').textContent(), 'Exceptions page closed. Reload for a fresh selection.'); }
    finally { await f.context.close(); }
  }
  try {
    const guard = 'page.account_id !== account || '; assert.equal(source.split(guard).length, 2);
    await assert.rejects(refusal(source.replace(guard, '')), { name: 'AssertionError' }); await refusal(source);
  } finally { await browser.close(); }
});

test('decoded-key duplicate guard removal fails the closed-response control and restored source passes', async () => {
  const browser = await chromium.launch({ headless: true });
  async function refusal(script) {
    const f = await visit(browser, 'duplicate-guard', script);
    try { await f.page.getByRole('button', { name: 'Read exceptions', exact: true }).click(); await f.page.waitForFunction(() => !document.getElementById('exceptions-status').textContent.startsWith('Checking')); assert.equal(await f.page.locator('#exceptions-status').textContent(), 'Exceptions page closed. Reload for a fresh selection.'); }
    finally { await f.context.close(); }
  }
  try { const guard = 'seen.has(key) || '; assert.equal(source.split(guard).length, 2); await assert.rejects(refusal(source.replace(guard, '')), { name: 'AssertionError' }); await refusal(source); }
  finally { await browser.close(); }
});
