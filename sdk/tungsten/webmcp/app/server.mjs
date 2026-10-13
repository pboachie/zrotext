#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-only
import { createServer } from 'node:https';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { WorkflowToolClient, WorkflowToolError, workflowTools } from '../../../typescript/dist/workflow-tool-client.js';

const cookieName = '__Host-zt_webmcp';
const maxBody = 65536;
function token() { return randomBytes(32).toString('base64url'); }
const digest = value => createHash('sha256').update(value).digest();
const alias = method => `workflow_tools_${method.slice(9).replaceAll('.', '_')}`;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const failure = (code, state = 'refused', attempts = 0) => ({ available: false, code, state, attempts });

async function body(request) {
  const declared = request.headers['content-length'];
  if (request.headers['content-type'] !== 'application/json' ||
      declared !== undefined && (!/^\d+$/u.test(declared) || Number(declared) > maxBody)) throw new Error();
  const chunks = []; let size = 0;
  const deadline = setTimeout(() => request.destroy(new Error('Application input deadline')), 10000); deadline.unref();
  try { for await (const chunk of request) { size += chunk.length; if (size > maxBody) throw new Error(); chunks.push(chunk); } }
  finally { clearTimeout(deadline); }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)));
}

/** Single-operator candidate application. All configuration is server-owned. */
export async function createWorkflowApplication({ origin, accessKey, workflowOrigin, workflowCredential,
  allowlist = ['workflow.contact.read', 'workflow.action.status'], sessionMs = 300000,
  tls, workflowFetch } = {}) {
  const url = new URL(origin);
  if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password ||
      !/^[A-Za-z0-9_-]{43}$/u.test(accessKey ?? '') || Buffer.from(accessKey, 'base64url').toString('base64url') !== accessKey ||
      accessKey === workflowCredential || !Number.isSafeInteger(sessionMs) || sessionMs < 100 || sessionMs > 300000 ||
      !Array.isArray(allowlist) || !allowlist.length || new Set(allowlist).size !== allowlist.length ||
      !allowlist.every(method => workflowTools.some(tool => tool.name === method))) throw new Error('Invalid application configuration');
  const client = new WorkflowToolClient({ origin: workflowOrigin, credential: workflowCredential, fetchImpl: workflowFetch });
  const accessHash = digest(accessKey);
  const generated = new URL('../../generated/webmcp/manifest.json', import.meta.url);
  const manifest = await readFile(generated);
  const inventory = JSON.parse(await readFile(new URL('../../generated.lock.json', import.meta.url), 'utf8'));
  if (createHash('sha256').update(manifest).digest('hex') !== inventory['webmcp/manifest.json']) throw new Error('Generated catalog drift');
  const assets = new Map([
    ['/', ['text/html; charset=utf-8', await readFile(new URL('./index.html', import.meta.url))]],
    ['/app.mjs', ['text/javascript', await readFile(new URL('./app.mjs', import.meta.url))]],
    ['/adapter.mjs', ['text/javascript', await readFile(new URL('../index.mjs', import.meta.url))]],
    ['/typescript/dist/workflow-tools.js', ['text/javascript', await readFile(new URL('../../../typescript/dist/workflow-tools.js', import.meta.url))]],
    ['/typescript/dist/workflow-decisions.js', ['text/javascript', await readFile(new URL('../../../typescript/dist/workflow-decisions.js', import.meta.url))]],
  ]);
  const sessions = new Map(); let loginWindow = 0, loginCount = 0;
  const retire = id => { const session = sessions.get(id); if (session) { sessions.delete(id); clearTimeout(session.timer); session.abort.abort(); } };
  const lookup = request => {
    const pairs = (request.headers.cookie ?? '').split(';').map(part => part.trim()).filter(part => part.startsWith(cookieName + '='));
    if (pairs.length !== 1) return;
    const id = pairs[0].slice(cookieName.length + 1), session = sessions.get(id);
    if (!session || session.expires <= Date.now()) { retire(id); return; }
    return { id, session };
  };
  const server = createServer({ ...tls, maxHeaderSize: 8192 }, async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'none'; img-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    const send = (status, value) => { if (!response.destroyed && !response.writableEnded) { response.writeHead(status, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(value)); } };
    try {
      if (request.headers.host !== url.host || !request.socket.encrypted) return send(403, failure('forbidden'));
      const site = request.headers['sec-fetch-site'];
      if (site && !['same-origin', 'none'].includes(site)) return send(403, failure('forbidden'));
      const path = request.url;
      if (request.method === 'GET' && assets.has(path)) {
        const [type, bytes] = assets.get(path); response.writeHead(200, { 'Content-Type': type }); return response.end(bytes);
      }
      if (request.method !== 'POST' || request.headers.origin !== origin) return send(403, failure('forbidden'));
      if (path === '/session/login') {
        const now = Date.now(); if (now - loginWindow > 60000) { loginWindow = now; loginCount = 0; }
        if (++loginCount > 20) return send(429, failure('rate_limited'));
        const input = await body(request);
        if (!exact(input, ['accessKey']) || typeof input.accessKey !== 'string' || input.accessKey.length > 128 ||
            !timingSafeEqual(digest(input.accessKey), accessHash)) return send(401, failure('unauthorized'));
        const prior = lookup(request); if (prior) retire(prior.id);
        if (sessions.size >= 16) return send(503, failure('unavailable'));
        const id = token(), csrf = token(), expires = now + sessionMs, abort = new AbortController();
        const timer = setTimeout(() => retire(id), sessionMs); timer.unref();
        sessions.set(id, { csrf, expires, abort, timer, busy: false });
        response.setHeader('Set-Cookie', `${cookieName}=${id}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.ceil(sessionMs / 1000)}`);
        return send(200, { csrf, expires, allowlist: allowlist.map(alias), manifest: JSON.parse(manifest) });
      }
      const found = lookup(request);
      if (!found) return send(401, failure('unauthorized'));
      const { id, session } = found;
      if (request.headers['x-zrotext-csrf'] !== session.csrf) return send(403, failure('forbidden'));
      const input = await body(request);
      if (path === '/session/logout' && exact(input, [])) {
        retire(id); response.setHeader('Set-Cookie', `${cookieName}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
        return send(200, { closed: true });
      }
      if (path !== '/workflow/call') return send(404, failure('not_found'));
      if (!exact(input, ['method', 'params']) || !allowlist.includes(input.method)) return send(403, failure('forbidden'));
      if (session.busy) return send(409, failure('conflict'));
      // The authentication lifetime is checked again after potentially slow body input.
      if (session.abort.signal.aborted || session.expires <= Date.now()) return send(401, failure('unauthorized'));
      session.busy = true;
      const disconnected = new AbortController();
      const close = () => { if (!response.writableEnded) disconnected.abort(); };
      response.on('close', close);
      try {
        const result = await client.call(input.method, input.params, 1, AbortSignal.any([session.abort.signal, disconnected.signal]));
        if (session.abort.signal.aborted || session.expires <= Date.now()) return send(401, failure('response_unknown', 'unknown', 1));
        return send(200, { result });
      } catch (error) {
        if (error instanceof WorkflowToolError && error.code === 'unauthorized') {
          retire(id); return send(401, failure(error.code, error.state, error.attempts));
        }
        if (error instanceof WorkflowToolError) return send(400, failure(error.code, error.state, error.attempts));
        return send(503, failure('response_unknown', 'unknown', 1));
      } finally { session.busy = false; response.off('close', close); }
    } catch { return send(400, failure('invalid_request')); }
  });
  server.requestTimeout = 10000; server.headersTimeout = 10000; server.timeout = 12000; server.keepAliveTimeout = 1000; server.maxConnections = 64;
  server.on('close', () => { for (const id of sessions.keys()) retire(id); accessHash.fill(0); });
  return server;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const origin = process.env.ZT_WEBMCP_APP_ORIGIN;
    const server = await createWorkflowApplication({ origin, accessKey: process.env.ZT_WEBMCP_APP_ACCESS_KEY,
      workflowOrigin: process.env.ZT_WEBMCP_WORKFLOW_ORIGIN, workflowCredential: process.env.ZT_WEBMCP_WORKFLOW_CREDENTIAL,
      allowlist: process.env.ZT_WEBMCP_ALLOWLIST?.split(','),
      tls: { key: await readFile(process.env.ZT_WEBMCP_TLS_KEY), cert: await readFile(process.env.ZT_WEBMCP_TLS_CERT) } });
    server.listen(Number(new URL(origin).port || 443), '127.0.0.1');
    server.on('error', () => { console.error('WebMCP application listener unavailable'); process.exitCode = 1; });
  } catch { console.error('WebMCP application configuration unavailable'); process.exitCode = 1; }
}
