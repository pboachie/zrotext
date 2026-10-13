// SPDX-License-Identifier: AGPL-3.0-only
import { registerWorkflowTools } from '/adapter.mjs';
const login = document.querySelector('#login'), access = document.querySelector('#access');
const register = document.querySelector('#register'), logout = document.querySelector('#logout'), status = document.querySelector('#status');
let session, lifetime, registration, expiry, signIn, generation = 0;
const supported = () => globalThis.isSecureContext && typeof document.modelContext?.registerTool === 'function';
const unavailable = 'This browser does not provide native WebMCP. Use a browser with WebMCP enabled. No tools registered.';
function capability() {
  const enabled = supported();
  access.disabled = !enabled; login.querySelector('button').disabled = !enabled;
  if (!enabled) status.textContent = unavailable;
  return enabled;
}
function close() {
  generation++; signIn?.abort(); signIn = undefined;
  lifetime?.abort(); registration?.close(); clearTimeout(expiry);
  session = undefined; registration = undefined; register.disabled = true; logout.disabled = true;
  status.textContent = 'Signed out. No tools registered.';
  capability();
}
async function post(path, value, signal, csrf) {
  const current = generation;
  const response = await fetch(path, { method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
    headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-Zrotext-Csrf': csrf } : {}) }, body: JSON.stringify(value) });
  const data = await response.json();
  if (!response.ok) { if (response.status === 401 && path !== '/session/login' && current === generation) close(); throw Object.assign(new Error('Workflow application refused'), data); }
  return data;
}
login.addEventListener('submit', async event => {
  event.preventDefault(); close(); const key = access.value; access.value = '';
  if (!capability()) return;
  const current = generation; signIn = new AbortController();
  try {
    const authenticated = await post('/session/login', { accessKey: key }, signIn.signal);
    if (current !== generation) return;
    signIn = undefined; session = authenticated; lifetime = new AbortController();
    expiry = setTimeout(close, Math.max(0, session.expires - Date.now()));
    register.disabled = false; logout.disabled = false; status.textContent = 'Signed in. Choose Register workflow tools to continue.';
  } catch { if (current === generation) status.textContent = 'Sign-in unavailable.'; }
});
register.addEventListener('click', async () => {
  register.disabled = true;
  const current = generation;
  try {
    const active = session, permission = lifetime;
    if (!active || !document.modelContext?.registerTool) throw new Error();
    const owned = await registerWorkflowTools({ manifest: active.manifest, allowlist: active.allowlist,
      registry: { kind: 'document', registerTool: (...args) => document.modelContext.registerTool(...args) }, signal: permission.signal,
      transport: { isAuthorized: () => session === active && !permission.signal.aborted && active.expires > Date.now(),
        call: async (method, params, { signal }) => (await post('/workflow/call', { method, params }, signal, active.csrf)).result } });
    if (current !== generation) { owned.close(); return; }
    registration = owned;
    status.textContent = 'Workflow tools registered for this session.';
  } catch { if (current === generation) { close(); status.textContent = 'Registration unavailable. Sign in again to retry.'; } }
});
logout.addEventListener('click', async () => {
  const csrf = session?.csrf; close();
  const current = generation;
  if (csrf) try { await post('/session/logout', {}, undefined, csrf); } catch { if (current === generation) status.textContent = 'Tools closed. Server sign-out could not be confirmed; the session will expire.'; }
});
addEventListener('pagehide', close);
capability();
