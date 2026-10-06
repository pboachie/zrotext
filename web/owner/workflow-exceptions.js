// SPDX-License-Identifier: AGPL-3.0-only
// Client-only foundation. Serving and authenticated account/context response metadata remain prerequisites.
"use strict";
(function (root) {
  const CAP = 65536, SESSION_CAP = 2048;
  const fields = ["account_id", "context_id", "id", "context_revision", "source_kind", "source_id", "reason", "request_digest", "revision", "state", "resolution_request_id", "resolved_at", "created_at"];
  function refuse() { throw Error("Workflow exceptions unavailable"); }
  function uuid(value) {
    if (typeof value !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(value)) refuse();
    return value;
  }
  function exact(value, names) {
    if (!value || Array.isArray(value) || typeof value !== "object" || Object.keys(value).length !== names.length || names.some(k => !Object.hasOwn(value, k))) refuse();
    return value;
  }
  function rawJson(bytes, cap) {
    if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > cap) refuse();
    if (bytes.length >= 3 && bytes[0] === 239 && bytes[1] === 187 && bytes[2] === 191) refuse();
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { refuse(); }
    let at = 0;
    const ws = () => { while (/[ \t\r\n]/.test(text[at] || "!")) at++; };
    function string() {
      const start = at++;
      while (at < text.length && at - start <= 1024) {
        const c = text[at++];
        if (c === '"') {
          let value; try { value = JSON.parse(text.slice(start, at)); } catch { refuse(); }
          if (value.length > 128 || /[\uD800-\uDFFF]/.test(value)) refuse();
          return value;
        }
        if (c === "\\") at++;
      }
      refuse();
    }
    function value(depth) {
      if (depth > 3) refuse(); ws(); const c = text[at];
      if (c === '"') return string();
      if (c === "{") {
        at++; const result = Object.create(null), seen = new Set(); ws();
        if (text[at] === "}") { at++; return result; }
        while (at < text.length) {
          ws(); if (text[at] !== '"') refuse(); const key = string();
          if (seen.has(key) || seen.size >= 13 || key === "__proto__") refuse(); seen.add(key);
          ws(); if (text[at++] !== ":") refuse(); result[key] = value(depth + 1); ws();
          const end = text[at++]; if (end === "}") return result; if (end !== ",") refuse();
        }
        refuse();
      }
      if (c === "[") {
        at++; const result = []; ws(); if (text[at] === "]") { at++; return result; }
        while (at < text.length) {
          if (result.length >= 20) refuse(); result.push(value(depth + 1)); ws();
          const end = text[at++]; if (end === "]") return result; if (end !== ",") refuse();
        }
        refuse();
      }
      if (text.startsWith("null", at)) { at += 4; return null; }
      const match = /^(0|[1-9][0-9]{0,2})/.exec(text.slice(at));
      if (!match) refuse(); at += match[0].length; return Number(match[0]);
    }
    const result = value(0); ws(); if (at !== text.length) refuse(); return result;
  }
  function timestamp(value) {
    if (typeof value !== "string" || value.length > 32) refuse();
    const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})[T ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,6})?(Z|[+-]([0-9]{2}):([0-9]{2}))$/.exec(value);
    if (!m) refuse(); const y = Number(m[1]), month = Number(m[2]), day = Number(m[3]);
    const days = [31, y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (!y || month < 1 || month > 12 || day < 1 || day > days[month - 1] || Number(m[4]) > 23 || Number(m[5]) > 59 || Number(m[6]) > 59 || m[8] && (Number(m[8]) > 23 || Number(m[9]) > 59)) refuse();
    return value;
  }
  function parsePage(bytes, selection, before = null) {
    const account = uuid(selection.account), context = uuid(selection.context); if (before !== null) uuid(before);
    const page = exact(rawJson(bytes, CAP), ["account_id", "context_id", "items", "next_cursor"]);
    if (page.account_id !== account || page.context_id !== context || !Array.isArray(page.items)) refuse();
    let last = before;
    const items = page.items.map(input => {
      const row = exact(input, fields); uuid(row.id); uuid(row.source_id);
      if (row.account_id !== account || row.context_id !== context || last !== null && row.id <= last) refuse(); last = row.id;
      if (!Number.isInteger(row.context_revision) || row.context_revision < 1 || row.context_revision > 128 || ![[1, 1], [1, 5], [2, 2], [2, 3], [2, 4]].some(([kind, reason]) => kind === row.source_kind && reason === row.reason)) refuse();
      if (typeof row.request_digest !== "string" || !/^\\x[0-9a-f]{64}$/.test(row.request_digest)) refuse();
      if (row.revision === 1 && row.state === "pending") { if (row.resolution_request_id !== null || row.resolved_at !== null) refuse(); }
      else if (row.revision === 2 && row.state === "resolved") { uuid(row.resolution_request_id); timestamp(row.resolved_at); }
      else refuse(); timestamp(row.created_at); return Object.freeze({ ...row });
    });
    if (page.next_cursor !== null && (uuid(page.next_cursor) !== last || items.length !== 20 || before !== null && page.next_cursor <= before)) refuse();
    return Object.freeze({ account_id: account, context_id: context, items: Object.freeze(items), next_cursor: page.next_cursor });
  }
  function parseSession(bytes, account) {
    const s = exact(rawJson(bytes, SESSION_CAP), ["account_id", "user_id", "session_id", "role"]);
    if (uuid(s.account_id) !== uuid(account) || s.role !== "owner") refuse(); uuid(s.user_id); uuid(s.session_id); return Object.freeze({ ...s });
  }
  function csrf(document) {
    const parts = document.cookie.split(";").map(s => s.trim()).filter(s => s.startsWith("__Host-zrotext_csrf="));
    if (parts.length !== 1) refuse(); let token; try { token = decodeURIComponent(parts[0].slice(20)); } catch { refuse(); }
    if (!token || token.length > 256 || /[^\x21-\x7e]/.test(token)) refuse(); return token;
  }
  function create({ document = root.document, window = root.window || root, fetch: request = window.fetch?.bind(window) } = {}) {
    const el = id => document.getElementById(id), account = el("exceptions-account"), context = el("exceptions-context"), ack = el("exceptions-ack"), rows = el("exceptions-rows"), status = el("exceptions-status"), read = el("exceptions-read"), next = el("exceptions-next"), clear = el("exceptions-clear");
    if ([account, context, ack, rows, status, read, next, clear].some(v => !v) || typeof request !== "function" || new URL(window.location.origin).protocol !== "https:") refuse();
    let closed = false, active = false, epoch = 0, outward = false, continuation = null, published = null;
    const unsettled = new Set(), removers = []; let controller = null, currentOp = null;
    const busy = () => outward || unsettled.size > 0;
    function buttons() { read.disabled = closed || busy(); next.disabled = closed || busy() || !continuation; }
    function scrub() { rows.replaceChildren(); continuation = null; published = null; next.disabled = true; }
    function close() {
      if (closed) return; closed = true; epoch++; scrub(); account.value = ""; context.value = ""; ack.checked = false;
      if (currentOp) { currentOp.account = ""; currentOp.context = ""; currentOp.before = null; currentOp.csrf = ""; }
      try { controller?.abort(); } finally { for (const remove of removers.splice(0)) remove(); status.textContent = "Exceptions page closed. Reload for a fresh selection."; buttons(); }
    }
    function track(work) {
      const p = Promise.resolve(work); unsettled.add(p); buttons();
      void p.finally(() => { unsettled.delete(p); buttons(); }).catch(() => {}); return p;
    }
    function wait(work, late) {
      const observed = track(work);
      return new Promise((resolve, reject) => {
        const signal = controller.signal;
        let finished = false;
        const finish = fn => { if (finished) return; finished = true; signal.removeEventListener("abort", abort); fn(); };
        const abort = () => finish(() => reject(Error("Exceptions read closed")));
        signal.addEventListener("abort", abort, { once: true });
        if (signal.aborted) abort();
        observed.then(value => { if (finished) { try { late?.(value); } catch {} } else finish(() => resolve(value)); }, () => finish(() => reject(Error("Exceptions read unavailable"))));
      });
    }
    function listen(target, name, fn) { target.addEventListener(name, fn); removers.push(() => target.removeEventListener(name, fn)); }
    const edited = () => { if (active) close(); else { scrub(); ack.checked = false; } };
    listen(account, "input", edited); listen(context, "input", edited); listen(ack, "change", () => { if (active) close(); });
    listen(clear, "click", close); listen(window, "pagehide", close); listen(document, "visibilitychange", () => { if (document.hidden) close(); });
    function live(op) {
      if (closed || document.hidden || epoch !== op.epoch || controller.signal.aborted || performance.now() >= op.deadline || account.value !== op.account || context.value !== op.context || !ack.checked || csrf(document) !== op.csrf) { close(); refuse(); }
    }
    async function bounded(response, cap, op) {
      live(op);
      if (response.status !== 200 || response.redirected || ["opaque", "opaqueredirect"].includes(response.type) || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get("content-type") || "") || !response.body) refuse();
      const reader = response.body.getReader(), chunks = []; let size = 0, ended = false;
      try {
        while (true) {
          const part = await wait(reader.read(), value => { if (value.value instanceof Uint8Array) value.value.fill(0); });
          try { live(op); } catch (error) { if (part.value instanceof Uint8Array) part.value.fill(0); throw error; }
          if (part.done) { ended = true; break; }
          if (!(part.value instanceof Uint8Array) || size + part.value.length > cap) refuse();
          const owned = Uint8Array.from(part.value); chunks.push(owned); size += owned.length;
        }
        const out = new Uint8Array(size); let at = 0; for (const p of chunks) { out.set(p, at); at += p.length; } return out;
      } finally {
        for (const p of chunks) p.fill(0);
        if (!ended) { try { void track(reader.cancel()).catch(() => {}); } catch {} }
        try { reader.releaseLock(); } catch { /* A held read remains charged until its actual settlement. */ }
      }
    }
    async function get(path, cap, op, content) {
      live(op); const url = window.location.origin + path;
      const response = await wait(request(url, { method: "GET", credentials: "same-origin", mode: "same-origin", redirect: "error", cache: "no-store", signal: controller.signal, headers: { accept: "application/json", ...(content ? { "x-zrotext-csrf": op.csrf } : {}) } }), value => { if (value.body) void track(value.body.cancel()).catch(() => {}); });
      try { live(op); if (response.url && response.url !== url) refuse(); return await bounded(response, cap, op); }
      catch (error) { if (response.body) try { void track(response.body.cancel()).catch(() => {}); } catch {} throw error; }
    }
    async function session(op) { const raw = await get("/v1/auth/session", SESSION_CAP, op, false); try { return parseSession(raw, op.account); } finally { raw.fill(0); } }
    function render(page) {
      const fragment = document.createDocumentFragment();
      for (const row of page.items) { const item = document.createElement("li"); item.textContent = `${row.id} · ${row.state} · source ${row.source_kind}/${row.source_id} · reason ${row.reason} · context revision ${row.context_revision} · created ${row.created_at}${row.resolved_at ? " · resolved " + row.resolved_at : ""}`; fragment.append(item); }
      rows.replaceChildren(fragment); continuation = page.next_cursor; published = { account: page.account_id, context: page.context_id }; status.textContent = page.items.length ? "Exceptions checked at this read. Permissions can change." : "No exceptions in this checked page. Permissions can change.";
    }
    async function load(isNext) {
      if (closed || busy()) return;
      let op;
      try {
        if (!ack.checked) refuse(); const a = uuid(account.value), c = uuid(context.value);
        const cursor = isNext ? continuation : null; if (isNext && (!cursor || !published || published.account !== a || published.context !== c)) refuse();
        op = { account: a, context: c, before: cursor, csrf: csrf(document), epoch, deadline: performance.now() + 10000 };
        // Copy the validated continuation before clearing old content, BEFORE the first await.
        active = true; outward = true; controller = new AbortController(); currentOp = op; scrub(); buttons(); status.textContent = "Checking exceptions…";
        const timer = setTimeout(close, Math.max(0, op.deadline - performance.now()));
        try {
          const first = await session(op); live(op);
          const path = "/v1/owner/workflow/contexts/" + op.context + "/exceptions" + (op.before ? "?before=" + op.before : "");
          const raw = await get(path, CAP, op, true); let page; try { page = parsePage(raw, op, op.before); } finally { raw.fill(0); }
          live(op); const final = await session(op); live(op);
          if (first.user_id !== final.user_id || first.session_id !== final.session_id || first.role !== final.role) refuse();
          render(page);
        } finally { clearTimeout(timer); }
      } catch { close(); }
      finally { outward = false; buttons(); if (op) { op.account = ""; op.context = ""; op.before = null; op.csrf = ""; } currentOp = null; }
    }
    listen(read, "click", () => { void load(false); }); listen(next, "click", () => { void load(true); }); buttons();
    return Object.freeze({ read: () => load(false), next: () => load(true), close, state: () => Object.freeze({ closed, busy: busy(), hasNext: Boolean(continuation) }) });
  }
  const api = Object.freeze({ create, parsePage, parseSession });
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ZtWorkflowExceptions = api;
  if (root.document?.querySelector("[data-workflow-exceptions]")) create({ document: root.document, window: root });
})(globalThis);
