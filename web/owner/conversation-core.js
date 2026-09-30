// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  const fields = ["account", "session", "interval", "device", "line", "generation", "peer", "reader", "manifest"];
  function scope(input) {
    const out = {};
    for (const key of fields) {
      if (typeof input?.[key] !== "string" || !input[key] || input[key].length > 128) throw new Error("Conversation unavailable.");
      out[key] = input[key];
    }
    if (!/^\+[1-9][0-9]{1,14}$/.test(out.peer) || !/^[1-9][0-9]*$/.test(out.generation)) throw new Error("Conversation unavailable.");
    return Object.freeze(out);
  }
  const same = (a, b) => fields.every((key) => a[key] === b[key]);
  function body(value) {
    if (typeof value !== "string" || !value || value.startsWith("\uFEFF") || value.includes("\0") || !value.isWellFormed() || new TextEncoder().encode(value).length > 32768) throw new Error("Enter valid message text within the size limit.");
    return value;
  }
  // An injected authenticated adapter owns authority, encryption and transport.
  // There is no default adapter, persistent credential or production endpoint.
  function create(adapter, now = () => performance.now()) {
    let current = null, until = 0, draft = "", review = null, revision = 0, busy = false, messages = [];
    function invalidate(clear = false) {
      revision++; review = null;
      if (clear) { current = null; until = 0; draft = ""; messages = []; }
    }
    function live() { if (!current || now() >= until) { invalidate(true); throw new Error("Conversation authorization expired."); } }
    async function authorize() {
      invalidate(true);
      const ticket = revision, started = now();
      const value = await adapter.authority();
      if (ticket !== revision) throw new Error("Conversation changed.");
      const selected = scope(value.scope);
      if (value.phase !== "active" || !Number.isFinite(value.validForMs) || value.validForMs <= 0 || value.validForMs > 60000 || now() >= started + value.validForMs) throw new Error("Conversation inactive.");
      current = selected; until = started + value.validForMs;
      return selected;
    }
    function edit(value) { live(); invalidate(); draft = value; }
    async function prepare() {
      live(); if (busy) throw new Error("Request already in progress.");
      invalidate();
      const ticket = revision, selected = current, text = body(draft);
      busy = true;
      try {
        const candidate = await adapter.prepare(Object.freeze({ scope: selected, body: text }));
        live();
        if (ticket !== revision || !same(selected, current) || text !== draft) throw new Error("Message changed. Review it again.");
        if (!candidate || typeof candidate.confirm !== "function") throw new Error("Message unavailable.");
        const confirm = candidate.confirm.bind(candidate);
        review = Object.freeze({ scope: selected, body: text, confirm, ticket });
        return Object.freeze({ peer: selected.peer, body: text, account: selected.account, line: selected.line });
      } finally { busy = false; }
    }
    async function confirm() {
      live();
      if (busy || !review || review.ticket !== revision || review.body !== draft || !same(review.scope, current)) throw new Error("Review the current message first.");
      const approved = review;
      // Consume before the first await. Repeated clicks never create a second send.
      review = null; busy = true;
      try {
        const ticket = revision;
        const result = await approved.confirm(() => { live(); if (ticket !== revision || !same(approved.scope, current)) throw new Error("Conversation changed."); });
        if (ticket !== revision) throw new Error("Result unavailable. Do not retry automatically.");
        live();
        if (!["simulator_accepted", "queued"].includes(result?.status)) throw new Error("Result unavailable. Do not retry automatically.");
        messages.push(Object.freeze({ direction: "outbound", body: approved.body, status: result.status })); draft = "";
        return result;
      } finally { busy = false; }
    }
    async function read(event) {
      live(); const ticket = revision, selected = current;
      const text = body(await adapter.read(Object.freeze({ scope: selected, event })));
      live(); if (ticket !== revision || !same(selected, current)) throw new Error("Conversation changed.");
      messages.push(Object.freeze({ direction: "inbound", body: text }));
      return text;
    }
    function state() {
      if (current && now() >= until) invalidate(true);
      const visibleReview = review && !busy ? Object.freeze({ body: review.body, scope: review.scope }) : null;
      return Object.freeze({ scope: current, draft, review: visibleReview, canConfirm: !!visibleReview, busy, messages: Object.freeze([...messages]) });
    }
    return Object.freeze({ authorize, edit, prepare, confirm, read, clear: () => invalidate(true), state });
  }
  const api = Object.freeze({ create, scope });
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.ZtConversation = api;
})(globalThis);
