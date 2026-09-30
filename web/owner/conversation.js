// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(() => {
  const el = (id) => document.getElementById(id);
  let adapter = globalThis.ZtConversationSimulatorAdapter;
  const setup = globalThis.ZtConversationOwnerSetup;
  if (!adapter && !setup) return; // No implicit credentials, network or activation.
  let controller = adapter ? ZtConversation.create(adapter) : null;
  let setupPending = false, setupRevision = 0;
  let custodyLifetime = null;
  let hadScope = false;
  function render() {
    const s = controller ? controller.state() : { scope: null, draft: "", review: null, canConfirm: false, busy: setupPending, messages: [] };
    if (s.scope) hadScope = true;
    else if (hadScope && adapter && !globalThis.ZtConversationSimulatorAdapter) adapter.close();
    el("composer").disabled = !s.scope || s.busy;
    el("confirm").disabled = !s.canConfirm;
    el("confirmation").hidden = !s.review;
    el("review-body").textContent = s.review?.body || "";
    el("review-peer").textContent = s.review ? `Account ${s.review.scope.account} · Line ${s.review.scope.line} · To ${s.review.scope.peer}` : "";
    el("selection").textContent = s.scope ? `Account ${s.scope.account} · Line ${s.scope.line} · Peer ${s.scope.peer}` : "";
    el("body").value = s.draft;
    el("messages").replaceChildren();
    for (const message of s.messages) {
      const p = document.createElement("p"); p.textContent = `${message.direction === "inbound" ? "Phone received" : message.status === "queued" ? "Queued for delivery" : "Simulator accepted"}: ${message.body}`;
      el("messages").append(p);
    }
  }
  async function action(fn) {
    try { await fn(); } catch { el("status").textContent = "Action unavailable. Check authorization and review again; no automatic retry occurs."; }
    render();
  }
  el("connect").disabled = false;
  el("connect").addEventListener("click", () => action(async () => {
    if (setupPending) throw Error("Setup in progress");
    setupPending = true; el("connect").disabled = true;
    el("status").textContent = "Checking conversation authorization.";
    let ticket = ++setupRevision;
    try {
    if (setup && !globalThis.ZtConversationSimulatorAdapter) {
      if (!el("session-custody").checked) throw Error("Explicit session custody decision required");
      adapter?.close(); controller?.clear(); controller = null;
      hadScope = false; ticket = ++setupRevision;
      render();
      custodyLifetime?.abort(); custodyLifetime = new AbortController();
      const sdk = await import("/v1/owner/conversation-sdk/sdk/conversation-custody.js");
      const options = await setup.custodyOptions();
      const custody = await sdk.prepareConversationCustody02({ ...options, signal: custodyLifetime.signal });
      if (ticket !== setupRevision) { custody.close(); throw Error("Setup closed"); }
      try { adapter = ZtConversationOwnerTransport.create({ ...setup.transportOptions, enabled: true, custody }); }
      catch (error) { custody.close(); throw error; }
      controller = ZtConversation.create(adapter);
      adapter.onClose?.(clear);
      setup.onClose?.(clear);
    }
    await controller.authorize(); el("status").textContent = setup ? "Conversation authorized for this session." : "Fixture conversation authorized.";
    if (adapter.initialEvent) await controller.read(adapter.initialEvent);
    } finally { setupPending = false; el("connect").disabled = false; }
  }));
  el("body").addEventListener("input", () => { try { controller.edit(el("body").value); } catch { controller.clear(); } render(); });
  el("review").addEventListener("click", () => action(async () => {
    await controller.prepare(); render();
    if (controller.state().canConfirm) el("review-body").focus();
  }));
  el("confirm").addEventListener("click", () => action(async () => {
    const result = await controller.confirm(); el("status").textContent = result.status === "queued" ? "Confirmed message queued. Delivery is pending." : "Simulator accepted the confirmed message. Carrier delivery is not tested.";
  }));
  el("cancel").addEventListener("click", () => { try { controller.edit(controller.state().draft); } catch { controller.clear(); } render(); el("body").focus(); });
  const clear = () => { setupRevision++; custodyLifetime?.abort(); adapter?.close?.(); controller?.clear(); hadScope = false; render(); el("status").textContent = "Conversation cleared. Check authorization again."; };
  el("clear").addEventListener("click", clear);
  window.addEventListener("pagehide", clear);
  document.addEventListener("visibilitychange", () => { if (document.hidden) clear(); });
  adapter?.onClose?.(clear);
  setInterval(render, 1000);
  render();
})();
