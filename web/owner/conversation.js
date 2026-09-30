// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(() => {
  const el = (id) => document.getElementById(id);
  const adapter = globalThis.ZtConversationSimulatorAdapter;
  if (!adapter) return; // No implicit credentials, network or activation.
  const controller = ZtConversation.create(adapter);
  function render() {
    const s = controller.state();
    el("composer").disabled = !s.scope || s.busy;
    el("confirm").disabled = !s.canConfirm;
    el("confirmation").hidden = !s.review;
    el("review-body").textContent = s.review?.body || "";
    el("review-peer").textContent = s.review ? `Account ${s.review.scope.account} · Line ${s.review.scope.line} · To ${s.review.scope.peer}` : "";
    el("selection").textContent = s.scope ? `Account ${s.scope.account} · Line ${s.scope.line} · Peer ${s.scope.peer}` : "";
    el("body").value = s.draft;
    el("messages").replaceChildren();
    for (const message of s.messages) {
      const p = document.createElement("p"); p.textContent = `${message.direction === "inbound" ? "Phone received" : "Simulator accepted"}: ${message.body}`;
      el("messages").append(p);
    }
  }
  async function action(fn) {
    try { await fn(); } catch { el("status").textContent = "Action unavailable. Check authorization and review again; no automatic retry occurs."; }
    render();
  }
  el("connect").disabled = false;
  el("connect").addEventListener("click", () => action(async () => {
    await controller.authorize(); el("status").textContent = "Fixture conversation authorized.";
    if (adapter.initialEvent) await controller.read(adapter.initialEvent);
  }));
  el("body").addEventListener("input", () => { try { controller.edit(el("body").value); } catch { controller.clear(); } render(); });
  el("review").addEventListener("click", () => action(async () => {
    await controller.prepare(); render();
    if (controller.state().canConfirm) el("review-body").focus();
  }));
  el("confirm").addEventListener("click", () => action(async () => {
    await controller.confirm(); el("status").textContent = "Simulator accepted the confirmed message. Carrier delivery is not tested.";
  }));
  el("cancel").addEventListener("click", () => { try { controller.edit(controller.state().draft); } catch { controller.clear(); } render(); el("body").focus(); });
  const clear = () => { controller.clear(); render(); el("status").textContent = "Conversation cleared. Check authorization again."; };
  el("clear").addEventListener("click", clear);
  window.addEventListener("pagehide", clear);
  document.addEventListener("visibilitychange", () => { if (document.hidden) clear(); });
  adapter.onClose?.(clear);
  setInterval(render, 1000);
  render();
})();
