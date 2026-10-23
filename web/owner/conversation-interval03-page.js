// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  function mount({ getHistory, renderHistory = () => {}, document = root.document, window = root.window,
    create = options => root.ZtConversationInterval03.create(options), discover = history => root.ZtConversationInterval03.contentChoices(history) } = {}) {
    const el = id => document.getElementById(id); if (!el("conversation-interval03")) return;
    let controller, busy = false, messageCursor = null, nextMessageCursor = null;
    const messages = {
      ready: "Your existing browser and phone keys are selected. Prepare a conversation request when you are ready.",
      saved_attempt: "Your original conversation request is saved. Check it to continue from the same step.",
      reserved: "Review this conversation and its selected readers, then approve the exact saved request.",
      signed_request: "The exact approval is saved. Confirm it with your current password and a fresh authenticator code.",
      requested: "Waiting for approval on the paired phone. Check this same request after approving it there.",
      install_pending: "Phone approval verified. Waiting for the phone to finish installing this consent.",
      active_verified: "Original browser and phone consent proofs verified. Current permission expires separately; message sending still requires its own review.",
      unknown: "The result is uncertain. Check the saved request. Nothing is sent or repeated automatically.",
      historical_only: "This request belongs to your earlier sign-in. You can check or stop it; this sign-in cannot approve it again.",
      stopping: "Local approval is withdrawn. Check the original request to confirm the service has stopped it.",
      stopped: "This consent is stopped. Its history stays saved. You may explicitly prepare a new request.",
      expired: "This consent expired. Its history stays saved. You may explicitly prepare a new request.",
      permission_expired: "Current permission ended. Check the original request and phone connection before continuing.",
      interrupted: "Setup needs attention. Keep the original request and check your sign-in, saved keys and phone connection.",
      closed: "Conversation setup closed. Original requests and keys remain saved in this browser."
    };
    function selection() {
      const raw = el("integration-readers").value.trim();
      if (raw && !el("integration-transfer-consent").checked) throw Error("Explicit selected-reader consent required");
      const integrationReaders = raw ? raw.split(/\r?\n/).map(line => {
        const parts = line.split(",").map(s => s.trim()); if (parts.length !== 3) throw Error("Compared reader selection required");
        return { connectorId: parts[0], readGrantId: parts[1], keyId: parts[2] };
      }).sort((a, b) => a.keyId.localeCompare(b.keyId)) : [];
      return { peer: el("owner-peer").value, archiveReaderKeyId: el("interval-archive").value, phoneSignerKeyId: el("interval-phone").value,
        integrationReaders, retentionConsent: el("interval-retain").checked };
    }
    function render() {
      const s = controller?.state(), waiting = busy || !!getHistory()?.state().busy;
      const show = (id, visible, enabled = true) => { el(id).hidden = !visible; el(id).disabled = waiting || !enabled; };
      show("interval-open", !s || s.closed);
      show("interval-begin", !!s && !s.closed && (s.phase === "ready" || s.canPrepareFresh || s.reconciled && ["stopped", "expired"].includes(s.phase)));
      el("interval-begin").textContent = s?.canPrepareFresh ? "Prepare fresh unsent request" : "Prepare conversation request";
      show("interval-resume", !!s && !s.closed && !!s.openingId && !s.reserveSubmitted && !s.hasReceipt && !s.localStopped && !s.canPrepareFresh);
      show("interval-check", !!s && !s.closed && s.reserveSubmitted);
      show("interval-review", !!s && !s.closed && s.reconciled && s.phase === "reserved" && !s.originalSaved && !s.historical && !s.localStopped);
      const request = !!s && !s.closed && s.reconciled && s.originalSaved && ["signed_request", "reserved"].includes(s.phase) && !s.historical && !s.localStopped;
      show("interval-request", request); el("interval-factors").hidden = !request;
      el("interval-stop").hidden = !s || s.closed || !s.hasReceipt || ["stopped", "expired"].includes(s.phase);
      el("interval-stop").disabled = !s || s.closed;
      show("interval-close", !!s && !s.closed);
      if (el("interval-summary")) el("interval-summary").textContent = s?.expiresMs
        ? `Conversation: ${s.peer}. Original expiry: ${new Date(Number(s.expiresMs)).toLocaleString()}. Additional selected readers: ${s.readerCount}.` : "";
      if (s && messages[s.phase]) el("interval-status").textContent = messages[s.phase];
      if (el("interval-message-body")) {
        el("interval-message-composer").hidden = !s || s.closed;
        el("interval-message-body").disabled = waiting || !s || s.closed || !s.verifiedActive;
        el("interval-message-ceiling").disabled = waiting || !s || s.closed || !s.verifiedActive;
        el("interval-message-review").disabled = waiting || !s || s.closed || !s.verifiedActive;
        el("interval-message-confirmation").hidden = !s?.messageReview;
        el("interval-message-confirm").disabled = waiting || !s?.messageReview;
        el("interval-message-cancel").disabled = !s || s.closed;
        el("interval-message-history").disabled = waiting || !s || s.closed;
        el("interval-message-next").hidden = nextMessageCursor === null; el("interval-message-next").disabled = waiting || !s || s.closed;
        el("interval-message-review-body").textContent = s?.messageReview?.content ?? "";
        el("interval-message-review-summary").textContent = s?.messageReview
          ? `To ${s.messageReview.peer}. At most ${s.messageReview.smsCeiling} SMS segment(s). Confirm before ${new Date(Number(s.messageReview.expiresMs)).toLocaleTimeString()}.` : "";
        const messageStates = { review: "Review the exact text and SMS limit, then confirm once.", accepted: "The service accepted this message. Carrier delivery is pending.",
          unknown: "The outcome is uncertain. Check the original saved attempt before preparing another message.", interrupted: "Sending was interrupted. Open saved attempts; nothing is signed or sent again automatically.",
          expired: "This review expired. The original attempt history stays saved. Prepare a fresh review only after checking any uncertain send.", canceled: "Local message approval canceled.", stopped: "Conversation stopped. Saved messages can still be checked." };
        if (s && messageStates[s.messagePhase]) el("interval-message-status").textContent = messageStates[s.messagePhase] + (s.lastMessageId ? ` Original message: ${s.lastMessageId}.` : "");
        if (!s || s.closed) {
          el("interval-message-body").value = ""; el("interval-message-review-body").textContent = ""; el("interval-message-attempts").replaceChildren();
          messageCursor = nextMessageCursor = null;
        }
      }
    }
    function close() { controller?.close(); render(); }
    async function action(run) {
      if (busy) return; busy = true; render(); renderHistory();
      try { await run(); } catch { el("interval-status").textContent = messages.interrupted; }
      finally { busy = false; el("interval-password").value = ""; el("interval-factor").value = ""; render(); renderHistory(); }
    }
    function choices(id, values) {
      const select = el(id), previous = select.value; select.replaceChildren();
      for (const item of values) { const option = document.createElement("option"); option.value = item.keyId; option.textContent = "Approved key · " + item.keyId.slice(-12); select.append(option); }
      if (values.some(v => v.keyId === previous)) select.value = previous;
      if (!values.length) throw Error("Recover approved content keys first");
    }
    el("interval-open").addEventListener("click", () => action(async () => {
      close(); const history = getHistory(); if (!history?.state().durable) throw Error("Recover complete profile history first");
      const keys = await discover(history); choices("interval-archive", keys.archives); choices("interval-phone", keys.phones);
      controller = create({ enabled: true, history, readSelection: selection }); controller.onClose(render); await controller.open();
    }));
    el("interval-begin").addEventListener("click", () => action(() => controller.begin({ durationMs: Number(el("interval-duration").value) })));
    el("interval-resume").addEventListener("click", () => action(() => controller.resumeReservation()));
    el("interval-check").addEventListener("click", () => action(() => controller.check()));
    el("interval-review").addEventListener("click", () => action(() => controller.review({ disclosure: el("interval-disclosure").checked })));
    el("interval-request").addEventListener("click", () => action(() => {
      const credentials = { password: el("interval-password").value, factor: el("interval-factor").value };
      el("interval-password").value = ""; el("interval-factor").value = ""; return controller.request(credentials);
    }));
    el("interval-stop").addEventListener("click", async () => {
      // Stop is deliberately available during another action: withdraw local
      // approval now, then reconcile its original service request.
      const pending = controller?.stop(); render();
      try { await pending; } catch { el("interval-status").textContent = messages.stopping; } finally { render(); renderHistory(); }
    });
    if (el("interval-message-body")) {
      for (const id of ["interval-message-body", "interval-message-ceiling"]) el(id).addEventListener("input", () => { controller?.cancelMessage(); render(); });
      el("interval-message-review").addEventListener("click", () => action(() => controller.reviewMessage({ content: el("interval-message-body").value, smsCeiling: Number(el("interval-message-ceiling").value) })));
      el("interval-message-confirm").addEventListener("click", () => action(async () => { await controller.confirmMessage(); el("interval-message-body").value = ""; }));
      el("interval-message-cancel").addEventListener("click", () => { controller?.cancelMessage(); render(); });
      async function listMessages(afterMessageId) {
        const page = await controller.messageHistory({ afterMessageId, limit: 16 }); messageCursor = afterMessageId; nextMessageCursor = page.nextMessageId;
        const list = el("interval-message-attempts"); list.replaceChildren();
        for (const r of page.attempts) {
          const row = document.createElement("li"), label = document.createElement("span");
          label.textContent = `${r.message_id} · ${r.stage === "accepted" ? "Accepted; delivery pending" : r.stage === "submit_reserved" ? "Outcome uncertain" : "Not submitted; original attempt retained"}. `; row.append(label);
          if (["submit_reserved", "accepted"].includes(r.stage)) {
            const check = document.createElement("button"); check.type = "button"; check.textContent = "Check original message";
            check.addEventListener("click", () => action(async () => { await controller.checkMessage(r.message_id); await listMessages(messageCursor); })); row.append(check);
          }
          list.append(row);
        }
        if (!page.attempts.length) { const row = document.createElement("li"); row.textContent = "No saved message attempts for this conversation in this browser."; list.append(row); }
      }
      el("interval-message-history").addEventListener("click", () => action(() => listMessages(null)));
      el("interval-message-next").addEventListener("click", () => action(() => { if (nextMessageCursor === null) throw Error("No next page"); return listMessages(nextMessageCursor); }));
    }
    for (const id of ["interval-archive", "interval-phone", "interval-retain"]) el(id).addEventListener("input", close);
    for (const id of ["interval-close", "clear", "profile-close"]) el(id).addEventListener("click", close);
    window.addEventListener("pagehide", close); render(); return Object.freeze({ render, close, busy: () => busy });
  }
  const api = Object.freeze({ mount }); if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ZtInterval03Page = api;
})(globalThis);
