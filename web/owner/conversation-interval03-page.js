// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  function mount({ getHistory, renderHistory = () => {}, document = root.document, window = root.window,
    create = options => root.ZtConversationInterval03.create(options), discover = history => root.ZtConversationInterval03.contentChoices(history) } = {}) {
    const el = id => document.getElementById(id); if (!el("conversation-interval03")) return;
    let controller, busy = false;
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
      show("interval-begin", !!s && !s.closed && (s.phase === "ready" || s.reconciled && ["stopped", "expired"].includes(s.phase)));
      show("interval-resume", !!s && !s.closed && !!s.openingId && !s.reserveSubmitted && !s.hasReceipt && !s.localStopped);
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
    for (const id of ["interval-archive", "interval-phone", "interval-retain"]) el(id).addEventListener("input", close);
    for (const id of ["interval-close", "clear", "profile-close"]) el(id).addEventListener("click", close);
    window.addEventListener("pagehide", close); render(); return Object.freeze({ render, close, busy: () => busy });
  }
  const api = Object.freeze({ mount }); if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ZtInterval03Page = api;
})(globalThis);
