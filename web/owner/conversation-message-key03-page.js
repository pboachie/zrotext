// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  function mount({ getHistory, renderHistory = () => {}, document = root.document, window = root.window,
    create = options => root.ZtBrowserMessageEnrollment03.create(options), url = root.URL, Blob = root.Blob } = {}) {
    const el = id => document.getElementById(id); if (!el("browser-message-key03")) return;
    let controller, busy = false, download;
    const messages = {
      key_selected: "Choose how to approve this browser. Its message key stays in this browser.",
      awaiting_offline_approval: "Public approval request saved. Use your existing offline custodian, then select its signed public output below.",
      saved_attempt: "Your original browser setup is saved. Recover its history before checking or continuing that same approval.",
      ready_install: "Signed approval verified and saved. Enter your current password and a fresh authenticator code to approve this browser.",
      unknown: "The result is uncertain. Your original request and key are saved. Check its status before taking another action.",
      saved_accepted: "The service accepted this browser approval. Confirm it in the complete saved history before continuing.",
      history_required: "Continue the history check below. Each click checks one bounded page; your saved request stays in place.",
      confirmed: "Browser message-key approval confirmed and saved. Phone connection and conversation consent are the next separate steps.",
      accepted_key_missing: "Approval is retained, but its private key is unavailable in this browser. Use explicit replacement approval with your existing custodian.",
      interrupted: "Setup paused. The saved request and existing key remain. Check the original request or resume its public approval.",
      closed: "Browser setup closed. Saved public requests and retained keys remain in this browser."
    };
    function render() {
      const s = controller?.state(), waiting = busy || !!getHistory()?.state().busy;
      const show = (id, visible, available = true) => { const v = el(id); v.hidden = !visible; v.disabled = waiting || !available; };
      show("message-open", !s || s.closed);
      const canPrepare = !!s && !s.closed && (!s.hasProposal || s.confirmed || s.canPrepareFresh || s.canReplaceMissing);
      show("message-prepare", canPrepare);
      el("message-prepare").textContent = s?.canReplaceMissing ? "Prepare replacement approval" : s?.canPrepareFresh ? "Prepare fresh unsubmitted request" : "Prepare public approval request";
      el("message-options").hidden = !canPrepare;
      if (s?.canReplaceMissing) el("message-operation").value = "replace";
      show("message-resume", !!s && !s.closed && s.hasProposal && !s.hasOriginal, !!getHistory()?.state().durable);
      show("message-resume-install", !!s && !s.closed && s.canResumeInstall && s.phase !== "ready_install", !!getHistory()?.state().durable);
      el("message-signed-label").hidden = !s || s.closed || !s.hasProposal || s.hasOriginal;
      show("message-authorize", !!s && !s.closed && s.hasProposal && !s.hasOriginal, !!getHistory()?.state().durable);
      el("message-factors").hidden = !s || s.closed || s.phase !== "ready_install";
      show("message-install", !!s && !s.closed && s.phase === "ready_install");
      show("message-recover", !!s && !s.closed && s.hasProposal && !s.confirmed && s.phase !== "history_required");
      show("message-next-history", !!s && !s.closed && s.phase === "history_required" && !getHistory()?.state().durable);
      show("message-check", !!s && !s.closed && s.hasOriginal && !s.confirmed, !!getHistory()?.state().durable);
      show("message-confirm", !!s && !s.closed && s.hasReceipt && !s.confirmed, !!getHistory()?.state().durable);
      show("message-close", !!s && !s.closed);
      if (s && messages[s.phase]) el("message-status").textContent = messages[s.phase];
    }
    function close() { controller?.close(); if (download) url.revokeObjectURL(download); download = null; el("message-artifacts").replaceChildren(); render(); }
    async function action(run) {
      if (busy) return; busy = true; render(); renderHistory();
      try { await run(); } catch { el("message-status").textContent = "Setup needs attention. Keep the saved request, check the original status, and confirm your current sign-in and compared receipts."; }
      finally { busy = false; el("message-password").value = ""; el("message-factor").value = ""; render(); renderHistory(); }
    }
    function artifact(value) {
      if (download) url.revokeObjectURL(download); el("message-artifacts").replaceChildren();
      download = url.createObjectURL(new Blob([value.proposal], { type: "application/octet-stream" }));
      const a = document.createElement("a"); a.href = download; a.download = "browser-message-manifest-proposal.bin"; a.textContent = "Download saved public approval request"; el("message-artifacts").append(a);
    }
    el("message-open").addEventListener("click", () => action(async () => {
      close(); const history = getHistory(); if (!history?.state().durable) throw Error("Recover the accepted profile history first");
      controller = create({ enabled: true, history }); controller.onClose(render); await controller.open();
    }));
    el("message-prepare").addEventListener("click", () => action(async () => artifact(await controller.prepare({ operation: el("message-operation").value,
      retain: el("message-retain").checked, newKey: el("message-retain").checked }))));
    el("message-resume").addEventListener("click", () => action(async () => artifact(await controller.resumeProposal())));
    el("message-resume-install").addEventListener("click", () => action(() => controller.resumeInstall()));
    el("message-authorize").addEventListener("click", () => action(async () => {
      if (el("message-signed").files.length !== 1) throw Error("Signed public output required"); await controller.authorize(el("message-signed").files[0]);
    }));
    el("message-install").addEventListener("click", () => action(() => {
      const factor = { password: el("message-password").value, factor: el("message-factor").value };
      el("message-password").value = ""; el("message-factor").value = ""; return controller.install(factor);
    }));
    el("message-recover").addEventListener("click", () => action(() => controller.recoverHistory()));
    el("message-next-history").addEventListener("click", () => action(() => getHistory().next()));
    el("message-check").addEventListener("click", () => action(() => controller.check()));
    el("message-confirm").addEventListener("click", () => action(() => controller.confirm()));
    el("message-close").addEventListener("click", close); el("clear").addEventListener("click", close);
    for (const id of ["message-operation", "message-retain", "message-signed"]) el(id).addEventListener("input", () => { if (busy) close(); });
    window.addEventListener("pagehide", close); render();
    return Object.freeze({ render, close, busy: () => busy });
  }
  const api = Object.freeze({ mount }); if (typeof module !== "undefined" && module.exports) module.exports = api; else root.ZtMessageKey03Page = api;
})(globalThis);
