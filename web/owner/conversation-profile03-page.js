// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(function (root) {
  function mount(context = root) {
    const { document, window, ZtProfile03Setup, URL, Blob } = context;
    if (!ZtProfile03Setup || !document?.getElementById("profile03-setup")) return;
    const el = id => document.getElementById(id);
    let controller, busy = false, url;
    const selection = () => ({ enabled: el("owner-enabled").checked, retentionConsent: el("profile-retained-consent").checked, compared: el("profile-compared").checked,
      account_id: el("owner-account").value, device_id: el("owner-device").value, line_id: el("owner-line").value,
      rootFingerprint: el("owner-fingerprint").value, pairedFingerprint: el("line-paired-fingerprint").value,
      manifestVersion: el("owner-version").value, manifestDigest: el("owner-digest").value, origin: el("root-origin").value });
    const messages = { awaiting_offline_approval: "Public profile proposal prepared. Approve it with your existing offline custodian, then select the signed public output.",
      awaiting_phone: "Waiting for the paired phone. Check this same setup after the phone confirms it.", awaiting_owner: "Paired phone signature verified. Confirm this exact setup with a fresh owner factor.",
      accepted_pending_current: "Acceptance receipt saved. Check the current phone connection.", accepted: "Phone profile accepted and independently rechecked. Conversation content consent remains a separate step.",
      outcome_unknown: "Outcome unknown. The original public request is saved in this browser. Check the original setup; do not restart it.",
      historical_only: "This saved attempt belongs to an earlier sign-in. Its status can be inspected; this sign-in cannot approve its old signed request.",
      expired: "This attempt expired. Its history remains saved. A fresh explicit attempt must preserve the phone's earlier signed history.",
      choose_recovery: "Choose the saved attempt below, then check its original status.", recovery_loaded: "Saved original attempt loaded. Check its status before taking another action.",
      refused: "Action unavailable. Check the original saved setup and current owner/phone access. Nothing is retried automatically.", closed: "Setup closed. Original public recovery records and the retained approval key remain in this browser." };
    function render() {
      const s = controller?.state() ?? { phase: "unprepared", closed: true, openingId: null };
      el("profile-reserve").disabled = busy || s.closed || s.phase !== "awaiting_offline_approval";
      el("profile-check").disabled = busy || s.closed || !s.openingId;
      el("profile-approve").disabled = busy || s.closed || s.phase !== "awaiting_owner";
      el("profile-recover").disabled = busy || s.closed || s.phase !== "choose_recovery" || !el("profile-openings").value;
      for (const id of ["profile-begin", "profile-find", "profile-close"]) el(id).disabled = busy;
      const phase = s.closed ? "closed" : s.phase;
      if (messages[phase]) el("profile-status").textContent = messages[phase] + (s.openingId ? ` Original attempt: ${s.openingId}.` : "");
    }
    function close() { controller?.close(); if (url) URL.revokeObjectURL(url); url = null; el("profile-artifacts").replaceChildren(); render(); }
    function fresh() { close(); controller = ZtProfile03Setup.create({ enabled: true, readSelection: selection }); controller.onClose(render); return controller; }
    const publicPoint = () => { if (el("profile-phone-point").files.length !== 1) throw Error("Existing paired public point required"); return el("profile-phone-point").files[0]; };
    async function action(fn) {
      if (busy) return; busy = true; render();
      try { await fn(); } catch { if (!controller) el("profile-status").textContent = messages.refused; }
      finally { busy = false; el("profile-password").value = ""; el("profile-factor").value = ""; render(); }
    }
    const credentials = () => { const value = { password: el("profile-password").value, factor: el("profile-factor").value }; el("profile-password").value = ""; el("profile-factor").value = ""; return value; };
    el("profile-begin").addEventListener("click", () => action(async () => {
      const file = publicPoint(), current = fresh(), value = await current.begin(file);
      if (controller !== current || current.state().closed) throw Error("Profile page closed");
      const a = document.createElement("a"); url = URL.createObjectURL(new Blob([value.proposal], { type: "application/octet-stream" }));
      a.href = url; a.download = "payload-profile-upgrade-proposal.bin"; a.textContent = "Download public proposal for existing offline approval"; el("profile-artifacts").append(a);
    }));
    el("profile-reserve").addEventListener("click", () => action(async () => {
      if (el("profile-signed").files.length !== 1) throw Error("Existing signed public proposal required");
      await controller.reserve(el("profile-signed").files[0], credentials());
    }));
    el("profile-check").addEventListener("click", () => action(() => controller.check()));
    el("profile-approve").addEventListener("click", () => action(() => controller.approve(credentials())));
    el("profile-find").addEventListener("click", () => action(async () => {
      const file = publicPoint(), current = fresh(), value = await current.find(file);
      if (controller !== current || current.state().closed) throw Error("Profile page closed");
      el("profile-openings").replaceChildren();
      for (const id of value.openings) { const option = document.createElement("option"); option.value = id; option.textContent = id; el("profile-openings").append(option); }
    }));
    el("profile-openings").addEventListener("change", render);
    el("profile-recover").addEventListener("click", () => action(() => controller.recover(el("profile-openings").value)));
    el("profile-close").addEventListener("click", close); el("clear").addEventListener("click", close);
    el("owner-setup").addEventListener("input", event => { if (!["profile-password", "profile-factor", "profile-signed", "profile-openings"].includes(event.target.id)) close(); });
    window.addEventListener("pagehide", close); render();
  }
  if (typeof module === "object" && module.exports) module.exports = { mount };
  else mount();
})(globalThis);
