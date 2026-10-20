// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(() => {
  if (!globalThis.ZtManifest03History || !document.getElementById("profile-history-open")) return;
  const el = id => document.getElementById(id); let controller, busy = false;
  const selection = () => ({ enabled: el("owner-enabled").checked, retentionConsent: el("profile-retained-consent").checked, compared: el("profile-compared").checked,
    account_id: el("owner-account").value, device_id: el("owner-device").value, line_id: el("owner-line").value,
    rootFingerprint: el("owner-fingerprint").value, pairedFingerprint: el("line-paired-fingerprint").value,
    manifestVersion: el("owner-version").value, manifestDigest: el("owner-digest").value, origin: el("root-origin").value });
  function render() {
    const s = controller?.state(); el("profile-history-open").disabled = busy;
    el("profile-history-next").disabled = busy || !s || s.closed || s.durable || s.version === null;
    el("profile-history-current").disabled = busy || !s || s.closed || !s.durable;
    const messages = { reading_history: "Original signed setup verified. Continue to check the next saved history page.",
      verified_history: "Complete accepted history saved in this browser. Check the current phone connection.",
      current_selection: "Current phone selection verified. Browser message-key approval and conversation consent remain separate steps.",
      interrupted: "History check interrupted. Saved setup and keys remain. Continue the read, or reopen saved history after signing in again.",
      closed: "History check closed. Your saved public checkpoint remains in this browser." };
    if (s && messages[s.phase]) el("profile-history-status").textContent = messages[s.phase];
  }
  function close() { controller?.close(); render(); }
  async function action(run) {
    if (busy) return; busy = true; render();
    try { await run(); } catch { el("profile-history-status").textContent = "History check unavailable. Check your current sign-in and independently compared setup receipts."; }
    finally { busy = false; render(); }
  }
  el("profile-history-open").addEventListener("click", () => action(async () => {
    close(); controller = ZtManifest03History.create({ enabled: true, readSelection: selection }); controller.onClose(render);
    if (el("profile-phone-point").files.length !== 1) throw Error("Existing paired public point required");
    await controller.open(el("profile-phone-point").files[0]);
  }));
  el("profile-history-next").addEventListener("click", () => action(() => controller.next()));
  el("profile-history-current").addEventListener("click", () => action(() => controller.current()));
  el("clear").addEventListener("click", close); el("profile-close").addEventListener("click", close);
  el("owner-setup").addEventListener("input", event => { if (!["profile-password", "profile-factor", "profile-signed", "profile-openings"].includes(event.target.id)) close(); });
  window.addEventListener("pagehide", close); render();
})();
