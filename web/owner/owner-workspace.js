// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(() => {
  const views = Object.freeze({
    "/owner/devices": ["overview", "Overview", "Your current phones and writer metadata, with setup close at hand."],
    "/owner/phones": ["phones", "Phones & lines", "Choose a phone to inspect its connection and manage its SMS lines."],
    "/owner/activity": ["activity", "Message activity", "Follow message outcomes and review requests that need your attention."],
    "/owner/integrations": ["integrations", "Integrations", "Manage API access and inspect webhook deliveries."],
    "/owner/security": ["security", "Security & sessions", "Review account access and manage signed-in sessions."],
    "/owner/setup": ["setup", "Add a phone", "Scan, compare, connect and approve the selected SIM. Completed steps stay saved."]
  });
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  function validateSetup(value, session) {
    if (!value || value.schema_version !== 1 || value.account_id !== session.account_id ||
        value.session_id !== session.session_id || !Number.isSafeInteger(value.observed_at_ms) ||
        typeof value.truncated !== "boolean" || !Array.isArray(value.pairings) || !Array.isArray(value.line_activations) ||
        value.pairings.length > 50 || value.line_activations.length > 50 || typeof value.sms_line_activation_available !== "boolean" || !Array.isArray(value.devices) || value.devices.length > 50) throw new Error("Saved setup progress could not be verified.");
    const seenPairings = new Set(), seenDevices = new Set();
    for (const item of value.pairings) {
      if (seenPairings.has(item.pairing_id) || !uuid.test(item.pairing_id) || typeof item.display_name !== "string" || !Number.isSafeInteger(item.expires_at_ms) ||
          !["pending_claim", "awaiting_proof", "awaiting_approval", "approved", "expired", "cancelled", "proof_rejected", "revoked"].includes(item.status) ||
          (item.approved_device_id !== null && !uuid.test(item.approved_device_id))) throw new Error("Saved pairing progress was invalid.");
      if (item.status === "awaiting_approval" && (!/^[0-9]{8}$/.test(item.comparison_code) || !/^[A-F0-9]{64}$/.test(item.key_fingerprint))) throw new Error("Saved comparison was invalid.");
      seenPairings.add(item.pairing_id);
    }
    for (const item of value.devices) {
      if (seenDevices.has(item.device_id) || ![item.device_id, item.setup_line_id, item.setup_opening_id].every(id => uuid.test(id)) || typeof item.revoked !== "boolean" || !/^[A-F0-9]{64}$/.test(item.key_fingerprint) || ![null, 1, 2].includes(item.line_activation_version)) throw new Error("Saved phone progress was invalid.");
      seenDevices.add(item.device_id);
    }
    for (const item of value.line_activations) {
      if (![item.line_id, item.challenge_id, item.device_id].every(id => uuid.test(id)) ||
          !/^[1-9][0-9]*$/.test(item.generation) || !Number.isSafeInteger(item.expires_at_ms) || BigInt(item.generation) > 9223372036854775807n || !uuid.test(item.opening_id) ||
          typeof item.same_session !== "boolean" || !["awaiting_device", "awaiting_owner", "approved", "expired", "retired", "session_changed", "connection_changed", "revoked"].includes(item.status)) throw new Error("Saved line progress was invalid.");
    }
    return value;
  }
  if (typeof module !== "undefined" && module.exports) { module.exports = { views, validateSetup }; return; }
  const selected = views[location.pathname] || views["/owner/devices"];
  const body = document.body;
  body.dataset.workspaceView = selected[0];
  body.dataset.progressState = "checking";
  document.querySelector(".owner-utilities").append(document.getElementById("logout"));
  document.querySelector(".owner-menu > summary").textContent = "Menu";
  const byId = id => document.getElementById(id);
  byId("workspace-title").textContent = selected[1];
  byId("workspace-intro").textContent = selected[2];
  document.title = selected[1] + " · ZROtext";
  for (const section of document.querySelectorAll("[data-workspace]")) {
    if (!section.dataset.workspace.split(" ").includes(selected[0])) section.setAttribute("inert", "");
  }
  for (const link of document.querySelectorAll(".owner-nav a")) {
    link.removeAttribute("aria-current");
    if (new URL(link.href).pathname === (selected[0] === "setup" ? "/owner/phones" : location.pathname)) link.setAttribute("aria-current", "page");
  }
  let epoch = 0, busy = false, active = true, timer = null, deviceId = null, snapshot = null;
  let requestedPairing = new URLSearchParams(location.search).get("pairing");
  if (requestedPairing !== null && !uuid.test(requestedPairing)) requestedPairing = null;
  let adding = new URLSearchParams(location.search).get("new") === "1";
  let checkingApproval = new URLSearchParams(location.search).get("approval") === "checking";
  function stage(value) {
    body.dataset.setupStage = value;
    byId("pair-title").textContent = value === "compare" ? "Compare your phone" : "Scan with your phone";
    if (value === "compare") message("Phone proof received. Compare the code and complete fingerprint below.");
    for (const item of document.querySelectorAll("[data-setup-step]")) {
      item.removeAttribute("aria-current");
      if (item.dataset.setupStep === value || (value === "complete" && item.dataset.setupStep === "line")) item.setAttribute("aria-current", "step");
    }
    byId("setup-connection").hidden = value !== "connect";
    byId("setup-complete").hidden = value !== "complete";
  }
  async function read(path) {
    const response = await fetch(path, { credentials: "same-origin", cache: "no-store", redirect: "error", signal: AbortSignal.timeout(15000) });
    if (!response.ok) throw new Error(response.status === 401 ? "Sign in to continue your saved setup." : "Could not check saved progress. Try Check progress when the server is available.");
    return response.json();
  }
  function schedule() {
    if (timer !== null) clearTimeout(timer);
    timer = null;
    if (active && !document.hidden && ["overview", "setup"].includes(selected[0])) timer = setTimeout(refresh, 10000);
  }
  function message(text) { byId("setup-resume-status").textContent = text; }
  async function refresh() {
    if (busy || !active || !["overview", "setup"].includes(selected[0])) return;
    const current = epoch;
    busy = true; byId("setup-refresh").disabled = true;
    try {
      const before = await read("/v1/auth/session");
      if (before.role !== "owner" || !uuid.test(before.account_id) || !uuid.test(before.session_id)) throw new Error("Sign in with your owner account to continue.");
      const progress = validateSetup(await read("/v1/account/setup"), before);
      const after = await read("/v1/auth/session");
      if (current !== epoch || !active) return;
      if (after.account_id !== before.account_id || after.session_id !== before.session_id) throw new Error("Your account changed. Sign in and check progress again.");
      snapshot = progress;
      body.dataset.progressState = "ready";
      byId("create-form").querySelector("button[type=submit]").disabled = progress.truncated;
      const pending = progress.pairings.find(p => ["pending_claim", "awaiting_proof", "awaiting_approval"].includes(p.status) && p.expires_at_ms > progress.observed_at_ms);
      const approved = progress.pairings.find(p => p.status === "approved" && p.approved_device_id && (!requestedPairing || p.pairing_id === requestedPairing));
      if (!deviceId && pending) {
        message(pending.status === "awaiting_approval" ? "Phone proof received. Compare both values to continue." : "Your phone pairing is saved. Continue on the phone, or replace the saved attempt if you cannot scan it.");
        stage(pending.status === "awaiting_approval" ? "compare" : "pair");
        if (selected[0] === "setup") {
          if (checkingApproval && requestedPairing === pending.pairing_id) globalThis.ZtOwnerPairing?.resumeUnknown(pending);
          else globalThis.ZtOwnerPairing?.resume(pending);
        }
        return;
      }
      const retainedDevice = progress.devices.find(d => !d.revoked && (!requestedPairing || d.pairing_id === requestedPairing));
      deviceId ||= adding ? null : approved?.approved_device_id || retainedDevice?.device_id || null;
      if (!deviceId) {
        message(progress.truncated ? "Some older setup records are outside this view. Check your phone overview before adding another phone." : "No unfinished phone setup found. Add a phone when you are ready.");
        const retired = progress.pairings.find(p => ["expired", "cancelled", "proof_rejected"].includes(p.status) && (!requestedPairing || p.pairing_id === requestedPairing));
        if (retired && selected[0] === "setup") globalThis.ZtOwnerPairing?.retire(retired.pairing_id);
        stage("pair"); return;
      }
      const devices = await read("/v1/enrollment/devices");
      const afterDevices = await read("/v1/auth/session");
      if (current !== epoch || !active) return;
      if (afterDevices.account_id !== before.account_id || afterDevices.session_id !== before.session_id) throw new Error("Your sign-in changed. Check progress again.");
      const device = devices.devices?.find(d => d.device_id === deviceId && !d.revoked);
      if (!device) { deviceId = null; message("The saved phone is unavailable in this page of devices. Review your phone overview before adding another."); stage("pair"); return; }
      if (!device.active_socket_lease) {
        stage("connect");
        message("Phone approval is saved. Choose its SIM and permissions in the app, then Start connection.");
        return;
      }
      const line = progress.line_activations.find(a => a.device_id === deviceId && a.status === "approved");
      if (line) { stage("complete"); message("Phone connected · Line approval recorded. Carrier testing is a separate action."); return; }
      stage("line");
      message("Phone connection observed. Continue with its selected SIM declaration below.");
      if (selected[0] === "setup") {
        const pendingLine = progress.line_activations.find(a => a.device_id === deviceId && ["awaiting_device", "awaiting_owner"].includes(a.status));
        if (!progress.sms_line_activation_available) { message("Phone connected. Line activation is unavailable on this server; your successful phone approval is saved."); return; }
        if (progress.truncated && !pendingLine) {
          globalThis.ZtSmsLinesController?.blockNew("Saved progress is incomplete. Locate the existing phone and line before requesting another declaration.");
          message("Some setup records are outside this view. A new line request is blocked until the existing ceremony is located."); return;
        }
        const locator = progress.devices?.find(d => d.device_id === deviceId && !d.revoked);
        const affected = progress.line_activations.find(a => a.device_id === deviceId && ["session_changed", "connection_changed"].includes(a.status));
        await globalThis.ZtSmsLinesController?.selectDevice(deviceId, pendingLine || affected || null, locator || null);
        const changed = progress.line_activations.find(a => a.device_id === deviceId && a.status === "session_changed");
        if (affected?.status === "connection_changed") message("Phone approval is saved. The phone connection changed, so a fresh declaration is required before line approval.");
        else if (changed && !pendingLine) message("Phone approval is saved. Your sign-in changed, so review a fresh phone declaration; the account and subscription are unchanged.");
      }
    } catch (error) {
      if (current === epoch && active) { snapshot = null; body.dataset.progressState = "error"; byId("create-form").querySelector("button[type=submit]").disabled = true; message(error.message); }
    } finally {
      busy = false; byId("setup-refresh").disabled = false; schedule();
    }
  }
  globalThis.ZtOwnerWorkspace = Object.freeze({ stage, refresh, approvedDevice(id) { if (uuid.test(id)) { deviceId = id; stage("connect"); refresh(); } }, snapshot: () => snapshot,
    canCreate: () => snapshot !== null && !snapshot.truncated,
    async assertCurrent() {
      const saved = snapshot;
      if (!saved) throw new Error("Check setup progress before continuing.");
      const fresh = await read("/v1/auth/session");
      if (saved !== snapshot || fresh.account_id !== saved.account_id || fresh.session_id !== saved.session_id) {
        epoch++; snapshot = null; globalThis.ZtOwnerPairing?.clear();
        message("Your sign-in changed. Check progress before continuing the affected step.");
        throw new Error("Your sign-in changed. Check progress before continuing.");
      }
    },
    approvalStarted(id) {
      if (!uuid.test(id)) return;
      checkingApproval = true; requestedPairing = id;
      history.replaceState(null, "", "/owner/setup?pairing=" + encodeURIComponent(id) + "&approval=checking");
    },
    pairingStarted(id) {
      if (!uuid.test(id)) return;
      requestedPairing = id; adding = false;
      message("Pairing QR ready. Scan it with the gateway app to continue.");
      history.replaceState(null, "", "/owner/setup?pairing=" + encodeURIComponent(id));
    }
  });
  byId("setup-refresh").addEventListener("click", refresh);
  document.addEventListener("zrotext-owner-session", event => {
    epoch++; snapshot = null; deviceId = null;
    if (event.detail?.signedIn) refresh();
    else { stage("pair"); message("Sign in to continue your saved setup."); }
  });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); else if (timer !== null) { clearTimeout(timer); timer = null; } });
  window.addEventListener("pagehide", () => { active = false; epoch++; snapshot = null; if (timer !== null) clearTimeout(timer); });
  window.addEventListener("pageshow", () => { active = true; refresh(); });
  byId("create-form").querySelector("button[type=submit]").disabled = true;
  stage("pair");
})();
