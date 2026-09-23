// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const byId = (id) => document.getElementById(id);
let activePairingId = null;
let nextDeviceCursor = null;
let shownDeviceCount = 0;
let nextMessageCursor = null;
let shownMessageCount = 0;

function message(id, value) {
  byId(id).textContent = value;
}

function csrfToken() {
  const part = document.cookie.split(";").map((piece) => piece.trim())
    .find((piece) => piece.startsWith("__Host-zrotext_csrf="));
  return part ? part.slice("__Host-zrotext_csrf=".length) : null;
}

async function api(path, method = "GET", body = undefined) {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && path !== "/v1/auth/login") {
    const csrf = csrfToken();
    if (!csrf) throw new Error("Your sign-in expired. Sign in again.");
    headers["x-zrotext-csrf"] = csrf;
  }
  const response = await fetch(path, {
    method, headers, credentials: "same-origin", cache: "no-store", redirect: "error",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const descriptions = {
      400: "Check the entered values and try again.",
      401: "Your sign-in expired. Sign in again.",
      403: "This action was refused. Refresh the page and sign in again.",
      404: "The pairing or device was not found, expired, or is no longer available.",
      409: "This action conflicts with the current device state.",
      413: "The request is too large.",
      429: "Too many requests. Wait before trying again.",
      503: "The service is unavailable. Try again later.",
    };
    throw new Error(descriptions[response.status] || `Request failed (${response.status}).`);
  }
  return response.status === 204 ? null : response.json();
}

function showSignedIn(signedIn) {
  byId("sign-in").hidden = signedIn;
  byId("owner-content").hidden = !signedIn;
  byId("logout").hidden = !signedIn;
}

function clearPairing() {
  activePairingId = null;
  byId("pair-ticket").hidden = true;
  byId("approve-form").hidden = true;
  for (const id of ["pair-id", "pair-token", "browser-code", "browser-fingerprint", "phone-code", "phone-fingerprint"]) {
    byId(id).textContent = "";
    if ("value" in byId(id)) byId(id).value = "";
  }
  byId("compared").checked = false;
}

async function loadDevices(reset = true) {
  message("device-status", "Loading devices…");
  if (reset) {
    byId("device-list").replaceChildren();
    byId("more-devices").hidden = true;
    nextDeviceCursor = null;
    shownDeviceCount = 0;
  }
  try {
    const path = nextDeviceCursor
      ? `/v1/enrollment/devices?before=${encodeURIComponent(nextDeviceCursor)}`
      : "/v1/enrollment/devices";
    const page = await api(path);
    const devices = page.devices;
    if (reset && devices.length === 0) {
      message("device-status", "No approved devices yet.");
      return;
    }
    nextDeviceCursor = page.next_cursor;
    shownDeviceCount += devices.length;
    byId("more-devices").hidden = !nextDeviceCursor;
    message("device-status", `${shownDeviceCount} device${shownDeviceCount === 1 ? "" : "s"} shown${nextDeviceCursor ? "; more available" : ""}. Revoked devices stay visible.`);
    for (const device of devices) {
      const row = document.createElement("li");
      const detail = document.createElement("div");
      const name = document.createElement("strong");
      const id = document.createElement("code");
      const state = document.createElement("span");
      name.textContent = device.display_name;
      id.textContent = device.device_id;
      state.textContent = device.revoked ? "Revoked" : "Approved";
      detail.append(name, id, state);
      row.append(detail);
      if (!device.revoked) {
        const revoke = document.createElement("button");
        revoke.type = "button";
        revoke.textContent = "Revoke";
        revoke.setAttribute("aria-label", `Revoke ${device.display_name}`);
        revoke.addEventListener("click", async () => {
          if (!window.confirm(`Revoke ${device.display_name}? Its gateway connection will lose authorization.`)) return;
          revoke.disabled = true;
          try {
            await api(`/v1/enrollment/devices/${encodeURIComponent(device.device_id)}`, "DELETE");
            await loadDevices();
          } catch (error) {
            message("device-status", error.message);
            revoke.disabled = false;
          }
        });
        row.append(revoke);
      }
      byId("device-list").append(row);
    }
  } catch (error) {
    message("device-status", `Could not load devices. ${error.message}`);
  }
}

function localTime(milliseconds) {
  const date = new Date(milliseconds);
  return Number.isFinite(milliseconds) && !Number.isNaN(date.getTime())
    ? date.toLocaleString() : "Time unavailable";
}

async function loadMessages(reset = true) {
  message("message-status", "Loading message states…");
  if (reset) {
    byId("message-list").replaceChildren();
    byId("more-messages").hidden = true;
    nextMessageCursor = null;
    shownMessageCount = 0;
  }
  try {
    const path = nextMessageCursor
      ? `/v1/owner/messages?before=${encodeURIComponent(nextMessageCursor)}`
      : "/v1/owner/messages";
    const page = await api(path);
    if (reset && page.messages.length === 0) {
      message("message-status", "No messages yet.");
      return;
    }
    nextMessageCursor = page.next_cursor;
    shownMessageCount += page.messages.length;
    byId("more-messages").hidden = !nextMessageCursor;
    message("message-status", `${shownMessageCount} message${shownMessageCount === 1 ? "" : "s"} shown${nextMessageCursor ? "; more available" : ""}.`);
    for (const item of page.messages) {
      const row = document.createElement("li");
      const state = document.createElement("strong");
      const id = document.createElement("code");
      const device = document.createElement("span");
      const created = document.createElement("time");
      state.textContent = item.state.replaceAll("_", " ");
      id.textContent = item.message_id;
      device.textContent = `Gateway ${item.device_id}`;
      created.textContent = ` · Created ${localTime(item.created_at_ms)}`;
      const createdDate = new Date(item.created_at_ms);
      if (!Number.isNaN(createdDate.getTime())) created.dateTime = createdDate.toISOString();
      row.append(state, id, device, created);
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = `Writer events (${item.events.length}${item.events_truncated ? " most recent" : ""})`;
      details.append(summary);
      if (item.events.length === 0) {
        const none = document.createElement("p");
        none.textContent = "No writer event has been recorded yet.";
        details.append(none);
      } else {
        const list = document.createElement("ol");
        for (const event of item.events) {
          const entry = document.createElement("li");
          const segment = event.segment_index === null || event.segment_count === null
            ? "" : ` · segment ${event.segment_index + 1}/${event.segment_count}`;
          entry.textContent = `${localTime(event.received_at_ms)} · ${event.evidence.replaceAll("_", " ")} → ${event.resulting_state.replaceAll("_", " ")}${segment}`;
          list.append(entry);
        }
        details.append(list);
      }
      row.append(details);
      byId("message-list").append(row);
    }
  } catch (error) {
    message("message-status", `Could not load messages. ${error.message}`);
  }
}

async function checkPairing() {
  if (!activePairingId) return;
  const pairingId = activePairingId;
  message("pair-status", "Checking phone proof…");
  try {
    const view = await api(`/v1/enrollment/pairings/${encodeURIComponent(pairingId)}`);
    if (pairingId !== activePairingId) return;
    if (view.approved_device_id) {
      message("approved-result", `Approved device UUID: ${view.approved_device_id}`);
      message("pair-status", "Pairing complete.");
      clearPairing();
      await loadDevices();
      return;
    }
    if (!view.claimed) {
      message("pair-status", "Waiting for the phone to claim this pairing.");
      return;
    }
    if (!view.proof_verified) {
      message("pair-status", "Phone claimed the pairing. Waiting for its key proof. If proof failed, cancel and create a new pairing.");
      return;
    }
    byId("browser-code").textContent = view.comparison_code;
    byId("browser-fingerprint").textContent = view.key_fingerprint;
    byId("approve-form").hidden = false;
    message("pair-status", "Key proof accepted. Compare the code and fingerprint with the phone before approval.");
  } catch (error) {
    message("pair-status", `Could not check pairing. ${error.message}`);
    byId("approve-form").hidden = true;
    // A 404 includes expiry, cancellation and exhaustion. Retire the
    // one-time token locally rather than presenting it as still usable.
    if (error.message.startsWith("The pairing or device")) clearPairing();
  }
}

byId("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  message("login-status", "Signing in…");
  const password = byId("password").value;
  byId("password").value = "";
  try {
    await api("/v1/auth/login", "POST", { email: byId("email").value, password });
    showSignedIn(true);
    message("login-status", "");
    message("global-status", "Signed in.");
    await Promise.all([loadDevices(), loadMessages()]);
  } catch (error) {
    message("login-status", `Sign-in failed. ${error.message}`);
  }
});

byId("logout").addEventListener("click", async () => {
  try {
    await api("/v1/auth/logout", "POST");
    clearPairing();
    byId("device-list").replaceChildren();
    byId("more-devices").hidden = true;
    nextDeviceCursor = null;
    shownDeviceCount = 0;
    byId("message-list").replaceChildren();
    byId("more-messages").hidden = true;
    nextMessageCursor = null;
    shownMessageCount = 0;
    showSignedIn(false);
    message("global-status", "Signed out.");
  } catch (error) {
    message("global-status", `Could not sign out. ${error.message}`);
  }
});

byId("create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (activePairingId) {
    message("pair-status", "Finish or cancel the current pairing before creating another.");
    return;
  }
  clearPairing();
  message("approved-result", "");
  message("pair-status", "Creating pairing…");
  try {
    const ticket = await api("/v1/enrollment/pairings", "POST", { display_name: byId("display-name").value });
    activePairingId = ticket.pairing_id;
    byId("server-origin").textContent = window.location.origin;
    byId("pair-id").textContent = ticket.pairing_id;
    byId("pair-token").textContent = ticket.token;
    byId("pair-ticket").hidden = false;
    message("pair-status", "Pairing created. Enter the ID and token on the phone within five minutes.");
  } catch (error) {
    message("pair-status", `Could not create pairing. ${error.message}`);
  }
});

byId("check-proof").addEventListener("click", checkPairing);
byId("cancel-pairing").addEventListener("click", async () => {
  if (!activePairingId) return;
  try {
    await api(`/v1/enrollment/pairings/${encodeURIComponent(activePairingId)}/cancel`, "POST");
    clearPairing();
    message("pair-status", "Pairing cancelled. Create a new one when ready.");
  } catch (error) {
    message("pair-status", `Could not cancel pairing. ${error.message}`);
  }
});

byId("approve-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!activePairingId || !byId("compared").checked) return;
  message("pair-status", "Approving device…");
  try {
    const result = await api(`/v1/enrollment/pairings/${encodeURIComponent(activePairingId)}/approve`, "POST", {
      comparison_code: byId("phone-code").value,
      key_fingerprint: byId("phone-fingerprint").value.toUpperCase(),
    });
    message("approved-result", `Approved device UUID: ${result.device_id}`);
    message("pair-status", "Pairing complete. Enter this UUID on the phone for its authenticated gateway connection.");
    clearPairing();
    await loadDevices();
  } catch (error) {
    message("pair-status", `Approval failed. ${error.message} Check the phone values. Repeated mismatches lock this pairing.`);
  }
});

byId("refresh-devices").addEventListener("click", loadDevices);
byId("more-devices").addEventListener("click", () => loadDevices(false));
byId("refresh-messages").addEventListener("click", loadMessages);
byId("more-messages").addEventListener("click", () => loadMessages(false));

(async () => {
  try {
    await api("/v1/auth/session");
    showSignedIn(true);
    await Promise.all([loadDevices(), loadMessages()]);
  } catch (error) {
    showSignedIn(false);
    message("global-status", error.message.startsWith("Your sign-in") ? "Sign in to manage devices." : `Could not verify session. ${error.message}`);
  }
})();
