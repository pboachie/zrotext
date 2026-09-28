// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const byId = (id) => document.getElementById(id);
const requestTimeoutMs = 30_000;
const timeFormat = new Intl.DateTimeFormat(undefined, {
  year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", second: "numeric",
});
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const errors = Object.freeze({
  400: "Check the entered values and try again.",
  401: "Your sign-in expired or the credentials were not accepted.",
  403: "This action was refused. Refresh the page and sign in again.",
  404: "The requested item was not found, expired, or is no longer available.",
  429: "Too many attempts. Wait before trying again.",
  503: "The service is unavailable. Try again later.",
});

function status(id, value) {
  byId(id).textContent = value;
}

function csrfToken() {
  const cookie = document.cookie.split(";").map((part) => part.trim())
    .find((part) => part.startsWith("__Host-zrotext_csrf="));
  return cookie ? cookie.slice("__Host-zrotext_csrf=".length) : null;
}

function exclusive(handler) {
  let running = false;
  return async (event) => {
    if (event && typeof event.preventDefault === "function") event.preventDefault();
    if (running) return;
    running = true;
    const submitter = event && event.submitter;
    if (submitter) submitter.disabled = true;
    try {
      await handler(event);
    } finally {
      running = false;
      if (submitter) submitter.disabled = false;
    }
  };
}

async function request(path, method = "GET", body = undefined) {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  const csrf = csrfToken();
  if (csrf) headers["x-zrotext-csrf"] = csrf;
  let response;
  try {
    response = await fetch(path, {
      method, headers, credentials: "same-origin", cache: "no-store", redirect: "error",
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(requestTimeoutMs) : undefined,
    });
  } catch (error) {
    throw new Error(error && error.name === "TimeoutError"
      ? "The server did not respond in time. Try again."
      : "Could not reach the server. Check your connection and try again.");
  }
  if (!response.ok) {
    const error = new Error(errors[response.status] || `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return response.status === 204 ? null : response.json();
}

function isUuid(value) {
  return typeof value === "string" && uuidPattern.test(value);
}

function text(kind, value) {
  const node = document.createElement(kind);
  node.textContent = value;
  return node;
}

function deviceItem(device) {
  if (!isUuid(device.device_id) || typeof device.display_name !== "string"
    || typeof device.revoked !== "boolean" || typeof device.active_socket_lease !== "boolean"
    || typeof device.pending_messages !== "number" || typeof device.in_flight_messages !== "number") {
    throw new Error("A device entry was invalid.");
  }
  const item = document.createElement("li");
  item.append(
    text("strong", device.display_name),
    text("span", ` — ${device.revoked ? "revoked" : device.active_socket_lease
      ? "connected" : "not connected"}`
      + `, ${device.pending_messages} pending, ${device.in_flight_messages} in flight`),
  );
  return item;
}

async function refreshDevices() {
  const body = await request("/v1/observer/devices");
  if (!body || !Array.isArray(body.devices)) {
    throw new Error("The device-status response was invalid.");
  }
  const list = byId("device-list");
  list.replaceChildren();
  if (body.devices.length === 0) {
    list.append(text("li", "No gateway devices are enrolled for this account yet."));
    return;
  }
  for (const device of body.devices) list.append(deviceItem(device));
}

async function showSignedIn() {
  byId("accept-section").hidden = true;
  byId("sign-in-section").hidden = true;
  byId("verify-section").hidden = true;
  byId("status-section").hidden = false;
  byId("password-section").hidden = false;
  byId("logout").hidden = false;
  try {
    await refreshDevices();
    status("device-status", "");
  } catch (error) {
    status("device-status", `Could not load device status. ${error.message}`);
  }
}

async function loadSession() {
  let session = null;
  try {
    session = await request("/v1/auth/session");
  } catch (error) {
    if (error.status !== 401) {
      status("observer-status", `Could not check your session. ${error.message}`);
      return;
    }
  }
  if (session && session.role === "observer") {
    await showSignedIn();
    return;
  }
  if (session && session.role === "owner") {
    status("observer-status", "You are signed in as the owner. Use the Devices page for the full dashboard.");
    byId("accept-section").hidden = true;
    byId("verify-section").hidden = true;
    byId("status-section").hidden = true;
    byId("password-section").hidden = true;
    byId("logout").hidden = false;
    return;
  }
  byId("accept-section").hidden = false;
  byId("verify-section").hidden = true;
  byId("status-section").hidden = true;
  byId("password-section").hidden = true;
  byId("logout").hidden = true;
  byId("sign-in-section").hidden = false;
}

byId("accept-form").addEventListener("submit", exclusive(async (event) => {
  event.preventDefault();
  const token = byId("accept-token").value.trim();
  const password = byId("accept-password").value;
  status("accept-status", "Accepting invitation…");
  try {
    await request("/v1/auth/seats/accept", "POST", { token, password });
    byId("accept-section").hidden = true;
    byId("verify-section").hidden = false;
    status("accept-status", "Invitation accepted. Check your email for a verification code.");
  } catch (error) {
    status("accept-status", `Acceptance failed. ${error.message}`);
  } finally {
    byId("accept-token").value = "";
    byId("accept-password").value = "";
  }
}));

byId("verify-form").addEventListener("submit", exclusive(async (event) => {
  event.preventDefault();
  const token = byId("verify-code").value.trim();
  const password = byId("verify-password").value;
  status("verify-status", "Verifying email…");
  try {
    await request("/v1/auth/verify-email", "POST", { token, password });
    byId("verify-section").hidden = true;
    byId("sign-in-section").hidden = false;
    status("verify-status", "Email verified. Sign in below.");
  } catch (error) {
    status("verify-status", `Verification failed. ${error.message}`);
  } finally {
    byId("verify-code").value = "";
    byId("verify-password").value = "";
  }
}));

byId("login-form").addEventListener("submit", exclusive(async (event) => {
  event.preventDefault();
  const email = byId("login-email").value;
  const password = byId("login-password").value;
  status("login-status", "Signing in…");
  try {
    await request("/v1/auth/login", "POST", { email, password });
    status("login-status", "Signed in.");
    await loadSession();
  } catch (error) {
    status("login-status", error.status === 403
      ? "Verify your email before signing in."
      : `Sign-in failed. ${error.message}`);
  } finally {
    byId("login-password").value = "";
  }
}));

byId("password-form").addEventListener("submit", exclusive(async (event) => {
  event.preventDefault();
  const current = byId("current-password").value;
  const next = byId("new-password").value;
  status("password-status", "Changing password…");
  try {
    await request("/v1/auth/password", "POST", {
      current_password: current,
      new_password: next,
    });
    status("password-status", "Password changed. All sessions were signed out; sign in again.");
    byId("status-section").hidden = true;
    byId("password-section").hidden = true;
    byId("logout").hidden = true;
    byId("sign-in-section").hidden = false;
  } catch (error) {
    status("password-status", `Password change failed. ${error.message}`);
  } finally {
    byId("current-password").value = "";
    byId("new-password").value = "";
  }
}));

byId("logout").addEventListener("click", exclusive(async () => {
  try {
    await request("/v1/auth/logout", "POST");
  } catch (error) {
    status("observer-status", `Sign-out failed. ${error.message}`);
    return;
  }
  byId("status-section").hidden = true;
  byId("password-section").hidden = true;
  byId("logout").hidden = true;
  byId("sign-in-section").hidden = false;
  status("observer-status", "Signed out.");
}));

byId("refresh-devices").addEventListener("click", exclusive(async () => {
  status("device-status", "Refreshing…");
  try {
    await refreshDevices();
    status("device-status", "");
  } catch (error) {
    status("device-status", `Could not refresh device status. ${error.message}`);
    if (error.status === 401) {
      byId("status-section").hidden = true;
      byId("password-section").hidden = true;
      byId("logout").hidden = true;
      byId("sign-in-section").hidden = false;
    }
  }
}));

loadSession();
