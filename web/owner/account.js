// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const byId = (id) => document.getElementById(id);
let viewEpoch = 0;
const requestTimeoutMs = 30_000;

function status(id, value) {
  byId(id).textContent = value;
}

// Ignore repeat submits while the first request is still running, so a double
// click cannot send a second registration, code, or MFA change.
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

function csrfToken() {
  const cookie = document.cookie.split(";").map((part) => part.trim())
    .find((part) => part.startsWith("__Host-zrotext_csrf="));
  return cookie ? cookie.slice("__Host-zrotext_csrf=".length) : null;
}

function clearMfaSecrets() {
  byId("mfa-secret").textContent = "";
  byId("mfa-provisioning-uri").textContent = "";
  byId("mfa-secret-panel").hidden = true;
  byId("mfa-confirm-code").value = "";
  byId("mfa-confirm-form").hidden = true;
  byId("recovery-codes").replaceChildren();
  byId("recovery-panel").hidden = true;
}

const errors = Object.freeze({
  400: "Check the entered values and try again.",
  401: "Your sign-in expired or the credentials were not accepted.",
  403: "This action was refused. Sign in again before managing MFA.",
  404: "This feature is unavailable on this server.",
  429: "Too many attempts. Wait before trying again.",
  503: "The service is unavailable. Try again later.",
});

async function request(path, method = "GET", body = undefined, invite = "") {
  const headers = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (invite) headers["x-zrotext-registration-token"] = invite;
  if (method !== "GET" && path.startsWith("/v1/auth/mfa/")) {
    const csrf = csrfToken();
    if (!csrf) throw new Error("Sign in before managing MFA.");
    headers["x-zrotext-csrf"] = csrf;
  }
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
  return response.status === 202 || response.status === 204 ? null : response.json();
}

async function refreshMfa() {
  const epoch = viewEpoch;
  const state = await request("/v1/auth/mfa");
  if (epoch !== viewEpoch) return;
  if (!state || typeof state.enabled !== "boolean" || typeof state.pending !== "boolean") {
    throw new Error("The MFA status response was invalid.");
  }
  byId("mfa-enroll-form").hidden = state.enabled;
  byId("mfa-disable-form").hidden = !state.enabled;
  status("mfa-status", state.enabled ? "Authenticator enabled."
    : state.pending ? "Setup is pending. Start it again to show a new secret."
      : "Authenticator is not enabled.");
}

async function loadSession() {
  const epoch = viewEpoch;
  try {
    await request("/v1/auth/session");
    if (epoch !== viewEpoch) return;
    byId("mfa-section").hidden = false;
    await refreshMfa();
  } catch (error) {
    if (epoch !== viewEpoch) return;
    viewEpoch += 1;
    byId("mfa-section").hidden = true;
    clearMfaSecrets();
    status("account-status", error.status === 401
      ? "Sign in on the Devices page to manage your authenticator."
      : `Could not check your account session. ${error.message}`);
  }
}

byId("register-form").addEventListener("submit", exclusive(async (event) => {
  event.preventDefault();
  const email = byId("register-email").value;
  const password = byId("register-password").value;
  const invite = byId("register-token").value.trim();
  status("register-status", "Sending registration request…");
  try {
    await request("/v1/auth/register", "POST", { email, password }, invite);
    status("register-status", "Request received. If registration is open for this address, check your mailbox for a code.");
    byId("resend-email").value = email;
  } catch (error) {
    status("register-status", `Registration request failed. ${error.message}`);
  } finally {
    byId("register-password").value = "";
    byId("register-token").value = "";
  }
}));

byId("verify-form").addEventListener("submit", exclusive(async (event) => {
  event.preventDefault();
  const token = byId("verification-code").value.trim();
  status("verify-status", "Verifying email…");
  try {
    await request("/v1/auth/verify-email", "POST", { token });
    status("verify-status", "Email verified. You can sign in on the Devices page.");
  } catch (error) {
    status("verify-status", `Verification failed. ${error.message}`);
  } finally {
    byId("verification-code").value = "";
  }
}));

byId("resend-form").addEventListener("submit", exclusive(async (event) => {
  event.preventDefault();
  status("resend-status", "Requesting a new code…");
  try {
    await request("/v1/auth/resend-verification", "POST", {
      email: byId("resend-email").value,
      password: byId("resend-password").value,
    });
    status("resend-status", "Request received. If this account is eligible, check your mailbox for a new code.");
  } catch (error) {
    status("resend-status", `Code request failed. ${error.message}`);
  } finally {
    byId("resend-password").value = "";
  }
}));

byId("mfa-enroll-form").addEventListener("submit", exclusive(async (event) => {
  event.preventDefault();
  clearMfaSecrets();
  const epoch = viewEpoch;
  try {
    const enrollment = await request("/v1/auth/mfa/enroll", "POST", {
      password: byId("mfa-enroll-password").value,
    });
    if (epoch !== viewEpoch) return;
    if (!enrollment || typeof enrollment.secret_base32 !== "string" ||
        !/^[A-Z2-7]{16,}$/.test(enrollment.secret_base32) ||
        typeof enrollment.provisioning_uri !== "string" ||
        !enrollment.provisioning_uri.startsWith("otpauth://totp/")) {
      throw new Error("The enrollment response was invalid.");
    }
    byId("mfa-secret").textContent = enrollment.secret_base32;
    byId("mfa-provisioning-uri").textContent = enrollment.provisioning_uri;
    byId("mfa-secret-panel").hidden = false;
    byId("mfa-confirm-form").hidden = false;
    status("mfa-status", "Add the secret to your authenticator, then confirm its code.");
  } catch (error) {
    if (epoch !== viewEpoch) return;
    status("mfa-status", `Could not start authenticator setup. ${error.message}`);
    if (error.status === 401 || error.status === 403) await loadSession();
  } finally {
    byId("mfa-enroll-password").value = "";
  }
}));

byId("mfa-confirm-form").addEventListener("submit", exclusive(async (event) => {
  event.preventDefault();
  const epoch = viewEpoch;
  try {
    const recovery = await request("/v1/auth/mfa/confirm", "POST", {
      code: byId("mfa-confirm-code").value.trim(),
    });
    if (epoch !== viewEpoch) return;
    if (!recovery || !Array.isArray(recovery.recovery_codes) ||
        recovery.recovery_codes.length === 0 || recovery.recovery_codes.length > 20 ||
        !recovery.recovery_codes.every((code) => typeof code === "string" && code.length <= 64)) {
      throw new Error("The recovery-code response was invalid.");
    }
    clearMfaSecrets();
    for (const code of recovery.recovery_codes) {
      const item = document.createElement("li");
      item.textContent = code;
      byId("recovery-codes").append(item);
    }
    byId("recovery-panel").hidden = false;
    status("mfa-status", "Authenticator enabled. Save the recovery codes before leaving.");
    byId("mfa-enroll-form").hidden = true;
    byId("mfa-disable-form").hidden = false;
    try {
      await refreshMfa();
      if (epoch !== viewEpoch) return;
      status("mfa-status", "Authenticator enabled. Save the recovery codes before leaving.");
    } catch (error) {
      if (epoch !== viewEpoch) return;
      if (error.status === 401 || error.status === 403) await loadSession();
      else status("mfa-status", "Authenticator enabled. Save the recovery codes; status refresh is unavailable.");
    }
  } catch (error) {
    if (epoch !== viewEpoch) return;
    status("mfa-status", `Could not confirm authenticator. ${error.message}`);
    if (error.status === 401 || error.status === 403) await loadSession();
  }
}));

byId("dismiss-recovery").addEventListener("click", () => {
  clearMfaSecrets();
  status("mfa-status", "Recovery codes cleared from this page.");
});

byId("mfa-disable-form").addEventListener("submit", exclusive(async (event) => {
  event.preventDefault();
  const epoch = viewEpoch;
  try {
    await request("/v1/auth/mfa/disable", "POST", {
      password: byId("mfa-disable-password").value,
      code: byId("mfa-disable-code").value.trim(),
    });
    if (epoch !== viewEpoch) return;
    clearMfaSecrets();
    byId("mfa-enroll-form").hidden = false;
    byId("mfa-disable-form").hidden = true;
    status("mfa-status", "Authenticator disabled.");
    try {
      await refreshMfa();
      if (epoch !== viewEpoch) return;
      status("mfa-status", "Authenticator disabled.");
    } catch (error) {
      if (epoch !== viewEpoch) return;
      if (error.status === 401 || error.status === 403) await loadSession();
      else status("mfa-status", "Authenticator disabled. Status refresh is unavailable.");
    }
  } catch (error) {
    if (epoch !== viewEpoch) return;
    status("mfa-status", `Could not disable authenticator. ${error.message}`);
    if (error.status === 401 || error.status === 403) await loadSession();
  } finally {
    byId("mfa-disable-password").value = "";
    byId("mfa-disable-code").value = "";
  }
}));

window.addEventListener("pagehide", () => {
  viewEpoch += 1;
  clearMfaSecrets();
});
loadSession();
