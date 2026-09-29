// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const byId = (id) => document.getElementById(id);
const requestTimeoutMs = 30_000;
const timeFormat = new Intl.DateTimeFormat(undefined, {
  year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric",
});
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const invitationLabels = Object.freeze({
  open: "Open",
  accepted: "Accepted",
  canceled: "Canceled",
  expired: "Expired",
});

const seatLabels = Object.freeze({
  active: "Active",
  pending_verification: "Awaiting email verification",
  removed: "Removed",
});

const errors = Object.freeze({
  400: "Check the entered values, your password, and your code, then try again.",
  401: "Your sign-in expired or the credentials were not accepted.",
  403: "This action was refused. Refresh the page and sign in again.",
  404: "The requested item was not found, expired, or is no longer available.",
  409: "The seat or invitation limit is reached.",
  429: "Too many requests. Wait before trying again.",
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

// Ignore repeat submits while the first request is still running, so a double
// click cannot invite twice or remove two seats.
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
  return response.status === 202 || response.status === 204 ? null : response.json();
}

function validEmail(value) {
  return typeof value === "string" && value.length <= 254
    && value === value.trim().toLowerCase()
    && value.split("@").length === 2
    && value.indexOf(" ") === -1;
}

function isUuid(value) {
  return typeof value === "string" && uuidPattern.test(value);
}

// The server reports whether removing a seat freed its address. In the rare
// case it could not delete the observer's record, the seat is still removed and
// every credential revoked, but the address stays occupied.
function addressNote(free) {
  return free
    ? "The address is free and can be invited again."
    : "The address stays occupied and cannot accept a new invitation.";
}

function text(kind, value) {
  const node = document.createElement(kind);
  node.textContent = value;
  return node;
}

async function loadSeats() {
  const body = await request("/v1/auth/seats");
  if (!body || !Array.isArray(body.seats) || !Array.isArray(body.invitations)) {
    throw new Error("The seats response was invalid.");
  }
  const invitations = byId("invitation-list");
  invitations.replaceChildren();
  if (body.invitations.length === 0) {
    invitations.append(text("li", "No invitations yet."));
  }
  for (const invitation of body.invitations) {
    if (!isUuid(invitation.id) || !validEmail(invitation.email)
      || typeof invitation.expires_at_ms !== "number"
      || typeof invitation.created_at_ms !== "number") {
      throw new Error("An invitation entry was invalid.");
    }
    const item = document.createElement("li");
    const label = invitationLabels[invitation.status] || "Unknown";
    item.append(
      text("strong", invitation.email),
      text("span", ` — ${label}, expires ${timeFormat.format(new Date(invitation.expires_at_ms))}`),
    );
    if (invitation.status === "open") {
      const cancel = document.createElement("button");
      cancel.type = "button";
      cancel.className = "quiet";
      cancel.textContent = "Cancel invitation";
      cancel.addEventListener("click", exclusive(async () => {
        status("invitation-status", "Canceling invitation…");
        try {
          await request(`/v1/auth/seats/invitations/${invitation.id}`, "DELETE");
          status("invitation-status", "Invitation canceled. The token no longer works.");
          await loadSeats();
        } catch (error) {
          status("invitation-status", `Could not cancel the invitation. ${error.message}`);
        }
      }));
      item.append(cancel);
    }
    invitations.append(item);
  }

  const seats = byId("seat-list");
  seats.replaceChildren();
  if (body.seats.length === 0) {
    seats.append(text("li", "No observer seats yet."));
  }
  for (const seat of body.seats) {
    // A removed seat whose user was deleted has no user id.
    if ((seat.user_id !== null && !isUuid(seat.user_id)) || !validEmail(seat.email)
      || typeof seat.created_at_ms !== "number"
      || typeof seat.email_verified !== "boolean"
      || typeof seat.address_free !== "boolean") {
      throw new Error("A seat entry was invalid.");
    }
    const item = document.createElement("li");
    const label = seatLabels[seat.status] || "Unknown";
    item.append(
      text("strong", seat.email),
      text("span", ` — ${label} since ${timeFormat.format(new Date(seat.created_at_ms))}`),
    );
    if (seat.status === "removed") {
      item.append(text("span", ` — ${addressNote(seat.address_free)}`));
    }
    if (seat.status !== "removed" && isUuid(seat.user_id)) {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "quiet";
      remove.textContent = "Remove seat";
      remove.addEventListener("click", exclusive(async () => {
        status("seat-status", "Removing the seat…");
        try {
          const removed = await request(`/v1/auth/seats/${seat.user_id}`, "DELETE");
          if (!removed || removed.status !== "removed" || typeof removed.address_free !== "boolean") {
            throw new Error("The removal response was invalid.");
          }
          status(
            "seat-status",
            `Seat removed. Its sessions and credentials are revoked. ${addressNote(removed.address_free)}`,
          );
          await loadSeats();
        } catch (error) {
          status("seat-status", `Could not remove the seat. ${error.message}`);
        }
      }));
      item.append(remove);
    }
    seats.append(item);
  }
}

byId("invite-form").addEventListener("submit", exclusive(async (event) => {
  event.preventDefault();
  const email = byId("invite-email").value.trim().toLowerCase();
  const password = byId("invite-password").value;
  const code = byId("invite-code").value.trim();
  if (password === "") {
    status("invite-status", "Enter your password to invite an observer.");
    return;
  }
  status("invite-status", "Creating invitation…");
  try {
    // An invitation grants a persistent read seat, so it needs the same proof
    // as API-key creation: the current password and, with MFA on, a code.
    const proof = { email, current_password: password };
    if (code !== "") proof.code = code;
    const issued = await request("/v1/auth/seats/invitations", "POST", proof);
    if (!issued || !isUuid(issued.id) || typeof issued.token !== "string"
      || !issued.token.startsWith("zti_")
      || typeof issued.expires_at_ms !== "number") {
      throw new Error("The invitation response was invalid.");
    }
    byId("invite-token").textContent = issued.token;
    byId("invite-accept-url").textContent = `${window.location.origin}/owner/observer`;
    byId("invite-token-panel").hidden = false;
    status("invite-status", "Invitation created. Deliver the token out of band.");
    await loadSeats();
  } catch (error) {
    status("invite-status", `Invitation failed. ${error.message}`);
  } finally {
    byId("invite-email").value = "";
    byId("invite-password").value = "";
    byId("invite-code").value = "";
  }
}));

byId("dismiss-invite-token").addEventListener("click", () => {
  byId("invite-token").textContent = "";
  byId("invite-token-panel").hidden = true;
  status("invite-status", "Token cleared from this page.");
});

byId("refresh-seats").addEventListener("click", exclusive(async () => {
  status("seats-status", "Refreshing…");
  try {
    await loadSeats();
    status("seats-status", "");
  } catch (error) {
    status("seats-status", error.status === 401
      ? "Sign in on the Devices page to manage seats."
      : `Could not refresh seats. ${error.message}`);
  }
}));

window.addEventListener("pagehide", () => {
  byId("invite-token").textContent = "";
});

(async () => {
  // Keep the one-time token panel closed even if the page loads with stale
  // DOM state; the token itself is only set after a fresh creation.
  byId("invite-token-panel").hidden = true;
  byId("invite-token").textContent = "";
  try {
    await loadSeats();
    status("seats-status", "");
  } catch (error) {
    status("seats-status", error.status === 401
      ? "Sign in on the Devices page to manage seats."
      : `Could not load seats. ${error.message}`);
  }
})();
