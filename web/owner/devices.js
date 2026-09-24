// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const byId = (id) => document.getElementById(id);
let activePairingId = null;
let nextDeviceCursor = null;
let shownDeviceCount = 0;
let nextMessageCursor = null;
let shownMessageCount = 0;
let pendingMfaChallenge = null;
let nextKeyCursor = null;
let shownKeyCount = 0;
let ownerEpoch = 0;
let selectedInboundMessageId = null;
let nextInboundCursor = null;
let shownInboundCount = 0;
let inboundLoadGeneration = 0;
let selectedWebhookEndpointId = null;
let nextWebhookCursor = null;
let shownWebhookCount = 0;
let webhookLoadGeneration = 0;
let endpointLoadGeneration = 0;
let availableWebhookEndpointIds = new Set();
let sessionLoadGeneration = 0;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const webhookStatusLabels = Object.freeze({ pending: "Pending", leased: "In progress", succeeded: "Succeeded", dead: "Stopped" });
const webhookReasonLabels = Object.freeze({ failed: "Attempts exhausted", policy_rejected: "Policy rejected", retired: "Retired", legacy: "Legacy failure" });
const webhookOutcomeLabels = Object.freeze({ ack: "Acknowledged", timeout: "Timed out", http_error: "HTTP error", network_error: "Network error", policy_rejected: "Policy rejected" });
const inboundClassificationLabels = Object.freeze({
  captured_local: "Captured locally",
  sim_unverified: "SIM unverified",
  send_unverified: "Send unverified",
  encryption_unverified: "Encryption unverified",
});
const inboundContentLabels = Object.freeze({
  metadata_only: "Metadata only",
  opaque_pilot: "Opaque pilot event",
});

function message(id, value) {
  byId(id).textContent = value;
}

function csrfToken() {
  const part = document.cookie.split(";").map((piece) => piece.trim())
    .find((piece) => piece.startsWith("__Host-zrotext_csrf="));
  return part ? part.slice("__Host-zrotext_csrf=".length) : null;
}

async function api(path, method = "GET", body = undefined) {
  const requestEpoch = ownerEpoch;
  const headers = {};
  const isPasswordReset = path === "/v1/auth/password/reset/request" ||
    path === "/v1/auth/password/reset/confirm";
  if (body !== undefined) headers["content-type"] = "application/json";
  if ((method !== "GET" && path !== "/v1/auth/login" && path !== "/v1/auth/login/mfa" && !isPasswordReset)
      || path.startsWith("/v1/auth/api-keys")) {
    const csrf = csrfToken();
    if (!csrf) throw new Error("Your sign-in expired. Sign in again.");
    headers["x-zrotext-csrf"] = csrf;
  }
  const response = await fetch(path, {
    method, headers, credentials: "same-origin", cache: "no-store", redirect: "error",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (requestEpoch !== ownerEpoch) {
    throw new Error("Your sign-in expired. Sign in again.");
  }
  if (response.status === 401 && path !== "/v1/auth/login" && path !== "/v1/auth/login/mfa" && !isPasswordReset) {
    clearOwnerState();
    message("global-status", "Your sign-in expired. Sign in again.");
  }
  if (!response.ok) {
    const descriptions = {
      400: "Check the entered values and try again.",
      401: isPasswordReset ? "The reset token was not accepted. Request a new one and try again."
        : path === "/v1/auth/login" ? "Email or password was not accepted."
        : path === "/v1/auth/login/mfa" ? "Code was not accepted. Try again."
          : "Your sign-in expired. Sign in again.",
      403: "This action was refused. Refresh the page and sign in again.",
      404: "The requested item was not found, expired, or is no longer available.",
      409: "This action conflicts with the current device state.",
      413: "The request is too large.",
      429: "Too many requests. Wait before trying again.",
      503: "The service is unavailable. Try again later.",
    };
    const error = new Error(descriptions[response.status] || `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  if (response.status === 204) return null;
  const result = await response.json();
  if (requestEpoch !== ownerEpoch) {
    throw new Error("Your sign-in expired. Sign in again.");
  }
  return result;
}

function showSignedIn(signedIn) {
  byId("sign-in").hidden = signedIn;
  byId("owner-content").hidden = !signedIn;
  byId("logout").hidden = !signedIn;
}

function clearMfaChallenge() {
  pendingMfaChallenge = null;
  byId("mfa-code").value = "";
  byId("mfa-form").hidden = true;
  byId("login-form").hidden = false;
  message("mfa-status", "");
}

async function completeSignIn() {
  await api("/v1/auth/session");
  clearMfaChallenge();
  clearResetFields();
  showSignedIn(true);
  message("login-status", "");
  message("global-status", "Signed in.");
  await Promise.all([loadDevices(), loadDeviceCapacity(), loadMessages(), loadKeys(), loadWebhookEndpoints(), loadSessions()]);
}

function clearPairing() {
  activePairingId = null;
  byId("pair-cap-devices-link").hidden = true;
  byId("pair-ticket").hidden = true;
  byId("approve-form").hidden = true;
  for (const id of ["pair-id", "pair-token", "browser-code", "browser-fingerprint", "phone-code", "phone-fingerprint"]) {
    byId(id).textContent = "";
    if ("value" in byId(id)) byId(id).value = "";
  }
  byId("compared").checked = false;
}

function clearKeySecret() {
  byId("key-secret").textContent = "";
  byId("key-secret-panel").hidden = true;
}

function clearInboundHistory() {
  inboundLoadGeneration += 1;
  selectedInboundMessageId = null;
  nextInboundCursor = null;
  shownInboundCount = 0;
  byId("inbound-message-id").value = "";
  byId("inbound-selected-id").textContent = "";
  byId("inbound-selected").hidden = true;
  byId("inbound-event-list").replaceChildren();
  byId("more-inbound-events").hidden = true;
  byId("more-inbound-events").disabled = false;
  message("inbound-history-status", "");
}

function clearWebhookHistory() {
  webhookLoadGeneration += 1;
  selectedWebhookEndpointId = null;
  nextWebhookCursor = null;
  shownWebhookCount = 0;
  byId("webhook-delivery-list").replaceChildren();
  byId("more-webhook-deliveries").hidden = true;
  byId("more-webhook-deliveries").disabled = false;
  message("webhook-history-status", "");
}

function clearWebhookEndpoints() {
  endpointLoadGeneration += 1;
  availableWebhookEndpointIds = new Set();
  clearWebhookHistory();
  byId("webhook-endpoint").replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = "Choose an endpoint";
  byId("webhook-endpoint").append(placeholder);
  byId("webhook-endpoint").value = "";
  byId("webhook-endpoint").disabled = true;
  message("webhook-endpoint-status", "");
}

function clearOwnerState() {
  ownerEpoch += 1;
  sessionLoadGeneration += 1;
  clearMfaChallenge();
  clearPairing();
  clearKeySecret();
  clearInboundHistory();
  clearWebhookEndpoints();
  byId("device-list").replaceChildren();
  byId("device-cap-prompt").hidden = true;
  message("device-cap-prompt", "");
  byId("more-devices").hidden = true;
  nextDeviceCursor = null;
  shownDeviceCount = 0;
  byId("message-list").replaceChildren();
  byId("more-messages").hidden = true;
  nextMessageCursor = null;
  shownMessageCount = 0;
  byId("key-list").replaceChildren();
  byId("more-keys").hidden = true;
  nextKeyCursor = null;
  shownKeyCount = 0;
  message("key-create-status", "");
  clearPasswordFields();
  clearResetFields();
  message("change-password-status", "");
  byId("session-list").replaceChildren();
  byId("revoke-other-sessions-form").hidden = true;
  byId("revoke-sessions-password").value = "";
  byId("revoke-sessions-mfa-code").value = "";
  message("session-status", "");
  showSignedIn(false);
}

function clearPasswordFields() {
  for (const id of ["current-password", "new-password", "confirm-new-password", "password-mfa-code"]) {
    byId(id).value = "";
  }
}

function clearResetFields() {
  for (const id of ["reset-email", "reset-token", "reset-new-password", "reset-confirm-password"]) {
    byId(id).value = "";
  }
}

function dateText(milliseconds) {
  return milliseconds === null ? "Never" : new Date(milliseconds).toLocaleString();
}

function validSession(session) {
  return session && uuidPattern.test(session.id) && typeof session.current === "boolean" &&
    Number.isSafeInteger(session.created_at_ms) && Number.isSafeInteger(session.expires_at_ms) &&
    (session.last_used_at_ms === null || Number.isSafeInteger(session.last_used_at_ms));
}

async function loadSessions() {
  const requestEpoch = ownerEpoch;
  const generation = ++sessionLoadGeneration;
  message("session-status", "Loading sessions…");
  try {
    const result = await api("/v1/auth/sessions");
    if (requestEpoch !== ownerEpoch || generation !== sessionLoadGeneration) return;
    if (!result || !Array.isArray(result.sessions) || result.sessions.length > 100 ||
        !result.sessions.every(validSession) ||
        result.sessions.filter((session) => session.current).length !== 1) {
      throw new Error("The session response was invalid.");
    }
    byId("session-list").replaceChildren();
    for (const session of result.sessions) {
      const item = document.createElement("li");
      const heading = document.createElement("strong");
      const detail = document.createElement("span");
      heading.textContent = session.current ? "This session" : "Other session";
      detail.textContent = `Created ${dateText(session.created_at_ms)} · Last used ${dateText(session.last_used_at_ms)} · Expires ${dateText(session.expires_at_ms)}`;
      item.append(heading, detail);
      byId("session-list").append(item);
    }
    const otherCount = result.sessions.filter((session) => !session.current).length;
    byId("revoke-other-sessions-form").hidden = otherCount === 0;
    message("session-status", otherCount === 0 ? "Only this session is active." :
      `${otherCount} other session${otherCount === 1 ? "" : "s"} active.`);
  } catch (error) {
    if (requestEpoch !== ownerEpoch || generation !== sessionLoadGeneration) return;
    byId("session-list").replaceChildren();
    byId("revoke-other-sessions-form").hidden = true;
    message("session-status", `Could not load sessions. ${error.message}`);
  }
}

function inboundDateText(milliseconds) {
  const date = new Date(milliseconds);
  return Number.isSafeInteger(milliseconds) && Number.isFinite(date.getTime())
    ? date.toLocaleString() : "Unknown time";
}

function validWebhookPage(page, cursor) {
  return page && Array.isArray(page.deliveries) && page.deliveries.length <= 20 &&
    (page.next_before === null || (uuidPattern.test(page.next_before) && page.next_before !== cursor &&
      page.deliveries.length > 0 && page.next_before === page.deliveries[page.deliveries.length - 1].delivery_id)) &&
    page.deliveries.every((delivery) => uuidPattern.test(delivery.delivery_id) &&
      uuidPattern.test(delivery.event_id) &&
      Object.hasOwn(webhookStatusLabels, delivery.status) &&
      Number.isInteger(delivery.generation) && delivery.generation >= 1 && delivery.generation <= 3 &&
      Number.isInteger(delivery.attempt_count) && delivery.attempt_count >= 0 && delivery.attempt_count <= 7 &&
      Number.isSafeInteger(delivery.created_at_ms) && Number.isSafeInteger(delivery.updated_at_ms) &&
      (delivery.next_attempt_at_ms === null || Number.isSafeInteger(delivery.next_attempt_at_ms)) &&
      (delivery.terminal_reason === null || Object.hasOwn(webhookReasonLabels, delivery.terminal_reason)) &&
      Array.isArray(delivery.attempts) && delivery.attempts.length <= 21 &&
      delivery.attempts.every((attempt) => Number.isInteger(attempt.generation) &&
        attempt.generation >= 1 && attempt.generation <= 3 &&
        Number.isInteger(attempt.attempt_number) && attempt.attempt_number >= 1 && attempt.attempt_number <= 7 &&
        Number.isSafeInteger(attempt.started_at_ms) &&
        (attempt.completed_at_ms === null || Number.isSafeInteger(attempt.completed_at_ms)) &&
        (attempt.outcome === null || Object.hasOwn(webhookOutcomeLabels, attempt.outcome)) &&
        (attempt.http_status === null || (Number.isInteger(attempt.http_status) && attempt.http_status >= 100 && attempt.http_status <= 599))));
}

function showWebhookDelivery(delivery) {
  const row = document.createElement("li");
  const heading = document.createElement("strong");
  const detail = document.createElement("span");
  const attempts = document.createElement("ol");
  heading.textContent = `${webhookStatusLabels[delivery.status]} · delivery ${delivery.delivery_id}`;
  detail.textContent = `Event ${delivery.event_id} · generation ${delivery.generation} · ${delivery.attempt_count} current attempt${delivery.attempt_count === 1 ? "" : "s"} · created ${inboundDateText(delivery.created_at_ms)} · updated ${inboundDateText(delivery.updated_at_ms)}${delivery.next_attempt_at_ms === null ? "" : ` · next attempt ${inboundDateText(delivery.next_attempt_at_ms)}`}${delivery.terminal_reason === null ? "" : ` · ${webhookReasonLabels[delivery.terminal_reason]}`}`;
  for (const attempt of delivery.attempts) {
    const item = document.createElement("li");
    item.textContent = `Generation ${attempt.generation}, attempt ${attempt.attempt_number}: ${attempt.outcome === null ? "In progress" : webhookOutcomeLabels[attempt.outcome]} · started ${inboundDateText(attempt.started_at_ms)} · ${attempt.completed_at_ms === null ? "not completed" : `completed ${inboundDateText(attempt.completed_at_ms)}`}${attempt.http_status === null ? "" : ` · HTTP ${attempt.http_status}`}`;
    attempts.append(item);
  }
  row.append(heading, detail, attempts);
  byId("webhook-delivery-list").append(row);
}

async function loadWebhookEndpoints() {
  clearWebhookEndpoints();
  const requestEpoch = ownerEpoch;
  const generation = endpointLoadGeneration;
  message("webhook-endpoint-status", "Loading endpoints…");
  try {
    const page = await api("/v1/webhooks");
    if (requestEpoch !== ownerEpoch || generation !== endpointLoadGeneration) return;
    if (!page || !Array.isArray(page.endpoints) || page.endpoints.length > 8 ||
        !page.endpoints.every((endpoint) => uuidPattern.test(endpoint.endpoint_id))) {
      throw new Error("The endpoint response was invalid.");
    }
    for (const endpoint of page.endpoints) {
      availableWebhookEndpointIds.add(endpoint.endpoint_id);
      const option = document.createElement("option");
      option.value = endpoint.endpoint_id;
      option.textContent = `Endpoint ${endpoint.endpoint_id}`;
      byId("webhook-endpoint").append(option);
    }
    byId("webhook-endpoint").disabled = page.endpoints.length === 0;
    message("webhook-endpoint-status", page.endpoints.length === 0 ? "No webhook endpoints yet." : `${page.endpoints.length} endpoint${page.endpoints.length === 1 ? "" : "s"} available.`);
  } catch (error) {
    if (requestEpoch !== ownerEpoch || generation !== endpointLoadGeneration) return;
    message("webhook-endpoint-status", `Could not load endpoints. ${error.message}`);
  }
}

async function loadWebhookDeliveries(reset = true) {
  if (!selectedWebhookEndpointId || (!reset && !nextWebhookCursor)) return;
  const endpointId = selectedWebhookEndpointId;
  const cursor = reset ? null : nextWebhookCursor;
  const requestEpoch = ownerEpoch;
  const generation = ++webhookLoadGeneration;
  const moreButton = byId("more-webhook-deliveries");
  moreButton.disabled = true;
  message("webhook-history-status", "Loading deliveries…");
  if (reset) {
    byId("webhook-delivery-list").replaceChildren();
    moreButton.hidden = true;
    nextWebhookCursor = null;
    shownWebhookCount = 0;
  }
  try {
    const path = `/v1/webhooks/${encodeURIComponent(endpointId)}/deliveries?limit=20${cursor ? `&before=${encodeURIComponent(cursor)}` : ""}`;
    const page = await api(path);
    if (requestEpoch !== ownerEpoch || generation !== webhookLoadGeneration || endpointId !== selectedWebhookEndpointId) return;
    if (!validWebhookPage(page, cursor)) throw new Error("The delivery response was invalid.");
    for (const delivery of page.deliveries) showWebhookDelivery(delivery);
    shownWebhookCount += page.deliveries.length;
    nextWebhookCursor = page.next_before;
    moreButton.hidden = !nextWebhookCursor;
    moreButton.disabled = false;
    message("webhook-history-status", shownWebhookCount === 0 ? "No deliveries recorded for this endpoint." :
      `${shownWebhookCount} deliver${shownWebhookCount === 1 ? "y" : "ies"} shown${nextWebhookCursor ? "; more available" : ""}.`);
  } catch (error) {
    if (requestEpoch !== ownerEpoch || generation !== webhookLoadGeneration || endpointId !== selectedWebhookEndpointId) return;
    moreButton.disabled = false;
    message("webhook-history-status", `Could not load deliveries. ${error.message}`);
  }
}

function showInboundEvent(event) {
  const row = document.createElement("li");
  const classification = document.createElement("strong");
  const detail = document.createElement("span");
  classification.textContent = inboundClassificationLabels[event.classification] || "Unrecognized classification";
  const parts = Number.isInteger(event.part_count) && event.part_count >= 1 && event.part_count <= 6
    ? `${event.part_count} part${event.part_count === 1 ? "" : "s"}` : "Unknown part count";
  detail.textContent = `Observed ${inboundDateText(event.observed_at_ms)} · received ${inboundDateText(event.received_at_ms)} · ${parts} · ${inboundContentLabels[event.content_kind] || "Unrecognized content kind"}`;
  row.append(classification, detail);
  byId("inbound-event-list").append(row);
}

async function loadInboundEvents(reset = true) {
  if (!selectedInboundMessageId || (!reset && !nextInboundCursor)) return;
  const messageId = selectedInboundMessageId;
  const cursor = reset ? null : nextInboundCursor;
  const requestEpoch = ownerEpoch;
  const generation = ++inboundLoadGeneration;
  const moreButton = byId("more-inbound-events");
  moreButton.disabled = true;
  message("inbound-history-status", "Loading inbound events…");
  if (reset) {
    byId("inbound-event-list").replaceChildren();
    moreButton.hidden = true;
    nextInboundCursor = null;
    shownInboundCount = 0;
  }
  try {
    const path = `/v1/inbound/messages/${encodeURIComponent(messageId)}/events?limit=20${cursor ? `&before=${encodeURIComponent(cursor)}` : ""}`;
    const page = await api(path);
    if (requestEpoch !== ownerEpoch || generation !== inboundLoadGeneration || messageId !== selectedInboundMessageId) return;
    if (!Array.isArray(page.events) || page.events.length > 20 ||
        (page.next_before !== null && !uuidPattern.test(page.next_before)) ||
        (page.events.length === 0 && page.next_before !== null)) {
      throw new Error("The event response was invalid.");
    }
    for (const event of page.events) showInboundEvent(event);
    shownInboundCount += page.events.length;
    nextInboundCursor = page.next_before;
    moreButton.hidden = !nextInboundCursor;
    moreButton.disabled = false;
    message("inbound-history-status", shownInboundCount === 0
      ? "No inbound events recorded for this message."
      : `${shownInboundCount} event${shownInboundCount === 1 ? "" : "s"} shown${nextInboundCursor ? "; more available" : ""}.`);
  } catch (error) {
    if (requestEpoch !== ownerEpoch || generation !== inboundLoadGeneration || messageId !== selectedInboundMessageId) return;
    moreButton.disabled = false;
    message("inbound-history-status", `Could not load inbound events. ${error.message}`);
  }
}

async function loadKeys(reset = true) {
  message("key-list-status", "Loading keys…");
  if (reset) {
    byId("key-list").replaceChildren();
    byId("more-keys").hidden = true;
    nextKeyCursor = null;
    shownKeyCount = 0;
  }
  try {
    const path = nextKeyCursor
      ? `/v1/auth/api-keys?before=${encodeURIComponent(nextKeyCursor)}`
      : "/v1/auth/api-keys";
    const page = await api(path);
    if (reset && page.keys.length === 0) {
      message("key-list-status", "No API keys yet.");
      return;
    }
    nextKeyCursor = page.next_cursor;
    shownKeyCount += page.keys.length;
    byId("more-keys").hidden = !nextKeyCursor;
    message("key-list-status", `${shownKeyCount} key${shownKeyCount === 1 ? "" : "s"} shown${nextKeyCursor ? "; more available" : ""}. Revoked and expired keys stay visible.`);
    for (const key of page.keys) {
      const row = document.createElement("li");
      const detail = document.createElement("div");
      const prefix = document.createElement("strong");
      const metadata = document.createElement("span");
      prefix.textContent = `ztk_${key.public_prefix}…`;
      metadata.textContent = ` ${key.status} · ${key.scopes.join(", ")} · created ${dateText(key.created_at_ms)} · expires ${dateText(key.expires_at_ms)}`;
      detail.append(prefix, metadata);
      if (key.bound_device_id) {
        const device = document.createElement("code");
        device.textContent = `Bound device: ${key.bound_device_id}`;
        detail.append(device);
      }
      row.append(detail);
      if (key.status !== "revoked") {
        const revoke = document.createElement("button");
        revoke.type = "button";
        revoke.textContent = "Revoke";
        revoke.setAttribute("aria-label", `Revoke API key ${key.public_prefix}`);
        revoke.addEventListener("click", async () => {
          if (!window.confirm(`Revoke API key ztk_${key.public_prefix}…? Requests using it will lose authorization.`)) return;
          revoke.disabled = true;
          try {
            await api(`/v1/auth/api-keys/${encodeURIComponent(key.id)}`, "DELETE");
            await loadKeys();
          } catch (error) {
            message("key-list-status", `Could not revoke key. ${error.message}`);
            revoke.disabled = false;
          }
        });
        row.append(revoke);
      }
      byId("key-list").append(row);
    }
  } catch (error) {
    message("key-list-status", `Could not load keys. ${error.message}`);
  }
}

async function loadDeviceCapacity() {
  const prompt = byId("device-cap-prompt");
  prompt.hidden = true;
  prompt.textContent = "";
  try {
    const result = await api("/v1/billing/status");
    const capacity = result.deviceCapacity;
    if (result.mode !== "test" || !capacity ||
        !Number.isSafeInteger(capacity.limit) || capacity.limit < 0 ||
        !Number.isSafeInteger(capacity.active) || capacity.active < 0) return;
    if (capacity.overLimit) {
      prompt.textContent = `${capacity.active} active devices exceed your plan limit of ${capacity.limit}. Choose which devices to revoke below. Existing devices continue working until you revoke them; no device is removed automatically. A new pairing requires available plan capacity.`;
    } else if (capacity.enrollmentBlocked) {
      prompt.textContent = capacity.limit === 0
        ? "Your current plan allows no devices. No device is removed automatically; a new pairing requires a plan with capacity."
        : `${capacity.active} active devices have reached your plan limit of ${capacity.limit}. Choose a device below to revoke before approving a replacement. No device is removed automatically.`;
    }
    prompt.hidden = !prompt.textContent;
  } catch (_error) {
    // Billing may be disabled; keep device management available on its own.
    prompt.hidden = true;
    prompt.textContent = "";
  }
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
      state.textContent = device.revoked
        ? "Revoked"
        : device.active_socket_lease === true
          ? "Approved · authenticated socket lease observed (may lag up to 90 seconds) · SMS readiness unknown"
          : device.active_socket_lease === false
            ? "Approved · no current authenticated socket lease · SMS readiness unknown"
            : "Approved for connection · live status unavailable";
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
            await Promise.all([loadDevices(), loadDeviceCapacity()]);
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
      if (item.state === "unknown") {
        const warning = document.createElement("p");
        warning.className = "message-uncertain";
        warning.textContent = "Outcome unknown. The phone may have sent this SMS. Sending a new message could duplicate it.";
        row.append(warning);
      }
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
    if (error.message.startsWith("The requested item")) clearPairing();
  }
}

byId("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  clearMfaChallenge();
  showSignedIn(false);
  message("login-status", "Signing in…");
  const password = byId("password").value;
  byId("password").value = "";
  try {
    const result = await api("/v1/auth/login", "POST", { email: byId("email").value, password });
    if (result && typeof result.challenge_token === "string" && result.challenge_token.startsWith("ztm_")) {
      pendingMfaChallenge = result.challenge_token;
      byId("login-form").hidden = true;
      byId("mfa-form").hidden = false;
      message("login-status", "");
      message("mfa-status", "Finish sign-in with your second factor.");
      byId("mfa-code").focus();
      return;
    }
    if (result !== null) throw new Error("Unexpected sign-in response. Try again.");
    await completeSignIn();
  } catch (error) {
    message("login-status", `Sign-in failed. ${error.message}`);
  }
});

byId("mfa-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!pendingMfaChallenge) return;
  const code = byId("mfa-code").value.trim();
  byId("mfa-code").value = "";
  message("mfa-status", "Verifying code…");
  let factorAccepted = false;
  try {
    const result = await api("/v1/auth/login/mfa", "POST", {
      challenge_token: pendingMfaChallenge, code,
    });
    if (result !== null) throw new Error("Unexpected verification response. Try again.");
    factorAccepted = true;
    await completeSignIn();
  } catch (error) {
    if (factorAccepted) {
      clearMfaChallenge();
      message("login-status", `Could not verify the new session. ${error.message}`);
    } else {
      message("mfa-status", `Code verification failed. ${error.message}`);
    }
  }
});

byId("cancel-mfa").addEventListener("click", () => {
  clearMfaChallenge();
  message("login-status", "Enter your password to start again.");
});

byId("logout").addEventListener("click", async () => {
  try {
    await api("/v1/auth/logout", "POST");
    clearOwnerState();
    message("global-status", "Signed out.");
  } catch (error) {
    message("global-status", `Could not sign out. ${error.message}`);
  }
});

byId("reset-request-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const email = byId("reset-email").value.trim();
  const submit = byId("reset-request-submit");
  submit.disabled = true;
  message("reset-request-status", "Sending instructions…");
  try {
    await api("/v1/auth/password/reset/request", "POST", { email });
    byId("reset-email").value = "";
    message("reset-request-status", "If this address has an owner account, reset instructions will arrive by email.");
  } catch (error) {
    message("reset-request-status", `Could not request a reset. ${error.message}`);
  } finally {
    submit.disabled = false;
  }
});

byId("reset-confirm-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const token = byId("reset-token").value.trim();
  const newPassword = byId("reset-new-password").value;
  const confirmed = byId("reset-confirm-password").value;
  byId("reset-new-password").value = "";
  byId("reset-confirm-password").value = "";
  if (newPassword !== confirmed) {
    message("reset-confirm-status", "New passwords do not match. Enter them again.");
    return;
  }
  const submit = byId("reset-confirm-submit");
  submit.disabled = true;
  message("reset-confirm-status", "Resetting password…");
  try {
    await api("/v1/auth/password/reset/confirm", "POST", { token, new_password: newPassword });
    byId("reset-token").value = "";
    message("reset-confirm-status", "Password reset. Sign in with your new password.");
  } catch (error) {
    message("reset-confirm-status", `Could not reset password. ${error.message}`);
  } finally {
    submit.disabled = false;
  }
});

byId("change-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const currentPassword = byId("current-password").value;
  const newPassword = byId("new-password").value;
  const confirmed = byId("confirm-new-password").value;
  const code = byId("password-mfa-code").value.trim();
  clearPasswordFields();
  if (newPassword !== confirmed) {
    message("change-password-status", "New passwords do not match. Enter them again.");
    return;
  }
  const submit = byId("change-password-submit");
  submit.disabled = true;
  message("change-password-status", "Changing password…");
  try {
    await api("/v1/auth/password", "POST", {
      current_password: currentPassword, new_password: newPassword,
      ...(code ? { code } : {}),
    });
    clearOwnerState();
    message("global-status", "Password changed. Sign in again. All sessions and API keys were revoked; reissue keys used by integrations.");
  } catch (error) {
    message("change-password-status", `Could not change password. ${error.message}`);
  } finally {
    submit.disabled = false;
  }
});

byId("refresh-sessions").addEventListener("click", loadSessions);
byId("revoke-other-sessions-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!window.confirm("Sign out all other sessions?")) return;
  const currentPassword = byId("revoke-sessions-password").value;
  const code = byId("revoke-sessions-mfa-code").value.trim();
  byId("revoke-sessions-password").value = "";
  byId("revoke-sessions-mfa-code").value = "";
  byId("revoke-other-sessions").disabled = true;
  message("session-status", "Signing out other sessions…");
  try {
    await api("/v1/auth/sessions/revoke-others", "POST", {
      current_password: currentPassword,
      ...(code ? { code } : {}),
    });
    await loadSessions();
  } catch (error) {
    message("session-status", `Could not sign out other sessions. ${error.message}`);
  } finally {
    byId("revoke-other-sessions").disabled = false;
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
  byId("pair-cap-devices-link").hidden = true;
  try {
    const result = await api(`/v1/enrollment/pairings/${encodeURIComponent(activePairingId)}/approve`, "POST", {
      comparison_code: byId("phone-code").value,
      key_fingerprint: byId("phone-fingerprint").value.toUpperCase(),
    });
    message("approved-result", `Approved device UUID: ${result.device_id}`);
    message("pair-status", "Pairing complete. Enter this UUID on the phone, then start its gateway connection. Approval does not confirm the phone is connected or ready to send.");
    clearPairing();
    await Promise.all([loadDevices(), loadDeviceCapacity()]);
  } catch (error) {
    if (error.status === 409) {
      message("pair-status", "Device limit reached. Existing devices keep working. Choose which device to revoke below, then retry when your plan has available capacity. Nothing was removed automatically.");
      byId("pair-cap-devices-link").hidden = false;
      await loadDeviceCapacity();
    } else {
      message("pair-status", `Approval failed. ${error.message} Check the phone values. Repeated mismatches lock this pairing.`);
    }
  }
});

byId("refresh-devices").addEventListener("click", () => Promise.all([loadDevices(), loadDeviceCapacity()]));
byId("more-devices").addEventListener("click", () => loadDevices(false));
byId("refresh-messages").addEventListener("click", loadMessages);
byId("more-messages").addEventListener("click", () => loadMessages(false));
byId("refresh-keys").addEventListener("click", loadKeys);
byId("more-keys").addEventListener("click", () => loadKeys(false));
byId("dismiss-key-secret").addEventListener("click", clearKeySecret);
window.addEventListener("pagehide", clearKeySecret);
window.addEventListener("pagehide", () => { clearPasswordFields(); clearResetFields(); });
byId("inbound-history-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const messageId = byId("inbound-message-id").value.trim();
  if (!uuidPattern.test(messageId)) {
    message("inbound-history-status", "Enter a valid message UUID.");
    return;
  }
  inboundLoadGeneration += 1;
  selectedInboundMessageId = messageId;
  nextInboundCursor = null;
  shownInboundCount = 0;
  byId("inbound-event-list").replaceChildren();
  byId("more-inbound-events").hidden = true;
  byId("inbound-selected-id").textContent = messageId;
  byId("inbound-selected").hidden = false;
  await loadInboundEvents();
});
byId("more-inbound-events").addEventListener("click", () => loadInboundEvents(false));
byId("refresh-webhook-endpoints").addEventListener("click", loadWebhookEndpoints);
byId("webhook-endpoint").addEventListener("change", async () => {
  const endpointId = byId("webhook-endpoint").value;
  clearWebhookHistory();
  if (!availableWebhookEndpointIds.has(endpointId)) return;
  selectedWebhookEndpointId = endpointId;
  await loadWebhookDeliveries();
});
byId("more-webhook-deliveries").addEventListener("click", () => loadWebhookDeliveries(false));
byId("key-create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const createEpoch = ownerEpoch;
  clearKeySecret();
  const scopes = [...byId("key-create-form").querySelectorAll('input[name="scope"]:checked')]
    .map((input) => input.value);
  if (scopes.length === 0) {
    message("key-create-status", "Choose at least one scope.");
    return;
  }
  message("key-create-status", "Creating key…");
  try {
    const created = await api("/v1/auth/api-keys", "POST", {
      scopes, lifetime_days: Number(byId("key-lifetime").value),
    });
    if (createEpoch !== ownerEpoch) return;
    byId("key-secret").textContent = created.token;
    byId("key-secret-panel").hidden = false;
    message("key-create-status", "Key created. Copy it now; this is its only display.");
    await loadKeys();
  } catch (error) {
    message("key-create-status", `Could not create key. ${error.message}`);
  }
});

(async () => {
  try {
    await api("/v1/auth/session");
    clearResetFields();
    showSignedIn(true);
    await Promise.all([loadDevices(), loadDeviceCapacity(), loadMessages(), loadKeys(), loadWebhookEndpoints(), loadSessions()]);
  } catch (error) {
    showSignedIn(false);
    message("global-status", error.message.startsWith("Your sign-in") ? "Sign in to manage devices." : `Could not verify session. ${error.message}`);
  }
})();
