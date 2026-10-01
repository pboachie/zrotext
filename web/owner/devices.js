// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const byId = (id) => document.getElementById(id);
let activePairingId = null;
let nextDeviceCursor = null;
let shownDeviceCount = 0;
let nextMessageCursor = null;
let shownMessageCount = 0;
let nextOptOutReviewCursor = null;
let shownOptOutReviewCount = 0;
let optOutReviewLoadGeneration = 0;
let ownerHoldsLoadGeneration = 0;
let nextOwnerHoldsCursor = null;
let shownOwnerHoldsCount = 0;
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
let deviceLoadGeneration = 0;
let messageLoadGeneration = 0;
let summaryGeneration = 0;
let summaryBusy = false;
let summaryActiveRequest = null;
let summaryLastAttempt = 0;
let summaryLastStarted = 0;
let summaryRetryable = false;
let summaryQueued = false;
let summarySnapshot = null;
let summaryTimer = null;
const summaryDevices = new Map();
let keyLoadGeneration = 0;
const requestTimeoutMs = 30_000;
const dashboardRefreshMs = 15_000;
let dashboardTimer = null;
let dashboardRefreshing = false;
let dashboardSignedIn = false;
let dashboardPageActive = true;
// Live updates: one same-origin event stream signals device and message
// changes. While it is connected the periodic snapshot refresh pauses; on any
// failure the stream closes, snapshot refresh resumes, and the stream is
// retried with capped backoff so a dead endpoint cannot spin the tab.
const liveRetryBaseMs = 1_000;
const liveRetryMaxMs = 60_000;
// A stream that stayed connected this long counts as healthy, so the next
// failure restarts from the base retry delay. Without this, a stream that
// connects and immediately drops would retry at the base delay forever.
const liveHealthyMs = 30_000;
let liveEvents = null;
let liveRetryTimer = null;
let liveConnected = false;
let liveFailures = 0;
let liveOpenedAt = 0;
// Distinguishes the first stream of a sign-in (the page just loaded its
// lists) from a reconnect, whose fresh server baseline hides every change
// made while no stream was open.
let liveStreamEverOpened = false;
let deviceLoads = 0;
let messageLoads = 0;
// Live-triggered reloads are coalesced: once a section has reloaded from a
// change signal, further signals inside this floor merge into a single
// trailing reload, so a busy tenant cannot rebuild its lists on every poll.
const liveReloadFloorMs = dashboardRefreshMs;
let devicesLiveReloadedAt = 0;
let messagesLiveReloadedAt = 0;
let devicesTrailingReload = null;
let messagesTrailingReload = null;
// A signal that arrives while a live-triggered reload is still in flight is
// remembered and answered with one guarded follow-up reload when that load
// completes, so the freshest state is never silently dropped.
let devicesSignalDuringLoad = false;
let messagesSignalDuringLoad = false;
let browsingOlderDevices = false;
let browsingOlderMessages = false;
const preconditionFreshMs = 90_000;
let preconditionTimer = null;
let preconditionRows = [];
const fleetRows = new Map();
let selectedDeviceId = null;
const activityRows = new Map();
let fleetSnapshotFailed = false;

function stopPreconditionAging() {
  if (preconditionTimer !== null) window.clearTimeout(preconditionTimer);
  preconditionTimer = null;
}

function clearPreconditionRows() {
  stopPreconditionAging();
  preconditionRows = [];
}

function agePreconditions() {
  stopPreconditionAging();
  if (!dashboardSignedIn || !dashboardPageActive || document.hidden) return;
  let nextExpiry = Infinity;
  for (const entry of preconditionRows) {
    // Include request latency and time spent suspended. Once expired, a clock
    // adjustment cannot make a saved observation fresh again.
    const elapsed = Math.max(0, performance.now() - entry.started, Date.now() - entry.wallStarted);
    entry.expired ||= elapsed >= entry.remaining || fleetSnapshotFailed;
    const text = devicePreconditionsText(entry.device, entry.expired);
    if (entry.element.textContent !== text) entry.element.textContent = text;
    if (!entry.expired) nextExpiry = Math.min(nextExpiry, entry.remaining - elapsed);
  }
  if (Number.isFinite(nextExpiry)) {
    preconditionTimer = window.setTimeout(agePreconditions, Math.max(1, Math.ceil(nextExpiry)));
  }
}

function stopDashboardRefresh() {
  if (dashboardTimer !== null) window.clearTimeout(dashboardTimer);
  dashboardTimer = null;
}

function cancelPendingLiveReloads() {
  if (devicesTrailingReload !== null) window.clearTimeout(devicesTrailingReload);
  if (messagesTrailingReload !== null) window.clearTimeout(messagesTrailingReload);
  devicesTrailingReload = null;
  messagesTrailingReload = null;
  // A signal queued during an in-flight reload belongs to the stream that
  // sent it; once that stream drops, the fallback refresh takes over.
  devicesSignalDuringLoad = false;
  messagesSignalDuringLoad = false;
}

function stopLiveUpdates() {
  if (liveRetryTimer !== null) window.clearTimeout(liveRetryTimer);
  liveRetryTimer = null;
  cancelPendingLiveReloads();
  if (liveEvents) liveEvents.close();
  liveEvents = null;
  liveConnected = false;
  liveFailures = 0;
}

function liveUpdatesAllowed() {
  return dashboardSignedIn && dashboardPageActive && !document.hidden && byId("auto-refresh").checked;
}

function startLiveUpdates() {
  if (liveEvents || !liveUpdatesAllowed()) return;
  // Without EventSource the dashboard keeps its periodic snapshot refresh.
  if (typeof window.EventSource !== "function") return;
  const source = new window.EventSource("/owner/events");
  liveEvents = source;
  source.addEventListener("open", () => {
    if (liveEvents !== source) return;
    const reconnected = liveStreamEverOpened;
    liveStreamEverOpened = true;
    liveConnected = true;
    liveOpenedAt = Date.now();
    stopDashboardRefresh();
    // A reconnect takes a fresh baseline fingerprint, so anything that
    // changed while no stream was open would never be signalled. One
    // guarded reload closes that gap.
    if (reconnected) refreshDashboard();
  });
  source.addEventListener("changed", (event) => {
    if (liveEvents !== source || !canRefreshDashboard()) return;
    let sections;
    try {
      sections = JSON.parse(event.data).changed;
    } catch (_error) {
      return;
    }
    if (!Array.isArray(sections)) return;
    if (sections.includes("devices")) requestLiveDevicesReload();
    if (sections.includes("messages")) requestLiveMessagesReload();
  });
  source.addEventListener("error", () => {
    if (liveEvents !== source) return;
    source.close();
    liveEvents = null;
    liveConnected = false;
    cancelPendingLiveReloads();
    if (Date.now() - liveOpenedAt >= liveHealthyMs) liveFailures = 0;
    scheduleDashboardRefresh();
    scheduleLiveRetry();
  });
}

function scheduleLiveRetry() {
  if (liveRetryTimer !== null || !dashboardSignedIn || !dashboardPageActive) return;
  const delay = Math.min(liveRetryMaxMs, liveRetryBaseMs * 2 ** Math.min(liveFailures, 6));
  liveFailures += 1;
  liveRetryTimer = window.setTimeout(() => {
    liveRetryTimer = null;
    startLiveUpdates();
  }, delay);
}

function syncLiveUpdates() {
  if (liveUpdatesAllowed()) startLiveUpdates();
  else stopLiveUpdates();
}

function canRefreshDashboard() {
  return dashboardSignedIn && dashboardPageActive && !document.hidden && byId("auto-refresh").checked;
}

function requestLiveDevicesReload() {
  if (browsingOlderDevices || viewingList("device-list")) return;
  if (deviceLoads) {
    devicesSignalDuringLoad = true;
    return;
  }
  const now = Date.now();
  if (devicesTrailingReload !== null) return;
  if (now - devicesLiveReloadedAt < liveReloadFloorMs) {
    devicesTrailingReload = window.setTimeout(() => {
      devicesTrailingReload = null;
      if (!canRefreshDashboard() || deviceLoads || browsingOlderDevices || viewingList("device-list")) return;
      devicesLiveReloadedAt = Date.now();
      loadDevices(true, true);
    }, devicesLiveReloadedAt + liveReloadFloorMs - now);
    return;
  }
  devicesLiveReloadedAt = now;
  loadDevices(true, true);
}

function requestLiveMessagesReload() {
  if (browsingOlderMessages || viewingList("message-list")) return;
  if (messageLoads) {
    messagesSignalDuringLoad = true;
    return;
  }
  const now = Date.now();
  if (messagesTrailingReload !== null) return;
  if (now - messagesLiveReloadedAt < liveReloadFloorMs) {
    messagesTrailingReload = window.setTimeout(() => {
      messagesTrailingReload = null;
      if (!canRefreshDashboard() || messageLoads || browsingOlderMessages || viewingList("message-list")) return;
      messagesLiveReloadedAt = Date.now();
      loadMessages(true, true);
    }, messagesLiveReloadedAt + liveReloadFloorMs - now);
    return;
  }
  messagesLiveReloadedAt = now;
  loadMessages(true, true);
}

function scheduleDashboardRefresh() {
  stopDashboardRefresh();
  if (canRefreshDashboard() && !liveConnected && !dashboardRefreshing) {
    dashboardTimer = window.setTimeout(refreshDashboard, dashboardRefreshMs);
  }
}

function viewingList(id) {
  const list = byId(id);
  return list.contains(document.activeElement) || list.querySelector("details[open]") !== null;
}

async function refreshDashboard() {
  stopDashboardRefresh();
  if (!canRefreshDashboard() || dashboardRefreshing) return;
  dashboardRefreshing = true;
  try {
    const requests = [];
    if (!deviceLoads && !browsingOlderDevices && !viewingList("device-list")) requests.push(loadDevices(true, true));
    if (!messageLoads && !browsingOlderMessages && !viewingList("message-list")) requests.push(loadMessages(true, true));
    await Promise.all(requests);
  } finally {
    dashboardRefreshing = false;
    scheduleDashboardRefresh();
  }
}
const passwordResetPaths = new Set(["/v1/auth/password/reset/request", "/v1/auth/password/reset/confirm"]);
const unauthenticatedPaths = new Set(["/v1/auth/login", "/v1/auth/login/mfa", ...passwordResetPaths]);
// Reads that return account content also carry the CSRF header. Session,
// MFA and billing status stay cookie-only: the page asks for them to learn
// whether it is signed in at all.
const csrfReadPrefixes = [
  "/v1/auth/api-keys", "/v1/owner/", "/v1/webhooks", "/v1/inbound/messages/",
  "/v1/enrollment/devices", "/v1/enrollment/pairings/",
];
const statusDescriptions = Object.freeze({
  400: "Check the entered values and try again.",
  403: "This action was refused. Refresh the page and sign in again.",
  404: "The requested item was not found, expired, or is no longer available.",
  409: "This action conflicts with the current device state.",
  413: "The request is too large.",
  429: "Too many requests. Wait before trying again.",
  503: "The service is unavailable. Try again later.",
});
// One shared formatter: Date#toLocaleString builds a new Intl formatter on
// every call, which dominates rendering of long message and webhook lists.
const timeFormat = new Intl.DateTimeFormat(undefined, {
  year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", second: "numeric",
});
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const holdChannels = Object.freeze({ email: "Email", phone_call: "Phone call", web_form: "Web form", postal_mail: "Postal mail", in_person: "In person", other: "Other" });
const holdReasons = Object.freeze({ opt_out: "Opt-out", consent_withdrawn: "Consent withdrawn", complaint: "Complaint", wrong_number: "Wrong number" });
const reviewDecisions = Object.freeze({ confirmed_opt_out: "Confirmed opt-out", not_opt_out: "Not an opt-out" });
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

// Ignore repeat submits and clicks while the first request is still running,
// so a double click cannot create a second pairing or one-time API key.
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
  const part = document.cookie.split(";").map((piece) => piece.trim())
    .find((piece) => piece.startsWith("__Host-zrotext_csrf="));
  return part ? part.slice("__Host-zrotext_csrf=".length) : null;
}

function unauthorizedDescription(path) {
  if (passwordResetPaths.has(path)) return "The reset token was not accepted. Request a new one and try again.";
  if (path === "/v1/auth/login") return "Email or password was not accepted.";
  if (path === "/v1/auth/login/mfa") return "Code was not accepted. Try again.";
  return "Your sign-in expired. Sign in again.";
}

async function api(path, method = "GET", body = undefined) {
  const requestEpoch = ownerEpoch;
  const headers = {};
  const unauthenticated = unauthenticatedPaths.has(path);
  if (body !== undefined) headers["content-type"] = "application/json";
  if ((method !== "GET" && !unauthenticated) || csrfReadPrefixes.some((prefix) => path.startsWith(prefix))) {
    const csrf = csrfToken();
    if (!csrf) throw new Error("Your sign-in expired. Sign in again.");
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
    const failure = new Error(error && error.name === "TimeoutError"
      ? "The server did not respond in time. Try again."
      : "Could not reach the server. Check your connection and try again.");
    failure.retryable = true;
    throw failure;
  }
  if (requestEpoch !== ownerEpoch) {
    throw new Error("Your sign-in expired. Sign in again.");
  }
  if (response.status === 401 && !unauthenticated) {
    clearOwnerState();
    message("global-status", "Your sign-in expired. Sign in again.");
  }
  if (!response.ok) {
    const description = response.status === 401 ? unauthorizedDescription(path) : statusDescriptions[response.status];
    const error = new Error(description || `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  // Review decisions return 201 with an intentionally empty body.
  if (response.status === 204 || (response.status === 201 && path === "/v1/owner/opt-out-review/decisions")) return null;
  const result = await response.json();
  if (requestEpoch !== ownerEpoch) {
    throw new Error("Your sign-in expired. Sign in again.");
  }
  return result;
}

function showSignedIn(signedIn) {
  dashboardSignedIn = signedIn;
  if (!signedIn) {
    stopDashboardRefresh();
    stopLiveUpdates();
    clearPreconditionRows();
  }
  byId("sign-in").hidden = signedIn;
  byId("owner-content").hidden = !signedIn;
  byId("logout").hidden = !signedIn;
  if (typeof document.dispatchEvent === "function" && typeof CustomEvent === "function") {
    document.dispatchEvent(new CustomEvent("zrotext-owner-session", { detail: { signedIn } }));
  }
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
  await loadOwnerData();
  scheduleDashboardRefresh();
  startLiveUpdates();
}

function loadOwnerData() {
  // The above-the-fold sections load first and alone; the below-the-fold
  // panels wait for them so a sign-in never occupies half the request pool.
  return Promise.all([loadDevices(), loadMessages()]).then(() => loadSummary()).finally(() => loadBelowFoldSections());
}

function loadBelowFoldSections() {
  // Below-the-fold panels fill in one at a time after the visible lists,
  // keeping a sign-in at two concurrent requests for the data the owner
  // sees first and one for everything after.
  const sections = [loadOptOutReview, loadOwnerHolds, loadKeys, loadWebhookEndpoints, loadSessions];
  return sections.reduce((chain, load) => chain.then(() => load()), Promise.resolve());
}

function clearPairing() {
  activePairingId = null;
  byId("pair-cap-devices-link").hidden = true;
  byId("pair-ticket").hidden = true;
  byId("approve-form").hidden = true;
  for (const id of ["pair-id", "pair-token", "browser-code", "browser-fingerprint", "phone-code", "phone-fingerprint"]) {
    const element = byId(id);
    element.textContent = "";
    if ("value" in element) element.value = "";
  }
  byId("compared").checked = false;
}

function clearKeySecret() {
  byId("key-secret").textContent = "";
  byId("key-secret-panel").hidden = true;
}

function clearKeyProofFields() {
  byId("key-password").value = "";
  byId("key-mfa-code").value = "";
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
  summaryBusy = false;
  summaryActiveRequest = null;
  summaryLastAttempt = 0;
  summaryLastStarted = 0;
  summaryRetryable = false;
  summaryGeneration += 1;
  summaryQueued = false;
  summarySnapshot = null;
  if (summaryTimer !== null) window.clearTimeout(summaryTimer);
  summaryTimer = null;
  summaryDevices.clear();
  byId("summary-device").value = "";
  updateSummaryDevices([], true);
  renderSummary("Sign in to load authoritative metadata.");
  ownerEpoch += 1;
  browsingOlderDevices = false;
  browsingOlderMessages = false;
  liveStreamEverOpened = false;
  sessionLoadGeneration += 1;
  deviceLoadGeneration += 1;
  messageLoadGeneration += 1;
  optOutReviewLoadGeneration += 1;
  keyLoadGeneration += 1;
  clearMfaChallenge();
  clearPairing();
  clearKeySecret();
  clearInboundHistory();
  clearWebhookEndpoints();
  byId("device-list").replaceChildren();
  fleetRows.clear();
  selectedDeviceId = null;
  fleetSnapshotFailed = false;
  renderSelectedDevice();
  byId("device-detail-content").hidden = true;
  message("device-detail-status", "Sign in to inspect device snapshots.");
  message("fleet-summary", "Sign in to load fleet observations.");
  byId("device-cap-prompt").hidden = true;
  message("device-cap-prompt", "");
  byId("more-devices").hidden = true;
  nextDeviceCursor = null;
  shownDeviceCount = 0;
  byId("message-list").replaceChildren();
  activityRows.clear();
  byId("more-messages").hidden = true;
  nextMessageCursor = null;
  shownMessageCount = 0;
  byId("opt-out-review-list").replaceChildren();
  byId("more-opt-out-review").hidden = true;
  nextOptOutReviewCursor = null;
  shownOptOutReviewCount = 0;
  message("opt-out-review-status", "");
  ownerHoldsLoadGeneration += 1;
  nextOwnerHoldsCursor = null;
  shownOwnerHoldsCount = 0;
  byId("owner-holds-list").replaceChildren();
  byId("more-owner-holds").hidden = true;
  for (const id of ["hold-recipient", "hold-channel", "hold-reason", "hold-reported-at"]) byId(id).value = "";
  message("owner-holds-status", "");
  message("owner-hold-create-status", "");
  byId("key-list").replaceChildren();
  byId("more-keys").hidden = true;
  nextKeyCursor = null;
  shownKeyCount = 0;
  message("key-create-status", "");
  clearKeyProofFields();
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

function formatTime(milliseconds, fallback) {
  const date = new Date(milliseconds);
  return Number.isFinite(milliseconds) && Number.isFinite(date.getTime()) ? timeFormat.format(date) : fallback;
}

function dateText(milliseconds) {
  return milliseconds === null ? "Never" : formatTime(milliseconds, "Time unavailable");
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
    byId("session-list").replaceChildren(...result.sessions.map((session) => {
      const item = document.createElement("li");
      const heading = document.createElement("strong");
      const detail = document.createElement("span");
      heading.textContent = session.current ? "This session" : "Other session";
      detail.textContent = `Created ${dateText(session.created_at_ms)} · Last used ${dateText(session.last_used_at_ms)} · Expires ${dateText(session.expires_at_ms)}`;
      item.append(heading, detail);
      return item;
    }));
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
  return Number.isSafeInteger(milliseconds) ? formatTime(milliseconds, "Unknown time") : "Unknown time";
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

function webhookDeliveryRow(delivery) {
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
  return row;
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
    byId("webhook-endpoint").append(...page.endpoints.map((endpoint) => {
      availableWebhookEndpointIds.add(endpoint.endpoint_id);
      const option = document.createElement("option");
      option.value = endpoint.endpoint_id;
      option.textContent = `Endpoint ${endpoint.endpoint_id}`;
      return option;
    }));
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
    byId("webhook-delivery-list").append(...page.deliveries.map(webhookDeliveryRow));
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

function inboundEventRow(event) {
  const row = document.createElement("li");
  const classification = document.createElement("strong");
  const detail = document.createElement("span");
  classification.textContent = inboundClassificationLabels[event.classification] || "Unrecognized classification";
  const parts = Number.isInteger(event.part_count) && event.part_count >= 1 && event.part_count <= 6
    ? `${event.part_count} part${event.part_count === 1 ? "" : "s"}` : "Unknown part count";
  detail.textContent = `Observed ${inboundDateText(event.observed_at_ms)} · received ${inboundDateText(event.received_at_ms)} · ${parts} · ${inboundContentLabels[event.content_kind] || "Unrecognized content kind"}`;
  row.append(classification, detail);
  return row;
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
    if (!page || !Array.isArray(page.events) || page.events.length > 20 ||
        (page.next_before !== null && !uuidPattern.test(page.next_before)) ||
        (page.events.length === 0 && page.next_before !== null)) {
      throw new Error("The event response was invalid.");
    }
    byId("inbound-event-list").append(...page.events.map(inboundEventRow));
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
  if (!reset && !nextKeyCursor) return;
  const requestEpoch = ownerEpoch;
  const generation = ++keyLoadGeneration;
  const stale = () => requestEpoch !== ownerEpoch || generation !== keyLoadGeneration;
  const cursor = reset ? null : nextKeyCursor;
  const moreButton = byId("more-keys");
  moreButton.disabled = true;
  message("key-list-status", "Loading keys…");
  if (reset) {
    byId("key-list").replaceChildren();
    moreButton.hidden = true;
    nextKeyCursor = null;
    shownKeyCount = 0;
  }
  try {
    const path = cursor
      ? `/v1/auth/api-keys?before=${encodeURIComponent(cursor)}`
      : "/v1/auth/api-keys";
    const page = await api(path);
    if (stale()) return;
    if (!page || !Array.isArray(page.keys)) throw new Error("The key response was invalid.");
    moreButton.disabled = false;
    if (reset && page.keys.length === 0) {
      message("key-list-status", "No API keys yet.");
      return;
    }
    nextKeyCursor = page.next_cursor || null;
    shownKeyCount += page.keys.length;
    moreButton.hidden = !nextKeyCursor;
    message("key-list-status", `${shownKeyCount} key${shownKeyCount === 1 ? "" : "s"} shown${nextKeyCursor ? "; more available" : ""}. Revoked and expired keys stay visible.`);
    const rows = [];
    for (const key of page.keys) {
      const row = document.createElement("li");
      const detail = document.createElement("div");
      const prefix = document.createElement("strong");
      const metadata = document.createElement("span");
      prefix.textContent = `ztk_${key.public_prefix}…`;
      // No expiry is either a key minted before the default existed or the
      // explicit never opt-in; the list cannot tell them apart, so it says
      // "never" without claiming the key is old.
      const expires = key.expires_at_ms === null ? "never" : dateText(key.expires_at_ms);
      metadata.textContent = ` ${key.status} · ${key.scopes.join(", ")} · created ${dateText(key.created_at_ms)} · expires ${expires} · last used ${dateText(key.last_used_at_ms)}`;
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
      rows.push(row);
    }
    byId("key-list").append(...rows);
  } catch (error) {
    if (stale()) return;
    moreButton.disabled = false;
    message("key-list-status", `Could not load keys. ${error.message}`);
  }
}

async function loadDeviceCapacity() {
  const prompt = byId("device-cap-prompt");
  prompt.hidden = true;
  prompt.textContent = "";
  try {
    const result = await api("/v1/billing/device-capacity");
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

function deviceQueueText(device) {
  const validCount = (value) => Number.isSafeInteger(value) && value >= 0 && value <= 1_000;
  if (!validCount(device.pending_messages) || !validCount(device.in_flight_messages) ||
      !Number.isSafeInteger(device.status_observed_at_ms) || device.status_observed_at_ms <= 0 ||
      device.status_observed_at_ms > 8_640_000_000_000_000) return "Queue status unavailable.";
  const count = (value) => value === 1_000 ? "1,000+" : String(value);
  return `Pending: ${count(device.pending_messages)} · In flight: ${count(device.in_flight_messages)} · Snapshot ${dateText(device.status_observed_at_ms)}`;
}

function validPreconditionReport(device) {
  const report = device.reported_preconditions;
  if (!report || !["not_selected", "active", "inactive", "unavailable"].includes(report.selected_sim) ||
      !["granted", "denied", "unavailable"].includes(report.sms_permission) ||
      !["enabled", "disabled", "unavailable"].includes(report.airplane_mode) ||
      typeof report.fresh !== "boolean" || !Number.isSafeInteger(report.received_at_ms) ||
      report.received_at_ms <= 0 || report.received_at_ms > 8_640_000_000_000_000) {
    return false;
  }
  return Number.isSafeInteger(device.status_observed_at_ms) &&
    device.status_observed_at_ms >= report.received_at_ms &&
    device.status_observed_at_ms <= 8_640_000_000_000_000;
}

function preconditionRemaining(device) {
  if (!validPreconditionReport(device) || device.revoked ||
      device.active_socket_lease !== true || !device.reported_preconditions.fresh) return 0;
  return Math.max(0, preconditionFreshMs - (device.status_observed_at_ms - device.reported_preconditions.received_at_ms));
}

function devicePreconditionsText(device, expired = false) {
  if (!validPreconditionReport(device) || device.revoked) {
    return "Android preconditions unavailable; carrier readiness unknown.";
  }
  const report = device.reported_preconditions;
  const fresh = !expired && preconditionRemaining(device) > 0;
  const freshness = device.active_socket_lease === false ? "disconnected; last report" :
    device.active_socket_lease !== true ? "connection status unavailable; last report" :
      fresh ? "fresh at snapshot time" : "stale report";
  const networkNames = { in_service: "in service", out_of_service: "out of service",
    emergency_only: "emergency only", power_off: "radio powered off", unavailable: "unavailable" };
  const network = typeof report.network_service === "string" && Object.hasOwn(networkNames, report.network_service)
    ? networkNames[report.network_service] : "unavailable";
  const observations = `Android (${freshness}): selected SIM ${report.selected_sim.replaceAll("_", " ")}; SMS permission ${report.sms_permission}; airplane mode ${report.airplane_mode}; Android-reported network service ${network}. Received ${dateText(report.received_at_ms)}.`;
  if (!fresh) return `${observations} Historical observations; refresh to check for a newer report. Carrier readiness unknown.`;
  const blockers = [];
  if (report.selected_sim === "not_selected") blockers.push("No SIM selected: select a SIM in the gateway app");
  if (report.selected_sim === "inactive") blockers.push("Selected SIM inactive: check the selected SIM on the phone");
  if (report.sms_permission === "denied") blockers.push("SMS permission denied: check the gateway app permissions on the phone");
  if (report.airplane_mode === "enabled") blockers.push("Airplane mode enabled: check the phone settings");
  if (["out_of_service", "emergency_only", "power_off"].includes(report.network_service))
    blockers.push("Network service limited: check the selected SIM's network service on the phone");
  const unknown = [report.selected_sim, report.sms_permission, report.airplane_mode].includes("unavailable");
  const explanation = blockers.length ? `Reported local blockers: ${blockers.join(". ")}.` :
    unknown ? "Local preconditions are incomplete; check the gateway app on the phone." : "No reported local blockers at snapshot time.";
  return `${observations} ${explanation}${blockers.length && unknown ? " Other local preconditions are unavailable." : ""} Carrier readiness unknown.`;
}

function deviceConnectivityText(device) {
  return device.revoked ? "Revoked · gateway authorization removed" :
    device.active_socket_lease === true
      ? "Approved · authenticated socket lease observed (may lag up to 90 seconds) · SMS readiness unknown"
      : device.active_socket_lease === false
        ? "Approved · no current authenticated socket lease · SMS readiness unknown"
        : "Approved for connection · live status unavailable";
}

function renderSelectedDevice() {
  for (const row of activityRows.values()) updateActivityDeviceContext(row);
  const entry = fleetRows.get(selectedDeviceId);
  for (const [id, row] of fleetRows) row.select.setAttribute("aria-pressed", String(id === selectedDeviceId));
  const content = byId("device-detail-content");
  preconditionRows = preconditionRows.filter(row => row.element !== byId("device-detail-preconditions"));
  content.hidden = !entry;
  if (!entry) {
    message("device-detail-status", selectedDeviceId
      ? "The selected device is absent from this loaded page. It may have been removed or moved to an older page. Choose another device or load more."
      : "Choose a device to inspect its latest loaded snapshot.");
    for (const id of ["device-detail-name", "device-detail-id", "device-detail-connectivity", "device-detail-queue", "device-detail-preconditions"]) byId(id).textContent = "";
    return;
  }
  const device = entry.device;
  byId("device-detail-name").textContent = device.display_name || "Unnamed gateway";
  byId("device-detail-id").textContent = device.device_id;
  byId("device-detail-connectivity").textContent = deviceConnectivityText(device);
  byId("device-detail-queue").textContent = deviceQueueText(device);
  byId("device-detail-preconditions").textContent = devicePreconditionsText(device, entry.observation.expired);
  message("device-detail-status", fleetSnapshotFailed
    ? "Refresh failed. Showing an older loaded snapshot; current connectivity and queue counts are unknown."
    : `Loaded observation: ${dateText(device.status_observed_at_ms)}. This is not an exact heartbeat time.`);
  preconditionRows.push({ ...entry.observation, element: byId("device-detail-preconditions") });
  agePreconditions();
}

function updateFleetRow(device, started, wallStarted) {
  let entry = fleetRows.get(device.device_id);
  if (!entry) {
    const row = document.createElement("li");
    const detail = document.createElement("div");
    const name = document.createElement("strong");
    const id = document.createElement("code");
    const state = document.createElement("span");
    const queue = document.createElement("span");
    const preconditions = document.createElement("span");
    preconditions.setAttribute("aria-live", "off");
    detail.append(name, id, state, queue, preconditions);
    const revoke = document.createElement("button");
    revoke.type = "button";
    revoke.className = "quiet";
    revoke.textContent = "Revoke";
    const select = document.createElement("button");
    select.type = "button";
    select.className = "fleet-select";
    select.textContent = "View details";
    row.append(detail, revoke, select);
    entry = { row, name, id, state, queue, preconditions, revoke, select, device };
    fleetRows.set(device.device_id, entry);
    select.addEventListener("click", () => { selectedDeviceId = entry.device.device_id; renderSelectedDevice(); });
    revoke.addEventListener("click", async () => {
      const current = entry.device;
      if (current.revoked || !window.confirm(`Revoke ${current.display_name}? Its gateway connection will lose authorization.`)) return;
      entry.revoking = true;
      revoke.disabled = true;
      try {
        await api(`/v1/enrollment/devices/${encodeURIComponent(current.device_id)}`, "DELETE");
        await Promise.all([loadDevices(), loadDeviceCapacity()]);
      } catch (error) {
        message("device-status", error.message);
      } finally {
        entry.revoking = false;
        revoke.disabled = false;
      }
    });
  }
  entry.device = device;
  entry.name.textContent = device.display_name || "Unnamed gateway";
  entry.id.textContent = device.device_id;
  entry.state.textContent = deviceConnectivityText(device);
  entry.queue.textContent = deviceQueueText(device);
  entry.preconditions.textContent = devicePreconditionsText(device);
  entry.revoke.hidden = !!device.revoked;
  entry.revoke.disabled = !!entry.revoking;
  entry.revoke.setAttribute("aria-label", `Revoke ${device.display_name}`);
  entry.select.setAttribute("aria-label", `View details for ${device.display_name || "unnamed gateway"}`);
  entry.select.setAttribute("aria-controls", "device-detail");
  entry.row.setAttribute("data-device-id", device.device_id);
  entry.observation = { device, element: entry.preconditions, started, wallStarted,
    remaining: preconditionRemaining(device), expired: false };
  return entry;
}

async function loadDevices(reset = true, automatic = false) {
  if (!reset && !nextDeviceCursor) return;
  deviceLoads += 1;
  if (!automatic) browsingOlderDevices = !reset;
  const requestEpoch = ownerEpoch;
  const generation = ++deviceLoadGeneration;
  const started = performance.now();
  const wallStarted = Date.now();
  const stale = () => requestEpoch !== ownerEpoch || generation !== deviceLoadGeneration;
  const cursor = reset ? null : nextDeviceCursor;
  const moreButton = byId("more-devices");
  moreButton.disabled = true;
  if (!automatic) message("device-status", "Loading devices…");
  if (reset) {
    message("fleet-summary", fleetRows.size ? "Refreshing loaded observations; previous snapshots remain visible." : "Fleet observations are loading.");
  }
  try {
    const path = cursor
      ? `/v1/enrollment/devices?before=${encodeURIComponent(cursor)}`
      : "/v1/enrollment/devices";
    const page = await api(path);
    if (stale()) return;
    if (automatic && (!canRefreshDashboard() || viewingList("device-list"))) return;
    if (!page || !Array.isArray(page.devices)) throw new Error("The device response was invalid.");
    const devices = page.devices;
    if (devices.some(device => !device || typeof device.device_id !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(device.device_id)) ||
        new Set(devices.map(device => device.device_id)).size !== devices.length) throw new Error("The device response contained ambiguous identities.");
    updateSummaryDevices(devices, reset);
    const focused = document.activeElement;
    if (reset) {
      clearPreconditionRows();
      const ids = new Set(devices.map(device => device.device_id));
      for (const id of fleetRows.keys()) if (!ids.has(id)) fleetRows.delete(id);
    }
    fleetSnapshotFailed = false;
    for (const device of devices) updateFleetRow(device, started, wallStarted);
    preconditionRows = [...fleetRows.values()].map(entry => entry.observation);
    byId("device-list").replaceChildren(...[...fleetRows.values()].map(entry => entry.row));
    if (focused && byId("device-list").contains(focused) && !focused.hidden && typeof focused.focus === "function") focused.focus({ preventScroll: true });
    nextDeviceCursor = page.next_cursor || null;
    shownDeviceCount = fleetRows.size;
    moreButton.hidden = !nextDeviceCursor;
    const observed = [...fleetRows.values()].filter(entry => !entry.device.revoked && entry.device.active_socket_lease === true).length;
    message("fleet-summary", `${shownDeviceCount} loaded device${shownDeviceCount === 1 ? "" : "s"} · ${observed} authenticated socket lease${observed === 1 ? "" : "s"} observed. Counts cover loaded pages only; carrier readiness remains unknown.`);
    message("device-status", shownDeviceCount === 0 ? "No approved devices yet." : `${shownDeviceCount} device${shownDeviceCount === 1 ? "" : "s"} shown${nextDeviceCursor ? "; more available" : ""}. Revoked devices stay visible.`);
    renderSelectedDevice();
    agePreconditions();
  } catch (error) {
    if (stale()) return;
    moreButton.disabled = false;
    fleetSnapshotFailed = true;
    message("fleet-summary", fleetRows.size ? "Refresh failed. Loaded page observations and counts may be stale." : "Fleet observations unavailable. Retry Refresh.");
    renderSelectedDevice();
    agePreconditions();
    message("device-status", `Could not load devices. ${fleetRows.size ? "Showing the previous snapshot; counts may be stale. " : ""}${error.message}`);
  } finally {
    deviceLoads -= 1;
    if (deviceLoads === 0 && devicesSignalDuringLoad) {
      // Answer a signal that arrived while this reload was in flight.
      devicesSignalDuringLoad = false;
      if (canRefreshDashboard()) requestLiveDevicesReload();
    }
    if (!stale()) moreButton.disabled = false;
  }
}

function updateSummaryDevices(devices, reset) {
  const select = byId("summary-device");
  const selected = select.value;
  if (reset) summaryDevices.clear();
  for (const device of devices) if (device && uuidPattern.test(device.device_id)) summaryDevices.set(device.device_id, device.display_name || "Unnamed gateway");
  const all = document.createElement("option");
  all.value = ""; all.textContent = "All devices in this account";
  const options = [all];
  for (const [id, name] of summaryDevices) {
    const option = document.createElement("option"); option.value = id; option.textContent = name; options.push(option);
  }
  if (selected && !summaryDevices.has(selected)) {
    const option = document.createElement("option"); option.value = selected;
    option.textContent = "Selected device (absent from loaded fleet pages)"; options.push(option);
  }
  select.replaceChildren(...options);
  select.value = selected;
}

function validSummary(value, device) {
  const count = item => item && Number.isSafeInteger(item.value) && item.value >= 0 && item.value <= value.count_bound &&
    typeof item.capped === "boolean" && (!item.capped || item.value === value.count_bound);
  return value && value.scope === (device ? "device" : "account") && value.device_id === (device || null) && value.timezone === "UTC" &&
    Number.isSafeInteger(value.day_start_ms) && Number.isSafeInteger(value.day_end_ms) &&
    value.day_end_ms - value.day_start_ms === 86_400_000 &&
    Number.isSafeInteger(value.observed_at_ms) && value.observed_at_ms >= value.day_start_ms && value.observed_at_ms < value.day_end_ms &&
    value.count_bound === 1000 && value.max_age_ms === 30000 &&
    count(value.submitted_today) && count(value.pending) && count(value.in_flight);
}

function renderSummary(status = "") {
  const snapshot = summarySnapshot;
  byId("message-summary").setAttribute("data-stale", String(Boolean(snapshot && snapshot.expired)));
  for (const [id, field] of [["summary-submitted", "submitted_today"], ["summary-pending", "pending"], ["summary-flight", "in_flight"]]) {
    byId(id).textContent = snapshot ? `${snapshot.value[field].value}${snapshot.value[field].capped ? "+ (capped)" : ""}${snapshot.expired ? " (stale)" : ""}` :
      summaryBusy ? "Loading…" : "Unavailable";
  }
  if (status) message("summary-status", status);
  else if (snapshot) message("summary-status", `${snapshot.error ? snapshot.error + ". " : ""}${snapshot.value.scope === "account" ? "Account" : "Selected device"} observation: ${dateText(snapshot.value.observed_at_ms)}. UTC day; capped values are lower bounds. ${snapshot.expired ? "Historical metadata; current counts are unknown." : "These writer states do not establish delivery."}`);
}

function ageSummary() {
  if (summaryTimer !== null) window.clearTimeout(summaryTimer);
  summaryTimer = null;
  if (!summarySnapshot || !dashboardSignedIn) { scheduleSummaryRetry(); return; }
  const elapsed = Math.max(0, performance.now() - summarySnapshot.started, Date.now() - summarySnapshot.wallStarted);
  summarySnapshot.expired ||= elapsed >= summarySnapshot.remaining || (typeof navigator !== "undefined" && navigator.onLine === false);
  renderSummary();
  if (!dashboardPageActive || document.hidden) return;
  const automatic = byId("auto-refresh").checked;
  const delay = summarySnapshot.expired ? 15000 : Math.min(15000, Math.max(1, Math.ceil(summarySnapshot.remaining - elapsed)));
  if (!automatic && summarySnapshot.expired) return;
  summaryTimer = window.setTimeout(() => {
    summaryTimer = null;
    if (automatic && summaryRefreshDue() && canRefreshDashboard() && (typeof navigator === "undefined" || navigator.onLine !== false)) loadSummary(true);
    else ageSummary();
  }, delay);
}

function summaryRefreshDue() {
  return Math.max(Date.now() - summaryLastAttempt, performance.now() - summaryLastStarted) >= 15000;
}

function resumeSummary() {
  ageSummary();
  if (summarySnapshot && summarySnapshot.expired && summaryRefreshDue() && canRefreshDashboard()) loadSummary(true);
}

function scheduleSummaryRetry() {
  if (!summaryRetryable || !dashboardSignedIn || !dashboardPageActive || document.hidden || !byId("auto-refresh").checked) return;
  if (summaryTimer !== null) window.clearTimeout(summaryTimer);
  summaryTimer = window.setTimeout(() => {
    summaryTimer = null;
    if (canRefreshDashboard() && (typeof navigator === "undefined" || navigator.onLine !== false)) loadSummary(true);
    else scheduleSummaryRetry();
  }, 15000);
}

async function loadSummary(automatic = false, scopeChanged = false) {
  if (!dashboardSignedIn || !dashboardPageActive) return;
  if (scopeChanged) {
    summaryGeneration += 1;
    summarySnapshot = null;
    if (summaryTimer !== null) window.clearTimeout(summaryTimer);
    summaryTimer = null;
  }
  if (summaryBusy) { if (scopeChanged) summaryQueued = true; return; }
  summaryBusy = true;
  const requestToken = {};
  summaryActiveRequest = requestToken;
  const generation = ++summaryGeneration, epoch = ownerEpoch, device = byId("summary-device").value;
  const started = performance.now(), wallStarted = Date.now();
  summaryLastAttempt = wallStarted;
  summaryLastStarted = started;
  const stale = () => epoch !== ownerEpoch || generation !== summaryGeneration || device !== byId("summary-device").value;
  byId("refresh-summary").disabled = true;
  renderSummary(automatic && summarySnapshot ? "Refreshing authoritative metadata…" : "Loading authoritative metadata…");
  try {
    const value = await api(`/v1/owner/message-summary${device ? `?device_id=${encodeURIComponent(device)}` : ""}`);
    if (stale()) return;
    if (!validSummary(value, device)) throw new Error("The summary response was invalid.");
    summarySnapshot = { value, started, wallStarted, expired: false, remaining: Math.min(value.max_age_ms, value.day_end_ms - value.observed_at_ms) };
    summaryRetryable = false;
    ageSummary();
  } catch (error) {
    if (stale()) return;
    if (summarySnapshot) { summarySnapshot.expired = true; summarySnapshot.error = "Refresh failed"; }
    summaryRetryable = error.status >= 500 || error.retryable === true;
    renderSummary(`Summary unavailable. ${summarySnapshot ? "Showing historical metadata; current counts are unknown. " : ""}${error.message}`);
    if (summarySnapshot) ageSummary(); else scheduleSummaryRetry();
  } finally {
    if (summaryActiveRequest === requestToken) {
      summaryBusy = false;
      summaryActiveRequest = null;
      if (!stale()) { byId("refresh-summary").disabled = false; renderSummary(); }
      if (summaryQueued && dashboardSignedIn) { summaryQueued = false; loadSummary(false, true); }
    }
  }
}

byId("refresh-summary").addEventListener("click", () => loadSummary());
byId("summary-device").addEventListener("change", () => { loadSummary(false, true); renderSummary("Loading selected scope…"); });
window.addEventListener("offline", () => { if (summarySnapshot) { summarySnapshot.expired = true; summarySnapshot.error = "Offline"; } ageSummary(); });
window.addEventListener("online", () => { if (canRefreshDashboard()) loadSummary(true); });

function localTime(milliseconds) {
  return formatTime(milliseconds, "Time unavailable");
}

function updateActivityDeviceContext(row) {
  const gateway = fleetRows.get(row.activityDeviceId);
  row.activityDeviceLink.hidden = !gateway;
  row.activityDeviceUnavailable.hidden = Boolean(gateway);
  row.activityDeviceLink.textContent = gateway ? `View device ${gateway.device.display_name || row.activityDeviceId}` : "Device context unavailable";
  row.activityDeviceUnavailable.textContent = `Device: ${row.activityDeviceId} · absent from loaded fleet pages`;
}

async function loadMessages(reset = true, automatic = false) {
  if (!reset && !nextMessageCursor) return;
  messageLoads += 1;
  if (!automatic) browsingOlderMessages = !reset;
  const requestEpoch = ownerEpoch;
  const generation = ++messageLoadGeneration;
  const stale = () => requestEpoch !== ownerEpoch || generation !== messageLoadGeneration;
  const cursor = reset ? null : nextMessageCursor;
  const moreButton = byId("more-messages");
  moreButton.disabled = true;
  if (!automatic) message("message-status", "Loading message states…");
  try {
    const path = cursor
      ? `/v1/owner/messages?before=${encodeURIComponent(cursor)}`
      : "/v1/owner/messages";
    const page = await api(path);
    if (stale()) return;
    if (automatic && (!canRefreshDashboard() || viewingList("message-list"))) return;
    if (!page || !Array.isArray(page.messages) || page.messages.length > 20 ||
        new Set(page.messages.map(item => item && item.message_id)).size !== page.messages.length ||
        !page.messages.every((item) => item && typeof item.message_id === "string" && typeof item.device_id === "string" &&
          typeof item.state === "string" && Array.isArray(item.events) && item.events.length <= 32 &&
          item.events.every(event => event && typeof event.evidence === "string" && typeof event.resulting_state === "string"))) {
      throw new Error("The message response was invalid.");
    }
    if (reset) {
      const present = new Set(page.messages.map(item => item.message_id));
      for (const [id, row] of activityRows) {
        if (!present.has(id)) { row.remove(); activityRows.delete(id); }
      }
      moreButton.hidden = true;
      nextMessageCursor = null;
      shownMessageCount = 0;
    }
    moreButton.disabled = false;
    if (reset && page.messages.length === 0) {
      message("message-status", "No messages yet.");
      return;
    }
    nextMessageCursor = page.next_cursor || null;
    shownMessageCount = new Set([...activityRows.keys(), ...page.messages.map(item => item.message_id)]).size;
    moreButton.hidden = !nextMessageCursor;
    message("message-status", `${shownMessageCount} message${shownMessageCount === 1 ? "" : "s"} shown${nextMessageCursor ? "; more available" : ""}.`);
    const rows = [];
    for (const item of page.messages) {
      const previous = activityRows.get(item.message_id);
      const row = previous || document.createElement("li");
      const wasOpen = previous && previous.activityDetails.open;
      const focused = previous && row.contains(document.activeElement) ? document.activeElement : null;
      row.className = "activity-row";
      const state = document.createElement("strong");
      const id = document.createElement("code");
      const device = document.createElement("span");
      const created = document.createElement("time");
      const states = { accepted: "Accepted · not sent", queued: "Queued · not sent", claimed: "Claimed · not sent",
        submitting: "Submitting · radio attempt unconfirmed", submitted: "Sent callback · delivery unconfirmed",
        delivered: "Delivered callback · unread status unknown", delivery_unknown: "Delivery unknown",
        unknown: "Outcome unknown", failed: "Failed", cancelled: "Cancelled", expired: "Expired" };
      state.textContent = Object.hasOwn(states, item.state) ? states[item.state] : "Unrecognized state · outcome unknown";
      state.className = "activity-state";
      state.setAttribute("data-state", Object.hasOwn(states, item.state) ? item.state : "unknown");
      id.textContent = item.message_id;
      {
        const link = document.createElement("button");
        link.type = "button";
        link.className = "quiet activity-device";
        link.setAttribute("aria-controls", "device-detail-content");
        link.addEventListener("click", () => {
          if (requestEpoch !== ownerEpoch) return;
          if (!fleetRows.has(item.device_id)) return;
          selectedDeviceId = item.device_id;
          renderSelectedDevice();
          if (typeof byId("device-detail-title").scrollIntoView === "function") byId("device-detail-title").scrollIntoView({ block: "nearest" });
          message("message-status", "Selected device context in the fleet panel. Message paging and history are unchanged.");
        });
        const unavailable = document.createElement("span");
        device.append(link, unavailable);
        row.activityDeviceId = item.device_id;
        row.activityDeviceLink = link;
        row.activityDeviceUnavailable = unavailable;
        updateActivityDeviceContext(row);
      }
      created.textContent = `Time: ${localTime(item.created_at_ms)}`;
      const createdDate = new Date(item.created_at_ms);
      if (!Number.isNaN(createdDate.getTime())) created.dateTime = createdDate.toISOString();
      const direction = document.createElement("span");
      direction.textContent = "Direction: Outbound";
      const recipient = document.createElement("span");
      recipient.textContent = "Recipient: unavailable";
      const cells = document.createElement("div");
      cells.className = "activity-cells";
      cells.append(created, direction, device, recipient, state);
      row.replaceChildren(cells, id);
      if (item.state === "unknown" || item.state === "delivery_unknown" || !Object.hasOwn(states, item.state)) {
        const warning = document.createElement("p");
        warning.className = "message-uncertain";
        warning.textContent = "Outcome unknown. The phone may have sent this SMS. Sending a new message could duplicate it.";
        row.append(warning);
      }
      const details = document.createElement("details");
      details.open = Boolean(wasOpen);
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
          const result = Object.hasOwn(states, event.resulting_state) ? states[event.resulting_state] : "Unrecognized state · outcome unknown";
          entry.textContent = `${localTime(event.received_at_ms)} · ${event.evidence.replaceAll("_", " ")} → ${result}${segment}`;
          list.append(entry);
        }
        details.append(list);
      }
      row.append(details);
      row.activityDetails = details;
      activityRows.set(item.message_id, row);
      if (focused) row.activityRestoreFocus = focused.tagName === "SUMMARY" ? summary : device.children[0];
      rows.push(row);
    }
    byId("message-list").append(...rows);
    for (const row of rows) {
      if (row.activityRestoreFocus && typeof row.activityRestoreFocus.focus === "function") row.activityRestoreFocus.focus();
      row.activityRestoreFocus = null;
    }
  } catch (error) {
    if (stale()) return;
    moreButton.disabled = false;
    message("message-status", `Could not load messages. ${activityRows.size ? "Showing older metadata; current states are unknown. " : ""}${error.message}`);
  } finally {
    messageLoads -= 1;
    if (messageLoads === 0 && messagesSignalDuringLoad) {
      // Answer a signal that arrived while this reload was in flight.
      messagesSignalDuringLoad = false;
      if (canRefreshDashboard()) requestLiveMessagesReload();
    }
    if (!stale()) moreButton.disabled = false;
  }
}

async function loadOptOutReview(reset = true) {
  if (!reset && !nextOptOutReviewCursor) return;
  const requestEpoch = ownerEpoch;
  const generation = ++optOutReviewLoadGeneration;
  const stale = () => requestEpoch !== ownerEpoch || generation !== optOutReviewLoadGeneration;
  const cursor = reset ? null : nextOptOutReviewCursor;
  const moreButton = byId("more-opt-out-review");
  moreButton.disabled = true;
  message("opt-out-review-status", "Loading active review holds…");
  if (reset) {
    byId("opt-out-review-list").replaceChildren();
    moreButton.hidden = true;
    nextOptOutReviewCursor = null;
    shownOptOutReviewCount = 0;
  }
  try {
    const path = cursor
      ? `/v1/owner/opt-out-review?before=${encodeURIComponent(cursor)}`
      : "/v1/owner/opt-out-review";
    const page = await api(path);
    if (stale()) return;
    if (!page || !Array.isArray(page.holds) || page.holds.length > 20 ||
        !page.holds.every((hold) => hold && /^\+[1-9][0-9]{1,14}$/.test(hold.recipient_e164) &&
          ["sms_review", "sms_unsolicited_review"].includes(hold.source) &&
          uuidPattern.test(hold.review_event_id) &&
          (hold.decision === null || Object.hasOwn(reviewDecisions, hold.decision)) &&
          Number.isSafeInteger(hold.observed_at_ms) && Number.isSafeInteger(hold.changed_at_ms)) ||
        (page.next_cursor !== null && !uuidPattern.test(page.next_cursor))) {
      throw new Error("The review response was invalid.");
    }
    nextOptOutReviewCursor = page.next_cursor;
    shownOptOutReviewCount += page.holds.length;
    moreButton.hidden = !nextOptOutReviewCursor;
    moreButton.disabled = false;
    if (reset && page.holds.length === 0) {
      message("opt-out-review-status", "No active ambiguous SMS holds.");
      return;
    }
    message("opt-out-review-status", `${shownOptOutReviewCount} hold${shownOptOutReviewCount === 1 ? "" : "s"} shown${nextOptOutReviewCursor ? "; more available" : ""}.`);
    const rows = [];
    for (const hold of page.holds) {
      const row = document.createElement("li");
      const recipient = document.createElement("strong");
      const source = document.createElement("span");
      const observed = document.createElement("time");
      const changed = document.createElement("time");
      recipient.textContent = hold.recipient_e164;
      source.textContent = hold.source === "sms_unsolicited_review"
        ? " · Possible withdrawal outside a pilot reply window"
        : " · Possible withdrawal in a pilot reply window";
      observed.textContent = ` · Observed ${localTime(hold.observed_at_ms)}`;
      const date = new Date(hold.observed_at_ms);
      if (!Number.isNaN(date.getTime())) observed.dateTime = date.toISOString();
      changed.textContent = ` · Blocked ${localTime(hold.changed_at_ms)}`;
      const changedDate = new Date(hold.changed_at_ms);
      if (!Number.isNaN(changedDate.getTime())) changed.dateTime = changedDate.toISOString();
      row.append(recipient, source, observed, changed);
      if (hold.decision !== null) {
        const decision = document.createElement("p");
        decision.textContent = `${reviewDecisions[hold.decision]} recorded · Recipient remains blocked.`;
        row.append(decision);
      } else {
        appendReviewDecision(row, hold);
      }
      rows.push(row);
    }
    byId("opt-out-review-list").append(...rows);
  } catch (error) {
    if (stale()) return;
    moreButton.disabled = false;
    message("opt-out-review-status", `Could not load review holds. ${error.message}`);
  }
}

function appendReviewDecision(row, hold) {
  const form = document.createElement("form");
  form.method = "post";
  form.action = "/v1/owner/opt-out-review/decisions";
  const label = document.createElement("label");
  const select = document.createElement("select");
  select.id = `decision-${hold.review_event_id}`;
  select.required = true;
  label.htmlFor = select.id;
  label.textContent = `Review result for ${hold.recipient_e164}`;
  for (const [value, text] of [["", "Choose a decision"], ...Object.entries(reviewDecisions)]) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = text;
    select.append(option);
  }
  const button = document.createElement("button");
  button.type = "submit";
  button.textContent = "Record permanent decision";
  form.append(label, select, button);
  const rowEpoch = ownerEpoch;
  form.addEventListener("submit", exclusive(async () => {
    if (rowEpoch !== ownerEpoch || !Object.hasOwn(reviewDecisions, select.value)) return;
    button.disabled = true;
    select.disabled = true;
    message("opt-out-review-status", "Recording decision…");
    try {
      await api("/v1/owner/opt-out-review/decisions", "POST", {
        review_event_id: hold.review_event_id, decision: select.value,
      });
      if (rowEpoch !== ownerEpoch) return;
      await loadOptOutReview();
      if (rowEpoch === ownerEpoch) message("opt-out-review-status", "Decision recorded. The recipient remains blocked.");
    } catch (error) {
      if (rowEpoch !== ownerEpoch) return;
      message("opt-out-review-status", error.status === 409
        ? "A decision is already recorded. Refresh the review queue. The recipient remains blocked."
        : `Could not confirm the decision. Refresh before retrying. ${error.message}`);
    } finally {
      button.disabled = false;
      select.disabled = false;
    }
  }));
  row.append(form);
}

async function loadOwnerHolds(reset = true) {
  if (!reset && !nextOwnerHoldsCursor) return;
  const epoch = ownerEpoch;
  const generation = ++ownerHoldsLoadGeneration;
  const stale = () => epoch !== ownerEpoch || generation !== ownerHoldsLoadGeneration;
  const cursor = reset ? null : nextOwnerHoldsCursor;
  const more = byId("more-owner-holds");
  more.disabled = true;
  if (reset) {
    byId("owner-holds-list").replaceChildren();
    nextOwnerHoldsCursor = null;
    shownOwnerHoldsCount = 0;
    more.hidden = true;
  }
  message("owner-holds-status", "Loading active requests…");
  try {
    const page = await api(cursor ? `/v1/owner/opt-out-holds?before=${encodeURIComponent(cursor)}` : "/v1/owner/opt-out-holds");
    if (stale()) return;
    if (!page || !Array.isArray(page.holds) || page.holds.length > 20 ||
        !page.holds.every((hold) => hold && uuidPattern.test(hold.hold_id) &&
          /^\+[1-9][0-9]{1,14}$/.test(hold.recipient_e164) &&
          Object.hasOwn(holdChannels, hold.channel) && Object.hasOwn(holdReasons, hold.reason) &&
          Number.isSafeInteger(hold.reported_at_ms) && Number.isSafeInteger(hold.created_at_ms)) ||
        (page.next_cursor !== null && !uuidPattern.test(page.next_cursor))) throw new Error("The request list was invalid.");
    nextOwnerHoldsCursor = page.next_cursor;
    shownOwnerHoldsCount += page.holds.length;
    for (const hold of page.holds) {
      const row = document.createElement("li");
      row.textContent = `${hold.recipient_e164} · ${holdChannels[hold.channel]} · ${holdReasons[hold.reason]} · Received ${localTime(hold.reported_at_ms)} · Blocked ${localTime(hold.created_at_ms)}`;
      byId("owner-holds-list").append(row);
    }
    more.hidden = !nextOwnerHoldsCursor;
    message("owner-holds-status", shownOwnerHoldsCount ? `${shownOwnerHoldsCount} active request(s) shown.` : "No active requests received elsewhere.");
  } catch (error) {
    if (!stale()) message("owner-holds-status", `Could not load requests. ${error.message}`);
  } finally {
    if (!stale()) more.disabled = false;
  }
}

async function createOwnerHold() {
  const epoch = ownerEpoch;
  const body = {
    recipient_e164: byId("hold-recipient").value.trim(),
    channel: byId("hold-channel").value,
    reason: byId("hold-reason").value,
    reported_at_ms: new Date(byId("hold-reported-at").value).getTime(),
  };
  if (!/^\+[1-9][0-9]{1,14}$/.test(body.recipient_e164) || !Object.hasOwn(holdChannels, body.channel) ||
      !Object.hasOwn(holdReasons, body.reason) || !Number.isSafeInteger(body.reported_at_ms)) {
    message("owner-hold-create-status", "Enter a valid international number, channel, reason and local receipt time.");
    return;
  }
  message("owner-hold-create-status", "Recording request…");
  try {
    await api("/v1/owner/opt-out-holds", "POST", body);
    if (epoch !== ownerEpoch) return;
    for (const id of ["hold-recipient", "hold-channel", "hold-reason", "hold-reported-at"]) byId(id).value = "";
    message("owner-hold-create-status", "Request recorded. The recipient is blocked; queued messages not yet authorized for sending were cancelled. Sending already in progress may still finish.");
    await Promise.all([loadOwnerHolds(), loadMessages()]);
  } catch (error) {
    if (epoch !== ownerEpoch) return;
    message("owner-hold-create-status", error.status === 409
      ? "An active request already blocks this recipient. Refresh the requests below."
      : `Could not confirm the request. Refresh before retrying. ${error.message}`);
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
    if (error.status === 404) clearPairing();
  }
}

byId("login-form").addEventListener("submit", exclusive(async (event) => {
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
}));

byId("mfa-form").addEventListener("submit", exclusive(async (event) => {
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
}));

byId("cancel-mfa").addEventListener("click", () => {
  clearMfaChallenge();
  message("login-status", "Enter your password to start again.");
});

byId("logout").addEventListener("click", exclusive(async () => {
  try {
    await api("/v1/auth/logout", "POST");
    clearOwnerState();
    message("global-status", "Signed out.");
  } catch (error) {
    message("global-status", `Could not sign out. ${error.message}`);
  }
}));

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
  const revokeApiKeys = byId("revoke-sessions-api-keys").checked;
  if (!window.confirm(revokeApiKeys
    ? "Sign out all other sessions and revoke every API key?"
    : "Sign out all other sessions?")) return;
  const currentPassword = byId("revoke-sessions-password").value;
  const code = byId("revoke-sessions-mfa-code").value.trim();
  byId("revoke-sessions-password").value = "";
  byId("revoke-sessions-mfa-code").value = "";
  byId("revoke-sessions-api-keys").checked = false;
  byId("revoke-other-sessions").disabled = true;
  message("session-status", "Signing out other sessions…");
  try {
    await api("/v1/auth/sessions/revoke-others", "POST", {
      current_password: currentPassword,
      ...(code ? { code } : {}),
      revoke_api_keys: revokeApiKeys,
    });
    clearKeySecret();
    await Promise.all([loadSessions(), loadKeys()]);
  } catch (error) {
    message("session-status", `Could not sign out other sessions. ${error.message}`);
  } finally {
    byId("revoke-other-sessions").disabled = false;
  }
});

byId("create-form").addEventListener("submit", exclusive(async (event) => {
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
}));

byId("check-proof").addEventListener("click", checkPairing);
byId("cancel-pairing").addEventListener("click", exclusive(async () => {
  if (!activePairingId) return;
  try {
    await api(`/v1/enrollment/pairings/${encodeURIComponent(activePairingId)}/cancel`, "POST");
    clearPairing();
    message("pair-status", "Pairing cancelled. Create a new one when ready.");
  } catch (error) {
    message("pair-status", `Could not cancel pairing. ${error.message}`);
  }
}));

byId("approve-form").addEventListener("submit", exclusive(async (event) => {
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
}));

byId("refresh-devices").addEventListener("click", () => Promise.all([loadDevices(), loadDeviceCapacity()]));
byId("more-devices").addEventListener("click", () => loadDevices(false));
byId("refresh-messages").addEventListener("click", () => loadMessages());
byId("more-messages").addEventListener("click", () => loadMessages(false));
byId("refresh-opt-out-review").addEventListener("click", () => loadOptOutReview());
byId("more-opt-out-review").addEventListener("click", () => loadOptOutReview(false));
byId("refresh-owner-holds").addEventListener("click", () => loadOwnerHolds());
byId("more-owner-holds").addEventListener("click", () => loadOwnerHolds(false));
byId("owner-hold-form").addEventListener("submit", exclusive(createOwnerHold));
byId("refresh-keys").addEventListener("click", () => loadKeys());
byId("more-keys").addEventListener("click", () => loadKeys(false));
byId("dismiss-key-secret").addEventListener("click", clearKeySecret);
byId("auto-refresh").addEventListener("change", () => {
  ageSummary();
  syncLiveUpdates();
  scheduleDashboardRefresh();
});
document.addEventListener("visibilitychange", () => {
  resumeSummary();
  syncLiveUpdates();
  scheduleDashboardRefresh();
  agePreconditions();
});
window.addEventListener("pagehide", () => {
  if (summaryTimer !== null) window.clearTimeout(summaryTimer);
  summaryTimer = null;
  dashboardPageActive = false;
  stopDashboardRefresh();
  stopLiveUpdates();
  stopPreconditionAging();
  clearKeySecret(); clearKeyProofFields(); clearPasswordFields(); clearResetFields();
});
window.addEventListener("pageshow", () => {
  dashboardPageActive = true;
  resumeSummary();
  agePreconditions();
  scheduleDashboardRefresh();
  startLiveUpdates();
});
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
byId("key-create-form").addEventListener("submit", exclusive(async (event) => {
  event.preventDefault();
  const createEpoch = ownerEpoch;
  clearKeySecret();
  const scopes = [...byId("key-create-form").querySelectorAll('input[name="scope"]:checked')]
    .map((input) => input.value);
  const currentPassword = byId("key-password").value;
  const code = byId("key-mfa-code").value.trim();
  clearKeyProofFields();
  if (scopes.length === 0) {
    message("key-create-status", "Choose at least one scope.");
    return;
  }
  if (!currentPassword) {
    message("key-create-status", "Enter your password to create a key.");
    return;
  }
  message("key-create-status", "Creating key…");
  try {
    const created = await api("/v1/auth/api-keys", "POST", {
      scopes,
      lifetime_days: byId("key-lifetime").value === "never" ? null : Number(byId("key-lifetime").value),
      current_password: currentPassword,
      ...(code ? { code } : {}),
    });
    if (createEpoch !== ownerEpoch) return;
    byId("key-secret").textContent = created.token;
    byId("key-secret-panel").hidden = false;
    message("key-create-status", "Key created. Copy it now; this is its only display.");
    await loadKeys();
  } catch (error) {
    message("key-create-status", `Could not create key. ${error.message}`);
  }
}));

(async () => {
  message("global-status", "Checking your sign-in…");
  try {
    await api("/v1/auth/session");
    message("global-status", "");
    clearResetFields();
    showSignedIn(true);
    await loadOwnerData();
    scheduleDashboardRefresh();
    startLiveUpdates();
  } catch (error) {
    showSignedIn(false);
    message("global-status", error.message.startsWith("Your sign-in") ? "Sign in to manage devices." : `Could not verify session. ${error.message}`);
  }
})();
