// SPDX-License-Identifier: AGPL-3.0-only
// Owner SMS approval key and SMS line activation. The private key is a
// non-extractable WebCrypto key kept in this browser's IndexedDB; the server
// only ever receives its public key and signatures over statements this page
// rebuilt itself.
"use strict";

const signing = globalThis.ZtSmsLineSigning;
const pollIntervalMs = 2000;
// Once the owner statement is verified the page only needs to notice final
// approval or closure, which the server reports on the same view.
const verifiedPollIntervalMs = 10000;
const pollBackoffMaxMs = 30000;
const maxPollMs = 10 * 60 * 1000;
const requestTimeoutMs = 15000;
let session = null;
let serverKeys = [];
let localKey = null;
let activation = null;
let activationOpeningRound = 0;
let pollTimer = null;
let pollRound = 0;

const byId = (id) => document.getElementById(id);
// Tests replace the poll scheduler; the page uses the browser timer.
const schedule = (fn, ms) => (globalThis.ZtSmsLinesSchedule || setTimeout)(fn, ms);

function say(id, text) {
  byId(id).textContent = text;
}

function csrfToken() {
  const part = document.cookie.split(";").map((piece) => piece.trim())
    .find((piece) => piece.startsWith("__Host-zrotext_csrf="));
  return part ? part.slice("__Host-zrotext_csrf=".length) : null;
}

const failures = {
  400: "The request was not accepted. Check the values and try again.",
  401: "Your sign-in expired or the code was not accepted.",
  403: "The server refused this action. An approval key may already be active, or the phone disconnected or the request expired.",
  404: "Not found. The key or activation no longer exists, or SMS line activation is disabled on this server.",
  409: "Revoke the active SMS approval key first.",
  429: "Too many attempts. Wait a few minutes and try again.",
};

/** A definite HTTP answer from the server, as opposed to a lost request. */
class ApiRejection extends Error {
  constructor(status) {
    super(failures[status] || "The server could not complete this request.");
    this.status = status;
  }
}

async function api(path, method = "GET", body = undefined) {
  const csrf = csrfToken();
  if (!csrf) throw new Error("Your sign-in expired. Sign in again.");
  const headers = { "x-zrotext-csrf": csrf };
  if (body !== undefined) headers["content-type"] = "application/json";
  let response;
  try {
    response = await fetch(path, {
      method, headers, credentials: "same-origin", cache: "no-store", redirect: "error",
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(requestTimeoutMs) : undefined,
    });
  } catch {
    throw new Error("Could not reach the server. Check your connection and try again.");
  }
  if (!response.ok) throw new ApiRejection(response.status);
  return response.status === 204 ? null : response.json();
}

// IndexedDB holds the CryptoKey object itself; a non-extractable key is stored
// by structured clone and its private bytes are never readable by script.
function indexedDbKeyStore() {
  const open = () => new Promise((resolve, reject) => {
    const request = indexedDB.open("zrotext-owner", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("keys");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  const run = async (mode, action) => {
    const db = await open();
    try {
      return await new Promise((resolve, reject) => {
        const request = action(db.transaction("keys", mode).objectStore("keys"));
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
    } finally {
      db.close();
    }
  };
  return {
    get: () => run("readonly", (store) => store.get("sms-approval")),
    put: (value) => run("readwrite", (store) => store.put(value, "sms-approval")),
    remove: () => run("readwrite", (store) => store.delete("sms-approval")),
  };
}

const keyStore = () => globalThis.ZtSmsKeyStore || indexedDbKeyStore();

function activeServerKey() {
  return serverKeys.find((key) => key.active) || null;
}

function renderKeys() {
  const active = activeServerKey();
  const held = active && localKey && localKey.fingerprint === active.fingerprint;
  say("key-summary", !active
    ? "No active SMS approval key. Create one to approve line activations."
    : held ? `Active key ${active.fingerprint.slice(0, 12)}… is held by this browser.`
      : `Active key ${active.fingerprint.slice(0, 12)}… is held by another browser. Approve from there, or revoke it here.`);
  byId("key-create").hidden = Boolean(active);
  byId("key-revoke").hidden = !active;
  byId("activation-approve").disabled = !held || !activation || !activation.ownerStatement ||
    Boolean(activation.v2 && (activation.phase !== "review" || document.hidden));
}

async function loadKeys() {
  serverKeys = await api("/v1/auth/sms-line-owner-keys");
  localKey = (await keyStore().get()) || null;
  renderKeys();
}

async function createKey(mfaCode) {
  const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sec1 = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const fingerprint = signing.base64url(await signing.sha256(sec1));
  const challenge = await api("/v1/auth/sms-line-owner-keys/challenge", "POST",
    { signing_key_sec1_b64: signing.base64(sec1) });
  if (challenge.fingerprint !== fingerprint) throw new Error("The server returned a different key fingerprint.");
  const statement = await signing.registrationStatement({
    accountId: session.account_id, userId: session.user_id, sessionId: session.session_id,
    challengeId: challenge.challenge_id, nonce: signing.fromBase64(challenge.nonce_b64), publicKeySec1: sec1,
  });
  const signature = signing.p1363ToDer(new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, keys.privateKey, statement)));
  // Store before registering so a registered key is never lost to a failed write.
  await keyStore().put({ privateKey: keys.privateKey, fingerprint });
  try {
    await api("/v1/auth/sms-line-owner-keys", "POST", {
      challenge_id: challenge.challenge_id, nonce_b64: challenge.nonce_b64,
      signature_der_b64: signing.base64(signature), mfa_code: mfaCode,
    });
  } catch (error) {
    // Only a definite refusal proves the key was not registered. After a lost
    // response the server may have committed it, so keep the key and let the
    // key list show whether it is active.
    if (error instanceof ApiRejection && error.status >= 400 && error.status < 500) await keyStore().remove();
    throw error;
  }
}

async function revokeKey(mfaCode) {
  const active = activeServerKey();
  if (!active) return;
  await api(`/v1/auth/sms-line-owner-keys/${encodeURIComponent(active.fingerprint)}`, "DELETE", { mfa_code: mfaCode });
  if (localKey && localKey.fingerprint === active.fingerprint) await keyStore().remove();
}

let lineCursor = null;
let linesLoading = false;

function lineLabel(line) {
  const revoked = line.device_revoked ? " (phone revoked; activate it on another phone)" : "";
  const phone = line.device_name ? ` on ${line.device_name}${revoked}` : "";
  const scope = line.purpose ? ` (${line.purpose})` : "";
  return `${line.line_id.slice(0, 8)}… ${line.state}${phone}${scope}, generation ${line.generation}`;
}

async function loadLines(more = false) {
  // One request at a time, so a double click cannot append the same page twice.
  if (linesLoading) return;
  linesLoading = true;
  try {
    await loadLinePage(more);
  } finally {
    linesLoading = false;
  }
}

async function loadLinePage(more) {
  const query = more && lineCursor ? `?before=${encodeURIComponent(lineCursor)}` : "";
  const page = await api(`/v1/auth/sms-lines${query}`);
  const items = page.lines.map((line) => {
    const item = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = lineLabel(line);
    const use = document.createElement("button");
    use.type = "button";
    use.textContent = "Use this line";
    use.addEventListener("click", () => {
      if (activation?.v2) invalidateV2(activation);
      byId("activation-line").value = line.line_id;
      say("activation-status", "Line selected. Choose the phone, then request its declaration.");
    });
    item.replaceChildren(label, use);
    return item;
  });
  const list = byId("line-list");
  if (more) list.append(...items);
  else list.replaceChildren(...items);
  lineCursor = page.next_cursor;
  byId("line-more").hidden = !lineCursor;
  say("lines-status", !more && items.length === 0 ? "No lines yet. Activate your first line below." : "");
}

async function loadDevices() {
  const page = await api("/v1/enrollment/devices");
  const select = byId("activation-device");
  select.replaceChildren(...page.devices.filter((device) => !device.revoked).map((device) => {
    const option = document.createElement("option");
    option.value = device.device_id;
    option.textContent = `${device.display_name}${device.active_socket_lease ? "" : " (not connected)"}`;
    return option;
  }));
}

function stopPolling() {
  if (pollTimer !== null && !globalThis.ZtSmsLinesSchedule) clearTimeout(pollTimer);
  pollTimer = null;
  pollRound += 1;
}

function schedulePoll() {
  const round = pollRound;
  const current = activation;
  if (!current) return;
  const delay = current.backoffMs ?? (current.ownerStatement ? verifiedPollIntervalMs : pollIntervalMs);
  pollTimer = schedule(() => (round === pollRound ? poll() : undefined), delay);
}

// A hidden tab cannot act on an activation; polling resumes when it returns.
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    if (activation?.v2) invalidateV2(activation);
    stopPolling();
  } else if (activation && pollTimer === null) {
    schedulePoll();
  }
});

/** Checks the server's statements against what this page opened and rebuilds the bytes to sign. */
async function verifiedOwnerStatement(view) {
  const statement = signing.fromBase64(view.device_statement_b64);
  const deviceSignature = signing.fromBase64(view.device_signature_der_b64);
  const parsed = signing.parseDeviceStatement(statement);
  if (parsed.accountId !== session.account_id || parsed.lineId !== activation.lineId ||
      parsed.deviceId !== activation.deviceId || parsed.challengeId !== activation.challengeId ||
      parsed.generation !== BigInt(activation.generation) || parsed.activeSubscriptionCount !== 1)
    throw new Error("The phone's declaration does not match this activation. Do not approve it.");
  const owner = await signing.ownerApprovalStatement(statement, deviceSignature);
  if (!signing.equalBytes(owner, signing.fromBase64(view.owner_statement_b64)))
    throw new Error("The server's approval statement does not match the phone's declaration. Do not approve it.");
  return { owner, parsed };
}

async function poll() {
  if (activation?.v2) return pollV2(activation);
  pollTimer = null;
  const current = activation;
  if (!current) return;
  let view;
  try {
    view = await api(`/v1/auth/sms-lines/${current.lineId}/activations/${current.challengeId}`);
  } catch (error) {
    if (activation !== current) return;
    say("activation-status", `${error.message} Retrying…`);
    // Poll errors back off exponentially, capped, instead of retrying
    // at the fixed cadence.
    current.backoffMs = Math.min((current.backoffMs ?? pollIntervalMs) * 2, pollBackoffMaxMs);
    if (Date.now() - current.startedAt < maxPollMs) schedulePoll();
    return;
  }
  // A newer activation replaced this one while the request was in flight.
  if (activation !== current) return;
  current.backoffMs = null;
  if (view.status === "awaiting_owner" && !current.ownerStatement) {
    try {
      const { owner, parsed } = await verifiedOwnerStatement(view);
      if (activation !== current) return;
      current.ownerStatement = owner;
      say("review-api", String(parsed.androidApiLevel));
      say("review-subscription", String(parsed.selectedSubscriptionId));
      say("review-count", String(parsed.activeSubscriptionCount));
      byId("activation-review").hidden = false;
      renderKeys();
      say("activation-status", "The phone signed its declaration. Check it, then approve.");
    } catch (error) {
      if (activation !== current) return;
      activation = null;
      say("activation-status", error.message);
      return;
    }
  } else if (view.status === "activated") {
    byId("activation-review").hidden = true;
    activation = null;
    say("activation-status", "The line is active on this phone.");
    await loadLines().catch(() => {});
    return;
  } else if (view.status === "closed") {
    byId("activation-review").hidden = true;
    activation = null;
    say("activation-status", "This activation can no longer complete. The phone may have disconnected or the request expired; start again.");
    return;
  } else if (view.status === "awaiting_device") {
    say("activation-status", "Waiting for the phone to sign its declaration…");
  }
  // The server reports expiry as "closed"; this only bounds a stuck page.
  if (Date.now() - current.startedAt > maxPollMs) {
    activation = null;
    say("activation-status", "No answer from the server. Start again.");
    return;
  }
  schedulePoll();
}

async function startActivation(deviceId, lineId) {
  if (activation?.v2 && ["opening", "opening_unknown", "approving", "approval_unknown"].includes(activation.phase))
    throw new Error("Check the existing selected SIM request before starting another.");
  stopPolling();
  byId("activation-review").hidden = true;
  signing.uuidBytes(lineId);
  const round = ++activationOpeningRound;
  let opened;
  try {
    opened = await api(`/v1/auth/sms-lines/${lineId}/activations`, "POST", { device_id: deviceId });
  } catch (error) {
    if (round !== activationOpeningRound) return;
    throw error;
  }
  if (round !== activationOpeningRound) return;
  activation = { deviceId, lineId, challengeId: opened.challenge_id, generation: opened.generation,
    ownerStatement: null, startedAt: Date.now() };
  renderKeys();
  say("activation-status", "Waiting for the phone to sign its declaration…");
  await poll();
}

async function approveActivation() {
  if (activation?.v2) return approveV2();
  const current = activation;
  const active = activeServerKey();
  if (!activation || !activation.ownerStatement || !localKey || !active || localKey.fingerprint !== active.fingerprint)
    throw new Error("This browser does not hold the active SMS approval key.");
  const signature = signing.p1363ToDer(new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, localKey.privateKey, activation.ownerStatement)));
  if (activation !== current) throw new Error("The activation changed. Review the current request first.");
  await api(`/v1/auth/sms-lines/${activation.lineId}/activations/${activation.challengeId}/approve`, "POST",
    { owner_signature_der_b64: signing.base64(signature) });
  byId("activation-approve").disabled = true;
  say("activation-status", "Approved. Waiting for the server to confirm…");
  stopPolling();
  await poll();
}

// Explicit selected-SIM flow. No v2 failure is retried through legacy routes.
const v2OpenKeys = ["challenge_id", "account_id", "line_id", "device_id", "generation", "expires_at_ms"];
const v2ViewKeys = ["challenge_id", "device_id", "generation", "expires_at_ms", "status",
  "observation_b64url", "device_statement_b64url", "device_signature_der_b64url", "owner_statement_b64url"];

function canonicalUuidV2(value) {
  if (typeof value !== "string" || value.length !== 36) throw new Error("Invalid activation identity.");
  signing.uuidBytes(value);
  return value;
}

function invalidateV2(current) {
  current.revision += 1;
  current.ownerStatement = null;
  byId("activation-review").hidden = true;
  stopPolling();
  renderKeys();
}

function currentV2(current, revision, key = null) {
  return activation === current && current.revision === revision && !document.hidden &&
    session === current.session && byId("activation-mode").value === "v2" &&
    byId("activation-device").value === current.deviceId && byId("activation-line").value.trim() === current.lineId &&
    (!key || (localKey === key && activeServerKey()?.fingerprint === key.fingerprint));
}

function requireCurrentV2(current, revision, key = null) {
  if (!currentV2(current, revision, key)) throw new Error("The phone, page or approval changed. Review the request again.");
}

async function apiV2(path, method = "GET", body = undefined, keys = null) {
  const csrf = csrfToken();
  if (!csrf) throw new Error("Your sign-in expired. Sign in again.");
  const response = await fetch(path, {
    method, credentials: "same-origin", cache: "no-store", redirect: "error",
    headers: { "x-zrotext-csrf": csrf, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(requestTimeoutMs) : undefined,
  });
  if (!response.ok) throw new ApiRejection(response.status);
  const expected = method === "GET" ? 200 : keys === v2OpenKeys ? 201 : 204;
  if (response.status !== expected) throw new Error("Unexpected activation response.");
  if (response.status === 204) return null;
  if (response.headers.get("content-type")?.split(";")[0].trim() !== "application/json")
    throw new Error("Invalid activation response.");
  return signing.flatV2Response(await response.text(), keys);
}

function expiryV2(value) {
  if (typeof value !== "bigint" || value <= 0n || value > (1n << 63n) - 1n)
    throw new Error("Invalid activation expiry.");
  return value;
}

function holdV2(current, phase) {
  current.phase = phase;
  current.ownerStatement = null;
  stopPolling();
  byId("activation-review").hidden = true;
  byId("activation-recheck").hidden = false;
  byId("activation-start").disabled = true;
  renderKeys();
  say("activation-status", "Outcome unknown. Check this same request before starting another; it will not be repeated automatically.");
}

async function startV2(deviceId, lineId) {
  if (activation?.v2 && ["opening", "opening_unknown", "approving", "approval_unknown"].includes(activation.phase))
    throw new Error("Check the existing selected SIM request before starting another.");
  canonicalUuidV2(deviceId); canonicalUuidV2(lineId);
  canonicalUuidV2(session.account_id); canonicalUuidV2(session.session_id);
  activationOpeningRound += 1;
  stopPolling();
  activation = { v2: true, deviceId, lineId, openingId: crypto.randomUUID(), session,
    revision: 0, phase: "opening", ownerStatement: null, startedAt: Date.now() };
  byId("activation-review").hidden = true;
  await openV2(activation);
}

async function openV2(current) {
  const revision = current.revision;
  requireCurrentV2(current, revision);
  current.phase = "opening";
  byId("activation-start").disabled = true;
  byId("activation-recheck").hidden = true;
  try {
    const opened = await apiV2(`/v1/auth/sms-lines/${current.lineId}/activations-v2`, "POST",
      { device_id: current.deviceId, opening_id: current.openingId }, v2OpenKeys);
    requireCurrentV2(current, revision);
    for (const key of ["challenge_id", "account_id", "line_id", "device_id"]) canonicalUuidV2(opened[key]);
    if (opened.account_id !== current.session.account_id || opened.line_id !== current.lineId || opened.device_id !== current.deviceId)
      throw new Error("The server returned a different activation.");
    signing.positiveI64(opened.generation);
    current.challengeId = opened.challenge_id;
    current.generation = opened.generation;
    current.expires = expiryV2(opened.expires_at_ms);
    current.phase = "awaiting_device";
    byId("activation-start").disabled = false;
    say("activation-status", "Waiting for the phone's selected SIM declaration…");
    await pollV2(current);
  } catch (error) {
    if (activation !== current) return;
    if (error instanceof ApiRejection && error.status >= 400 && error.status < 500) {
      current.phase = "refused";
      byId("activation-start").disabled = false;
      say("activation-status", error.message);
    } else holdV2(current, "opening_unknown");
  }
}

async function verifiedOwnerStatementV2(current, view) {
  const statement = signing.fromBase64url(view.device_statement_b64url);
  const der = signing.canonicalDer(signing.fromBase64url(view.device_signature_der_b64url));
  const parsed = signing.parseDeviceStatementV2(statement);
  const observation = signing.fromBase64url(view.observation_b64url, 121);
  const rebuilt = signing.deviceStatementV2({ accountId: current.session.account_id, lineId: current.lineId,
    deviceId: current.deviceId, challengeId: current.challengeId, generation: current.generation,
    nonce: parsed.nonce, observation });
  if (!signing.equalBytes(rebuilt, statement)) throw new Error("The phone's declaration does not match this activation. Do not approve it.");
  const owner = await signing.ownerApprovalStatementV2(rebuilt, der);
  if (!signing.equalBytes(owner, signing.fromBase64url(view.owner_statement_b64url)))
    throw new Error("The approval statement does not match the phone's declaration. Do not approve it.");
  return { owner, parsed };
}

async function pollV2(current) {
  pollTimer = null;
  const revision = current.revision;
  if (!currentV2(current, revision) || !current.challengeId ||
      ["opening", "opening_unknown", "approving"].includes(current.phase)) return;
  try {
    const view = await apiV2(`/v1/auth/sms-lines/${current.lineId}/activations-v2/${current.challengeId}`, "GET", undefined, v2ViewKeys);
    requireCurrentV2(current, revision);
    if (view.challenge_id !== current.challengeId || view.device_id !== current.deviceId || view.generation !== current.generation ||
        expiryV2(view.expires_at_ms) !== current.expires || !["awaiting_device", "awaiting_owner", "activated"].includes(view.status))
      throw new Error("The activation status does not match this request.");
    if (view.status === "activated") {
      activation = null; stopPolling();
      byId("activation-review").hidden = true; byId("activation-recheck").hidden = true;
      byId("activation-start").disabled = false;
      say("activation-status", "The server approved the selected SIM declaration. Check the phone to confirm local installation.");
      renderKeys(); await loadLines().catch(() => {}); return;
    }
    if (["approval_unknown", "awaiting_confirmation"].includes(current.phase)) {
      holdV2(current, "approval_unknown");
      say("activation-status", "Approval is not yet confirmed. Check this request again; no approval will be repeated.");
      return;
    }
    if (current.expires <= BigInt(Date.now())) throw new Error("The activation expired. Request a fresh declaration.");
    if (view.status === "awaiting_owner") {
      const { owner, parsed } = await verifiedOwnerStatementV2(current, view);
      requireCurrentV2(current, revision);
      current.ownerStatement = owner; current.phase = "review";
      say("review-api", String(parsed.androidApiLevel));
      say("review-subscription", String(parsed.selectedSubscriptionId));
      say("review-count", String(parsed.activeSubscriptionCount));
      say("review-kind", parsed.selectedKind === 2 ? "eSIM (phone declaration)" : "Physical SIM (phone declaration)");
      byId("activation-review").hidden = false;
      say("activation-status", "Review the phone's selected SIM and complete subscription count, then approve.");
      renderKeys();
    } else {
      current.ownerStatement = null; current.phase = "awaiting_device";
      byId("activation-review").hidden = true; renderKeys();
    }
    schedulePoll();
  } catch (error) {
    if (!currentV2(current, revision)) return;
    invalidateV2(current);
    if (current.phase === "approval_unknown") holdV2(current, "approval_unknown");
    else { current.phase = "refused"; byId("activation-start").disabled = false; say("activation-status", error.message); }
  }
}

async function freshOwnerV2(current, revision, key) {
  const fresh = await apiV2("/v1/auth/session");
  requireCurrentV2(current, revision, key);
  if (["account_id", "user_id", "session_id"].some((k) => fresh[k] !== current.session[k]))
    throw new Error("Your sign-in changed. Review a fresh request.");
  const keys = await api("/v1/auth/sms-line-owner-keys");
  requireCurrentV2(current, revision, key);
  if (!Array.isArray(keys) || keys.filter((k) => k.active).length !== 1 || !keys.some((k) => k.active && k.fingerprint === key.fingerprint))
    throw new Error("The approval key changed. Review a fresh request.");
}

async function approveV2() {
  const current = activation, key = localKey;
  if (current.phase !== "review" || !current.ownerStatement || !key) throw new Error("Review the selected SIM declaration first.");
  const statement = current.ownerStatement.slice();
  current.revision += 1;
  const revision = current.revision;
  requireCurrentV2(current, revision, key);
  stopPolling();
  current.phase = "approving"; renderKeys();
  let submitting = false;
  try {
    await freshOwnerV2(current, revision, key);
    requireCurrentV2(current, revision, key);
    if (current.expires <= BigInt(Date.now())) throw new Error("The activation expired.");
    const signature = signing.p1363ToDer(new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, key.privateKey, statement)));
    requireCurrentV2(current, revision, key);
    await freshOwnerV2(current, revision, key);
    requireCurrentV2(current, revision, key);
    if (current.expires <= BigInt(Date.now())) throw new Error("The activation expired.");
    submitting = true;
    await apiV2(`/v1/auth/sms-lines/${current.lineId}/activations-v2/${current.challengeId}/approve`, "POST",
      { owner_signature_der_b64url: signing.base64url(signature) });
    requireCurrentV2(current, revision, key);
    current.phase = "awaiting_confirmation"; current.ownerStatement = null;
    renderKeys(); stopPolling(); await pollV2(current);
  } catch (error) {
    if (activation !== current) return;
    if (submitting && !(error instanceof ApiRejection && error.status >= 400 && error.status < 500)) holdV2(current, "approval_unknown");
    else { invalidateV2(current); current.phase = "refused"; say("activation-status", error.message); }
  }
}

async function recheckV2() {
  const current = activation;
  if (!current?.v2) return;
  requireCurrentV2(current, current.revision);
  if (current.phase === "opening_unknown") await openV2(current);
  else if (current.phase === "approval_unknown") await pollV2(current);
}

function guard(statusId, action) {
  return async (event) => {
    if (event && typeof event.preventDefault === "function") event.preventDefault();
    try {
      await action();
    } catch (error) {
      say(statusId, error.message);
    }
  };
}

async function init() {
  const response = await fetch("/v1/auth/session", { credentials: "same-origin", cache: "no-store" });
  if (!response.ok) {
    byId("signed-out").hidden = false;
    return;
  }
  session = await response.json();
  byId("approval-key").hidden = false;
  byId("activation").hidden = false;
  byId("lines").hidden = false;
  byId("line-more").addEventListener("click", guard("lines-status", () => loadLines(true)));
  byId("key-form").addEventListener("submit", guard("key-status", async () => {
    try {
      await createKey(byId("key-mfa").value.trim());
    } finally {
      byId("key-mfa").value = "";
      await loadKeys().catch(() => {});
    }
    say("key-status", "Key created and registered.");
  }));
  byId("key-revoke").addEventListener("click", guard("key-status", async () => {
    await revokeKey(byId("key-mfa").value.trim());
    byId("key-mfa").value = "";
    say("key-status", "Key revoked. SMS line activations it approved are revoked too.");
    await loadKeys();
  }));
  byId("activation-new-line").addEventListener("click", () => {
    if (activation?.v2) invalidateV2(activation);
    byId("activation-line").value = crypto.randomUUID();
  });
  byId("activation-form").addEventListener("submit", guard("activation-status", () =>
    byId("activation-mode").value === "v2"
      ? startV2(byId("activation-device").value, byId("activation-line").value.trim())
      : startActivation(byId("activation-device").value, byId("activation-line").value.trim())));
  byId("activation-recheck").addEventListener("click", guard("activation-status", recheckV2));
  for (const id of ["activation-device", "activation-line", "activation-mode"]) {
    byId(id).addEventListener("change", () => {
      if (activation?.v2) invalidateV2(activation);
    });
  }
  byId("activation-approve").addEventListener("click", guard("activation-status", approveActivation));
  await Promise.all([
    loadKeys().catch((error) => say("key-status", error.message)),
    loadDevices().catch((error) => say("activation-status", error.message)),
    loadLines().catch((error) => say("lines-status", error.message)),
  ]);
}

globalThis.ZtSmsLinesReady = init().catch((error) => say("global-status", error.message));
