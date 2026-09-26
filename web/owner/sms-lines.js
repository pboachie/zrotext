// SPDX-License-Identifier: AGPL-3.0-only
// Owner SMS approval key and SMS line activation. The private key is a
// non-extractable WebCrypto key kept in this browser's IndexedDB; the server
// only ever receives its public key and signatures over statements this page
// rebuilt itself.
"use strict";

const signing = globalThis.ZtSmsLineSigning;
const pollIntervalMs = 2000;
const maxPollMs = 10 * 60 * 1000;
const requestTimeoutMs = 15000;
let session = null;
let serverKeys = [];
let localKey = null;
let activation = null;
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
  byId("activation-approve").disabled = !held || !activation || !activation.ownerStatement;
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
    option.value = device.id;
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
  pollTimer = schedule(() => (round === pollRound ? poll() : undefined), pollIntervalMs);
}

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
  pollTimer = null;
  const current = activation;
  if (!current) return;
  let view;
  try {
    view = await api(`/v1/auth/sms-lines/${current.lineId}/activations/${current.challengeId}`);
  } catch (error) {
    if (activation !== current) return;
    say("activation-status", `${error.message} Retrying…`);
    if (Date.now() - current.startedAt < maxPollMs) schedulePoll();
    return;
  }
  // A newer activation replaced this one while the request was in flight.
  if (activation !== current) return;
  if (view.status === "awaiting_owner" && !current.ownerStatement) {
    try {
      const { owner, parsed } = await verifiedOwnerStatement(view);
      current.ownerStatement = owner;
      say("review-api", String(parsed.androidApiLevel));
      say("review-subscription", String(parsed.selectedSubscriptionId));
      say("review-count", String(parsed.activeSubscriptionCount));
      byId("activation-review").hidden = false;
      renderKeys();
      say("activation-status", "The phone signed its declaration. Check it, then approve.");
    } catch (error) {
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
  stopPolling();
  byId("activation-review").hidden = true;
  signing.uuidBytes(lineId);
  const opened = await api(`/v1/auth/sms-lines/${lineId}/activations`, "POST", { device_id: deviceId });
  activation = { deviceId, lineId, challengeId: opened.challenge_id, generation: opened.generation,
    ownerStatement: null, startedAt: Date.now() };
  renderKeys();
  say("activation-status", "Waiting for the phone to sign its declaration…");
  await poll();
}

async function approveActivation() {
  const active = activeServerKey();
  if (!activation || !activation.ownerStatement || !localKey || !active || localKey.fingerprint !== active.fingerprint)
    throw new Error("This browser does not hold the active SMS approval key.");
  const signature = signing.p1363ToDer(new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, localKey.privateKey, activation.ownerStatement)));
  await api(`/v1/auth/sms-lines/${activation.lineId}/activations/${activation.challengeId}/approve`, "POST",
    { owner_signature_der_b64: signing.base64(signature) });
  byId("activation-approve").disabled = true;
  say("activation-status", "Approved. Waiting for the server to confirm…");
  stopPolling();
  await poll();
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
    byId("activation-line").value = crypto.randomUUID();
  });
  byId("activation-form").addEventListener("submit", guard("activation-status", () =>
    startActivation(byId("activation-device").value, byId("activation-line").value.trim())));
  byId("activation-approve").addEventListener("click", guard("activation-status", approveActivation));
  await Promise.all([
    loadKeys().catch((error) => say("key-status", error.message)),
    loadDevices().catch((error) => say("activation-status", error.message)),
    loadLines().catch((error) => say("lines-status", error.message)),
  ]);
}

globalThis.ZtSmsLinesReady = init().catch((error) => say("global-status", error.message));
