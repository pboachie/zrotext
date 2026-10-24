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
    const session = await request("/v1/auth/session");
    if (epoch !== viewEpoch) return;
    showDataSession(session);
    byId("mfa-section").hidden = false;
    await refreshMfa();
  } catch (error) {
    if (epoch !== viewEpoch) return;
    viewEpoch += 1;
    clearDataControls();
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
  const password = byId("verify-password").value;
  status("verify-status", "Verifying email…");
  try {
    await request("/v1/auth/verify-email", "POST", { token, password });
    status("verify-status", "Email verified. You can sign in on the Devices page.");
  } catch (error) {
    status("verify-status", `Verification failed. ${error.message}`);
  } finally {
    byId("verification-code").value = "";
    byId("verify-password").value = "";
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

// Each entry binds a received cursor to the one implemented query field.
// Completed families may be repeated by the API; raw parts preserve that fact.
const exportStreams = [
  ["before", "next_cursor", "uuid"],
  ["contacts_before", "contacts_next_cursor", "uuid"],
  ["sealed_before", "conversation_inventory.sealed_events_next_cursor", "uuid"],
  ["interval_before", "conversation_inventory.intervals_next_cursor", "uuid"],
  ["confirmation_before", "confirmation_inventory.next_cursor", "uuid"],
  ["execution_before", "execution_inventory.next_cursor", "uuid"],
  ["agent_before", "agent_grants.next_cursor", "uuid"],
  ["original_reply_before", "original_replies.next_cursor", "text"],
  ["provider_receipts_after", "provider_receipts.next_cursor", "uuid"],
  ["contact_reader_pending_after", "contact_reader_issuance.pending_next_cursor", "text"],
  ["contact_reader_receipts_after", "contact_reader_issuance.receipt_next_cursor", "text"],
  ["sealed_deliveries_after", "sealed_event_deliveries.next_cursor", "uuid"],
  ["invoice_observations_after", "invoice_observations.next", "uuid"],
  ["invoice_periods_after", "invoice_billing.periods_next", "uuid"],
  ["invoice_usage_after", "invoice_billing.usage_next", "uuid"],
  ["invoice_audit_after", "invoice_billing.audit_next", "integer"],
  ...["openings", "offers", "allocations", "requests"].map((name, i) =>
    [["openings_after", "opening_offers_after", "opening_allocations_after", "opening_requests_after"][i], `opening_capacity.${name}.next_cursor`, "uuid"]),
  ...["heads", "versions", "mutations"].map((name, i) =>
    [["provider_configurations_after", "provider_configuration_versions_after", "provider_configuration_mutations_after"][i], `provider_configurations.${name}.next_cursor`, i === 1 ? "text" : "uuid"]),
  ...["templates", "versions"].map((name, i) =>
    [["templates_after", "template_versions_after"][i], `encrypted_templates.${name}.next_cursor`, "uuid"]),
  ...["grants", "envelopes", "access"].map((name, i) =>
    [["workflow_grants_before", "workflow_envelopes_before", "workflow_access_before"][i], `workflow_integrations.${name}.next_cursor`, "uuid"]),
  ...["contexts", "versions", "exceptions", "audit"].map((name, i) =>
    [["workflow_contexts_before", "workflow_versions_before", "workflow_exceptions_before", "workflow_audit_before"][i], `workflow_context.${name}.next_cursor`, "uuid"]),
  ...["actions", "versions", "mutations", "correlations", "message_links", "routines", "context_fences"].map((name, i) =>
    [["workflow_actions_before", "workflow_action_versions_before", "workflow_action_mutations_before", "workflow_correlations_before", "workflow_message_links_before", "workflow_routines_before", "workflow_context_fences_before"][i], `workflow_decisions.${name}.next_cursor`, "text"]),
  ...["policies", "series", "occurrences", "audit"].map((name, i) =>
    [["schedule_policies_before", "schedule_series_before", "schedule_occurrences_before", "schedule_audit_before"][i], `workflow_schedule.${name}.next_cursor`, i === 0 ? "text" : "uuid"]),
  ...["events", "selections", "versions", "grants", "policies", "readers"].map((name) =>
    [`managed_${name}_after`, `managed_reader_grants.${name}.next_cursor`, "text"]),
];
const replySections = ["grants", "requests", "consumptions", "sources", "access", "manifests"];
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const maxPageBytes = 8 * 1024 * 1024;
const maxPartBytes = 32 * 1024 * 1024;
let dataSession = null;
let takeout = null;
let downloadUrl = null;
let dataBusy = false;
let erasureReview = null;
let erasureSent = false;
const dataControllers = new Set();

function sessionIdentity(value) {
  if (!value || value.role !== "owner" ||
      ![value.account_id, value.user_id, value.session_id].every((v) =>
        typeof v === "string" && uuidPattern.test(v) && !/^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(v))) return null;
  return { account_id: value.account_id, user_id: value.user_id, session_id: value.session_id };
}

function sameIdentity(a, b) {
  return !!a && !!b && a.account_id === b.account_id && a.user_id === b.user_id && a.session_id === b.session_id;
}

function clearErasureSecrets() {
  byId("erasure-password").value = "";
  byId("erasure-code").value = "";
  byId("erasure-confirm").checked = false;
}

function clearDownload() {
  if (downloadUrl) URL.revokeObjectURL(downloadUrl);
  downloadUrl = null;
  byId("export-download").hidden = true;
  byId("export-download").removeAttribute("href");
}

function clearDataControls() {
  for (const controller of dataControllers) controller.abort();
  dataControllers.clear();
  clearDownload();
  takeout = null;
  dataSession = null;
  erasureReview = null;
  clearErasureSecrets();
  byId("data-section").hidden = true;
  byId("data-link").hidden = true;
  byId("erasure-form").hidden = true;
  byId("export-continue").hidden = true;
  byId("erasure-result").textContent = "";
  byId("erasure-result").hidden = true;
}

function showDataSession(value) {
  const identity = sessionIdentity(value);
  if (dataSession && !sameIdentity(dataSession, identity)) clearDataControls();
  dataSession = identity;
  byId("data-section").hidden = !identity;
  byId("data-link").hidden = !identity;
  if (identity) byId("data-account").textContent = `Signed-in account: ${identity.account_id}`;
  if (identity && erasureSent) erasureHold();
}

function captureDataSession() {
  const csrf = csrfToken();
  if (!dataSession || !csrf) throw new Error("Sign in as the account owner before using data controls.");
  return { ...dataSession, csrf, epoch: viewEpoch };
}

function checkDataEpoch(binding) {
  if (binding.epoch !== viewEpoch || !sameIdentity(binding, dataSession) || binding.csrf !== csrfToken()) {
    throw new Error("Account or session changed. This operation was stopped.");
  }
}

async function freshDataSession(binding) {
  checkDataEpoch(binding);
  const session = sessionIdentity(await request("/v1/auth/session"));
  checkDataEpoch(binding);
  if (!sameIdentity(binding, session)) {
    viewEpoch += 1;
    clearDataControls();
    throw new Error("Account or session changed. Sign in and review the account again.");
  }
}

function exactKeys(value, keys) {
  return !!value && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function field(value, path) {
  return path.split(".").reduce((v, key) => v && typeof v === "object" ? v[key] : undefined, value);
}

// Routing must not round PostgreSQL i64 cursors. Decode bounded JSON with exact
// integer values and duplicate-key refusal; downloadable bodies remain bytes.
function routingJson(text) {
  let at = 0;
  const fail = () => { throw new Error("Malformed export/result JSON."); };
  const whitespace = () => { while (/[\x20\x09\x0a\x0d]/.test(text[at] || "x")) at += 1; };
  function string() {
    const start = at++;
    while (at < text.length) {
      const ch = text[at++];
      if (ch === '"') return JSON.parse(text.slice(start, at));
      if (ch === "\\") at += 1;
    }
    return fail();
  }
  function value(depth) {
    if (depth > 64) return fail();
    whitespace();
    const ch = text[at];
    if (ch === '"') return string();
    if (ch === "{" || ch === "[") {
      at += 1;
      const object = ch === "{";
      const result = object ? Object.create(null) : [];
      const end = object ? "}" : "]";
      whitespace();
      if (text[at] === end) { at += 1; return result; }
      while (at < text.length) {
        whitespace();
        if (object) {
          if (text[at] !== '"') return fail();
          const key = string();
          if (Object.hasOwn(result, key)) return fail();
          whitespace();
          if (text[at++] !== ":") return fail();
          result[key] = value(depth + 1);
        } else result.push(value(depth + 1));
        whitespace();
        const delimiter = text[at++];
        if (delimiter === end) return result;
        if (delimiter !== ",") return fail();
      }
      return fail();
    }
    for (const [word, literal] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(word, at)) { at += word.length; return literal; }
    }
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(at, at + 129));
    if (!match) return fail();
    const token = match[0];
    if (token.length > 128) return fail();
    at += token.length;
    if (!/[.eE]/.test(token)) {
      const integer = BigInt(token);
      return integer >= BigInt(Number.MIN_SAFE_INTEGER) && integer <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(integer) : integer;
    }
    // Fractional/exponent syntax has no integer provenance, even if converting
    // it to Number would round to an allowed count or cursor.
    return Object.freeze({ nonIntegerNumber: token });
  }
  const result = value(0);
  whitespace();
  if (at !== text.length) return fail();
  return result;
}

function validateExportRouting(value, account) {
  const roots = ["original_replies", "provider_receipts", "opening_capacity", "provider_configurations", "contact_reader_issuance", "sealed_line_setup", "sealed_event_deliveries", "execution_inventory", "workflow_schedule", "workflow_integrations", "managed_reader_grants", "invoice_billing", "invoice_observations", "encrypted_templates", "workflow_context", "confirmation_inventory", "agent_grants", "workflow_decisions", "conversation_inventory", "generated_at_ms", "account", "devices", "contacts", "contacts_truncated", "contacts_next_cursor", "messages", "messages_truncated", "next_cursor"];
  if (!exactKeys(value, roots) || !value.account || value.account.account_id !== account) {
    throw new Error("Unsupported export shape or account mismatch; export is incomplete.");
  }
  const shapes = {
    opening_capacity: ["openings", "offers", "allocations", "requests"],
    provider_configurations: ["heads", "versions", "mutations"],
    encrypted_templates: ["templates", "versions"],
    workflow_integrations: ["grants", "envelopes", "access"],
    workflow_context: ["contexts", "versions", "exceptions", "audit"],
    workflow_decisions: ["actions", "versions", "mutations", "correlations", "message_links", "routines", "context_fences"],
    workflow_schedule: ["policies", "series", "occurrences", "audit"],
    managed_reader_grants: ["events", "selections", "versions", "grants", "policies", "readers"],
    contact_reader_issuance: ["state", "pending", "receipts", "pending_next_cursor", "receipt_next_cursor"],
    invoice_billing: ["entitlement", "periods", "usage", "audit", "periods_next", "usage_next", "audit_next"],
    invoice_observations: ["observations", "next"],
    conversation_inventory: ["consent", "intervals", "intervals_truncated", "intervals_next_cursor", "sealed_events", "sealed_events_truncated", "sealed_events_next_cursor"],
    confirmation_inventory: ["records", "truncated", "next_cursor"],
    execution_inventory: ["records", "truncated", "next_cursor"],
    agent_grants: ["grants", "truncated", "next_cursor"],
    sealed_line_setup: ["installed", "registrations", "exchanges"],
  };
  for (const [path, keys] of Object.entries(shapes)) {
    if (!exactKeys(field(value, path), keys)) throw new Error("Unsupported export paging shape; export is incomplete.");
  }
  const arrays = ["devices", "contacts", "messages", "contact_reader_issuance.pending", "contact_reader_issuance.receipts",
    "sealed_line_setup.registrations", "sealed_line_setup.exchanges", "invoice_billing.periods", "invoice_billing.usage", "invoice_billing.audit",
    "invoice_observations.observations", "conversation_inventory.intervals", "conversation_inventory.sealed_events",
    "confirmation_inventory.records", "execution_inventory.records", "agent_grants.grants"];
  for (const [, path] of exportStreams) {
    if (path.endsWith(".next_cursor")) {
      const parent = path.slice(0, -12);
      if (!Object.hasOwn(shapes, parent) && !exactKeys(field(value, parent), ["items", "next_cursor"])) {
        throw new Error("Unsupported export page; export is incomplete.");
      }
      if (!Object.hasOwn(shapes, parent)) arrays.push(`${parent}.items`);
    }
  }
  if (arrays.some((path) => !Array.isArray(field(value, path))) || typeof value.sealed_line_setup.installed !== "boolean") {
    throw new Error("Unsupported export collection; export is incomplete.");
  }
  const flags = [["messages_truncated", "next_cursor"], ["contacts_truncated", "contacts_next_cursor"],
    ["conversation_inventory.intervals_truncated", "conversation_inventory.intervals_next_cursor"],
    ["conversation_inventory.sealed_events_truncated", "conversation_inventory.sealed_events_next_cursor"],
    ["confirmation_inventory.truncated", "confirmation_inventory.next_cursor"],
    ["execution_inventory.truncated", "execution_inventory.next_cursor"], ["agent_grants.truncated", "agent_grants.next_cursor"]];
  for (const [flag, cursor] of flags) {
    if (typeof field(value, flag) !== "boolean" || field(value, flag) !== (field(value, cursor) !== null)) {
      throw new Error("Inconsistent export truncation; export is incomplete.");
    }
  }
}

function exportNext(state, value) {
  validateExportRouting(value, state.account_id);
  const query = { ...state.query };
  const active = new Set(state.active);
  const seen = new Set(state.seen);
  let section = state.section;
  for (const [name, path, kind] of exportStreams) {
    const cursor = field(value, path);
    if (cursor !== null && !(kind === "integer"
      ? (typeof cursor === "bigint" ? cursor > 0n && cursor <= 9223372036854775807n : Number.isSafeInteger(cursor) && cursor > 0)
      : typeof cursor === "string" && cursor.length > 0 && cursor.length <= 256 &&
        (kind === "uuid" ? uuidPattern.test(cursor) : /^[A-Za-z0-9_:\-]+$/.test(cursor)))) {
      throw new Error("Malformed or unsupported cursor (including unsafe integers); export is incomplete.");
    }
    if (!active.has(name)) continue;
    if (cursor === null) {
      if (name === "original_reply_before" && section < replySections.length - 1) {
        section += 1;
        query.original_reply_section = replySections[section];
        delete query.original_reply_before;
      } else active.delete(name);
    } else {
      const key = `${name}:${name === "original_reply_before" ? section : ""}:${cursor}`;
      if (seen.has(key)) throw new Error("Repeated export cursor; export is incomplete.");
      if (seen.size >= 4096) throw new Error("The cursor-history safety limit was reached. Keep the partial takeout and contact the operator.");
      seen.add(key);
      query[name] = String(cursor);
    }
  }
  return { query, active, seen, section };
}

async function dataResponse(path, binding, method = "GET", body) {
  checkDataEpoch(binding);
  const controller = new AbortController();
  dataControllers.add(controller);
  const timer = setTimeout(() => controller.abort(), requestTimeoutMs);
  let reader;
  try {
    const response = await fetch(path, {
      method, credentials: "same-origin", cache: "no-store", redirect: "error", signal: controller.signal,
      headers: { "x-zrotext-csrf": binding.csrf, ...(body === undefined ? {} : { "content-type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    checkDataEpoch(binding);
    if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") || "")) {
      const error = new Error("The server did not return a JSON result.");
      error.status = response.status;
      throw error;
    }
    if (!response.body || typeof response.body.getReader !== "function") throw new Error("Bounded response streaming is unavailable.");
    reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    while (true) {
      const chunk = await reader.read();
      checkDataEpoch(binding);
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maxPageBytes) throw new Error("The response exceeds the 8 MiB page limit.");
      chunks.push(chunk.value.slice());
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const value = routingJson(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
    checkDataEpoch(binding);
    return { status: response.status, value, bytes };
  } finally {
    if (reader) await reader.cancel().catch(() => {});
    controller.abort();
    clearTimeout(timer);
    dataControllers.delete(controller);
  }
}

function offerExportPart(state, pages, complete, interrupted) {
  if (pages.length === 0) return;
  clearDownload();
  const metadata = { format: "zrotext-owner-takeout-pages-v1", account_id: state.account_id,
    part: ++state.part, complete, interrupted, next_query: state.query,
    unfinished_streams: [...state.active], original_reply_section: replySections[state.section],
    scope: "All exposed API pages only; repeated families, limited inventories and changing data remain. Not a key or database backup." };
  const pieces = [JSON.stringify(metadata).slice(0, -1), ',"pages":['];
  pages.forEach((page, i) => {
    pieces.push(i ? "," : "", JSON.stringify({ query: page.query, active_streams: page.active }).slice(0, -1), ',"body":', page.bytes, "}");
  });
  pieces.push("]}");
  const blob = new Blob(pieces, { type: "application/json" });
  if (blob.size > maxPartBytes) throw new Error("The complete JSON part exceeds the 32 MiB safety limit.");
  downloadUrl = URL.createObjectURL(blob);
  const link = byId("export-download");
  link.href = downloadUrl;
  link.download = `zrotext-takeout-part-${state.part}.json`;
  link.textContent = `Download JSON part ${state.part}${complete ? " (last exposed page)" : " (incomplete export)"}`;
  link.hidden = false;
}

async function runExport(start) {
  if (dataBusy || erasureSent) return;
  dataBusy = true;
  let state;
  const pages = [];
  let size = 0;
  let interrupted = false;
  try {
    if (start) {
      clearDownload();
      const binding = captureDataSession();
      takeout = { ...binding, query: { original_reply_section: replySections[0] },
        active: new Set(exportStreams.map(([name]) => name)), seen: new Set(), section: 0, part: 0 };
    }
    state = takeout;
    if (!state || state.active.size === 0) return;
    await freshDataSession(state);
    status("export-status", "Reading a bounded export part…");
    // Reserve at least 1 MiB for the wrapper and eight bounded routing maps.
    while (pages.length < 8 && size <= 23 * 1024 * 1024 && state.active.size > 0) {
      const query = { ...state.query };
      const active = [...state.active];
      const result = await dataResponse(`/v1/owner/export?${new URLSearchParams(query)}`, state);
      if (result.status !== 200) throw new Error(`Export refused (${result.status}); collected pages remain incomplete.`);
      const next = exportNext(state, result.value);
      checkDataEpoch(state);
      pages.push({ query, active, bytes: result.bytes });
      size += result.bytes.byteLength;
      Object.assign(state, next);
    }
    checkDataEpoch(state);
    status("export-status", state.active.size === 0
      ? "All exposed API pages retrieved. Save this last part and keep every earlier part. The stated content and inventory limits still apply."
      : "This part is ready. Save it, then continue; the account export is incomplete.");
  } catch (error) {
    interrupted = true;
    if (state && state.epoch === viewEpoch) status("export-status", `Export interrupted and incomplete. ${error.message} You may continue the read after resolving the problem; no pages are stored across page exit.`);
    else status("export-status", "Export stopped because the account or page changed. Start again after signing in.");
  } finally {
    if (state && state.epoch === viewEpoch && sameIdentity(state, dataSession) && state.csrf === csrfToken()) {
      try { offerExportPart(state, pages, state.active.size === 0 && !interrupted, interrupted); }
      catch (error) {
        takeout = null;
        status("export-status", `Export incomplete; this part could not be offered. ${error.message} Start a new export.`);
      }
      byId("export-continue").hidden = state.active.size === 0;
    }
    dataBusy = false;
  }
}

function tableCounts(value) {
  return Array.isArray(value) && value.every((row) => exactKeys(row, ["table", "rows"]) &&
    typeof row.table === "string" && row.table.length > 0 && row.table.length <= 128 &&
    Number.isSafeInteger(row.rows) && row.rows >= 0);
}

function erasureSuccess(value, account) {
  return exactKeys(value, ["account_id", "deleted", "retained", "statement"]) && value.account_id === account &&
    tableCounts(value.deleted) && value.deleted.some((row) => row.table === "accounts" && row.rows === 1) &&
    Array.isArray(value.retained) && value.retained.every((row) => exactKeys(row, ["table", "rows", "reason"]) &&
      typeof row.table === "string" && row.table.length > 0 && row.table.length <= 128 &&
      (row.rows === null || Number.isSafeInteger(row.rows) && row.rows >= 0) &&
      typeof row.reason === "string" && row.reason.length > 0 && row.reason.length <= 4096) &&
    typeof value.statement === "string" && value.statement.length > 0 && value.statement.length <= 8192;
}

function erasureHold() {
  erasureSent = true;
  byId("erasure-review").disabled = true;
  byId("erasure-submit").disabled = true;
  byId("erasure-form").hidden = true;
  status("erasure-status", "Erasure outcome is UNKNOWN. Do not repeat this request. Preserve any response and contact the operator to review the account state; a failed sign-in alone does not confirm erasure.");
}

byId("export-start").addEventListener("click", () => runExport(true));
byId("export-continue").addEventListener("click", () => runExport(false));
byId("export-clear").addEventListener("click", () => {
  if (dataBusy) return;
  clearDownload(); takeout = null;
  byId("export-continue").hidden = true;
  status("export-status", "Export and continuation cleared from this page. Downloaded files remain on your device.");
});
byId("erasure-review").addEventListener("click", async () => {
  if (dataBusy || erasureSent) return;
  dataBusy = true;
  try {
    const binding = captureDataSession();
    await freshDataSession(binding);
    erasureReview = binding;
    clearErasureSecrets();
    byId("erasure-account").textContent = `Permanently erase reviewed account ${binding.account_id} on this server.`;
    byId("erasure-form").hidden = false;
    status("erasure-status", "Review the limits, then confirm with your current password and required factor.");
  } catch (error) { status("erasure-status", `Could not open erasure review. ${error.message}`); }
  finally { dataBusy = false; }
});
byId("erasure-cancel").addEventListener("click", () => {
  if (dataBusy || erasureSent) return;
  erasureReview = null; clearErasureSecrets(); byId("erasure-form").hidden = true;
  status("erasure-status", "Erasure review cancelled. No request was sent.");
});
byId("erasure-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (dataBusy || erasureSent) return;
  const binding = erasureReview;
  const password = byId("erasure-password").value;
  const code = byId("erasure-code").value.trim();
  if (!binding || !byId("erasure-confirm").checked || !password) {
    clearErasureSecrets();
    status("erasure-status", "Review and explicitly confirm the account, then enter your current password.");
    return;
  }
  dataBusy = true;
  let sent = false;
  try {
    await freshDataSession(binding);
    checkDataEpoch(binding);
    erasureSent = true; sent = true;
    byId("erasure-submit").disabled = true;
    clearErasureSecrets();
    const result = await dataResponse("/v1/owner/erasure", binding, "POST", {
      current_password: password, ...(code ? { code } : {}),
    });
    checkDataEpoch(binding);
    const value = result.value;
    if (result.status === 200 && erasureSuccess(value, binding.account_id)) {
      clearDownload(); takeout = null; erasureReview = null;
      byId("export-continue").hidden = true;
      byId("export-start").disabled = true;
      byId("erasure-review").disabled = true;
      byId("erasure-form").hidden = true;
      status("erasure-status", "The server confirmed erasure of the reviewed account. Read and save its deletion and retention result below; this is the confirmation.");
    } else if (result.status === 409 && exactKeys(value, ["code", "blocked", "statement"]) &&
        value.code === "erasure_blocked" && tableCounts(value.blocked) && value.blocked.length > 0 &&
        typeof value.statement === "string" && value.statement.length > 0 && value.statement.length <= 8192) {
      status("erasure-status", "Erasure blocked. The server reports that nothing was deleted. Contact the operator about the listed records.");
      byId("erasure-form").hidden = true;
      erasureReview = null;
      erasureSent = false;
      byId("erasure-submit").disabled = false;
    } else if ([400, 401, 403, 429, 501].includes(result.status) &&
        exactKeys(value, ["code"]) && typeof value.code === "string" && value.code.length > 0 && value.code.length <= 64) {
      status("erasure-status", `Erasure was refused (${result.status}); no erasure confirmation was received. Sign in and review the account before a new deliberate attempt.`);
      byId("erasure-form").hidden = true;
      erasureReview = null;
      erasureSent = false;
      byId("erasure-submit").disabled = false;
    } else { erasureHold(); }
    byId("erasure-result").textContent = new TextDecoder("utf-8", { fatal: true }).decode(result.bytes);
    byId("erasure-result").hidden = false;
  } catch (error) {
    if (sent && binding.epoch === viewEpoch) erasureHold();
    else if (binding && binding.epoch === viewEpoch) status("erasure-status", `Erasure request was not sent. ${error.message}`);
  } finally {
    clearErasureSecrets();
    dataBusy = false;
  }
});

window.addEventListener("pagehide", () => {
  viewEpoch += 1;
  clearMfaSecrets();
  clearDataControls();
});
window.addEventListener("pageshow", (event) => {
  if (event.persisted) loadSession();
});
loadSession();
