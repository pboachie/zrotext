// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const state = document.getElementById("billing-state");
const entitlementStatus = document.getElementById("entitlement-status");
const deviceCapStatus = document.getElementById("device-cap-status");
const manageDevices = document.getElementById("manage-devices");
const list = document.getElementById("subscriptions");
const error = document.getElementById("billing-error");
const checkout = document.getElementById("checkout");
const portal = document.getElementById("portal");
const refresh = document.getElementById("refresh");
const checkoutKey = crypto.randomUUID();
let statusGeneration = 0;
let checkoutBlocked = false;

const entitlementReasons = {
  active: "active subscription",
  grace: "payment grace",
  inactive: "no active subscription",
  ambiguous: "ambiguous: more than one live subscription",
  unmapped: "subscription price not mapped",
  startup_reset: "reset at server startup, pending reconciliation",
  provider_deleted: "subscription deleted at Stripe",
};

function csrfToken() {
  const entry = document.cookie.split(";").map((part) => part.trim())
    .find((part) => part.startsWith("__Host-zrotext_csrf="));
  return entry ? entry.slice("__Host-zrotext_csrf=".length) : "";
}

async function loadStatus() {
  const generation = ++statusGeneration;
  list.replaceChildren();
  error.textContent = "";
  state.textContent = "Loading billing status…";
  entitlementStatus.textContent = "";
  deviceCapStatus.textContent = "";
  manageDevices.hidden = true;
  portal.disabled = true;
  try {
    const response = await fetch("/v1/billing/status", { credentials: "same-origin", cache: "no-store" });
    if (!response.ok) throw new Error("Could not load billing status. Sign in again if your session expired.");
    const result = await response.json();
    if (generation !== statusGeneration) return;
    if (result.mode !== "test") throw new Error("Unexpected billing mode.");
    list.replaceChildren();
    for (const subscription of result.subscriptions) {
      const item = document.createElement("li");
      const checked = new Date(subscription.reconciledAtUnix * 1000).toLocaleString();
      const graceEnds = subscription.paymentGraceEndsAtUnix;
      const paymentNotice = subscription.stripeStatus !== "past_due" ? ""
        : Number.isSafeInteger(graceEnds) && graceEnds * 1000 > Date.now()
          ? ` · Payment failed: new outbound pauses ${new Date(graceEnds * 1000).toLocaleString()} unless payment recovers.`
          : " · Payment failed: new outbound is paused. Review payment in Stripe.";
      item.textContent = `${subscription.stripeStatus} · ${subscription.recognizedTestPrice ? "recognized test price" : "unrecognized test price"} · checked ${checked}${subscription.reconciliationPending ? " · newer event pending" : ""}${subscription.needsReview ? " · provider read needs operator review" : ""}${paymentNotice}`;
      list.append(item);
    }
    state.textContent = result.subscriptions.length
      ? `Last reconciled provider snapshots. ${result.pendingReconciliations} pending reconciliation(s). No access is confirmed here.`
      : `No reconciled subscription. ${result.pendingReconciliations} pending reconciliation(s). No access is confirmed here.`;
    if (result.reviewReconciliations || result.reviewRiskEvents) {
      state.textContent += ` Operator review required: ${result.reviewReconciliations || 0} subscription read(s), ${result.reviewRiskEvents || 0} payment-risk read(s).`;
    }
    const entitlement = result.projectedEntitlement;
    if (entitlement) {
      const reason = entitlement.reason === null || entitlement.reason === undefined
        ? "no projection yet"
        : entitlementReasons[entitlement.reason] || entitlement.reason;
      const outbound = Number.isSafeInteger(entitlement.outboundLimit)
        ? `outbound allowance ${entitlement.outboundLimit}/month`
        : "outbound allowance not projected";
      const cap = Number.isSafeInteger(entitlement.deviceCap)
        ? `device cap ${entitlement.deviceCap}`
        : "no device cap projected";
      entitlementStatus.textContent = `Projected entitlement: ${reason} · ${outbound} · ${cap}.`;
      if (entitlement.paymentHold) {
        entitlementStatus.textContent += " A refund or dispute hold is active: new outbound is paused pending review.";
      }
      if (entitlement.reason === "ambiguous") {
        entitlementStatus.textContent += " Use the customer portal to cancel the extra subscription; sending and new-device approval stay blocked while more than one live subscription exists.";
      }
    } else {
      entitlementStatus.textContent = "";
    }
    checkoutBlocked = result.nonterminalSubscriptions > 0 || result.pendingReconciliations > 0;
    if (checkoutBlocked) {
      entitlementStatus.textContent += " Checkout is closed while a subscription is live or pending; use the customer portal to manage it.";
    }
    const capacity = result.deviceCapacity;
    if (capacity && capacity.limit === null && capacity.enrollmentBlocked) {
      deviceCapStatus.textContent = "Device limit not yet available. New enrollment is currently blocked.";
    } else if (capacity && Number.isSafeInteger(capacity.limit) && Number.isSafeInteger(capacity.active)) {
      deviceCapStatus.textContent = capacity.overLimit
        ? `${capacity.active} devices enrolled; plan limit ${capacity.limit}. Existing devices keep working. Choose which devices to revoke; new enrollment remains blocked at or above the limit.`
        : capacity.enrollmentBlocked
          ? `${capacity.active} devices enrolled; plan limit ${capacity.limit}. New enrollment is currently blocked.`
          : `${capacity.active} devices enrolled; plan limit ${capacity.limit}.`;
      manageDevices.hidden = !capacity.enrollmentBlocked || capacity.active === 0;
    }
    if (result.moreSubscriptions) {
      const item = document.createElement("li");
      item.textContent = "More subscriptions exist; this page displays the latest 20.";
      list.append(item);
    }
    checkout.disabled = checkoutBlocked;
    portal.disabled = !result.customerBound;
  } catch (cause) {
    if (generation !== statusGeneration) return;
    list.replaceChildren();
    state.textContent = "Billing status unavailable.";
    entitlementStatus.textContent = "";
    deviceCapStatus.textContent = "";
    manageDevices.hidden = true;
    error.textContent = cause.message;
  }
}

async function openHosted(path) {
  error.textContent = "";
  const csrf = csrfToken();
  if (!csrf) {
    error.textContent = "Sign in again to continue.";
    return;
  }
  checkout.disabled = true;
  const portalWasEnabled = !portal.disabled;
  portal.disabled = true;
  let conflict = false;
  try {
    const headers = { "x-zrotext-csrf": csrf };
    if (path === "checkout") headers["idempotency-key"] = checkoutKey;
    const response = await fetch(`/v1/billing/${path}`, {
      method: "POST", credentials: "same-origin", cache: "no-store", headers,
    });
    if (response.status === 409 && path === "checkout") {
      conflict = true;
      throw new Error("A subscription already exists for this account. Use the customer portal to manage it.");
    }
    if (!response.ok) throw new Error("Could not open Stripe test billing. Refresh status and retry.");
    const result = await response.json();
    const destination = new URL(result.url);
    const expectedHost = path === "checkout" ? "checkout.stripe.com" : "billing.stripe.com";
    if (destination.protocol !== "https:" || destination.host !== expectedHost) {
      throw new Error("Unexpected billing destination.");
    }
    window.location.assign(destination.href);
  } catch (cause) {
    if (conflict) {
      // loadStatus clears the error line, so refresh the state first and
      // apply the guidance after the refreshed page has rendered.
      await loadStatus();
    }
    error.textContent = cause.message;
    checkout.disabled = checkoutBlocked;
    portal.disabled = !portalWasEnabled;
  }
}

checkout.addEventListener("click", () => openHosted("checkout"));
portal.addEventListener("click", () => openHosted("portal"));
refresh.addEventListener("click", loadStatus);
loadStatus();
