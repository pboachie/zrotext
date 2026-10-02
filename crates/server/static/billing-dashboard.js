// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

const state = document.getElementById("billing-state");
const entitlementStatus = document.getElementById("entitlement-status");
const localUsage = document.getElementById("local-usage");
const invoicePeriod = document.getElementById("invoice-period");
const usageSynchronization = document.getElementById("usage-synchronization");
const exposureCap = document.getElementById("exposure-cap");
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
  invoice_current: "current invoice snapshot",
  invoice_restricted: "invoice spend restricted",
};

const units = value => Number.isSafeInteger(value) && value >= 0;
const timestamp = value => units(value) && value <= 8640000000000000;
function invoiceSummary(invoice) {
  if (!invoice || typeof invoice !== "object" || Array.isArray(invoice)
      || typeof invoice.currentPeriodEligible !== "boolean" || !units(invoice.effectiveLimit)
      || (!invoice.currentPeriodEligible && invoice.effectiveLimit !== 0)
      || ![invoice.lastObservedEffectiveLimit, invoice.consumedUnits, invoice.previousOpenUnits].every(value => value === null || units(value))
      || ![invoice.startMs, invoice.endMs, invoice.graceUntilMs, invoice.cancelAtMs].every(value => value === null || timestamp(value))
      || !(invoice.lastObservedPhase === null || ["active", "grace", "restricted", "cancelled", "review"].includes(invoice.lastObservedPhase))
      || ((invoice.startMs === null) !== (invoice.endMs === null))
      || (invoice.startMs !== null && invoice.endMs <= invoice.startMs)
      || (invoice.startMs === null && invoice.consumedUnits !== null)
      || (invoice.currentPeriodEligible && (invoice.startMs === null || invoice.consumedUnits === null))) return null;
  const date = value => new Date(value).toISOString();
  let text = `Invoice snapshot: ${invoice.currentPeriodEligible ? "eligible at the status check" : "new discretionary spend restricted"}; current ceiling ${invoice.effectiveLimit}.`;
  text += invoice.startMs === null ? " No verified invoice period observed." : ` UTC invoice period ${date(invoice.startMs)} inclusive to ${date(invoice.endMs)} exclusive.`;
  text += invoice.consumedUnits === null ? " Invoice consumption unavailable." : ` ${invoice.consumedUnits} net consumed in this invoice period.`;
  text += invoice.previousOpenUnits === null ? " Prior unresolved usage unavailable." : ` ${invoice.previousOpenUnits} unresolved units from earlier periods.`;
  if (invoice.lastObservedPhase !== null) text += ` Last observed phase: ${invoice.lastObservedPhase}; observed ceiling ${invoice.lastObservedEffectiveLimit === null ? "unavailable" : invoice.lastObservedEffectiveLimit}.`;
  if (invoice.graceUntilMs !== null) text += ` Grace deadline ${date(invoice.graceUntilMs)}.`;
  if (invoice.cancelAtMs !== null) text += ` Cancellation deadline ${date(invoice.cancelAtMs)}.`;
  return `${text} This snapshot is not remaining capacity or permission to send. Soft cap unavailable.`;
}

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
  localUsage.textContent = "Loading local usage…";
  invoicePeriod.textContent = "";
  usageSynchronization.textContent = "";
  exposureCap.textContent = "";
  deviceCapStatus.textContent = "";
  manageDevices.hidden = true;
  portal.disabled = true;
  try {
    const response = await fetch("/v1/billing/status", { credentials: "same-origin", cache: "no-store", redirect: "error" });
    if (!response.ok) throw new Error("Could not load billing status. Sign in again if your session expired.");
    const result = await response.json();
    if (generation !== statusGeneration) return;
    if (result.mode !== "test") throw new Error("Unexpected billing mode.");
    if (!Array.isArray(result.subscriptions)) throw new Error("The billing status response was invalid.");
    const invoiceReason = result.projectedEntitlement?.reason;
    const invoiceEnabled = (result.invoicePeriod !== null && result.invoicePeriod !== undefined)
      || invoiceReason === "invoice_current" || invoiceReason === "invoice_restricted";
    const invoiceText = invoiceEnabled ? invoiceSummary(result.invoicePeriod) : null;
    invoicePeriod.textContent = invoiceEnabled ? invoiceText || "Invoice status unavailable; no current ceiling or period can be displayed." : "";
    const usage = result.localUsage;
    if (usage && [usage.used_units, usage.reserved_units, usage.refunded_units, usage.limit_units].every(value => Number.isSafeInteger(value) && value >= 0)
        && usage.refunded_units <= usage.reserved_units && usage.used_units === usage.reserved_units - usage.refunded_units
        && /^\d{4}-\d{2}-\d{2}$/.test(usage.period_start) && /^\d{4}-\d{2}-\d{2}$/.test(usage.period_end) && usage.period_end > usage.period_start) {
      localUsage.textContent = invoiceEnabled
        ? `Calendar usage history: ${usage.used_units} consumed, ${usage.reserved_units} gross reserved, ${usage.refunded_units} refunded. UTC calendar period ${usage.period_start} inclusive to ${usage.period_end} exclusive. Its recorded calendar limit ${usage.limit_units} is not the current invoice ceiling. This history does not confirm delivery or provider billing.`
        : `Local outbound admission usage: ${usage.used_units} consumed, ${usage.reserved_units} gross reserved, ${usage.refunded_units} refunded; hard cap ${usage.limit_units}${usage.used_units >= usage.limit_units ? " (reached)" : ""}. UTC period ${usage.period_start} inclusive to ${usage.period_end} exclusive. Soft cap unavailable. This is a local snapshot; it does not confirm delivery or provider billing.`;
    } else {
      localUsage.textContent = "Local usage unavailable; no current authoritative period. Soft cap unavailable.";
    }
    list.replaceChildren();
    const synchronization = result.usageSynchronization;
    const capSnapshot = result.exposureCap;
    if (capSnapshot && ["softUnits", "hardUnits", "outstandingUnits", "finalizedUnits"].every(key => units(capSnapshot[key]))
        && timestamp(capSnapshot.startMs) && timestamp(capSnapshot.endMs) && capSnapshot.endMs > capSnapshot.startMs
        && capSnapshot.hardUnits >= capSnapshot.softUnits
        && Number.isSafeInteger(capSnapshot.outstandingUnits + capSnapshot.finalizedUnits)) {
      const liability = capSnapshot.outstandingUnits + capSnapshot.finalizedUnits;
      exposureCap.textContent = `Tenant exposure: ${capSnapshot.finalizedUnits} finalized units, ${capSnapshot.outstandingUnits} outstanding units across all periods; soft cap ${capSnapshot.softUnits}${liability >= capSnapshot.softUnits ? " (reached)" : ""}, hard cap ${capSnapshot.hardUnits}${liability >= capSnapshot.hardUnits ? " (reached)" : ""}. UTC period ${new Date(capSnapshot.startMs).toISOString()} inclusive to ${new Date(capSnapshot.endMs).toISOString()} exclusive. These policy units are separate from message allowance. Other scoped and deployment limits also apply; this snapshot is not permission to spend.`;
    } else {
      exposureCap.textContent = "Tenant exposure caps unavailable; no current configured policy snapshot.";
    }
    if (synchronization && typeof synchronization.configured === "boolean"
        && ["pending", "leased", "acknowledged", "review", "uncertain"].every(key => units(synchronization[key]))
        && synchronization.uncertain <= synchronization.pending + synchronization.leased + synchronization.review) {
      usageSynchronization.textContent = `Retained local TEST forwarding records: ${synchronization.pending} pending, ${synchronization.leased} in flight, ${synchronization.acknowledged} acknowledged, ${synchronization.review} requiring review; ${synchronization.uncertain} currently classified unknown. Review also includes attempt-limit and manual-review records. ${synchronization.configured ? "A forwarding policy is configured." : "No active forwarding policy is configured."} Acknowledgement is a transport receipt, not validated usage, invoice settlement or spend authority.`;
    } else {
      usageSynchronization.textContent = "Billing synchronization unavailable; no verified forwarding snapshot.";
    }
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
      const outbound = invoiceEnabled
        ? invoiceText ? `current invoice ceiling ${result.invoicePeriod.effectiveLimit}` : "current invoice ceiling unavailable"
        : Number.isSafeInteger(entitlement.outboundLimit)
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
    localUsage.textContent = "Local usage unavailable. Refresh after signing in again; old usage is not shown.";
    invoicePeriod.textContent = "Invoice status unavailable; old observations are not shown.";
    usageSynchronization.textContent = "Billing synchronization unavailable; old observations are not shown.";
    exposureCap.textContent = "Tenant exposure caps unavailable; old observations are not shown.";
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
