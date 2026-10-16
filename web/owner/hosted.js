// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(() => {
  const byId = id => document.getElementById(id);
  const controller = ZrotextHostedOnboarding.create({ checkoutReturn: ["return", "cancel"].includes(new URLSearchParams(location.search).get("checkout")),
    onCheckoutAttempt: () => { const url = new URL(location.href); url.searchParams.set("checkout", "return"); history.replaceState(null, "", url); } });
  let email = "", registration = "closed", busy = false, epoch = 0, active = true, timer = null, pendingReads = 0, refreshQueued = false;
  const panels = ["hosted-account", "hosted-verify", "hosted-existing-session", "hosted-factor", "hosted-requirements", "hosted-billing", "hosted-phone"];
  const messages = {
    choose_test_subscription: "Review the verified TEST plan before checkout.",
    choose_subscription: "Review your subscription before checkout. Your account and phone progress are saved.",
    checkout_resumable: "Your checkout is still open. Continue the same checkout to finish payment.",
    checkout_recoverable: "The checkout reply was interrupted. Recover the existing checkout to check that same attempt.",
    billing_pending: "Confirming your subscription. No new purchase is needed. Check status or contact your service operator if this continues.",
    billing_restricted: "Your subscription needs attention. Check status or open subscription management to resolve it.",
    test_subscription_observed: "The server has observed an eligible TEST subscription. This is a test service, with no live paid-service entitlement.",
    subscription_observed: "Your subscription is confirmed. Continue to connect your phone.",
    billing_unavailable: "Subscription details are unavailable on this server. Sign-in and account recovery remain available.",
    billing_handoff: "Opening the secure payment page. Your subscription will be checked when you return."
  };
  function show(ids) { for (const id of panels) byId(id).hidden = !ids.includes(id); }
  function clearSecrets() { for (const input of document.querySelectorAll('input[type="password"], #hosted-invite, #hosted-verification-code, #hosted-factor-code')) input.value = ""; }
  function render() {
    const value = controller.view(), phase = value.phase;
    document.body.dataset.hostedPhase = phase;
    for (const link of document.querySelectorAll("[data-hosted-workspace]")) link.setAttribute("href",
      phase === "existing_session" && value.workspacePath === "/owner/observer" ? "/owner/observer" : "/owner/devices");
    byId("hosted-refresh").hidden = ["choose_test_subscription", "choose_subscription"].includes(phase);
    byId("hosted-checkout").hidden = true;
    byId("hosted-portal").hidden = true;
    byId("hosted-resume").hidden = true;
    byId("hosted-recover-checkout").hidden = true;
    byId("hosted-phone").hidden = true;
    byId("hosted-plan").hidden = true;
    byId("hosted-plan-terms").textContent = "";
    byId("hosted-status").textContent = value.message || "";
    if (phase === "loading") { show([]); byId("hosted-status").textContent = "Checking your current progress..."; return; }
    for (const id of ["hosted-step-account", "hosted-step-plan", "hosted-step-phone"]) byId(id).removeAttribute("aria-current");
    byId(["test_subscription_observed", "subscription_observed"].includes(phase) ? "hosted-step-phone" : phase.startsWith("billing") || ["choose_test_subscription", "choose_subscription", "checkout_resumable", "checkout_recoverable"].includes(phase) || value.recoverBilling ? "hosted-step-plan" : "hosted-step-account").setAttribute("aria-current", "step");
    if (phase === "existing_session") { show(["hosted-existing-session"]); return; }
    if (phase === "verification_requested") {
      show(["hosted-verify"]);
      const original = value.originalBrowser === true;
      byId("hosted-verification-address").textContent = email ? `Check the inbox for ${email}.` : "Use the code sent to your account email.";
      for (const id of ["hosted-verify-password-field", "hosted-resend-password-field"]) byId(id).hidden = original;
      for (const id of ["hosted-verify-password", "hosted-resend-password", "hosted-resend-email"]) byId(id).required = !original;
      byId("hosted-resend-email").value = email;
      byId("hosted-verify-fallback").hidden = !original;
      return;
    }
    if (phase === "second_factor") { show(["hosted-factor"]); byId("hosted-factor-code").focus(); return; }
    if (["choose_test_subscription", "choose_subscription", "checkout_resumable", "checkout_recoverable", "billing_pending", "billing_restricted", "test_subscription_observed", "subscription_observed", "billing_unavailable", "billing_handoff"].includes(phase) || value.recoverBilling) {
      show(["test_subscription_observed", "subscription_observed"].includes(phase) ? ["hosted-billing", "hosted-phone"] : ["hosted-requirements", "hosted-billing"]);
      byId("hosted-billing-state").textContent = value.recoverBilling ? "Your account and phone progress are preserved. Check status to recover the current billing step." : messages[phase];
      byId("hosted-mode").textContent = value.billingMode === "test" ? "TEST mode · no live charges" : value.billingMode === "live" ? "Hosted subscription" : "Billing capability unavailable";
      byId("hosted-portal").hidden = !value.portalAvailable;
      byId("hosted-resume").hidden = !value.resumeAvailable;
      byId("hosted-recover-checkout").hidden = !value.recoverAvailable;
      if (phase === "test_subscription_observed") byId("hosted-phone-status").textContent = "Continue in TEST mode. Phone enrollment still checks the server's account policy.";
      if (phase === "subscription_observed") byId("hosted-phone-status").textContent = value.entitlementReason === "grace"
        ? "Your existing service is in a limited payment grace period. Update payment details in subscription management; your phone setup is preserved."
        : "Use the same account and scan the pairing code in the Android app. Your phone permissions and Start connection remain deliberate steps.";
      return;
    }
    show(["hosted-account"]);
    if (phase === "sign_in") login();
    if (value.registration) registration = value.registration;
    byId("show-register").hidden = registration === "closed";
    byId("hosted-invite-field").hidden = registration !== "invite_only";
    if (registration === "closed") login();
    if (["registration_closed", "unavailable", "availability_unknown"].includes(phase) && !value.message) byId("hosted-status").textContent = "Account creation is unavailable. Existing users can sign in or recover access.";
  }
  function login() {
    byId("hosted-account-title").textContent = "Sign in";
    byId("hosted-login-form").hidden = false; byId("hosted-register-form").hidden = true;
    byId("hosted-email").value = email;
  }
  function register() {
    if (registration === "closed") return;
    byId("hosted-account-title").textContent = "Create account";
    byId("hosted-login-form").hidden = true; byId("hosted-register-form").hidden = false;
    byId("hosted-register-email").value = email;
  }
  function schedule() {
    if (timer !== null) clearTimeout(timer); timer = null;
    const value = controller.view();
    if (active && !document.hidden && (["billing_pending", "billing_handoff", "checkout_resumable"].includes(value.phase) || value.runtimeBilling)) {
      if (["billing_pending", "billing_handoff"].includes(value.phase) && pendingReads >= 6) {
        byId("hosted-billing-state").textContent = "Confirmation is taking longer. Your progress is saved. Check status when ready, or contact your service operator with reference HOSTED-SETUP.";
        return;
      }
      const delay = value.validUntil > Date.now() ? Math.max(1000, Math.min(10000, value.validUntil - Date.now())) : 10000;
      timer = setTimeout(() => { pendingReads++; run(() => controller.refresh(), { automatic: true }); }, delay);
    }
  }
  async function plan(current) {
    if (!controller.view().checkoutAvailable) return;
    try {
      const value = await controller.plan();
      if (current !== epoch || !active) return;
      render();
      // Stripe charge units differ from ISO display digits for ISK and UGX.
      // https://docs.stripe.com/currencies#special-cases
      const zeroDecimal = new Set(["bif", "clp", "djf", "gnf", "jpy", "kmf", "krw", "mga", "pyg", "rwf", "vnd", "vuv", "xaf", "xof", "xpf"]);
      const special = ["isk", "ugx"].includes(value.currency);
      if (value.unit_amount > 999999999999 || (special && value.unit_amount % 100 !== 0)) throw new Error("The configured charge units cannot be displayed exactly.");
      const divisor = zeroDecimal.has(value.currency) ? 1 : 100;
      const displayDigits = special || zeroDecimal.has(value.currency) ? 0 : 2;
      const amount = new Intl.NumberFormat(undefined, { style: "currency", currency: value.currency,
        minimumFractionDigits: displayDigits, maximumFractionDigits: displayDigits }).format(value.unit_amount / divisor);
      byId("hosted-plan-price").textContent = `${amount} every ${value.interval_count === 1 ? "" : value.interval_count + " "}${value.interval}${value.interval_count === 1 ? "" : "s"}`;
      byId("hosted-plan-phones").textContent = value.device_cap === null ? "Not specified by the service" : String(value.device_cap);
      byId("hosted-plan-usage").textContent = value.outbound_limit === null ? "Not specified by the service" : String(value.outbound_limit);
      byId("hosted-plan-terms").textContent = value.allowance_period === "subscription_invoice"
        ? `Recurring ${value.mode === "test" ? "TEST " : ""}subscription. Allowance per invoiced service period. Tax ${value.tax_behavior === "inclusive" ? "included" : "added where applicable"}; ${value.automatic_tax ? "calculated at checkout" : "final total at checkout"}. Review renewal and cancellation before confirming.`
        : "Recurring TEST subscription. Stripe confirms taxes, total, renewal and cancellation terms before you confirm.";
      byId("hosted-plan").hidden = false; byId("hosted-checkout").hidden = false;
    } catch (error) {
      if (current === epoch && active) { render(); byId("hosted-plan-terms").textContent = `Plan details could not be verified. ${error.message} Checkout is unavailable until the plan is confirmed.`; }
    }
  }
  async function run(action, { handoff = false, automatic = false } = {}) {
    if (busy || !active) return;
    if (!automatic) pendingReads = 0;
    const current = epoch; busy = true;
    for (const button of document.querySelectorAll("button")) button.disabled = true;
    try {
      const pending = action();
      if (automatic) { byId("hosted-billing").setAttribute("aria-busy", "true"); byId("hosted-phone").inert = true; }
      else render();
      const result = await pending;
      if (current !== epoch || !active) return;
      clearSecrets(); render();
      if (handoff && typeof result === "string") { location.assign(result); return; }
      if (controller.view().checkoutAvailable) await plan(current);
    } catch (error) {
      if (current === epoch && active) { render(); byId("hosted-status").textContent = error.message; }
    } finally {
      clearSecrets(); busy = false;
      byId("hosted-billing").removeAttribute("aria-busy"); byId("hosted-phone").inert = false;
      for (const button of document.querySelectorAll("button")) button.disabled = false;
      if (refreshQueued && active) {
        refreshQueued = false;
        Promise.resolve().then(() => { if (active) run(() => controller.refresh()); });
      } else schedule();
    }
  }
  function submit(id, action) { byId(id).addEventListener("submit", event => { event.preventDefault(); run(action); }); }
  byId("show-login").addEventListener("click", login); byId("show-register").addEventListener("click", register);
  byId("hosted-change-email").addEventListener("click", () => { show(["hosted-account"]); register(); });
  submit("hosted-login-form", () => { email = byId("hosted-email").value.trim(); return controller.login(email, byId("hosted-password").value); });
  submit("hosted-register-form", () => { email = byId("hosted-register-email").value.trim(); return controller.register(email, byId("hosted-register-password").value, byId("hosted-invite").value); });
  submit("hosted-verify-form", () => controller.view().originalBrowser === true ? controller.verifyOriginal(byId("hosted-verification-code").value.trim()) : controller.verify(byId("hosted-verification-code").value.trim(), byId("hosted-verify-password").value));
  submit("hosted-resend-form", () => { if (controller.view().originalBrowser === true) return controller.resendOriginal(); email = byId("hosted-resend-email").value.trim(); return controller.resend(email, byId("hosted-resend-password").value); });
  submit("hosted-factor-form", () => controller.secondFactor(byId("hosted-factor-code").value.trim()));
  byId("hosted-continue-verification").addEventListener("click", () => run(() => controller.resumeVerification()));
  byId("hosted-verify-fallback").addEventListener("click", () => run(() => controller.resumeVerification(true)));
  byId("hosted-refresh").addEventListener("click", () => run(() => controller.refresh()));
  byId("hosted-checkout").addEventListener("click", () => run(() => controller.handoff("checkout"), { handoff: true }));
  byId("hosted-resume").addEventListener("click", () => run(() => controller.handoff("resume"), { handoff: true }));
  byId("hosted-recover-checkout").addEventListener("click", () => run(() => controller.handoff("recover"), { handoff: true }));
  byId("hosted-portal").addEventListener("click", () => run(() => controller.handoff("portal"), { handoff: true }));
  document.addEventListener("visibilitychange", () => { const value = controller.view(); if (!document.hidden && (["billing_pending", "billing_handoff", "checkout_resumable"].includes(value.phase) || value.runtimeBilling)) run(() => controller.refresh()); });
  window.addEventListener("pagehide", () => { active = false; epoch++; refreshQueued = false; clearSecrets(); show([]); controller.invalidate(); if (timer !== null) clearTimeout(timer); });
  window.addEventListener("pageshow", event => { if (event.persisted) { active = true; epoch++; controller.select("hosted"); if (busy) refreshQueued = true; else run(() => controller.refresh()); } });
  document.querySelector(".owner-menu > summary").textContent = "Menu";
  controller.select("hosted");
  run(async () => { await controller.availability(); render(); try { return await controller.refresh(); } catch { return controller.view(); } });
})();
