// SPDX-License-Identifier: AGPL-3.0-only
"use strict";
(() => {
  const byId = id => document.getElementById(id);
  const controller = ZrotextHostedOnboarding.create({ checkoutReturn: ["return", "cancel"].includes(new URLSearchParams(location.search).get("checkout")) });
  let email = "", registration = "closed", busy = false, epoch = 0, active = true, timer = null;
  const panels = ["hosted-account", "hosted-verify", "hosted-factor", "hosted-requirements", "hosted-billing", "hosted-phone"];
  const messages = {
    choose_test_subscription: "Review the verified TEST plan before checkout.",
    billing_pending: "Confirming your subscription. Your existing attempt is being checked; no new purchase is needed.",
    billing_restricted: "Your subscription needs attention. Check status or open subscription management to resolve it.",
    test_subscription_observed: "The server has observed an eligible TEST subscription. This is a test service, with no live paid-service entitlement.",
    billing_unavailable: "Subscription details are unavailable on this server. Sign-in and account recovery remain available.",
    billing_handoff: "Opening the secure payment page. Your subscription will be checked when you return."
  };
  function show(ids) { for (const id of panels) byId(id).hidden = !ids.includes(id); }
  function clearSecrets() { for (const input of document.querySelectorAll('input[type="password"], #hosted-invite, #hosted-verification-code, #hosted-factor-code')) input.value = ""; }
  function render() {
    const value = controller.view(), phase = value.phase;
    document.body.dataset.hostedPhase = phase;
    byId("hosted-refresh").hidden = phase === "choose_test_subscription";
    byId("hosted-checkout").hidden = true;
    byId("hosted-portal").hidden = true;
    byId("hosted-plan").hidden = true;
    byId("hosted-plan-terms").textContent = "";
    byId("hosted-status").textContent = value.message || "";
    if (phase === "loading") return;
    for (const id of ["hosted-step-account", "hosted-step-plan", "hosted-step-phone"]) byId(id).removeAttribute("aria-current");
    byId(["test_subscription_observed"].includes(phase) ? "hosted-step-phone" : phase.startsWith("billing") || phase === "choose_test_subscription" ? "hosted-step-plan" : "hosted-step-account").setAttribute("aria-current", "step");
    if (phase === "verification_requested") { show(["hosted-verify"]); byId("hosted-verification-address").textContent = email ? `Check the inbox for ${email}.` : "Use the code sent to your account email."; return; }
    if (phase === "second_factor") { show(["hosted-factor"]); byId("hosted-factor-code").focus(); return; }
    if (["choose_test_subscription", "billing_pending", "billing_restricted", "test_subscription_observed", "billing_unavailable", "billing_handoff"].includes(phase)) {
      show(phase === "test_subscription_observed" ? ["hosted-billing", "hosted-phone"] : ["hosted-requirements", "hosted-billing"]);
      byId("hosted-billing-state").textContent = messages[phase];
      byId("hosted-mode").textContent = value.billingMode === "test" ? "TEST mode · no live charges" : "Billing capability unavailable";
      byId("hosted-portal").hidden = !value.portalAvailable;
      if (phase === "test_subscription_observed") byId("hosted-phone-status").textContent = "Continue in TEST mode. Phone enrollment still checks the server's account policy.";
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
    if (active && !document.hidden && ["billing_pending", "billing_handoff"].includes(controller.view().phase)) timer = setTimeout(() => run(() => controller.refresh()), 10000);
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
      byId("hosted-plan-terms").textContent = "Recurring TEST subscription. Stripe confirms taxes, total, renewal and cancellation terms before you confirm.";
      byId("hosted-plan").hidden = false; byId("hosted-checkout").hidden = false;
    } catch (error) {
      if (current === epoch && active) { render(); byId("hosted-plan-terms").textContent = `Plan details could not be verified. ${error.message} Checkout is unavailable until the plan is confirmed.`; }
    }
  }
  async function run(action, { handoff = false } = {}) {
    if (busy || !active) return;
    const current = epoch; busy = true;
    for (const button of document.querySelectorAll("button")) button.disabled = true;
    try {
      const result = await action();
      if (current !== epoch || !active) return;
      clearSecrets(); render();
      if (handoff) { location.assign(result); return; }
      if (controller.view().checkoutAvailable) await plan(current);
    } catch (error) {
      if (current === epoch && active) { render(); byId("hosted-status").textContent = error.message; }
    } finally {
      clearSecrets(); busy = false;
      for (const button of document.querySelectorAll("button")) button.disabled = false;
      schedule();
    }
  }
  function submit(id, action) { byId(id).addEventListener("submit", event => { event.preventDefault(); run(action); }); }
  byId("show-login").addEventListener("click", login); byId("show-register").addEventListener("click", register);
  byId("hosted-change-email").addEventListener("click", () => { show(["hosted-account"]); register(); });
  submit("hosted-login-form", () => { email = byId("hosted-email").value.trim(); return controller.login(email, byId("hosted-password").value); });
  submit("hosted-register-form", () => { email = byId("hosted-register-email").value.trim(); return controller.register(email, byId("hosted-register-password").value, byId("hosted-invite").value); });
  submit("hosted-verify-form", () => controller.verify(byId("hosted-verification-code").value.trim(), byId("hosted-verify-password").value));
  submit("hosted-resend-form", () => controller.resend(email, byId("hosted-resend-password").value));
  submit("hosted-factor-form", () => controller.secondFactor(byId("hosted-factor-code").value.trim()));
  byId("hosted-refresh").addEventListener("click", () => run(() => controller.refresh()));
  byId("hosted-checkout").addEventListener("click", () => run(() => controller.handoff("checkout"), { handoff: true }));
  byId("hosted-portal").addEventListener("click", () => run(() => controller.handoff("portal"), { handoff: true }));
  document.addEventListener("visibilitychange", () => { if (!document.hidden && ["billing_pending", "billing_handoff"].includes(controller.view().phase)) run(() => controller.refresh()); });
  window.addEventListener("pagehide", () => { active = false; epoch++; clearSecrets(); controller.invalidate(); if (timer !== null) clearTimeout(timer); });
  window.addEventListener("pageshow", event => { if (event.persisted) { active = true; epoch++; controller.select("hosted"); run(() => controller.refresh()); } });
  document.querySelector(".owner-menu > summary").textContent = "Menu";
  controller.select("hosted");
  run(async () => { await controller.availability(); render(); try { return await controller.refresh(); } catch { return controller.view(); } });
})();
