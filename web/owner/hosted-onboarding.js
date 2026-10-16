// SPDX-License-Identifier: AGPL-3.0-only
"use strict";

// Browser-only orchestration over the existing account and TEST billing APIs.
// Views are instructions for the owner UI, never authority to enroll or send.
(function (root) {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const count = (value) => Number.isSafeInteger(value) && value >= 0;
  const availabilityFields = Object.freeze(["schema_version", "deployment", "registration",
    "billing", "checkout_available", "plan_catalog_available"]);
  const errors = Object.freeze({
    400: "Check your entries and try again.",
    401: "Sign in again to continue.",
    403: "This action was refused. Sign in again.",
    404: "Hosted TEST billing is unavailable on this server.",
    409: "Refresh billing before continuing; an existing subscription may need the portal.",
    429: "Too many attempts. Wait before trying again.",
    503: "The service is unavailable. Try again later.",
  });

  function billingView(value) {
    if (!value || value.mode !== "test" || typeof value.customerBound !== "boolean" ||
        ![value.pendingReconciliations, value.reviewReconciliations,
          value.reviewRiskEvents, value.nonterminalSubscriptions].every(count) ||
        !value.projectedEntitlement || typeof value.projectedEntitlement.paymentHold !== "boolean") {
      throw new Error("The TEST billing response was invalid.");
    }
    const entitlement = value.projectedEntitlement;
    if ((entitlement.reason !== null && typeof entitlement.reason !== "string") ||
        (entitlement.outboundLimit !== null && !count(entitlement.outboundLimit)) ||
        (entitlement.deviceCap !== null && !count(entitlement.deviceCap))) {
      throw new Error("The entitlement response was invalid.");
    }
    const pending = value.pendingReconciliations > 0;
    const review = value.reviewReconciliations > 0 || value.reviewRiskEvents > 0;
    const existing = value.nonterminalSubscriptions > 0;
    const eligibleReason = ["active", "grace", "invoice_current"].includes(entitlement.reason);
    const restricted = review || entitlement.paymentHold || value.nonterminalSubscriptions > 1 ||
      (existing && (!eligibleReason || entitlement.outboundLimit === 0 || entitlement.deviceCap === 0));
    return Object.freeze({
      phase: pending ? "billing_pending" : restricted ? "billing_restricted"
        : existing ? "test_subscription_observed" : "choose_test_subscription",
      billingMode: "test",
      checkoutAvailable: !pending && !review && !existing && !entitlement.paymentHold,
      portalAvailable: value.customerBound,
      // A portal return or this read model cannot grant a production entitlement.
      productionReady: false,
      entitlementReason: entitlement.reason,
    });
  }

  function create(options = {}) {
    const fetcher = options.fetch || root.fetch.bind(root);
    const cookie = options.cookie || (() => root.document.cookie);
    const randomUUID = options.randomUUID || (() => root.crypto.randomUUID());
    let epoch = 0;
    let busy = false;
    let selection = null;
    let challenge = null;
    let session = null;
    let availability = null;
    let view = Object.freeze({ phase: "choose_hosting", productionReady: false });

    function publish(next) {
      view = Object.freeze({ productionReady: false, ...next });
      return view;
    }

    function clear() { session = null; challenge = null; }

    function csrfToken() {
      return cookie().split(";").map((part) => part.trim())
        .find((part) => part.startsWith("__Host-zrotext_csrf="))?.slice("__Host-zrotext_csrf=".length);
    }

    function registrationCsrf() {
      const proof = cookie().split(";").map(part => part.trim())
        .find(part => part.startsWith("__Host-zrotext_registration_csrf="))?.slice("__Host-zrotext_registration_csrf=".length);
      return /^ztrc_[A-Za-z0-9_-]{43}$/.test(proof || "") ? proof : null;
    }

    async function afterIntentVerification(guard, message) {
      clear();
      try {
        const current = await request("/v1/auth/session");
        guard();
        if (!["owner", "observer"].includes(current?.role) || !uuid.test(current.account_id) || !uuid.test(current.session_id)) throw new Error("The current sign-in could not be confirmed.");
        return publish({ phase: "existing_session", hosting: "hosted",
          message: "An account is already signed in in this browser. Open its workspace, or sign out there before using another account." });
      } catch (error) {
        guard();
        if (error.status !== 401) throw error;
      }
      return publish({ phase: "sign_in", hosting: "hosted", message });
    }

    function select(mode) {
      if (!["hosted", "self_hosted"].includes(mode)) throw new Error("Choose a hosting option.");
      epoch += 1;
      clear();
      availability = null;
      selection = mode;
      return publish({ phase: mode === "hosted" ? "availability_unknown" : "self_hosted", hosting: mode });
    }

    function invalidate() {
      epoch += 1;
      clear();
      availability = null;
      selection = null;
      return publish({ phase: "choose_hosting" });
    }

    async function request(path, method = "GET", body, extra = {}, csrf = false) {
      const headers = { ...extra };
      if (body !== undefined) headers["content-type"] = "application/json";
      if (csrf) {
        // Use the token captured with the expected session. Resampling here
        // could pair another tab's replacement session with its new CSRF.
        headers["x-zrotext-csrf"] = csrf;
      }
      let response;
      try {
        response = await fetcher(path, {
          method, headers, credentials: "same-origin", cache: "no-store", redirect: "error",
          body: body === undefined ? undefined : JSON.stringify(body),
          signal: typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(30_000) : undefined,
        });
      } catch {
        throw new Error("Could not reach the server. Try again.");
      }
      if (!response.ok) {
        const error = new Error(errors[response.status] || "The request failed.");
        error.status = response.status;
        throw error;
      }
      // Registration's 202 is intentionally opaque. Login's 202 carries an
      // MFA challenge and must be parsed before trying the session endpoint.
      if (response.status === 204 || (response.status === 202 && path !== "/v1/auth/login")) return null;
      let result;
      try { result = await response.json(); } catch { throw new Error("The server response was invalid."); }
      if (path === "/v1/auth/login" && response.status === 202 &&
          (!result || typeof result.challenge_token !== "string" ||
            !/^ztm_[A-Za-z0-9_-]{1,256}$/.test(result.challenge_token))) {
        throw new Error("The sign-in response was invalid.");
      }
      return result;
    }

    async function ownerSession() {
      const csrf = csrfToken();
      if (!csrf) throw new Error("Sign in again to continue.");
      const result = await request("/v1/auth/session");
      if (csrfToken() !== csrf) throw new Error("Your account session changed. Refresh before continuing.");
      if (!result || result.role !== "owner" || !uuid.test(result.account_id) || !uuid.test(result.session_id)) {
        throw new Error("Sign in with an owner account to continue.");
      }
      return { account: result.account_id, id: result.session_id, csrf };
    }

    async function sameSession(expected) {
      const current = await ownerSession();
      if (!expected || current.account !== expected.account || current.id !== expected.id ||
          current.csrf !== expected.csrf) {
        throw new Error("Your account session changed. Refresh before continuing.");
      }
      return current;
    }

    async function run(action) {
      if (selection !== "hosted") throw new Error("Choose hosted setup first.");
      if (busy) throw new Error("An onboarding request is already running.");
      const current = epoch;
      busy = true;
      // Remove stale billing buttons before every request, including failures.
      publish({ phase: "loading", hosting: "hosted" });
      const guard = () => {
        if (current !== epoch) throw new Error("Onboarding changed; refresh before continuing.");
      };
      try {
        return await action(guard);
      } catch (error) {
        if (current === epoch) {
          clear();
          publish({ phase: error.status === 401 || error.status === 403 ? "sign_in" : "unavailable",
            hosting: "hosted", message: error.message });
        }
        throw error;
      } finally {
        busy = false;
      }
    }

    async function refreshWithin(guard) {
      const before = await ownerSession();
      guard();
      const capability = await availabilityWithin(guard);
      if (capability.deployment !== "hosted" || capability.billing !== "test") {
        await sameSession(before);
        guard();
        session = before;
        challenge = null;
        return publish({ phase: "billing_unavailable", hosting: "hosted",
          message: "Hosted TEST billing is unavailable on this server." });
      }
      const billing = await request("/v1/billing/status");
      guard();
      await sameSession(before);
      guard();
      let next = billingView(billing);
      // A return marker only removes actions. It cannot assert payment success or failure.
      if (options.checkoutReturn === true && next.phase === "choose_test_subscription") {
        next = { ...next, phase: "billing_pending", checkoutAvailable: false };
      }
      session = before;
      challenge = null;
      return publish({ hosting: "hosted", ...next,
        checkoutAvailable: next.checkoutAvailable && availability.billing === "test" && availability.checkout_available });
    }

    async function availabilityWithin(guard) {
      availability = null;
      const value = await request("/v1/service/availability");
      guard();
      if (!value || typeof value !== "object" || Array.isArray(value) ||
          Object.keys(value).length !== availabilityFields.length ||
          !Object.keys(value).every((field) => availabilityFields.includes(field)) ||
          value.schema_version !== 1 ||
          !["hosted", "self_hosted"].includes(value.deployment) ||
          !["closed", "invite_only", "open"].includes(value.registration) ||
          !["disabled", "test", "live"].includes(value.billing) ||
          typeof value.checkout_available !== "boolean" || typeof value.plan_catalog_available !== "boolean" ||
          (value.checkout_available && (value.billing === "disabled" || !value.plan_catalog_available)) ||
          (value.deployment === "self_hosted" && (value.billing !== "disabled" || value.checkout_available || value.plan_catalog_available))) {
        throw new Error("Service availability could not be verified. Sign-in and recovery remain available.");
      }
      availability = Object.freeze({ schema_version: value.schema_version,
        deployment: value.deployment, registration: value.registration, billing: value.billing,
        checkout_available: value.checkout_available, plan_catalog_available: value.plan_catalog_available });
      return availability;
    }

    return Object.freeze({
      view: () => view,
      select,
      invalidate,
      availability: () => run(async (guard) => {
        const value = await availabilityWithin(guard);
        return publish({ hosting: "hosted", phase: value.deployment === "hosted" && value.registration !== "closed"
          ? "account_setup" : "registration_closed", registration: value.registration });
      }),
      register: (email, password, invite = "") => run(async (guard) => {
        clear();
        const value = await availabilityWithin(guard);
        if (value.deployment !== "hosted" || value.registration === "closed") {
          throw new Error("Registration is closed. Sign-in and recovery remain available.");
        }
        if (value.registration === "invite_only" && !invite.trim()) throw new Error("An invitation is required.");
        try {
          await request("/v1/auth/register", "POST", { email, password },
            invite ? { "x-zrotext-registration-token": invite.trim() } : {});
        } catch (error) {
          guard();
          if (!error.status) return afterIntentVerification(guard,
            "The registration result could not be confirmed. Continue email verification or sign in to check your account; do not create it again.");
          throw error;
        }
        guard();
        return publish({ phase: "verification_requested", hosting: "hosted", originalBrowser: Boolean(registrationCsrf()),
          message: "If registration is open for this address, check your mailbox for a code." });
      }),
      resumeVerification: (passwordFallback = false) => run(async (guard) => {
        clear(); guard();
        return publish({ phase: "verification_requested", hosting: "hosted", originalBrowser: !passwordFallback && Boolean(registrationCsrf()) });
      }),
      resendOriginal: () => run(async (guard) => {
        const proof = registrationCsrf();
        if (!proof) throw new Error("Use password verification in this browser to continue.");
        await request("/v1/auth/registration-intent/resend", "POST", {}, { "x-zrotext-registration-csrf": proof });
        guard();
        if (registrationCsrf() !== proof) throw new Error("Account setup changed in another tab. Check the current setup before continuing.");
        return publish({ phase: "verification_requested", hosting: "hosted", originalBrowser: true,
          message: "If this setup is still eligible, a fresh code will arrive. Use the most recent code or choose password verification." });
      }),
      verifyOriginal: (token) => run(async (guard) => {
        const proof = registrationCsrf();
        if (!proof) throw new Error("Use password verification in this browser to continue.");
        try {
          await request("/v1/auth/registration-intent/verify", "POST", { token }, { "x-zrotext-registration-csrf": proof });
        } catch (error) {
          guard();
          if (error.status === 400 && registrationCsrf() === proof) return publish({ phase: "verification_requested", hosting: "hosted", originalBrowser: true,
            message: "The code could not be verified here. Try the latest code or choose password verification; your existing account is unchanged." });
          if (!error.status || error.status === 409) return afterIntentVerification(guard,
            "The verification result could not be confirmed. Sign in to check your account, or use password verification. Do not register again.");
          throw error;
        }
        guard();
        return afterIntentVerification(guard, registrationCsrf() === proof
          ? "Email verification finished. Sign in to continue; your password manager can fill your account details."
          : "The verification request finished for an earlier setup. Sign in to the account you intended to use.");
      }),
      resend: (email, password) => run(async (guard) => {
        await request("/v1/auth/resend-verification", "POST", { email, password });
        guard();
        return publish({ phase: "verification_requested", hosting: "hosted" });
      }),
      verify: (token, password) => run(async (guard) => {
        await request("/v1/auth/verify-email", "POST", { token, password });
        guard();
        clear();
        return publish({ phase: "sign_in", hosting: "hosted" });
      }),
      login: (email, password) => run(async (guard) => {
        clear();
        const result = await request("/v1/auth/login", "POST", { email, password });
        guard();
        if (result && typeof result.challenge_token === "string" &&
            /^ztm_[A-Za-z0-9_-]{1,256}$/.test(result.challenge_token)) {
          challenge = result.challenge_token;
          return publish({ phase: "second_factor", hosting: "hosted" });
        }
        if (result !== null) throw new Error("The sign-in response was invalid.");
        return refreshWithin(guard);
      }),
      secondFactor: (code) => run(async (guard) => {
        if (!challenge) throw new Error("Sign in again to request a second-factor challenge.");
        const result = await request("/v1/auth/login/mfa", "POST", { challenge_token: challenge, code });
        guard();
        if (result !== null) throw new Error("The sign-in response was invalid.");
        return refreshWithin(guard);
      }),
      refresh: () => run(refreshWithin),
      plan: () => {
        const expected = session, previous = view;
        return run(async (guard) => {
          if (!previous.checkoutAvailable) throw new Error("Refresh subscription status before reviewing a plan.");
          const capability = await availabilityWithin(guard);
          if (capability.billing !== "test" || !capability.checkout_available || !capability.plan_catalog_available) throw new Error("A verified TEST plan is unavailable.");
          await sameSession(expected); guard();
          const value = await request("/v1/billing/plan");
          guard(); await sameSession(expected); guard();
          const fields = ["schema_version", "mode", "currency", "unit_amount", "interval", "interval_count", "outbound_limit", "device_cap"];
          if (!value || Object.keys(value).length !== fields.length || !Object.keys(value).every(key => fields.includes(key)) ||
              value.schema_version !== 1 || value.mode !== "test" || !/^[a-z]{3}$/.test(value.currency) ||
              !count(value.unit_amount) || !Number.isSafeInteger(value.interval_count) || value.interval_count < 1 ||
              !["day", "week", "month", "year"].includes(value.interval) ||
              (value.outbound_limit !== null && !count(value.outbound_limit)) || (value.device_cap !== null && !count(value.device_cap))) throw new Error("The configured TEST plan was invalid.");
          publish(previous);
          return Object.freeze({ ...value });
        });
      },
      handoff: (kind) => {
        const expected = session;
        const permitted = kind === "checkout" ? view.checkoutAvailable
          : kind === "portal" ? view.portalAvailable : false;
        return run(async (guard) => {
          if (!permitted) throw new Error("Refresh billing before requesting this handoff.");
          const value = await availabilityWithin(guard);
          if (value.deployment !== "hosted" || value.billing !== "test") {
            throw new Error("Hosted TEST billing is unavailable on this server.");
          }
          if (kind === "checkout" && !value.checkout_available) {
            throw new Error("Checkout is unavailable on this server.");
          }
          await sameSession(expected);
          guard();
          const headers = kind === "checkout" ? { "idempotency-key": randomUUID() } : {};
          const result = await request(`/v1/billing/${kind}`, "POST", undefined, headers, expected.csrf);
          guard();
          await sameSession(expected);
          guard();
          const host = kind === "checkout" ? "checkout.stripe.com" : "billing.stripe.com";
          let url;
          try { url = new URL(result.url); } catch { throw new Error("The billing handoff was invalid."); }
          if (url.protocol !== "https:" || url.hostname !== host || url.port || url.username || url.password) {
            throw new Error("The billing handoff was invalid.");
          }
          publish({ phase: "billing_handoff", hosting: "hosted", billingMode: "test" });
          // URL is returned transiently, never persisted or included in the view.
          return url.href;
        });
      },
    });
  }

  const api = Object.freeze({ create, billingView });
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.ZrotextHostedOnboarding = api;
})(globalThis);
