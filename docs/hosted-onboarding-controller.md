# Hosted TEST onboarding controller

`web/owner/hosted-onboarding.js` provides a browser controller for the existing
account and Stripe TEST APIs. The served `/owner/hosted` page uses it for
registration, verification, sign-in, configured TEST plan review, checkout,
return reconciliation and subscription management. Existing account, fleet and
billing pages remain available. There is no LIVE payment implementation or
commercial default catalog in this component. See [current TEST billing](STRIPE-TEST-BILLING.md) and the
[mode-isolation proposal](BILLING-MODES-PROPOSAL.md).

## Integration

Load the controller on an owner website and instantiate
`ZrotextHostedOnboarding.create()`. Its `view()` is a frozen presentation
snapshot. Render its values as text, and clear password, verification-code and
second-factor inputs after submit. The controller stores neither credentials
nor handoff URLs in its view, local storage, query strings or cookies.

Call `select("hosted")` before account operations, or `select("self_hosted")`
for self-hosted instructions. Self hosting performs no payment calls and does
not require a hosted subscription. Switching choices invalidates in-flight
presentation results. Call `invalidate()` on page exit, sign-out or account
replacement. An accepted server action may still complete after invalidation;
invalidation discards its browser result rather than claiming server rollback.

Hosted selection starts at `availability_unknown`. Call `availability()` to
read the coarse `/v1/service/availability` contract before showing signup.
Registration also rechecks it before submitting. Closed or unverified signup
leaves sign-in and existing recovery available; invite-only signup requires an
invitation. Refresh and checkout recheck availability, and checkout needs an
explicit TEST mode and enabled checkout capability. A LIVE capability does not
upgrade this TEST-only controller. The runtime must mount the availability
route before integrating this component; missing or contradictory responses
remove actionable controls.

The availability v1 response must contain exactly its six documented fields.
Valid self-hosted, disabled or LIVE capabilities preserve successful sign-in
and produce `billing_unavailable`, without reading TEST billing. Both portal
and checkout handoffs recheck hosted TEST mode. Portal remains usable when
registration is closed or new checkout is disabled, provided the authenticated
TEST customer binding remains current.

The hosted sequence uses these existing APIs:

1. `register(email, password, invite)` requests registration. The optional
   address-bound invite travels only in its existing header. A 202 response
   reports a request, not successful creation or permission to use the service.
2. `resumeVerification()` offers code-only verification when the independent
   registration proof cookie is present. This is presentation only; the server
   validates the HttpOnly intent, exact Origin, bound CSRF and current account.
   `resendOriginal()` posts an empty body and `verifyOriginal(token)` posts only
   the mailed code. A fixed fifteen-minute intent cannot be renewed by resend.
3. `resumeVerification(true)` selects explicit password fallback. Existing
   `resend(email, password)` and `verify(token, password)` remain available in
   another browser or after the original intent expires. All verification paths
   return to explicit sign-in; none issues an ordinary session.
4. `login(email, password)` establishes a session or requests a second factor.
   `secondFactor(code)` completes the private in-memory challenge. MFA failure
   clears the challenge and requires sign-in again.
5. `refresh()` reads the owner session and local TEST billing projection, then
   checks that the same account and session remain current. Observers are
   refused before requesting billing data.
6. `plan()` checks the same current owner session and capability, then reads
   `/v1/billing/plan`. The closed version-one response contains TEST mode,
   currency, integer charge units, recurrence and configured device/outbound
   allowances. The served page shows checkout only after these terms validate.
   Stripe charge units are used for display, including the documented ISK/UGX
   exceptions; unsupported fractional exceptions cannot be rounded into a
   purchase.
7. `handoff("checkout")` or `handoff("portal")` returns a transient validated
   HTTPS Stripe URL. The integrating website may navigate to that URL. It must
   refresh after return; neither return nor checkout completion grants access.

Checkout submits no browser-selected price, customer, tenant or return URL.
It uses the server's existing configured TEST price and quota policy. Server
authorization, exact Origin/CSRF checks, account locking, rate limits and
reconciliation remain authoritative. The controller checks owner-session
continuity before and after requesting a handoff; these checks do not replace
the server's mutation checks. It captures a stable CSRF cookie with each
session read and sends that captured token for mutations, so replacement
session cookies cannot silently select a different account. Missing or rotated
CSRF clears the controls. A server conflict requires an explicit refresh.
Actions are serialized, so repeated submissions cannot run in parallel.

## Served account and recovery flow

The account view preserves an email address in memory while moving between
registration, email verification, resend and sign-in. Password-manager attributes
remain present. Passwords, verification codes and MFA codes are cleared after
submit and page departure. Closed or unknown signup retains sign-in and recovery.
An uncertain registration or verification reply checks the ordinary session
once and offers verification/sign-in without replaying account creation. A valid
account already signed in is preserved and shown as an existing session.
Registration passwords and the HttpOnly intent never enter JavaScript storage;
the page reads only the independent registration CSRF proof. See
[the intent contract](registration-browser-intent.md).

Self-hosted owners continue through their server's account/setup interfaces
without a Stripe subscription.

The subscription view explains compatible Android, active SIM, internet and
separate carrier service before purchase. Configured TEST price, currency,
recurrence and allowances come from the server's verified provider metadata;
there are no sample commercial plans. Checkout is a transient Stripe navigation.
Returning to the page refreshes the server projection. A `checkout=return` or
`checkout=cancel` marker is conservative only: an empty stale subscription
projection remains pending and cannot offer another checkout. The marker never
grants entitlement or proves cancellation. Pending reconciliation
shows a status check and help path, with no second purchase control. An observed
eligible TEST subscription links into Add phone, where server enrollment and
line authority are checked independently. TEST never becomes LIVE eligibility.

Missing LIVE runtime support, configured prices, namespace verification or
provider readiness remains an explicit unavailable capability. This page does
not activate service signup, prices, deployment or a live launch.

## States and authority

Missing, malformed, live or disabled billing projections fail closed. Failed
refresh removes previously actionable controls. Pending reconciliation, review,
payment hold or any nonterminal subscription blocks a second checkout.
Recognized active, grace and invoice-current projections remain labeled TEST.
`productionReady` is always false. The controller never authorizes message
admission, device enrollment, a content reader or a private-key operation.
Pairing and key custody must use their existing separate protocols.

Recovery and account deletion remain on the existing account-security and
data-management interfaces. No billing result recovers a client-owned private
key, changes consent or erases an unresolved financial obligation.

This controller is for the owner website. Do not embed a Stripe checkout link
or a purchase-leading web flow in the Play-distributed Android app without a
reviewed applicable policy/program. Google identifies cloud services as digital
services and permits consumption-only apps to access purchases made elsewhere;
external-payment permissions depend on the applicable program and region.
See [Google's payment policy](https://support.google.com/googleplay/android-developer/answer/9858738)
and [its consumption-only guidance](https://support.google.com/googleplay/android-developer/answer/10281818).

## Verification

`node --test web/owner/hosted-onboarding.test.js` runs synthetic HTTP fixtures
through signup, verification, MFA, TEST checkout, pending reconciliation,
subscription observation, grace and portal return. It also covers stale
sessions, observer refusal, malformed/live modes, exact URL hosts, CSRF,
duplicate submit, unavailable billing and a switch to self hosting.
These fixtures prove browser orchestration only; they do not prove database
transactions, email delivery, provider acceptance, paid-service availability,
carrier delivery or Android policy approval.
