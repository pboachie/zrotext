# Hosted TEST onboarding controller

`web/owner/hosted-onboarding.js` provides a browser controller for the existing
account and Stripe TEST APIs. It is an integration component, not a served
onboarding page. The current account, fleet and billing pages remain the served
interfaces. There is no live payment implementation or commercial catalog in
this component. See [current TEST billing](STRIPE-TEST-BILLING.md) and the
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

The hosted sequence uses these existing APIs:

1. `register(email, password, invite)` requests registration. The optional
   address-bound invite travels only in its existing header. A 202 response
   reports a request, not successful creation or permission to use the service.
2. `resend(email, password)` requests another verification code when needed.
3. `verify(token, password)` verifies the email and returns to sign-in.
4. `login(email, password)` establishes a session or requests a second factor.
   `secondFactor(code)` completes the private in-memory challenge. MFA failure
   clears the challenge and requires sign-in again.
5. `refresh()` reads the owner session and local TEST billing projection, then
   checks that the same account and session remain current. Observers are
   refused before requesting billing data.
6. `handoff("checkout")` or `handoff("portal")` returns a transient validated
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
