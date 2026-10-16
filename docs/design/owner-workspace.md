# Owner workspace and coordinated setup

Status: **approved design; implementation and acceptance are tracked separately**.
This specification replaces the long, section-stacked owner workspace design.
It does not enable hosted signup, live billing, SMS dispatch or conversation
access. The normative machine-readable requirements and recovery examples are
in [the setup journey contract](../../protocol/v1/setup-journey-contract.json).

## Product outcome

An owner can see which phone needs attention, open its relevant details without
losing the list, and finish setup without copying device identifiers, stream
addresses, line identifiers or pairing credentials between screens. A returning
owner continues from current confirmed progress. The interface repeats only a
step whose session, key, SIM, permission or approval is no longer valid.

The dashboard and Android app share terminology, progress and recovery rules.
The existing dark green identity remains. Generated artwork is a composition
reference, not a source of availability, pricing, metrics or security claims.
Commercial decisions and private review artwork remain outside this public tree.

## Information architecture

| Destination | Purpose |
|---|---|
| Overview | Compact status summary, prioritized exceptions, phone list and recent activity |
| Phones & lines | Fleet management and a selected phone's current line state |
| Activity | Scoped message metadata, events, loading, historical and unknown outcomes |
| Integrations | API credentials, inbound metadata and webhook delivery tools |
| Team | Existing owner/observer membership controls |
| Settings | Account security, sessions, recovery and account management |
| Add phone | Focused scan, compare, connect and line-review wizard |
| Hosted setup | Account, plan, phone and finish journey, only for supported service capabilities |

These are real navigable destinations with current-location semantics, usable
Back/Forward and bookmark behavior. Navigation does not scroll a giant document
to an anchor. Implementations may reuse an embedded shell and controller IDs;
inactive destinations must be hidden from layout and accessibility navigation.
An inactive destination must not start unrelated polling or mutations.

Overview keeps routine observation compact. Phone selection opens a contextual
inspector beside the list at desktop widths. At narrow widths the same details
become a focused screen or accessible sheet with a clear way back to the list.
Pairing forms, passwords, API-key creation and webhook administration do not
extend the ordinary overview. Loading and empty data never become sample data.

## Layout and accessibility

- Keep the existing background, surface, raised, text, secondary, accent,
  caution and border tokens from `docs/DESIGN.md`.
- Show one current setup task and one primary action. Completed steps become
  a compact progress summary. Place explanations next to the decision they
  affect. Put technical details and manual alternatives behind named controls.
- At ordinary portrait size and default type size, Android Home and an ordinary
  setup step should fit without a long document scroll. Compact landscape,
  large text, keyboards and long errors retain readable scrolling; never clip
  content or shrink essential text to satisfy a viewport assertion.
- Preserve keyboard focus, semantic headings, error association, status
  announcements, focus return, reduced motion and non-color status cues.
- Web actions have at least a 44 CSS-pixel target; Android actions at least
  48 dp. At 200 percent web text scaling and Android enlarged text, actions
  remain reachable and content does not overlap or truncate essential values.
- Comparison codes and the complete fingerprint must be readable on both
  screens. A shortened fingerprint is not the full comparison decision.

## Coordinated Add phone flow

### Scan

The dashboard creates one bounded, one-use pairing ticket and shows its QR,
expiry and waiting state. A recognizable phone name is suggested; renaming is
optional. The phone uses an independently selected trusted service. A hosted
build may receive its canonical service origin through reviewed build
configuration; self-hosted owners enter and recognize their operator's origin.
The scanned payload cannot establish or replace service trust.

Camera access belongs only to scanning. Request scanner-specific permission at
the point of use only when the selected scanner requires it; a delegated scanner
need not add an app camera permission. Manual pairing is an accessible
alternative. SMS access and SIM selection are not prerequisites
for pairing. Ticket secrets remain short-lived and are cleared on departure.

### Compare and approve

Both screens show the code and full phone-key fingerprint together. The owner
compares them and chooses **Values match - approve phone** on the dashboard,
or **These do not match**. Do not require typing values that are already shown
or add duplicate confirmation checkboxes. The server still validates the exact
current proof, pairing, owner session and comparison values. Displaying values
or reading status never approves a phone.

After approval the phone uses a distinct, existing-key-authenticated binding
challenge to obtain its current approved device identity. It derives the device
stream address from its independently selected canonical origin. It never uses
an arbitrary returned or scanned address as trust. A status query cannot create
a missing key, replay enrollment proof, approve a phone or start a service.

If the first claim never attached a key, a fresh key proof cannot discover a
binding. The trusted server may report only a coarse terminal result for an
actual active-account ticket that is unclaimed, unapproved and expired or
cancelled. This closed observation grants no device identity or comparison
values. Missing rows, claimed-key mismatches and revoked or missing device
identities remain unknown; they cannot authorize ticket replacement.

### SIM, access and connection

The phone explicitly selects an active SIM. Enumerate supported choices without
silently selecting a different SIM or physical fallback. Show purpose-specific
access and request only missing Android permissions through their disclosures.
Receiving access remains an independent choice. Declining SMS access must not
erase successful pairing or imply that SMS can now be sent.

Show one **Start connection** action and an initially unchecked reboot-resume
option. Navigation, pairing success, permission grant and status observation do
not start the connection. Reboot resume is connection-only. Pause retains its
disclosure that permission-enabled local receiving can continue; revocation of
Android receiving access is a separate action.

### Line review and finish

Keep the SMS approval-key and MFA prerequisite inside the wizard when needed.
Use the selected phone automatically, generate the line identifier, and choose
a supported activation mode only from actual capability evidence. Ambiguous or
unsupported capability needs a clear explanation or explicit selection, not a
guessed mode. Automatically requesting a declaration is allowed only for the
already selected exact phone/line ceremony and must not duplicate an unresolved
request.

Show the phone's actual declaration, selected SIM, subscription count and
freshness. The owner chooses **Approve this phone and SIM** once. Changed SIM,
key, generation or session invalidates the relevant approval. Where the protocol
requires a separate phone-side line choice, retain that distinct choice; the
basic browser SMS declaration flow must not invent a redundant phone approval.

Finish says **Phone connected** and **Line approval recorded** only when each
fact is actually confirmed. Neither proves carrier service, delivery, content
consent or dispatch readiness. API setup, controlled carrier testing and
conversation access remain separately described follow-on tasks.

## Hosted account and payment journey

The website owns registration, verification, sign-in, security, plan review,
checkout, billing return and subscription management. The Android companion
connects an existing account's phone without a second account registration,
payment form or purchase-leading link.

Service availability must be checked before offering registration or checkout.
Open, invite-only, closed, disabled, TEST, LIVE and unavailable are distinct
states. Closed signup retains sign-in and recovery. Unknown availability does
not become an actionable purchase. Self-hosted software requires no hosted
subscription or Stripe customer.

1. Ask for email and password, support password managers, and disclose terms.
   Consent controls are not preselected. Company, phone number and workspace
   name are not compulsory fields without a product requirement.
2. Verify email in one focused view with resend and change-address recovery,
   then authenticate. Never persist a password to simulate seamless recovery.
3. Before payment, explain compatible Android, active SIM, internet and carrier
   requirements. Acknowledging requirements is not a carrier compatibility test.
4. Show authoritative plan price, currency, recurrence, phone cap, usage limits,
   applicable tax/total treatment and cancellation terms before purchase. A
   fixed server-configured price is acceptable; fabricated plans are not.
5. Create one account-bound checkout handoff. Card details are collected by the
   supported payment provider. Reconcile the actual provider/subscription state
   on return and after an interrupted redirect. A return URL is not entitlement.
6. Once the service confirms eligibility, continue into Add phone. Carry forward
   account and selected service context, not account passwords or API keys.

TEST checkout is labelled TEST throughout and cannot grant LIVE production
authority. Missing LIVE mode isolation, provider support or configured catalog
must remain an explicit implementation/launch gap, not be hidden by a successful
TEST fixture. Implementing this design does not authorize live activation,
customer purchases, external provider calls or release-stage advancement.

Hosted runtime observations bind the billing mode, account, current browser
session and observation time. Eligible service also requires a fresh, clean
entitlement with positive limits and no payment or review hold. The page never
turns an observed subscription into device, carrier or dispatch readiness.

Checkout recovery distinguishes an open session from an interrupted request.
An open session offers Continue existing checkout after a fresh status read.
An interrupted request offers Recover existing checkout only when the server
reports a recoverable durable operation. That explicit recovery replays the
same operation and request; it cannot allocate a replacement purchase. A null
recovery URL means the existing attempt has already ended, so the page refreshes
status instead of navigating. Unknown, mismatched or out-of-window attempts
retain their progress and an operator help path. Only a confirmed replaceable
state may offer a new checkout. Return flags confer no authority.

Automatic pending checks stop after six attempts and leave Check status and a
content-free help reference. Background reads preserve layout while disabling
actions; restoring a cached page queues a fresh read after older work settles.
Neither lifecycle recovery nor a lost reply automatically repeats a mutation.

## Recovery contract

Progress is a projection of current account, session, billing, device and line
facts. It is not a saved array of completed steps. Persist only bounded public
locators needed to discover authoritative progress: the selected service origin,
pairing identifier and original public key fingerprint. An existing local key
must match that fingerprint before recovery can make a network request.
Credentials, ticket tokens,
consent, private keys and active authority are never restored from a progress
checkpoint. Late observations from replaced accounts, sessions or screens
cannot restore a formerly actionable control.

| Interruption | Recovery |
|---|---|
| Closed page or expired login | Reauthenticate, read current facts, continue at the next valid task |
| Undelivered or expired email verification | Resend or correct address in context; preserve eligible account progress |
| Expired QR | Check the original attempt; continue if approved, otherwise retire it before explicit replacement |
| Unknown approval | Read status without repeating approval; expose help if unavailable; block duplicate pairing |
| Camera denied | Manual pairing on the same trusted service |
| Permission denied or offline phone | Specific local fix, then recheck; do not erase enrollment |
| Changed SIM | Fresh explicit selection and affected line review; retain account/subscription |
| New owner session during a session-bound line ceremony | Explain and repeat only the declaration step; never rebind old consent silently |
| Checkout pending or result unavailable | Bounded automatic reads and an explicit status check/help path; no second purchase |
| Confirmed unsuccessful checkout | Resume the existing valid checkout or reconcile it before replacement |
| Lost app data or device keys | Explain and require a new device pairing; account and plan recovery do not recover hardware keys |

An unavailable dependency eventually produces a useful explanation and support
reference instead of an indefinite spinner. The reference is content-free and
must not expose ticket tokens, personal data, message bodies or credentials.

## Maintenance and acceptance

Each changed surface must cite the requirement IDs it implements. Contract
changes require updating this specification, state/action fixtures and relevant
browser or Android tests together. Required acceptance includes authenticated
cross-screen behavior, responsive rendering, keyboard/large-text operation,
reload/session replacement, unknown outcomes and the current source capabilities.
Static source scans and contract vectors are useful checks, not proof that a
served page, installed Android app, provider or device works end to end.

The implementation ledger must separately record source/tests, browser runtime,
Android emulator/device, disposable database/provider fixtures, live capability
support and deployment acceptance. A green narrow test cannot close the full
journey. The design and recovery examples below remain binding when subsequent
features, integrations or business plans are added.
