# Provider route research

The generic [explicit transport proposal](../protocol/v1/provider-transport-proposal.md)
now records a proposed first adapter and per-action route decision for #643.
The research below remains historical inputs, not current provider eligibility,
account selection, capacity evidence or runtime activation.

**Research and evaluation only. This document selects nothing, changes no runtime
behavior, and does not make any capacity, coverage or availability claim.** It
records what public provider and regulator documentation says about adding a
non-phone outbound SMS route, so a later "explicit route selection" roadmap item
can start from verified facts. It was compiled on 2026-09-28 from the public
sources listed at the end; provider policies change frequently and every fact
here can be stale by the time it is read. No provider account was opened and no
test traffic was sent.

## Why this research exists

Today the only outbound path is the Android gateway phone: an allowlisted
synthetic pilot accepts a message, the delivery store records admission, the
device socket leases the job to one enrolled phone, and that phone's SIM sends
it ([architecture](ARCHITECTURE.md#message-semantics-and-the-duplicate-send-problem)).
The [roadmap](ROADMAP.md) keeps "provider-based high-volume sending" as a
planned capability, and the [product plan](PRODUCT-PLAN.md#managed-ai-and-larger-campaigns)
requires any provider route to document "supported countries, sender
eligibility, number ownership/portability, registration needs, cost units and
measured throughput for the chosen route" before capacity is promised. This
page gathers the public inputs for that evaluation. It deliberately describes
cost **models** (per-message usage, monthly number leases, one-time setup,
registration fees) and never prices.

## The option space

### Option A: keep the gateway phone as the only route (status quo)

One Android phone and SIM per line, carrier retail terms, two-way by default.
The SIM's number is the public sender identity, so recipients can reply and
opt out by text. Capacity is bounded by one radio operation at a time and by
whatever the carrier's plan tolerates; the [compliance guide](SMS-COMPLIANCE.md)
already warns that a consumer plan may restrict automated traffic. No new
trust boundary, no plaintext disclosure beyond the carrier, no registration
regime beyond the carrier's own terms. Architecture cost: none.

### Option B: cloud messaging APIs (CPaaS / aggregator HTTP APIs)

Twilio, Vonage, Telnyx and AWS End User Messaging SMS are the providers whose
public documentation was surveyed (others, such as Infobip, Sinch and Bird,
exist; their details were not verified here). The server would call an HTTPS
API, the provider delivers through its carrier connections, and delivery
receipts arrive as authenticated webhooks. This is the model the dormant
`crates/server/src/provider_sms` contract anticipates
([dormant contract](PROVIDER-SMS.md)); that module has no HTTP sender, route or
runtime caller today.

### Option C: direct carrier or SMPP interconnect relationships

Enterprise aggregator contracts (host-to-host SMPP or equivalent) with mobile
operators or large aggregators. These are negotiated, contract-bound
relationships rather than self-service APIs. Public documentation is thin by
nature; nothing about current availability, lead times or minimum volumes
could be verified from public sources. Listed for completeness, not evaluated.

### Option D: hybrid, phone plus provider

Keep the phone route for conversational and two-way traffic (receptionist,
personal assistant) and add a provider route for owner-approved larger sends.
The existing safety rule constrains this option the most: an ambiguous phone
submission becomes `unknown` and is never retried automatically or failed over
to another phone; the product plan extends the same rule to providers ("an
unknown phone submission must not be resent through a provider automatically").
Route choice would have to be an explicit, recorded decision per message made
before dispatch, never a mid-flight fallback.

## Sender identity models and where they work

Public provider documentation consistently splits origination identities into
five models. The country-by-country details below come from Twilio's and AWS's
published tables (see sources); where they disagree, both statements are
reported.

| Model | Properties (from provider docs) |
|---|---|
| Shared pool | Provider delivers from a number it shares across customers. AWS: shared identities exist "in some countries" but are "unavailable in some countries, including the United States and China", unregistered sender-ID countries may show generic IDs such as "NOTICE", and "carriers can, with little or no warning, decide to disallow messages sent from shared origination identities"; AWS's guidance is that "dedicated origination identities are always preferred to shared ones". |
| Dedicated long number (virtual mobile number) | Country-specific numeric identity, supports two-way SMS and consistent sender identity; AWS notes long codes have low throughput (about one message per second in the US/Canada) and may be flagged when several hundred messages per day are sent. |
| Alphanumeric sender ID | Brand-name identity (typically up to 11 characters), one-way only: AWS states "Sender IDs do not support two-way SMS messaging", so replies and STOP-by-text need a separate inbound-capable identity. Support and registration vary sharply by country (below). |
| Toll-free number (US) | Numeric, voice plus SMS; AWS: "US mobile carriers require that you register your toll-free number before live messaging will be enabled"; Twilio likewise requires completing toll-free verification for US/Canada SMS. |
| Short code | Carrier-approved dedicated multi-digit code, highest throughput, two-way capable; AWS: carrier approval means short codes "are less likely to be flagged as unsolicited", activation "can take 8-12 weeks" for all carrier networks, and acquisition carries a one-time setup fee plus recurring monthly charges (model, not price). |

Country highlights verified on 2026-09-28 (Twilio international alphanumeric
sender ID table; AWS country capabilities table):

- **United States and Canada: no alphanumeric sender IDs.** AWS: "Several
  major markets (including Canada, China, and the United States) don't support
  sender ID." US identity options are 10DLC numbers, toll-free numbers and
  short codes.
- **United Kingdom: alphanumeric supported; registration differs by
  provider.** Twilio lists the UK as dynamic (no registration); AWS requires
  UK sender ID registration. This is a concrete example of provider-specific
  process on top of country capability.
- **Ireland: regulator registry.** ComReg: "Organisations using SMS Sender IDs
  in their SMS text messages to mobile phone users in Ireland must register";
  since 3 July 2025 unregistered IDs are modified to "Likely Scam", with
  blocking deferred from its planned 3 October 2025 date while technical
  issues are resolved.
- **Singapore: regulator registry.** IMDA's SMS Sender ID Registry; AWS
  documents that unregistered sender IDs are changed to "LIKELY-SCAM" "per
  regulatory agency rules".
- **Continental Europe (examples):** Twilio lists Germany as dynamic
  alphanumeric; Austria, France and Spain require registration. AWS marks
  France alphanumeric-only characters (no dash) as of 1 March 2026, an example
  of per-country syntax rules changing.
- **India: registration with extra steps.** Both providers mark India sender
  IDs as registration-required; AWS describes India DLT registration of
  company and use case, with unregistered international (ILDO) routes as the
  alternative and local DLT routes only available from in-country regions.
- **Two-way SMS requires a dedicated numeric identity** (AWS: dedicated short
  code or long code); some countries offer inbound-only long codes precisely
  so recipients can opt out of sender-ID traffic (the AWS country table marks
  long codes in India, Pakistan, the Philippines, Saudi Arabia and the UAE as
  inbound-only).

**Number ownership and the SIM question.** A provider route cannot inherit the
gateway SIM's number by default; the product plan already warns "do not imply
every provider can send from an existing SIM number". The closest public
option, Twilio's Hosted Numbers, states "Hosted Number supports US and Canada
numbers" and "Mobile numbers are not supported" — it exists for landline and
toll-free numbers, not SIMs. The other option is porting a number to the
provider; number portability moves service to the provider, which would end
the SIM's use of that number (general portability behavior, not verified for
any specific carrier). Making the gateway number the identity of a provider
route is therefore not a supported path in any documentation surveyed; the
provider route would bring its own identity.

## Regulatory constraints by route and region

This is a survey of the registration regimes a provider route would inherit,
not legal advice. Consent, opt-out and identification duties apply regardless
of route and are already covered by the [compliance guide](SMS-COMPLIANCE.md),
which links the FCC (US robotexts), the UK ICO (PECR marketing texts) and the
CRTC (CASL).

- **US A2P 10DLC registration.** Twilio: 10DLC is the US-carrier-run standard
  for application-to-person long-code traffic; senders register a **brand**
  ("information about who is sending these messages") and a **campaign** (the
  purpose and opt-in/opt-out handling), and "anyone sending SMS/MMS messages
  over a 10DLC number from an application to the US must register", including
  individuals; brand types include Sole Proprietor, Low-Volume Standard and
  Standard. AWS confirms: "in the United States, local long codes cannot be
  used for A2P SMS messages" without a registered 10DLC, brand and campaign
  registration, roughly 7-10 days approval, and each 10DLC bound to one
  campaign. Unregistered traffic is blocked outright, not merely surcharged
  or filtered: Twilio announced that "all SMS and MMS messages sent to US
  phone numbers from unregistered 10DLC phone numbers will be fully blocked
  effective September 1st, 2023", and blocked attempts fail with Twilio error
  30034, which states Twilio "blocks messages to U.S. numbers" sent from a
  10DLC number without an approved campaign. The registration hub is The
  Campaign Registry; brands "must work with one of the registered messaging
  service providers (CSP)" — for ZROtext's hosted case that CSP would be the
  chosen provider, or ZROtext itself if it became one.
- **US toll-free verification.** AWS: "US mobile carriers require that you
  register your toll-free number before live messaging will be enabled."
  Twilio's send-SMS tutorial states the same requirement for US/Canada.
- **US short codes.** Carrier approval required before activation (AWS);
  setup plus recurring charges (AWS). The administration and monitoring bodies
  behind US/Canadian short codes were not verified here.
- **US consent law beyond registration.** TCPA/FCC consent and revocation
  rules continue to move: law-firm analyses report that the FCC's "one-to-one
  consent" rule was vacated by the Eleventh Circuit on 2025-01-24 before
  taking effect, and that revocation-handling rules (honor STOP-class
  revocations within ten business days) took effect in April 2025. These two
  items are from secondary sources and were not verified against primary
  records; treat as indicative of volatility, not as a statement of current
  law.
- **Regulator sender-ID registries (Ireland, Singapore).** Described above:
  registration is mandatory, and the penalty is on-display labeling
  ("Likely Scam" / "LIKELY-SCAM") now and blocking later. These are dated,
  documented regime changes — the strongest public evidence that sender
  eligibility can change under an account mid-life.
- **European Union / UK marketing rules.** PECR (UK) and national ePrivacy
  implementations require consent for marketing electronic messages (already
  linked in the compliance guide); GDPR applies to the personal data a
  provider route processes (recipients, message bodies, delivery metadata) and
  to the provider's role as a processor. Provider-specific alphanumeric
  registration (Germany dynamic; France, Spain, Austria registered per
  Twilio's table) stacks on top.
- **India DLT.** Registration of sender and content templates with the DLT
  ecosystem (AWS describes the company/use-case registration and the ILDO
  alternative).

The recurring pattern across providers: the **route owner** (ZROtext or the
account owner) must complete and maintain registrations per country and per
identity, and providers state that carriers change filtering and registration
rules with little notice. Any capacity or coverage statement ZROtext publishes
would need to be re-verified against the provider's current tables.

## What each option would require from the existing architecture

### Server outbound path (`crates/server`)

- **Option A:** nothing; the phone path already exists and stays the pilot.
- **Option B:** a new outbound adapter beside the device-socket dispatcher:
  an HTTP client with explicit timeout and retry policy that never repeats an
  ambiguous send (a gate the dormant [provider contract](PROVIDER-SMS.md)
  already lists as unverified and required). Admission would flow through the
  same metered, idempotent, budgeted acceptance as phone sends; the existing
  `provider_sms` route identity (provider, organization, profile, sender,
  configuration revision) is the shape a durable route-selection record would
  take, plus the durable admission/idempotency ledger and receipt tombstones
  that module defers to a future writer.
- **Option C:** the same server-side machinery as B, plus long contractual
  integration work outside this repository.
- **Option D:** all of B plus an explicit per-message route-selection record
  written before dispatch, shared suppression rechecked under the account
  lock at acceptance and again at submission, and honest `unknown` handling
  that never crosses routes automatically.

### Inbound and receipts

Phone-route evidence comes from the device stream. A provider route replaces
that with provider webhooks: the dormant Telnyx receipt verifier (Ed25519 over
the raw body, bounded skew, deduplication) shows the intended shape, but
correlation before the durable response exists, stale-event handling and
restart-safe deduplication remain open there. Two-way provider traffic also
needs an inbound webhook path feeding the same suppression machinery as
phone-received STOP replies; one-way alphanumeric identities cannot receive
replies, which changes how opt-out capture works in those countries (the
compliance guide's off-channel holds and review queue become the primary
path, or a dedicated inbound number is added).

### Plaintext and the sealed-content boundary

The phone route keeps content exposure at the carrier. A provider route hands
message plaintext to the provider and its carrier chain. The dormant contract
already treats this as an explicit choice: `ProviderPlaintext` is a disclosure
decision, sealed phone envelopes are rejected, and provider retention/export/
deletion questions are listed as approval gates. Any provider route therefore
interacts directly with the planned sealed-content API: either provider-route
messages are a documented plaintext-disclosure exception chosen per account,
or the route is restricted to traffic whose owners have explicitly accepted
that boundary.

### Credentials and operations

Provider API credentials and webhook verification keys need storage, rotation
and revocation comparable to the existing webhook-signing-secret handling. The
hosted-versus-self-hosted split matters: in the hosted service ZROtext holds
the provider account; a self-hosted deployment would either bring its own
provider credentials or have no provider route. Per-account budgets, per-route
quotas and the two-location writer rules (one authoritative writer; a provider
route adds a second non-database dependency that a hub failover does not
fence) all need design.

### Android gateway role

Options B and C do not remove the phone: conversational, two-way and
sealed-traffic journeys keep using enrolled devices, and the compliance
machinery (line-bound opt-outs, suppression) continues to run there. The
gateway app itself needs no change for a provider route; the dashboard and
owner APIs would need route visibility (which identity a message used, which
registration it depends on) so owners can see what recipients see.

## Capacity: what can and cannot be promised from documentation alone

Provider documentation publishes throughput figures as selection guidance,
not service defaults. AWS's chooser steers roughly 1-3 message parts per
second to toll-free, 10-75 to 10DLC and 100 or more to short codes, while
stating separately that toll-free throughput "average[s] three message parts
per second (MPS)" and that "US short codes support 100 message parts per
second by default", raisable beyond that rate for an additional monthly fee.
All providers qualify delivery as best-effort and country-dependent, and AWS
explicitly warns that its numbers are provisioned "through a single carrier
partner in each region/country", creating a single point of failure it tells
customers to work around. Consistent with the product plan ("publish capacity
only after testing the actual route"), no capacity claim should be derived
from this page; measured throughput per chosen route and country is a
prerequisite for any promise.

## Founder decisions needed

Nothing below is decided here; each item blocks the later route-selection work.

1. **Whether to adopt a provider route at all.** Options: stay phone-only;
   add a provider route for explicitly opted-in accounts only; add it
   generally. The trade is scale and country reach against plaintext
   disclosure to a provider and a new trust boundary that cuts across the
   sealed-content roadmap.
2. **Target regions.** Options: US-first (inherits 10DLC/toll-free
   registration), UK/Europe-first (alphanumeric identities, per-country
   registration, regulator registries in Ireland), multi-region from the
   start, or follow demand. This choice determines the whole registration
   workload.
3. **Sender identity model per region.** Options: dedicated numbers for
   two-way coverage; alphanumeric sender IDs where allowed (one-way, cheaper
   registration model in many countries but no replies); short codes where
   throughput justifies carrier approval and recurring charges. Shared pools
   are hard to reconcile with honest sender identification and appear
   disfavored in provider guidance.
4. **Registration ownership.** Options: ZROtext registers and holds
   brands/campaigns/countries for the hosted service; each account brings its
   own provider account and registrations; both. This sets who is the TCR
   "CSP" relationship owner and who answers regulator registries.
5. **SIM-number identity.** Options: keep the gateway number as the only
   public identity (provider route not used for that line); accept separate
   provider identities per line; investigate porting (which ends SIM use of
   the number, per general portability behavior — unverified for specific
   carriers). No surveyed provider can send from an existing SIM number.
6. **Hybrid routing policy.** If both routes exist: explicit owner-chosen
   route per message only, with `unknown` never auto-failing-over between
   routes — or a stricter single-route-per-account policy. Needs product
   language in the dashboard and API.
7. **Opt-out mechanics on one-way identities.** Where alphanumeric IDs are
   used, options: provide a dedicated inbound number for opt-out; rely on
   off-channel holds plus conspicuous opt-out instructions; avoid one-way
   identities for regulated workflows. The compliance guide's machinery is the
   backstop either way.

## Sources

Verified 2026-09-28 unless noted. Provider pages are living documents.

- Twilio, Programmable Messaging A2P 10DLC:
  https://www.twilio.com/docs/messaging/compliance/a2p-10dlc (page metadata
  dated 2026-07-07; brand/campaign model, mandatory registration, unregistered
  traffic treatment).
- Twilio Help Center, Shutdown of Unregistered 10DLC Messaging:
  https://help.twilio.com/articles/14910496447771-Shutdown-of-Unregistered-10DLC-Messaging-FAQ
  (US-bound SMS/MMS from unregistered 10DLC numbers fully blocked from
  2023-09-01).
- Twilio, error 30034 reference:
  https://www.twilio.com/docs/api/errors/30034 (blocked-message behavior and
  registration remedies for unregistered 10DLC traffic).
- Twilio Help Center, International Support for Alphanumeric Sender ID:
  https://help.twilio.com/articles/223133767-International-support-for-Alphanumeric-Sender-ID
  (country-by-country dynamic/registration-required/not-supported table).
- AWS End User Messaging SMS, supported countries and regions:
  https://docs.aws.amazon.com/sns/latest/dg/sns-supported-regions-countries.html
  (per-country short code/long code/sender ID/two-way matrix; Ireland,
  Singapore, India, UK, France notes).
- AWS End User Messaging SMS, choosing an origination identity:
  https://docs.aws.amazon.com/sms-voice/latest/userguide/phone-number-types.html
  (identity model properties, 10DLC/toll-free registration requirements,
  shared-pool caveats, throughput selection guidance, India ILDO/DLT).
- The Campaign Registry: https://www.campaignregistry.com/ (10DLC registration
  hub; brands register via CSPs).
- ComReg, SMS Sender ID Registry:
  https://www.comreg.ie/industry/electronic-communications/nuisance-communications/sms-sender-id-registry/
  (Irish registration duty, "Likely Scam" from 2025-07-03, blocking deferred
  from 2025-10-03).
- Vonage support, Singapore SMS Features and Restrictions (article series
  example): https://api.support.vonage.com/hc/en-us/articles/204017993-Singapore-SMS-Features-and-Restrictions
- Twilio, Send SMS and MMS messages (toll-free verification requirement;
  snippet-level verification):
  https://www.twilio.com/docs/messaging/tutorials/how-to-send-sms-messages
- Twilio Hosted Numbers FAQ (US/Canada landline and toll-free only; mobile
  numbers not supported): https://www.twilio.com/docs/phone-numbers/hosted-numbers
- Law-firm analyses of Insurance Marketing Coalition v. FCC (Eleventh Circuit,
  2025-01-24, vacating the one-to-one consent rule) and of the April 2025
  TCPA revocation rules (secondary sources; see the unverified list).
- In-repo baselines: [dormant provider contract](PROVIDER-SMS.md),
  [SMS compliance](SMS-COMPLIANCE.md), [architecture](ARCHITECTURE.md),
  [product plan](PRODUCT-PLAN.md).

## Not verified here

- Telnyx's current country and sender-ID tables (its help-center compilation
  was found via search only; no stable URL pinned). The dormant in-repo
  contract targets Telnyx SMS-v2, so Telnyx specifics need a follow-up pass
  before any Telnyx-based selection.
- The exact URL and current text of Vonage's United States "SMS Features and
  Restrictions" article; the series exists, and the US no-alphanumeric fact is
  corroborated by Twilio and AWS, but the Vonage US page itself was not read.
- Infobip, Sinch, Bird (MessageBird), Azure Communication Services and
  regional aggregators: not surveyed.
- Direct-carrier/SMPP option C availability, terms or lead times: no public
  documentation found.
- Primary records for the TCPA one-to-one consent vacatur and the revocation
  rules (court opinion, FCC orders): relied on law-firm summaries.
- IMDA SSIR start date (2023-01-31) and current blocking status: secondary
  sources; the AWS documentation independently confirms the LIKELY-SCAM
  behavior.
- Short-code administration bodies (US CSCA, Canadian CWTA) and current
  processes: only AWS's carrier-approval statements were verified.
- Whether porting a specific mobile number to a specific provider preserves
  any service on the donor SIM in edge cases: general behavior only.
- No provider account, registration, test send, carrier delivery or webhook
  endpoint was exercised; emulator or synthetic evidence does not exist for
  any claim on this page because none is made.
