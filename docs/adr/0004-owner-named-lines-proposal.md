# ADR 0004: Owner-named lines and not-ready policy

Status: Accepted (2026-10-12). The direction and guardrails below are
approved for implementation. Implementation, schema promotion and API
exposure still land through the normal one-behavior-per-PR review path;
acceptance of this ADR is not acceptance of any unreviewed code.

Decision record (2026-10-12): the default not-ready mode is `ignore`
(an explicit refusal that creates no message record and no unknown
outcome); queue and fallback are opt-in per line. A refusal carries a
stable error code and the line label and persists no message body or
recipient identity. A line is not-ready when its phone has been
disconnected for a configurable per-owner period with an approved
default of five minutes. A fallback send is recorded and surfaced as
sent by the line that actually sent it, and an optional per-request
flag forbids fallback for that message (a refusal instead). Suppression
on either the target or the fallback line blocks a fallback send, and
the fallback line must itself be sealed and approved like any active
line.

## Context and selected direction

The product direction is to let an owner activate each eligible SIM as its own
owner-named line and choose queue, ignore or fallback when the selected line
cannot send. Callers address a line label rather than a SIM slot, subscription
identifier or card identifier. The decision record above settles the default
mode, the offline threshold default and fallback authorization; the wire and
storage design remains subject to per-PR implementation review, and the
sections below record the guardrails and API-shape commitments that
implementation must uphold.

Current [sealed line setup](../conversation-sealed-line-setup.md) binds its proof
to one explicitly selected active subscription, a current connection epoch,
independent on-phone approval and durable installation. The current
[card-continuity check](../../android/app/src/main/java/org/zrotext/gateway/SimCardContinuity.kt)
compares the approved device-local card binding; a second SIM does not replace
a missing selected SIM. Its conservative physical-card check does not establish
carrier ownership or an individual eSIM profile's continuity. These existing
checks do not provide owner-named multi-line routing.

The [public device projection regression](../../protocol/v1/tests/test_public_api_v1.py)
excludes SIM identifiers from owner device fields. Existing
[delivery states](../DELIVERY-STATES.md),
[opt-out obligations](../SMS-COMPLIANCE.md) and exact action/line authority remain
prerequisites. The [device pacing proposal](0003-device-pacing-proposal.md) is
separate and unapproved; this document selects no pacing values.

## Identity and admission boundary

An owner-visible label is mutable presentation. It must resolve to an exact,
account-scoped line identity and its current approved binding before admission.
Renaming a label or reusing its text must not change the sender of retained work,
replay or status. The design needs an explicit rule for resolution, label changes
and policy-version changes; a cached label or browser value grants no authority.

Each line must independently satisfy its maintained activation, current device
connection, card continuity and phone approval requirements. Registering or
naming another line cannot transfer those approvals. Runtime readiness must be
an observation with source and freshness, not a promise that a phone or carrier
can send. Missing, stale or contradictory observations cannot invent authority.

Routing must compose with the existing authoritative writer and dispatch
identities, expiry, consent, suppression, quotas and device/account/action
fences. It must not create a second queue, reset an attempt or turn an owner mode
selection into execution permission. All applicable checks still need to hold
at the existing transaction and phone boundaries after waits.

## Mode semantics

Proposed default requiring approval: **a line with no explicit mode selection
refuses when it is not ready** (ignore semantics). Queue and fallback are
per-line opt-ins by the owner; neither is implied by account settings, another
line's selection or inactivity. Until a selection is approved and implemented,
no mode exists and a not-ready line can only refuse.

**Ignore:** propose an explicit not-ready refusal before acceptance, rather than
a silent drop. A refusal happens before acceptance: it creates no message
record, attempt or unknown outcome, and its response names the targeted line
and the readiness reason without telephony identifiers. Define its exact
response and whether a request identity is retained for idempotent re-submission;
do not claim that this mode or its default is implemented or approved.

**Queue:** propose retaining otherwise eligible unsent work on its exact selected
line in the existing queue until readiness or its original expiry. Waiting must
not allocate another attempt, extend expiry or transfer approval. Expiry and
loss of consent, activation, owner/action or line authority must prevent new
execution under the maintained fences. A queued item never converts to another
line on its own; any alternative sender requires the explicit fallback selection
below. Work that reaches its original expiry unsent ends expired without
allocating a new attempt. The final design must distinguish
cancelled/expired unsent work from an attempt that may already have started;
queue expiry cannot erase uncertainty or free liability while execution remains
possible.

**Fallback:** propose only an explicitly owner-named alternative, independently
active and approved, selected while the original dispatch is known not to have
started. Its sender is different. Require current purpose consent and applicable
suppression checks for both the selected and alternative lines, and all limits
on the line/device/account/action that would actually execute. A block on either
line must not be bypassed by choosing the other. These are proposed guardrails
requiring approval, not a shipped route or permission to relax current gates.

A fallback proposal must retain the exact actual sender binding in result/status
and inbound correlation. Replies and STOP must follow the actual sending line's
maintained identity; the selected label alone cannot attribute them. Review must
settle whether and how the related original-line workflow is also suppressed.
There is no same-number guarantee and no claim that a recipient consented to a
different sender merely because the owner selected it.

Proposed guardrail requiring explicit review: **never dispatch through an
alternate line after an unknown or possibly started outcome.** An observation
that a phone is offline is not evidence that its earlier attempt never began.
Preserve the original request/attempt identity and existing unknown reconciliation
rules; no automatic resend, identity replacement or success inferred from silence.

The dormant [sealed dispatch contract](../../protocol/v1/sealed-dispatch.md)
requires exact line-bound authority; its candidate outbound verifier compares
the protected line identity with the independently selected authority context.
Its cryptographic profile and live execution gates remain separate. This
proposal supplies no automatic ciphertext reroute, rewrap, decrypt or
plaintext fallback. Any future alternate-line sealed request needs separately
reviewed client-local preparation and exact authority for that sender; whether
such a flow is supported is an open decision.

## Readiness taxonomy

Each case below is proposed to classify a line as not ready. The observation
that establishes it must be authenticated and freshness-bound; a missing, stale
or contradictory observation must not be read as readiness, and none of these
observations grants or transfers authority. In every case the selected mode
decides the result: ignore refuses before acceptance, queue holds on the exact
selected line until readiness or original expiry, and fallback still requires
the explicit owner-named alternative under its own guardrails.

| Case | Establishing observation | Proposed result | Clears when |
|---|---|---|---|
| Inactive | line activation record shows the line is not active | not ready | owner activates the line |
| Revoked | activation or owner revocation record | not ready | fresh owner activation |
| Continuity check pending | card-continuity proof not currently satisfied for the approved binding | not ready | continuity check passes again |
| Changed card | approved device-local card binding no longer matches the observed card | not ready | owner re-approves activation |
| Phone offline | no current authenticated device-connection observation, stale beyond a threshold | not ready | fresh connection observation |

The offline threshold — how long a missing connection observation keeps a line
classified not ready — is deliberately not selected here and requires an
explicit decision. A line that becomes ready again does not resurrect authority
that expired, was revoked or was withdrawn while it was not ready.

## Public API shape commitments

Submit requests carry an optional line label; when it is absent, the
owner-configured default line is targeted. Labels resolve to immutable line
identity at admission under the identity rules above, so a rename or reuse
cannot redirect retained work. Responses, status and webhook bodies identify
the line by its resolved label only; slot numbers, subscription identifiers and
card identifiers never appear in them. The concrete field names, refusal bodies
and schema changes belong to a future reviewed API change that documents them
in the public OpenAPI document and keeps the existing route-drift and
identifier-exclusion regressions green. This proposal adds no route, field or
schema.

## Implementation questions and per-PR decisions

The headline decisions (default mode, refusal semantics, the offline
threshold default, per-request fallback opt-out, both-line suppression
and fallback-line eligibility) are recorded in the decision record at
the top of this ADR. The questions below are settled in the
implementation PRs that answer them, each with its own review; none of
them reopens the accepted direction.

1. What is the default mode? What exact refusal response and retained-request
   semantics does ignore have? Which mode changes affect only future requests?
2. When are label and policy resolved to immutable line identity/version? What
   happens to retained work after rename, label reuse, default-line change,
   replacement activation or removal? Can a request decline fallback explicitly?
3. Which authenticated observations establish readiness for inactive, revoked,
   continuity-pending, changed-card and offline states? What freshness rules and
   safe queued transitions apply to each? No offline threshold is selected here.
4. What current consent and exact approval authorize a different sender? How are
   both-line suppression, actual-sender replies/STOP, owner visibility and a
   proven-not-started dispatch decision represented without exposing SIM IDs?
5. Is sealed fallback supported at all? If so, what independently reviewed
   client-local re-preparation and exact action/line binding precede it? How is
   unknown work kept outside every alternate dispatch path?
6. What bounded API/storage/lifecycle design, lock order and export/erasure
   behavior support label/policy records and queued work? Reuse current retention
   and quotas where applicable; any new bounds need a separate explicit decision.

## Required future regression and rollout evidence

Before implementation acceptance, test each reviewed readiness/mode combination:
pre-acceptance ignore including the refusal for a line with no mode selection,
original-line queue and expiry, loss of authority, rename
and label reuse, explicit alternative eligibility, suppression on either line,
actual-sender reply/STOP routing, cross-account mismatch and unknown refusal.
Include races and response loss around the existing admission/dispatch boundary,
changed-card and revoked activation, and sealed target/profile mismatch. Preserve
current opt-out, duplicate-attempt and privacy controls rather than weakening them.

Future source changes need their own focused reviewed API/schema/Android/client
contracts and meaningful regressions. Synthetic or emulator results cannot prove
physical card security, carrier delivery or operational readiness. This ADR
proposal changes no runtime behavior and establishes none of those outcomes.
