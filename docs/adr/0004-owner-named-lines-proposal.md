# ADR 0004: Proposed owner-named lines and not-ready policy

Status: Proposed. The owner-named line and configurable not-ready policy
implementation is unavailable. This proposal requires review before code,
schema promotion, API exposure or operational use.

## Context and selected direction

The product direction is to let an owner activate each eligible SIM as its own
owner-named line and choose queue, ignore or fallback when the selected line
cannot send. Callers address a line label rather than a SIM slot, subscription
identifier or card identifier. This direction does not settle the default mode,
readiness thresholds, fallback authorization or the wire/storage design.

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

## Proposed identity and admission boundary

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

## Proposed mode semantics requiring approval

**Ignore:** propose an explicit not-ready refusal before acceptance, rather than
a silent drop. Define its response and whether a request identity is retained;
do not claim that this mode or its default is implemented or approved.

**Queue:** propose retaining otherwise eligible unsent work on its exact selected
line in the existing queue until readiness or its original expiry. Waiting must
not allocate another attempt, extend expiry or transfer approval. Expiry and
loss of consent, activation, owner/action or line authority must prevent new
execution under the maintained fences. The final design must distinguish
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

## Decisions required before implementation

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
pre-acceptance ignore, original-line queue and expiry, loss of authority, rename
and label reuse, explicit alternative eligibility, suppression on either line,
actual-sender reply/STOP routing, cross-account mismatch and unknown refusal.
Include races and response loss around the existing admission/dispatch boundary,
changed-card and revoked activation, and sealed target/profile mismatch. Preserve
current opt-out, duplicate-attempt and privacy controls rather than weakening them.

Future source changes need their own focused reviewed API/schema/Android/client
contracts and meaningful regressions. Synthetic or emulator results cannot prove
physical card security, carrier delivery or operational readiness. This ADR
proposal changes no runtime behavior and establishes none of those outcomes.
