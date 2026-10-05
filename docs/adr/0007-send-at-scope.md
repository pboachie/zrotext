# ADR 0007: Scoping a plain `send_at` request field

Status: proposed and unapproved. This document selects no scope, field, route,
approval model or runtime behavior, and it enables nothing. A `send_at` field
does not exist anywhere in the public tree today; the immediate send route
accepts only an `expires_at_ms` deadline. Implementation would require a
separate reviewed issue.

## Question

A plain request field that asks the gateway to transmit one message at a later
time (`send_at`) has been raised as a candidate addition to the send API. The
roadmap already tracks [Templates and scheduled follow-ups](../roadmap.json)
(id `scheduling`, stage build, depending on `contacts` and `approvals`). This
ADR decides whether such a field is covered by that capability, needs its own
roadmap item, or is out of scope, and records the semantics any later
implementation must carry.

## What the scheduling capability covers today

The `scheduling` capability's committed evidence is approval-first: bounded
preview and segment libraries, immutable client-encrypted template versions,
and "recipient-local timing, explicit expiry, pacing and default-off durable
schedule execution through shared workflow authority"
([roadmap](../ROADMAP.md)). Its exact-action contract binds `not_before` and
`expires_at` to every approved action
([workflow action contract](../../protocol/v1/workflow-action-contract.md)),
requires a fresh owner confirmation per occurrence
([encrypted scheduling](../encrypted-scheduling.md)), re-verifies current
authority at dispatch, and treats a change to timing as a new approval. The
dormant scheduling library is explicitly "not an activated scheduling
service". Nothing in this scope is a caller-chosen timestamp on an ordinary
API send.

## What the immediate send path does today

The allowlisted synthetic route `POST /v1/alpha/messages`
([router](../../crates/server/src/main.rs),
[handlers](../../crates/server/src/http_messages/mod.rs)) requires
`expires_at_ms` and treats it as a deadline, not a send time:

- Admission rejects an elapsed deadline and caps the alpha horizon 15 minutes
  ahead (`MAX_ALPHA_EXPIRY_MS`,
  [delivery store](../../crates/delivery-store/src/lib.rs)); the queued
  message is stored as `queued` with that `expires_at`.
- Suppression and owner holds are checked before the idempotency lookup at
  acceptance, and again under lock when a grant is issued, where a hit cancels
  the pre-grant work.
- Durable idempotency keys retain a request digest that includes
  `expires_at_ms`; a changed request under one key conflicts. Keys are kept
  7 days by default (deployment-configurable) and an exact replay returns
  the original result even after the message has expired.
- A periodic sweep marks ungranted queued or claimed work past its deadline
  as terminal `expired` and refunds its usage reservation. The delivery state
  model reaches `expired` only from accepted, queued or claimed — never after
  a submit intent exists — and an ambiguous radio submission becomes
  `unknown`, never retried automatically
  ([delivery states](../DELIVERY-STATES.md)).
- A grant is refused outright for an expired message, the grant fence carries
  a bounded TTL (a sealed caller may pass a tighter explicit deadline), and
  the post-grant confirmation re-checks that both the message and the fence
  are still unexpired before any frame is emitted.

When the separately opted-in workflow runtime is mounted, a scheduler worker
advances occurrence expiry during owner review and while waiting for a
window, renderer or phone, and never extends a deadline because a component
is absent. In a default deployment no worker runs; the library remains a
dormant candidate
([worker](../../crates/server/src/encrypted_schedule/worker.rs),
[store](../../crates/server/src/encrypted_schedule/store.rs)).

## Semantics any `send_at` field must carry

**Maximum horizon.** Today's only caller-settable timing bound is the
15-minute deadline cap. A `send_at` horizon must be an explicitly selected
ceiling, and it interacts with admission budgets: pending counts cover
unexpired queued work, so a caller could otherwise pin a device's entire
admission budget for the length of the horizon. The scheduling policy
identity's own bounds (pacing up to 86,400 seconds per occurrence) suggest a
horizon measured in days at most, but no number is selected here.

**Offline at the due time: expire, never send late.** A message whose due
time passes while the phone cannot take a grant must end as terminal
`expired`, like any deadline that lapses pre-grant. The state model already
forbids silent late behavior: expiry applies only before a submit intent
exists, ambiguous radio outcomes stay `unknown`, and dispatch never extends a
deadline because the phone is absent. A scheduled send that arrives long after
its useful time would contradict the roadmap's own acceptance language that
reminders "expire instead of arriving after their useful time" and that an
offline phone does not send expired invitations.

**Owner approval interaction.** Two authority models exist. The immediate
route authorizes a scoped API key bound to one device at submission; there is
no per-message owner confirmation, and a delayed radio effect would inherit
that submit-time authorization. The scheduling capability instead binds every
occurrence to an exact approved action, requires a fresh owner decision per
occurrence, and requires new confirmation when timing changes. A `send_at`
field on the immediate route must decide which model it uses before its shape
can be settled: whether submit-time API-key authorization extends to a future
radio effect, or whether scheduled sends may only enter through the
exact-action approval flow.

**Opt-out checked at send time, not submit time.** The acceptance check
answers whether work may be queued; the grant-time check under lock answers
whether it may be sent now. Any `send_at` semantics must state explicitly
that the dispatch-time recheck is load-bearing: a recipient who opts out, or
falls under an owner hold, between submission and the due time never receives
the message. The existing pre-grant cancel path and hold-cancels-queued-sends
behavior already express this pattern.

**Idempotency across the delayed dispatch.** The request digest must cover
`send_at`, so the same key with a changed time conflicts instead of silently
rescheduling. The idempotency retention window must cover or be explicitly
reconciled against the chosen horizon. The due-time dispatch must reuse the
accepted message's stable identity rather than mint a second message or
attempt, matching the existing rule that a request replay preserves its
dispatch identity and that an unknown outcome never becomes a new effect.

## Recommendation

`send_at` is **not covered** by the existing `scheduling` roadmap item, and it
is **not out of scope**; it should be tracked as its own roadmap item — a
separate capability entry, naturally within the same track — staged after the
scheduling capability completes its open acceptance work.

The scheduling item's committed scope and evidence chain are approval-first —
recipient-local windows, per-occurrence exact-action approval, shared
decision-service permits, default-off durable execution — and its open items
are about completing that model through actual consumers, owner journeys and
controlled-device acceptance, not about adding a caller-timestamped API field.
Conversely, the machinery a bounded `send_at` needs — terminal expiry
semantics, dispatch-time suppression rechecks, durable idempotency, a dormant
durable scheduler — already exists as restricted-pilot foundations, so the
field is architecturally compatible and does not belong in a discard pile.
A separate item lets it select its horizon, approval model, budget interaction
and acceptance evidence on their own merits, behind the same general-send
gates as every other send path.
