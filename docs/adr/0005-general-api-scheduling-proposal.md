# ADR: General API scheduling and approved workflow schedules

Status: Proposed

## Scope

A future general `send_at` API needs separately reviewed API and admission work
within the broader [scheduling roadmap](../PRODUCT-PLAN.md). Track a general
`send_at` API as a separate implementation issue under the existing scheduling
roadmap item; it does not need a new roadmap category. The existing
recipient-local workflow scheduler supplies useful foundations, but does not
make a due-time field available on the current message submission API. This
proposal changes no runtime behavior, authorization, setting or roadmap stage.

## Current boundaries

The [synthetic-alpha message API](../../crates/server/src/http_messages/mod.rs)
accepts a closed request containing message and device identities, an allowlisted
recipient, a short test-case identifier and `expires_at_ms`. The server creates
the fixed synthetic body. Unknown fields are rejected, including `send_at`.
The [public request schema](../../protocol/v1/openapi/public-v1.json) describes
that same boundary. An expiry deadline limits eligibility; it does not specify
a future dispatch time or authorize arbitrary message content.

[Delivery admission](../../crates/delivery-store/src/lib.rs) binds expiry into
the request digest and preserves retained replay identity. Its current alpha
expiry ceiling is fifteen minutes. That existing test-mode limit is not a
proposed horizon for general scheduling. Admission and the final grant check
also enforce current recipient suppression and owner holds. Alpha API-key
scope and the phone's local approval are distinct from exact-action workflow
approval; neither supplies a new general scheduling authority.

The [encrypted scheduler](../encrypted-scheduling.md) binds recipient-local
windows, content, purpose and timing to exact approved actions. Every recurrence
needs its own exact approved action. Missing or ambiguous timing waits for
review and still expires. The existing
[metadata worker](../../crates/server/src/encrypted_schedule/worker.rs) projects
expiry, withdrawal and existing message outcomes; it does not manufacture an
actor, renderer call or new send. Unattended effect admission remains a separate
reviewed capability. These foundations do not establish a complete ordinary
owner scheduling journey or an enabled general API dispatcher.

## Proposed design boundaries

Any future due-time must be part of the immutable request and, where required,
the exact approved action. Changing timing must not reuse an existing identity
to authorize a different effect. An identical retained replay preserves the
original identity and timing; an unknown submission result requires identical
reconciliation rather than a new scheduling request or automatic resend.

An offline phone must not renew expiry or revive expired work. Missed due times
before expiry require an explicit product decision; this proposal selects no
grace period or universal late-send behavior. Queueing cannot promise carrier
submission or delivery at the requested instant. Existing grant-winning or
unknown outcomes must remain honestly uncertain rather than being described
as prevented by a later cancellation.

Future dispatch must check current applicable consent, suppression, revocation
and approval boundaries at effect admission, including after blocking work.
Submit-time checks alone cannot preserve those conditions until a later send.
Stored owner or actor identifiers must not manufacture current credentials.
An API timestamp must not bypass the encrypted scheduler's authority fences.

## Decisions before implementation

Review the timestamp representation and timezone semantics, maximum horizon,
due-before-expiry rules, missed-due and offline outcomes, and whether changed
timing requires fresh owner review. Agree the caller's existing authority and
any required noninteractive capability, then review the admission, cancellation,
reconciliation and lifecycle composition. No new numeric default, approval
power, worker, queue, schema or activation is selected here.

## Future verification

Implementation needs controls for changed timing under the same idempotency
key, identical replay preserving the original identity, unknown responses and
restart without duplicate effects, concurrent claimants, expiry before dispatch,
and cancellation or consent withdrawal after scheduling. Test current-session
and approval loss after waits, offline and missed-due outcomes, and timezone
gaps or overlaps when local-time scheduling is supported. Preserve independent
positive controls and final authority checks. These are proposed tests, not
executed acceptance or physical-device and carrier evidence.
