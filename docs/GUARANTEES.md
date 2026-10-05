# Current delivery guarantees and their limits

ZROtext is in active development and remains a restricted pilot. A hosted SMS
service and general sending are unavailable. The controls below exist in the
source; their regression tests describe what is checked, rather than proving a
particular deployment, physical phone or carrier. See the [project
status](../README.md#project-status) and [current limits](SMS-COMPLIANCE.md).

## Delivery states require evidence

`submitted` means the phone reported a successful sent callback. It does not
mean the recipient received the message. `delivered` requires successful
delivery callbacks for all required segments. If a delivery receipt is absent,
the displayed result becomes `delivery_unknown` while preserving the submission
fact. The [delivery state model](DELIVERY-STATES.md) and [message
semantics](ARCHITECTURE.md#message-semantics-and-the-duplicate-send-problem)
describe these distinctions; the [domain state machine and its
tests](../crates/domain/src/lib.rs) include `submitted_is_not_delivered`.

## Ambiguous submission is not retry permission

A crash, timeout or conflicting callback can leave a radio attempt `unknown`.
That outcome does not authorize an automatic resend or a replacement grant on
another phone. Late evidence can reconcile the original attempt; proven
no-submit evidence can allow work to return to the queue. Keep the original
message identity when checking its outcome instead of creating another message
to resolve uncertainty.

The [domain tests](../crates/domain/src/lib.rs) include
`ambiguous_submit_is_unknown_and_cannot_be_regranted` and
`callback_after_unknown_reconciles_without_retry`. The [PostgreSQL delivery
tests](../crates/delivery-store/src/tests.rs) include
`postgres_fences_unknown_and_tenant_idempotency`. These controls reduce duplicate
send risk; they do not provide exactly-once SMS. A manual resend with a new
message identity can produce a duplicate.

## Idempotency is scoped and retained for a limited time

For an account, a retained idempotency key identifies the same canonical request
and message. Repeating that request returns its existing identity; using the
key with different request content conflicts. The same key in another account
is independent. A new key or message identity is not a retry of the original
request.

The [architecture](ARCHITECTURE.md#schema-boundaries) documents account/key uniqueness,
request digests and configurable retention, with a default of seven days.
This is not permanent deduplication or a carrier guarantee. The
`idempotency_is_global_per_account_and_rejects_changed_body` [domain
test](../crates/domain/src/lib.rs) and the [delivery-store
tests](../crates/delivery-store/src/tests.rs) cover these source-level rules.
The [send-first-message examples](SEND-FIRST-MESSAGE.md) use the restricted
synthetic-alpha plane; they do not expose general sending.

## One authoritative writer, with explicit fences

The server checks writer status, deployment epoch and enabled site, and binds
device sessions to a site, instance, connection epoch and unexpired lease.
Stale sessions cannot renew their ownership simply because another hub is
unreachable. The [device-session implementation](../crates/server/src/device_socket/mod.rs)
and [writer/session tests](../crates/server/src/device_socket/tests.rs), including
`writer_claim_replay_epoch_and_revocation`, implement these checks. The
[writer-promotion guide](WRITER-PROMOTION.md#the-fences-as-they-exist-in-the-code)
explains their scope.

The two-location architecture is a design with implemented fencing components,
not verified real-site failover. The Compose rehearsal uses one database writer,
has no replication and keeps dispatch disabled. It cannot prove resilience
between independent locations. Automatic failover still needs independent
observation authority, physical fencing and real-site acceptance; the optional
observation transport is default-off. See [two-location operation](MULTI-LOCATION.md)
and the [manual promotion rehearsal](WRITER-PROMOTION.md).

These source controls do not establish complete onboarding, hosted operation,
physical-device custody, carrier delivery or production availability. The
[roadmap](ROADMAP.md) keeps those remaining gates separate.
