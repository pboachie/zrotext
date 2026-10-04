# Dormant provider SMS contract

`crates/server/src/provider_sms` is a pure candidate contract and Telnyx SMS-v2
outbound-receipt verifier, with dormant known-correlation receipt persistence.
It has no provider HTTP route, network sender, provider account operations or
production receipt caller. Provider roadmap items remain open. This module does
not enable another delivery route.

The [explicit transport proposal](../protocol/v1/provider-transport-proposal.md)
settles the future route, authorized-reader, durable-intent, correlation and
suppression contract from #643. It adds no runtime caller or provider traffic.

## Existing delivery semantics

The attempt wrapper uses `zrotext_domain::MessageState` and its existing
transitions. An HTTP success records provider acceptance separately; it does
not establish carrier submission. A verified carrier receipt may establish
`Submitted`, and a downstream delivery receipt may establish `Delivered`.
`delivery_unconfirmed` preserves submission as `DeliveryUnknown`; it is different
from an unresolved submission (`Unknown`). A negative delivery receipt is a
separate sticky fact because the existing state enum has no carrier-delivery
failure variant. It must be displayed alongside the submission state by any
future consumer. Conflicting delivery evidence is rejected without replacing
already recorded facts.

A response lost after possible transmission leaves `Unknown`. There is no
retry, route replacement, `ProvenNoSubmit` or generic caller-selected evidence
operation in the provider wrapper. An explicit manual resend would be a new
message outside this module, with a duplicate-risk acknowledgement. An unknown
phone attempt must never fall back to this route.

## Route and request identity

The only current route variant is Telnyx SMS-v2 with an explicit account,
provider organization, messaging profile, fixed sender and configuration
revision. Its endpoint is the documented SMS-v2 API; no arbitrary URL, number
pool, alternate region, MMS or alpha-sender selection is supported. The sender
and recipient must be numeric international-format identities. This syntax
check is not proof of ownership, registration, permitted country or capacity.

The request digest binds this route, recipient and content digest. A future
writer must store it with the existing account-scoped admission idempotency
key and reject changed requests. The module only compares identities; it has
no admission key ledger. It retains no plaintext body. `ProviderPlaintext` is an
explicit disclosure choice, not a classifier that can identify arbitrary
ciphertext disguised as text. `SealedPhoneEnvelope` is rejected, and no phone
envelope decoder or decryptor is called.

`AdmissionSnapshot` is a trusted-caller model input. Its account, revision,
writer flag, suppression and short validity window are checked before the
single submission transition. Those values are not authorization proofs and
cannot close a database or network race. Only a future authoritative writer
transaction can serialize admission, recheck shared suppression and budgets,
record a durable submission intent, and apply the current writer/session fence.
Never construct this snapshot from an HTTP request or a webhook.

## Authenticated callback boundary

The verifier follows the provider's [messaging webhook contract](https://developers.telnyx.com/docs/messaging/messages/receiving-webhooks)
and [raw-body validation guidance](https://developers.telnyx.com/docs/development/api-fundamentals/webhooks/receiving-webhooks).
It verifies Ed25519 over the original timestamp and body bytes, before parsing.
The independently configured key must belong to the expected route. The caller
must supply a trustworthy current clock and a bounded key-rotation policy.
The body is limited to 32 KiB; timestamp skew is limited to five minutes in
either direction. Duplicate known fields, non-SMS/non-outbound payloads,
multiple recipients and mismatched organization/profile/sender/recipient are
rejected. Unknown fields are ignored and unknown terminal status values do not
invent successful delivery or safe-to-retry failure. No sensitive payload is
included in errors or Debug output.

Verified event identity and provider message identity are separate. Only a
known provider message ID can affect an attempt. A receipt preceding durable
response correlation is returned as `AwaitingCorrelation`; no recipient/body/time
heuristic links it automatically. The model deduplicates up to 64 semantic event
identities per attempt, ignores transport retry metadata and fails closed at
capacity without evicting replay identities. This is bounded in-memory behavior,
not durable or restart-safe deduplication by itself. The dormant ledger below
persists these same semantics. Different status events for the same message
remain distinct. Late or conflicting evidence cannot erase `Delivered`.

Telnyx [message redaction](https://developers.telnyx.com/docs/messaging/messages/message-redaction)
requires organization allowlisting; a profile update can be silently ignored
without it. Enabled redaction masks the destination in finalized webhooks.
This verifier requires the full recipient identity and therefore refuses those
callbacks even with a valid signature. Supporting masked callbacks needs a
separate reviewed correlation contract; removing recipient validation is not
supported. Provider read-time redaction is not storage deletion and does not
establish this application's provider erasure or retention policy.

## Dormant durable known-correlation ledger

`provider_sms::receipts` can apply a verified receipt only to an existing exact
account/route/request/provider-message correlation from a future trusted
committed intent. There is no production correlation creator, elected-writer
permit issuer, webhook, sender or configuration switch. The opaque permit has
private fields and no public constructor, default or deserializer; only test
builds contain a synthetic factory. Site and epoch checks supplement writer
authority and cannot elect a writer by themselves.

The [storage proposal](../protocol/v1/provider-receipt-storage-proposal.sql) is
**not auto-installed** by migrations. Without both proposal tables, receipt
operations are unavailable; partial installation fails closed. Its future
numbered promotion is coordinated separately after preceding migrations land.
PostgreSQL tests explicitly install the unnumbered proposal in their own unique
disposable schema. Their seeded correlations represent future authoritative
intent, not an API available to callers.

One transaction locks writer authority, the account and attempt, rehydrates the
existing `Attempt` reducer, and commits event digest, fact and state together.
It stores at most 64 exact events without eviction. Exact duplicates remain
no-ops at capacity or the maximum version; new evidence requires checked
version advancement. Conflicting evidence changes nothing. No body, recipient,
sender, signature or callback JSON is stored. Correlation and semantic hashes
are private linkage metadata rather than anonymous data.

Disabling an extant account prevents future admission but does not reject valid
metadata for an already irreversible known intent. Recording that evidence
cannot restore account access, dispatch or suppression. Erasure clears all
correlation, outcome and event metadata, retaining only an opaque attempt
identity fence for the account's lifetime. A replay cannot recreate the erased
attempt. At the maximum version, erasure retains that version as the monotone
fence; this exception permits only irreversible reduction, never new evidence
or resurrection. Full owner erasure removes that fence with the account; real
account locks serialize concurrent receipt writes. The owner export adds bounded
metadata pages, omits erased attempts and excludes external IDs and digests.
Absent proposal tables produce an empty page under the same final owner fence.

This slice does not provide atomic admission/usage/submission intent, early
callback quarantine, provider transport, suppression intake or delivery proof.
Issue #760 remains open until those dependencies and activation gates pass.

## Gates before any live route

A separate implementation and review must supply durable admission/idempotency,
submission intent, production receipt integration, secure early-callback correlation,
transactional writer/account/session fences, and account-scoped shared
suppression rechecks. Provider/carrier STOP handling stays enabled. Authenticated
inbound suppression integration, stale START ordering and operator blocks are
not implemented here; outbound receipts cannot alter suppression.

Endpoint-specific send-idempotency guarantees remain unverified. Do not infer
them from callback event IDs or another product's API. A future HTTP client must
have explicit timeout and retry policy and never automatically repeat an
ambiguous send. Provider access to plaintext, retention/export/deletion,
credential revocation, account budgets, registration and country eligibility
also require approval and verification before activation.

Tests use synthetic data, newly generated fixture keys and a public signature
vector produced independently with Node.js `node:crypto`. Cargo discovers the
sibling test module in the existing workspace CI job. No account, external send,
carrier delivery, device or deployed callback endpoint has been exercised.
