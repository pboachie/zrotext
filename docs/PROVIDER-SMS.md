# Dormant provider SMS contract

`crates/server/src/provider_sms` is a pure candidate contract and Telnyx SMS-v2
outbound-receipt verifier. It has no HTTP route, network sender, database access,
provider account operations or runtime caller. Provider roadmap items remain
open. This module does not enable another delivery route.

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
no durable key ledger. It retains no plaintext body. `ProviderPlaintext` is an
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
not durable or restart-safe deduplication. Different status events for the same
message remain distinct. Late or conflicting evidence cannot erase `Delivered`.

## Gates before any live route

A separate implementation and review must supply durable admission/idempotency,
submission intent, receipt tombstones, secure early-callback correlation,
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
