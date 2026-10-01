# Explicit provider transport (proposal)

Status: **PROPOSED; unavailable**. This settles the design in #643. It is not
a sender, migration, provider enrollment or permission to activate traffic.
The [dormant verifier](../../docs/PROVIDER-SMS.md) remains network-free.
Phone SMS and phone MMS retain their existing authority and gates.

## One recorded route per exact action

An authenticated owner chooses `phone` or `provider` before approving an action.
No default or error chooses the provider. The immutable action revision binds
account, action ID, selected route ID/revision, provider organization/profile,
fixed eligible sender, recipient, purpose, exact content commitment, content
reader identity, timing, expiry and approval/routine authority. A changed field
invalidates approval; use the shared exact-action contract from #635, not a
second provider approval model. An admission idempotency key is account-scoped
and compares the whole commitment, including route. Replays return the original
commitment and do not charge or send twice; changed requests conflict.

The first candidate adapter is the existing Telnyx SMS-v2 route type, with a
fixed numeric sender and organization/profile. Eligibility must be established
from authenticated provider configuration and reviewed country/registration,
consent and purpose policy. Syntax does not establish ownership. A route cannot
inherit a SIM number or portability rights. No arbitrary endpoint, sender pool,
MMS or automatic region switch is part of this contract. Account choices,
credentials, pricing and infrastructure setup remain private operations work.

Provider sending explicitly discloses the approved recipient and body to a
designated authorized content reader and the provider. The owner must approve
that disclosure. Customer-held ciphertext is opened only by that authorized
reader, never implicitly by the relay. Its output is authenticated to the exact
action commitment and delivered over the reviewed transport; keep plaintext
out of storage, receipts, errors and logs. A sealed phone envelope cannot be
converted or forwarded as provider plaintext. Reader failure, missing consent
or unavailable keys refuses the action; there is no plaintext fallback.

## Durable intent and the network uncertainty boundary

Admission stores the commitment and reserves existing usage once. Immediately
before submission, the authoritative writer serializes on the same account,
recipient/purpose suppression and action locks as phone admission. Recheck
current approval/routine grant, membership/session/revocation, writer/site epoch,
route revision/eligibility, expiry, pacing, per-account/per-agent budgets and
limits. Record a unique attempt and durable submit intent before network I/O.
The authenticated reader's output must still match the approved commitment.
Do not let the network sender reconstruct authorization from client fields.

Only the one worker holding the current durable intent/fence may make one
submission attempt. A crash after committing intent but before or during the
network call is conservatively `Unknown`: restart must not claim the request
was never sent. A timeout, connection reset, malformed response or response
loss likewise becomes `Unknown`. Do not repeat the send or change its route.
Provider request-idempotency is unverified and is not assumed. If a future
adapter proves a bounded endpoint-specific guarantee, it needs a separate
reviewed protocol revision; callback IDs do not establish that guarantee.

A trusted response may bind one provider message ID to the exact attempt;
record the binding transactionally before using it. Provider acceptance is a
separate fact, not `Submitted` or `Delivered`. The existing pure verifier and
`Attempt` transitions remain the source of receipt semantics: carrier evidence
may establish `Submitted`, delivery evidence `Delivered`, unconfirmed delivery
`DeliveryUnknown`, and negative delivery a separate sticky fact. Unrecognized
statuses confer no authority or retry permission. `Unknown` phone submission
never fails over to provider. A manual resend requires a new exact action,
fresh authorization and an explicit duplicate-risk acknowledgement.

## Receipts, early correlation and durable replay fences

Verify original bounded raw bytes, timestamp and independently configured
route key with `provider_sms::verify_receipt`. Preserve its size, freshness,
single-recipient and organization/profile/sender/recipient checks. The trusted
route/account is selected from endpoint configuration, never callback fields.
No signature or callback grants send, decryption or suppression authority.

An early callback cannot infer an attempt from recipient/body/time. Quarantine
verified but uncorrelated evidence by configured account/route revision and
provider message ID, with bounded storage and a bounded correlation deadline.
Retain only necessary encrypted evidence and semantic digest. A later trusted
response or separately verified read-only provider lookup may bind the exact
attempt; only then rerun the verifier against its request and apply evidence.
Without authoritative correlation the attempt remains `Unknown`. A lookup
must not create a send or accept a customer-supplied message ID. Capacity
exhaustion refuses durable callback acceptance; it must not evict replay fences
or acknowledge evidence it failed to store. An expired uncorrelated receipt
leaves a rejection tombstone and never permits resubmission.

Receipt identity is `(account, route revision, provider message ID, event ID)`.
Store semantic digest and resulting effect atomically with state change. Same
identity and digest is a no-op; different digest conflicts and changes no
delivery facts. A different route/account cannot reuse an identity. Preserve
the existing per-attempt 64-event bound; at capacity fail closed rather than
evicting consumed identities. A conflict goes to a metadata-only exceptions
queue and cannot erase delivery evidence. Durable tombstones outlive accepted
callback/replay windows; expired timestamps still fail verification after
compaction. Body deletion cannot delete the replay fence while evidence can
still be accepted. Retention policy must specify bounded durations before
runtime activation; indefinite raw callback retention is not permitted.

## Suppression and races

Authenticated inbound STOP and operator holds update the same account-scoped
recipient/purpose suppression generation used by all routes. Serialize STOP
and intent under the same locks. STOP winning first cancels queued work and
returns its reservation once; no provider call follows. Intent winning first
may already cause a send; record that limit and do not claim cancellation.
Apply provider/carrier STOP controls too. Outbound receipts cannot remove a
hold. START must be authenticated, correctly ordered after the current STOP,
and cannot release an operator hold or revive a cancelled action. A stale or
duplicate START changes nothing. New sending after a valid START needs a new
approved action. Cross-account and route-local suppression substitutes fail.

## Runtime slices and evidence required

1. Add reviewed account/route/action/attempt/receipt/suppression storage and
   additive migrations, integrating export/erasure, encrypted evidence, expiry
   sweeps, bounded queues, usage reservations and crash-safe replay tombstones.
2. Implement the authorized reader handoff and one-attempt sender with fencing,
   strict timeout/no-resend rules and independently verified callback handling.
   Keep the route disabled; no provider account or live calls in this design.
3. Test disposable PostgreSQL restarts before/after every commit, worker fence
   changes, response/callback ordering, mismatches, digest conflicts, capacity,
   STOP/START ordering, metering refunds and erasure boundaries. Obtain separate
   provider-specific eligibility, credential, endpoint-idempotency and delivery
   evidence before any activation. Measure capacity rather than infer it from
   the pure model or published provider claims.

[Synthetic transcripts](vectors/provider-transport-proposal.json) and the
test-only model in `scripts/test_provider_transport_proposal.py` exercise design
invariants. They use opaque recipient/content commitments, no addresses,
credentials or real traffic. They do not verify network delivery, persistence,
cryptography or provider integration. Existing Rust verifier tests remain the
cryptographic/receipt acceptance checks for the dormant code.
