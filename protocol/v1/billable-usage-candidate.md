# Billable usage candidate v1

Status: restricted source-only TEST candidate. This is a proposed charge-unit
policy requiring review, not a hosted billing launch decision. Core readiness
under #622, reviewed exposure reservation (#674), credit/invoice policy (#675),
and the contiguous migration train remain prerequisites. No production process
registers this worker or these review/error helpers. Free and self-hosted
execution does not acquire a new billing gate.

## Charge units and uncertainty

| Category | Proposed unit and success boundary | Candidate runtime |
| --- | --- | --- |
| Android execution | One logical message after the existing delivery transaction aggregates successful sent callbacks for every segment of the current attempt into `submitted`. Carrier delivery is a separate observation. | Implemented for existing metered synthetic delivery. Sealed production activation and physical delivery remain unverified. |
| Provider transport | One logical provider action after independently verified provider acceptance under its exact action identity; segments and callbacks do not mint additional actions. | Unavailable. Transport (#643) and independent provider completion proof are required. |
| AI-generated reply | One explicitly requested generation whose exact generation identity has a verified provider completion. Model completion, owner approval and message dispatch are distinct events. | Unavailable. Model/provider (#644) and exposure authority are required. |

Rejected admission, rejected/failed submission, unknown execution, cancelled
work, unapproved drafts, edited proposals, quote changes, durable intents and
dispatch grants create no Android billable unit. A generated draft could incur
the proposed AI unit only under an independently authorized and completed
generation; an owner approving it is not completion evidence. An intentional
regeneration would require a new authorized generation identity. Retrying the
same action or replaying a callback never creates another unit. Conflicting
execution evidence moves existing usage to review; it does not silently erase
the original success or issue a refund.

Existing `usage_ledger` reservations/refunds and `usage_periods` remain the
admission authority. The new binding copies the original reservation's tenant,
message, UTC calendar period and reporting timestamp, plus an immutable TEST
meter/customer policy version, in that same transaction. Only an explicitly
active TEST policy captures a binding. Policies are absent by default; enabling
or changing a policy is not exposed as an application route.

The first aggregate success inserts immutable finalized provenance and its
outbox atomically with the actual callback/state transition. An outbox failure
rolls the transaction back. The identifier is `zt-usage-v1-` followed by the
lowercase SHA-256 of the ASCII account UUID, colon, message UUID, and
`:android_execution:1`. This identifier is also the idempotency key. A refund
in the original admission ledger prevents later finalization; an existing
finalized row is never rewritten into a negative charge.

## TEST forwarding and review

The library worker defaults off and accepts only an explicitly supplied
synthetic/TEST transport. It has no HTTP provider, key discovery, products,
prices, purchases, account creation or runtime registration. No remote call
occurs inside a delivery or worker-claim transaction. Current customer-row
locking and a fresh post-lock lease check enforce one active worker lease per
customer across replicas. Leases last 15 seconds; transport has a five-second
deadline; seven attempts, capped exponential backoff and bounded `Retry-After`
prevent an unbounded retry loop. Lost responses reuse the original identifier. Provider reporting seconds are
floored from the original UTC reservation timestamp, never rounded into the
following second or calendar period.
Expired lease completions cannot overwrite a newer worker's result. The exact
lease row is locked before fresh expiry checks; a final database-clock check
after the write rolls back a completion that outlived its lease.

Exact-identifier TEST acknowledgements record HTTP acceptance separately from
asynchronous validation. Unknown responses, 429 and 5xx defer; other HTTP
failures and mismatched/live-mode acknowledgements require review. Usage older
than 35 days, over five minutes in the future, outside its original period,
after the period closes, or beyond the candidate's 23-hour retry window is
parked for review. The shorter retry window avoids assuming identifiers are
deduplicated forever: Stripe documents uniqueness for at least 24 hours.
These constraints follow the [recording usage documentation](https://docs.stripe.com/billing/subscriptions/usage-based/recording-usage-api)
and [meter-event identifier contract](https://docs.stripe.com/api/billing/meter-event/create).
The candidate request pins the repository's existing `2025-07-30.basil`
API-version contract; no real API compatibility check or provider call occurred.

The unmounted error verifier authenticates exact raw bytes before parsing.
It accepts a bounded platform thin error with explicit `livemode:false`, an
exact meter identity, and UTC millisecond validation interval. Absent mode,
connected-account context, missing related meter and unsupported shapes fail
closed pending a trusted retrieval/quarantine bridge. In particular, the
documented `no_meter_found` example has no related meter and cannot be guessed
into a tenant. Signed error samples are incomplete; ingestion pages all local
TEST policies for the verified meter and pauses each entire policy. Global
event IDs and raw-body digests reject conflicting replay. The first eager
outbox update is bounded; the durable policy error fences remaining claims.
Acknowledgement history survives review. No error webhook issues a credit,
dispatches a message or grants entitlement.

## Local reconciliation and correction requests

The content-free local projection reports finalized, acknowledged, pending and
review counts for one tenant and original UTC period. Provider observations
are trusted TEST-adapter inputs, bound to the current customer, meter, policy
and period, with an optional independently attributed invoice quantity. Missing
invoice quantities remain pending; mismatches remain divergent. Immutable snapshot identities reject changed replay; differing
totals or outstanding errors remain divergent. Matching totals are merely an
observation, not individual-event validation or an entitlement. No dashboard
or admission path polls Stripe. Invoice-line retrieval and attribution are
unavailable until the invoice policy and provider bridge are reviewed.

An unmounted owner review helper requires exact origin/CSRF, current password,
MFA where enabled, and a final locked live-owner/session fence. It records one
immutable `request_credit` (-1 requested unit) or `retain_charge` (0) decision
for an existing reviewed logical action. The protected write is followed by
a fresh owner-session check before commit; expiry rolls back the request.
Changed replay conflicts; one action
cannot accumulate duplicate credit requests. Closed reason codes and owner
identity are retained without message content. This is an attributed request,
not an issued monetary credit, negative meter event, provider adjustment or
quota refund. The maintainer must review this policy and #675 before any
provider adjustment bridge exists. Unknown/duplicate invoice quantities must
remain in review rather than being treated as a successful credit.

Binding/finalized/outbox/reconciliation/adjustment rows cascade with existing
tenant reservation and billing-customer erasure. Error receipts shared across
tenant mappings disappear when the last mapping is removed. Receipt-row locking
serializes concurrent final mapping removals before the cleanup check. Retaining copied
event/attempt UUIDs avoids coupling billable history to event-log retention;
there are no message bodies, routing numbers or model output in these tables.

## Verification boundary

Tests use disposable schemas, synthetic delivery callbacks and injected
transports. They do not send SMS, call Stripe, issue credit, retrieve invoices
or prove physical-device acceptance. Candidate migration 078 follows reviewed
scheduling migration 077. Publication and application require that predecessor
on canonical main and the complete contiguous 001–078 train; incomplete trains
must continue failing the existing contiguous-migration checks.
