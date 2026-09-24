# Stripe test-mode billing foundation

The server has an opt-in Stripe test-mode event route at `POST /v1/billing/stripe-events`. Set `STRIPE_BILLING_TEST_ENABLED=true` with `STRIPE_TEST_WEBHOOK_SECRET`, a test API key, and an allowlist of `STRIPE_TEST_PRICE_IDS` to enable it. It accepts test-mode events only. Production billing is disabled.

The test billing worker uses `STRIPE_TEST_RECONCILE_SECRET_KEY` for `GET /v1/subscriptions/{id}`, `GET /v1/charges/{id}`, `GET /v1/invoice_payments` and `GET /v1/invoices/{id}`. When hosted sessions are enabled, `STRIPE_TEST_SESSION_SECRET_KEY` is used for `POST /v1/customers`, `POST /v1/checkout/sessions` and `POST /v1/billing_portal/sessions`. The opt-in real-provider hosted-session smoke also performs `GET /v1/customers/{id}` with its separate `ZT_STRIPE_TEST_SECRET_KEY` test credential; Customer Read is needed for that smoke, but the deployed hosted-session route does not perform this read. No runtime Events Read permission is required by these paths. Each runtime key can be a separately scoped Stripe TEST restricted key. For existing installations, `STRIPE_TEST_SECRET_KEY` remains a fallback for either missing scoped key. A present but empty or live-mode scoped key fails startup; the signing secret is separate from both API keys. Review the exact Stripe permission grants and repeat the full TEST lifecycle before replacing an existing key.

The route bounds the raw request body, verifies Stripe's signature before parsing JSON, and rejects stale or live-mode events. It stores each event ID once and rejects a repeated ID with different content. A worker retrieves current subscription state from Stripe's fixed API host, avoiding reliance on delivery order. Customer IDs are tenant-bound; unbound or conflicting events cannot grant access.

An optional `STRIPE_TEST_QUOTA_PLANS` mapping assigns a positive UTC monthly outbound limit to each configured test price (`price_example123:100`). An optional third field assigns a nonnegative active-device cap (`price_example123:100:2`). If any mapped price has a device cap, every mapped price must have one; the values are operator configuration, not commercial defaults. Two-field mappings retain the legacy behavior of no device cap until cap enforcement has first been enabled. A recognized `active` subscription projects limits only when it is the account's sole nonterminal subscription — one nonterminal subscription per account, enforced server-side by the Checkout refusal below; a second live subscription projects `ambiguous`, which is zero outbound quota and a zero device cap. A current `past_due` subscription keeps the mapped limit for seven days from the signed `invoice.payment_failed` event's creation time, provided the failed invoice matches the current invoice in the freshly fetched subscription. The event time is capped at database receipt time if it is in the future. The last provider-confirmed non-`past_due` time is stored separately, so repeated `past_due` reads do not exclude a delayed matching failure event. After recovery, both failure creation and receipt must follow that boundary; a failure from an earlier cycle cannot restart grace. A changed current invoice pauses admission until a matching signed failure arrives, and rebinding within one continuous delinquency cannot extend the original deadline. Duplicate and delayed events retain the first grace start; a provider-confirmed recovery clears it. A missing trusted failure time or current invoice grants no grace. Metered admission checks a fresh database clock after locking billing state, so outbound pauses at expiry without another webhook. Existing message replays create no new reservation. The owner billing page shows the grace deadline or pause notice. Pending reconciliation, other inactive or unrecognized prices, and ambiguous subscriptions block new metered reservations. A downgrade lowers the current period limit without removing existing reservations; cancellation projects zero. Policy changes are audited. A changed test price or quota mapping resets prior allowances and queues fresh provider reads; an unchanged configuration preserves projections across restarts. These rules apply to `DeliveryStore::accept_metered`; a public metered send route is still pending.

Apply migration 021 before enabling this behavior, and drain older API and worker binaries before switching traffic. Previously stored failure events have no creation time in the database; they cannot retroactively begin a grace interval. Existing `past_due` accounts without a newly signed matching failure event remain paused until payment recovers.

When device caps are configured, reconciliation projects the active plan's device cap separately from monthly usage. Pairing approval checks the current payment-grace deadline, so a cap projected during grace cannot admit a new device after the seven days expire without another webhook. Inactive, ambiguous, or unmapped subscriptions project a zero cap. Existing enrolled devices keep authenticating after a downgrade or cancellation, even if the active count exceeds the new cap. Owner approval of a new pairing is blocked while the account is at or over its cap, a subscription reconciliation is pending, or the account has not yet received its first cap projection. The latter includes accounts without a customer binding, so cap-enabled deployment does not permit pre-subscription enrollment. The owner billing status and dashboard show the active count, cap, and over-limit state and link to the approved-device list. When over cap, the owner page explicitly asks which devices to revoke; each device has its own confirmed revoke action. A cap rejection during pairing directs the owner to this list without implying the phone proof was wrong. The owner can revoke devices to get below the cap before approving a replacement. No device is revoked automatically. Device-cap changes have an audit trail. A changed test entitlement configuration temporarily sets prior caps to zero until reconciliation completes. Cap enablement persists across API restarts: a new server without the cap mapping refuses to start against a cap-enabled database, and its reset transaction rolls back. A new worker without cap mappings also refuses reconciliation. Removing mappings after enablement therefore requires an explicit coordinated operator database change. Apply migration 017 and drain every old server binary before enabling cap mappings: old binaries lack the admission check, and the database marker only guards new binaries with mismatched configuration.

Signed test-mode refund and dispute events enter a separate risk queue. A bound customer with queued, held, or review-required risk cannot make a new metered reservation. The risk worker fetches the current Charge, paid InvoicePayment and subscription Invoice before attributing a durable hold to the tenant. A risk event received before customer binding is attached when the trusted binding arrives. Holds do not clear automatically; partial refund policy, dispute outcomes and an operator clearance route remain to be implemented. The server uses the fixed Stripe test API host with bounded requests. This is not proof of a Stripe-delivered webhook or production payment readiness.

Checkout and Portal flows remain separate features. Consult the [server implementation](../../crates/server/src/billing/mod.rs) and its tests for the current behavior.

## Restart recovery

Apply migration 025 after 023 and 024 before starting this server version. The
server stores a one-way hash of the test price allowlist, quota plan mapping,
and reconciliation key in PostgreSQL; it never stores the key itself. An unchanged configuration keeps existing outbound quotas and device
caps through restarts, including rolling restarts at multiple sites. The first
start after migration, a changed mapping or reconciliation key, or re-enabling test billing resets
test projections and queues provider reads for subscriptions whose last snapshot
is not `canceled` or `incomplete_expired`. Terminal snapshots remain clean.
When cap configuration permits test billing to be disabled, that transition
clears its old allowances.

The subscription and payment-risk queues each run every 10 seconds. Each tick
claims up to `STRIPE_TEST_RECONCILE_BATCH_SIZE` jobs (default 25, range 1–100)
with at most `STRIPE_TEST_RECONCILE_CONCURRENCY` simultaneous provider reads
across both queues (default 2, range 1–4). Risk work is probed every 10 seconds
even while a slow subscription batch remains active. With fast provider responses, 200 ready jobs at the
default batch size need about eight ticks, or 70–80 seconds from the first tick.
With slower responses, allow roughly `ceil(jobs / batch_size)` ticks plus the
time for each batch's provider reads and database work. Failed jobs wait for
their retry time; a provider outage can extend recovery indefinitely. Review
`billing_reconciliations` and `billing_risk_events` for pending rows and
`next_attempt_at` when recovery is slower than expected.

The metered API returns `billing_pending` with HTTP 503 and `Retry-After: 10`
while reconciliation is pending, and `payment_hold` with HTTP 402 when a
payment-risk hold blocks admission. A general `unavailable` 503 indicates a
different service failure. Retry-After is a polling hint, not a completion
promise. Device-cap admission also waits for pending reconciliation.

References: [Stripe signature verification](https://docs.stripe.com/webhooks#verify-signature), [event ordering](https://docs.stripe.com/webhooks#event-ordering), and [subscription events](https://docs.stripe.com/billing/subscriptions/webhooks).

Hosted Checkout and Portal requests share an atomic database budget: eight
requests per account per minute and 120 across the deployment per minute.
Requests exceeding either budget return HTTP 429 before calling Stripe.
Changing owner sessions, Checkout idempotency keys, or API instances does not
reset the account budget. Database errors fail closed with HTTP 503.

`POST /v1/billing/checkout` refuses to open a second subscription. Before any
Stripe call, it takes the per-account advisory lock that reconciliation uses
and returns HTTP 409 (`subscription_exists`) when the account has any
nonterminal `billing_subscriptions` row — any status except `canceled` and
`incomplete_expired` — or any `billing_reconciliations` row whose
`dirty_generation` exceeds its `processed_generation`. A refused request does
not spend the shared session budget, and the owner is directed to the
customer Portal instead. Terminal historical subscriptions do not block a new
Checkout once their reconciliation has caught up. Running the check under the
reconciliation lock also means concurrent Checkout attempts serialize with an
in-flight projection and cannot both observe a pre-commit state.

`GET /v1/billing/status` reports the projected entitlement that
reconciliation currently applies: the audited `reason` (`active`, `grace`,
`inactive`, `ambiguous`, `unmapped`, `startup_reset`, or null before the
first projection), the `outboundLimit` from the current `stripe_test` quota
policy, the effective `deviceCap`, whether a payment hold is active
(`paymentHold`), and the count of nonterminal subscriptions. The owner
dashboard renders this summary and closes the Checkout button while a
subscription is live or a reconciliation is pending, so an owner in
`past_due`, `unpaid`, or `paused` is routed to the Portal rather than into a
duplicate subscription that would project zero quota and a zero device cap.

Subscription reconciliation requires a complete Stripe items list with
`object=list` and `has_more=false`. A partial or malformed provider response
leaves reconciliation pending and cannot grant outbound quota or device caps.
