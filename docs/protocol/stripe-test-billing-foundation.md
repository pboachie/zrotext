<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# ZT-017 Stripe test-mode billing foundation

This branch is stacked on the inbound-server branch, which includes metering
migration 006 and inbound migration 007. Apply migrations 001–010 in order.

The billing route is absent by default. Setting
`STRIPE_BILLING_TEST_ENABLED=true` requires all of:

- `STRIPE_TEST_WEBHOOK_SECRET`: the `whsec_` secret for this test webhook endpoint.
- `STRIPE_TEST_SECRET_KEY`: an `sk_test_` key used only to retrieve current subscriptions.
- `STRIPE_TEST_PRICE_IDS`: comma-separated, server-chosen `price_` IDs.

There is no production-mode switch. Do not point the test webhook at a live
event destination. The route is `POST /v1/billing/stripe-events`. It reads at
most 64 KiB of raw bytes and verifies the `Stripe-Signature` HMAC-SHA256 over
`timestamp + "." + raw_body` before JSON parsing. It accepts only `v1`, a
five-minute timestamp window, and `livemode=false`. The event ID is unique in
PostgreSQL; a repeated ID with changed bytes gets HTTP 409. A valid event is
committed before HTTP 200. Database failures return 503.

Recognized subscription, Checkout completion, and invoice paid/failed events
only mark a subscription dirty. The worker retrieves the current subscription
from Stripe's fixed API host using the test key. It does not apply event
snapshots or compare `event.created`: [Stripe does not guarantee event order](https://docs.stripe.com/webhooks#event-ordering).
Generation checks prevent a stale worker result from overwriting a newer
reconciliation. A fetch failure is retried after one minute.

`billing_customers` binds one Stripe Customer ID to one tenant. An unknown
customer event is retained as `unbound` and cannot grant access. A trusted
future Checkout flow must call `bind_customer`; this queues verified events
that arrived before binding. Conflicting customer/subscription ownership is
retained as `conflict` for operator review. The database records subscription
status and whether its price is on the server allowlist. This branch also adds
an optional **test-only** price-to-outbound quota projection. It does not
charge anyone.

### Test-only outbound entitlement projection

Migration 009 adds the `source` column to `usage_quota_policies` and an audit
table for billing limit changes. `STRIPE_TEST_QUOTA_PLANS` is an optional
comma-separated mapping of allowlisted test prices to positive monthly
outbound counts, for example `price_example123:100`. Every price must also be
present in `STRIPE_TEST_PRICE_IDS`. Keep actual values in private deployment
configuration, outside the repositories. Without this mapping,
reconciliation records state but grants no new allowance.

Only one current, recognized `active` subscription on a mapped price may
project a positive limit. `trialing`, `past_due`, `unpaid`, `paused`,
`incomplete`, `canceled`, and `incomplete_expired` project zero. Another
nonterminal subscription makes the account ambiguous and projects zero.
Entitlement changes and the subscription snapshot commit in one transaction.
An active downgrade immediately lowers the current UTC monthly period limit;
already reserved units stay in the ledger and may exceed the new limit, so
new reservations stop. Cancellation projects zero. Duplicate and stale
reconciliations make no policy change or new audit entry.

`DeliveryStore::accept_metered` checks a bound customer, settled
reconciliation generations and a billing-sourced policy before reserving a
unit. A pending event or missing policy returns unavailable. A zero limit
returns quota exceeded. An idempotent replay retains its original message
and reservation. On account-route startup, old test allowances are set to
zero and known subscriptions are queued for a fresh provider read; disabling
billing test mode therefore leaves no old positive allowance. Billing test
mode requires migrations 009 and 010. The isolated entitlement branch uses
migration 009; when
combined with webhook replay and auth-abuse migration work, renumber this
migration and its fixture references to 011.

This branch has no Checkout or Portal route or customer-binding UI; separate
draft PRs cover those surfaces. It has no paid-mode entitlement, payment grace
rules, device/inbound caps, or operational alert for unbound/conflict events.
No public metered send route is wired yet. Signature
secret rotation needs multi-secret verification before production. Complete
those gates and review them independently before enabling paid service. Tests
use synthetic JSON shaped like Stripe's [Event](https://docs.stripe.com/api/events/object),
[Subscription](https://docs.stripe.com/api/subscriptions/object), and
[Invoice](https://docs.stripe.com/api/invoices/object) objects.

An opt-in integration test also fetched one real `invoice.paid` and one real
`invoice.payment_failed` event from the Stripe test API. It bound two synthetic
test Customers to separate disposable PostgreSQL tenants, checked the current
invoice subscription pointer, queued and deduplicated both events, and let the
worker fetch their current test subscriptions. The resulting local snapshots
were `canceled` and `incomplete_expired`, each with the recognized test price.
The test used private, process-only credentials and fixture IDs and removed its
database schema. A locally generated signature exercised the raw-body parser;
this did not test a Stripe-delivered webhook or Stripe's endpoint signature.
The provider-side payment, refund, and cancellation rehearsal is recorded in
`docs/implementation-status.md`; this branch does not handle a completed
hosted Checkout.

### Refund and dispute hold slice

Migration 010 in this isolated branch adds a durable risk queue and append-only
payment holds. Combine it as migration 012 after auth-abuse 010 and entitlement
011 in the integration stack. Signed test-mode `charge.refunded` (including a
partial refund), `refund.created` with a Charge, and `charge.dispute.created`
events are deduplicated by Stripe event ID. A bound customer with queued,
held, or review-required risk cannot make a new metered reservation. The
customer row lock serializes risk ingestion with reservation admission.

The risk worker fetches the current test Charge, a unique paid InvoicePayment
for its PaymentIntent, and the paid subscription Invoice. It requires the
Charge and Invoice customers to agree and binds the invoice's Subscription to
the local tenant. These payment reads pin Stripe API version
`2025-07-30.basil`; the fixed Stripe API host, test key, no redirects, bounded
response size and timeouts apply. A successful attribution appends a hold and
marks the risk job held. Ten failed attempts leave it in `needs_review`; a
known tenant stays blocked. Provider snapshots, a duplicate webhook, a late
`charge.dispute.closed`, and active subscription re-reconciliation cannot
silently clear a hold. An existing idempotent message replay still returns its
original reservation.

Any positive refund on a paid subscription invoice is conservatively held;
there is no automatic release, partial-refund quota rule, dispute outcome
policy, operator clearance route, or attribution of a refund without a Charge
or a charge without a PaymentIntent. A Charge with no unique paid subscription
invoice remains unresolved for review and may block a bound customer. This
slice uses synthetic signed test events and a PostgreSQL lifecycle test; it
does not establish a Stripe-delivered webhook or production payment readiness.

References: [Stripe webhook signature and raw-body rules](https://docs.stripe.com/webhooks#verify-signature),
[duplicate and unordered event guidance](https://docs.stripe.com/webhooks#event-ordering),
[subscription webhook events](https://docs.stripe.com/billing/subscriptions/webhooks).
The risk attribution chain follows the [Charge](https://docs.stripe.com/api/charges/object),
[InvoicePayment](https://docs.stripe.com/api/invoice-payment/list), and
[Invoice](https://docs.stripe.com/api/invoices/object) objects.
