<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# ZT-017 Stripe test-mode billing foundation

This branch is stacked on the inbound-server branch, which includes metering
migration 006 and inbound migration 007. Apply migrations 001–008 in order.

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
status and whether its price is on the server allowlist, but **does not grant
entitlements, change metering policy, or charge anyone**.

This slice has no Checkout or Portal route, customer-binding UI,
price-to-quota policy, payment grace rules, downgrade
handling, refund reconciliation, or operational alert for unbound/conflict
events. Signature-secret rotation needs multi-secret verification before
production. Complete those gates and review them independently before enabling
paid service. Tests use synthetic JSON shaped like Stripe's [Event](https://docs.stripe.com/api/events/object),
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
`docs/implementation-status.md`; this branch does not grant access or handle a
completed hosted Checkout.

References: [Stripe webhook signature and raw-body rules](https://docs.stripe.com/webhooks#verify-signature),
[duplicate and unordered event guidance](https://docs.stripe.com/webhooks#event-ordering),
[subscription webhook events](https://docs.stripe.com/billing/subscriptions/webhooks).
