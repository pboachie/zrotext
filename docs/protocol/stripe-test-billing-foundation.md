<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# ZT-017 Stripe test-mode billing foundation

This branch is stacked on the inbound-server branch, which includes metering
migration 006 and inbound migration 007. Apply migrations 001–008 in order.

The billing route is absent by default. Setting
`STRIPE_BILLING_TEST_ENABLED=true` requires all of:

- `STRIPE_TEST_WEBHOOK_SECRET`: the `whsec_` secret for this test webhook endpoint.
- `STRIPE_TEST_SECRET_KEY`: an `sk_test_` key used for current subscription retrieval and, when separately enabled, hosted test sessions.
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
customer event is retained as `unbound` and cannot grant access. The opt-in
Checkout flow calls `bind_customer`; this queues verified events
that arrived before binding. Conflicting customer/subscription ownership is
retained as `conflict` for operator review. The database records subscription
status and whether its price is on the server allowlist, but **does not grant
entitlements, change metering policy, or charge anyone**.

## Hosted test sessions

`STRIPE_TEST_HOSTED_SESSIONS_ENABLED=true` additionally requires configured
account routes and `STRIPE_TEST_CHECKOUT_PRICE_ID`, a single `price_` ID included
in `STRIPE_TEST_PRICE_IDS`. Both flags default to off. These routes are mounted
only when enabled:

- `POST /v1/billing/checkout` requires the owner session cookie, exact configured
  HTTPS Origin, CSRF cookie/header, and a lowercase UUIDv4 `Idempotency-Key`
  request header. The server uses the configured price and fixed return paths:
  `/billing/success` and `/billing/cancel` on `AUTH_ORIGIN`. It creates or reuses
  the tenant's bound Stripe Customer, then returns the hosted Checkout URL.
- `POST /v1/billing/portal` uses the same owner and CSRF checks. It requires an
  already-bound customer, returns 404 otherwise, and returns the hosted Portal
  URL with `/billing` on `AUTH_ORIGIN` as the return path.

Those three return paths are mounted as simple same-origin browser pages while
hosted sessions are enabled. A return from Stripe is **not** proof of payment
or an active entitlement; the pages say reconciliation is pending.

The client cannot choose a customer, price, metadata, or return URL. Both
session requests require empty bodies. Customer creation uses a tenant-scoped
Stripe idempotency key; Checkout uses the scoped
UUIDv4 key supplied by the owner browser plus a stable digest of the configured
price and return URLs. The Stripe API host is fixed, with
no proxy, redirect, or automatic HTTP retry and 3-second connect/10-second
request timeouts. Responses are capped at 32 KiB and must carry test-mode
objects, the expected customer, and an HTTPS URL on the exact Stripe hosted
domain. Successful responses use `Cache-Control: no-store`.

This slice has no live Stripe test account exercise, hosted-session dashboard
UI, price-to-quota policy, payment grace rules, downgrade
handling, refund reconciliation, or operational alert for unbound/conflict
events. Signature-secret rotation needs multi-secret verification before
production. Complete those gates and review them independently before enabling
paid service. Tests use synthetic JSON shaped like Stripe's [Event](https://docs.stripe.com/api/events/object),
[Subscription](https://docs.stripe.com/api/subscriptions/object), and
[Invoice](https://docs.stripe.com/api/invoices/object) objects plus a mocked
Stripe HTTP service and disposable PostgreSQL schema; they do not
assert a successful Checkout, charge, failed payment, or refund in Stripe test
mode.

References: [Stripe webhook signature and raw-body rules](https://docs.stripe.com/webhooks#verify-signature),
[duplicate and unordered event guidance](https://docs.stripe.com/webhooks#event-ordering),
[subscription webhook events](https://docs.stripe.com/billing/subscriptions/webhooks),
[Checkout Session creation](https://docs.stripe.com/api/checkout/sessions/create),
[Portal Session creation](https://docs.stripe.com/api/customer_portal/sessions/create), and
[Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests).
