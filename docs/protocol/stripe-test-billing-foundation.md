# Stripe test-mode billing foundation

The server has an opt-in Stripe test-mode event route at `POST /v1/billing/stripe-events`. Set `STRIPE_BILLING_TEST_ENABLED=true` with `STRIPE_TEST_WEBHOOK_SECRET`, `STRIPE_TEST_SECRET_KEY`, and an allowlist of `STRIPE_TEST_PRICE_IDS` to enable it. It accepts test-mode events only. Production billing is disabled.

The route bounds the raw request body, verifies Stripe's signature before parsing JSON, and rejects stale or live-mode events. It stores each event ID once and rejects a repeated ID with different content. A worker retrieves current subscription state from Stripe's fixed API host, avoiding reliance on delivery order. Customer IDs are tenant-bound; unbound or conflicting events cannot grant access.

An optional `STRIPE_TEST_QUOTA_PLANS` mapping assigns a positive UTC monthly outbound limit to each configured test price (`price_example123:100`). A recognized `active` subscription projects a limit only when it is the account's sole nonterminal subscription. Pending reconciliation, inactive or unrecognized prices, and ambiguous subscriptions block new metered reservations. A downgrade lowers the current period limit without removing existing reservations; cancellation projects zero. Each policy change is audited. Startup resets prior test allowances and queues a fresh provider read. These rules apply to `DeliveryStore::accept_metered`; a public metered send route is still pending.

Signed test-mode refund and dispute events enter a separate risk queue. A bound customer with queued, held, or review-required risk cannot make a new metered reservation. The risk worker fetches the current Charge, paid InvoicePayment and subscription Invoice before attributing a durable hold to the tenant. A risk event received before customer binding is attached when the trusted binding arrives. Holds do not clear automatically; partial refund policy, dispute outcomes and an operator clearance route remain to be implemented. The server uses the fixed Stripe test API host with bounded requests. This is not proof of a Stripe-delivered webhook or production payment readiness.

Checkout and Portal flows remain separate features. Consult the [server implementation](../../crates/server/src/billing/mod.rs) and its tests for the current behavior.

References: [Stripe signature verification](https://docs.stripe.com/webhooks#verify-signature), [event ordering](https://docs.stripe.com/webhooks#event-ordering), and [subscription events](https://docs.stripe.com/billing/subscriptions/webhooks).
