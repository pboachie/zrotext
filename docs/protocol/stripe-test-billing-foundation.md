# Stripe test-mode billing foundation

The server has an opt-in Stripe test-mode event route at `POST /v1/billing/stripe-events`. Set `STRIPE_BILLING_TEST_ENABLED=true` with `STRIPE_TEST_WEBHOOK_SECRET`, `STRIPE_TEST_SECRET_KEY`, and an allowlist of `STRIPE_TEST_PRICE_IDS` to enable it. It accepts test-mode events only. The public code does not enable production billing or grant service access from these events.

The route bounds the raw request body, verifies Stripe's signature before parsing JSON, and rejects stale or live-mode events. It stores each event ID once and rejects a repeated ID with different content. A worker retrieves current subscription state from Stripe's fixed API host, avoiding reliance on delivery order. Customer IDs are tenant-bound; unbound or conflicting events cannot grant access.

This foundation records subscription state and recognized prices. Checkout and Portal flows, metering policy changes, and customer entitlements are separate features. Consult the [server implementation](../../crates/server/src/billing/mod.rs) and its tests for the current behavior.

References: [Stripe signature verification](https://docs.stripe.com/webhooks#verify-signature), [event ordering](https://docs.stripe.com/webhooks#event-ordering), and [subscription events](https://docs.stripe.com/billing/subscriptions/webhooks).
