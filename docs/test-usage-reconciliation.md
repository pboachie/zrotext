<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Read-only TEST usage reconciliation

`STRIPE_TEST_USAGE_RECONCILE_ENABLED` defaults to false. Enabling it also
requires existing TEST billing and a separate TEST-only
`STRIPE_TEST_USAGE_RECONCILE_SECRET_KEY` with meter, price and invoice read
permission. This worker does not create accounts, prices, charges, credits,
subscriptions or entitlements. Free and self-hosted startup need no key.

The worker reads committed local billable policy/customer/month bindings and
calls the fixed Stripe HTTPS origin with the existing `2025-07-30.basil` pin.
No browser, model or webhook supplies provider quantities. Redirects, ambient
proxies and automatic retries are disabled. Requests have four-second deadlines,
64-KiB response bounds and a twenty-second observation deadline. Each five-minute
tick shares the existing billing worker concurrency budget. Enabled startup checks
the actual observation tables and columns before spawning; an unapplied schema
refuses startup. Drain registers its wakeup before checking the persistent flag,
so a notification during an observation or at the wait boundary cannot leave the
worker waiting for the next five-minute tick. A local cursor
advances after failed observations so one unavailable account cannot indefinitely
starve later accounts. Restart repeats reads, never usage submission.

The selected meter must be TEST-mode, active, sum-based, and retain the existing
`stripe_customer_id`/`value` mapping and stored event name. An ungrouped complete
summary must cover the exact UTC month with integral nonnegative quantities.
Missing fields, pagination, fractional quantities, overflow, a foreign meter or
changed totals are unavailable observations, never assumed zero. An explicitly
complete empty provider summary represents zero observed units.

Invoice comparison requires an existing immutable invoice-period binding with
exactly the same boundaries. A missing compatible binding remains pending.
Non-calendar subscription-anchored invoice periods are not reconciled here;
their own immutable period attribution requires a separate implementation.
The complete bounded TEST invoice must match its trusted customer and subscription.
Only one non-prorated usage line with the same meter and period may supply the
quantity. Transformed/tiered pricing and ambiguous usage lines are refused;
fixed subscription charges never substitute for usage. Provider observations are
sampled again to refuse a changed aggregate or invoice during the read.

The existing local `billable::reconcile` transaction rechecks customer/policy/meter
identity and appends its immutable observation. It compares finalized, acknowledged,
pending and review counts with provider aggregates and the optional invoice
quantity. `observed_equal` is observation of equal totals, not validation of each
event, approval of a correction, or new entitlement. Divergence and absent invoice
quantity stay explicit. No unknown liability is refunded or resent here.

Reviewed provider/AI charge units, adjustments, actual account configuration,
core readiness and launch authorization remain separate. This source candidate
uses synthetic test fixtures; it does not establish production billing acceptance.

Primary contracts: [meter summaries](https://docs.stripe.com/api/billing/meter-event-summary/list),
[invoice line identity](https://docs.stripe.com/api/invoice-line-item/object?api-version=2025-07-30.basil),
and [asynchronous usage reporting](https://docs.stripe.com/billing/subscriptions/usage-based/recording-usage-api).
