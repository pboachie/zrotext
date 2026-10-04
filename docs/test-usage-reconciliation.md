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
Calendar observations remain distinct from exact invoice-period observations.
The latter select the original immutable invoice identity/window and only local
messages attributed through `billing_invoice_usage.period_id`; messages in the
same calendar month without that attribution are excluded. Crossing a calendar
boundary never replaces invoice attribution with month totals. Missing retained
bindings, mixed policy/meter attribution and non-integral second boundaries refuse
the observation; missing evidence never becomes zero. A period without retained committed meter-policy attribution is unavailable;
today’s active policy cannot establish its original mapping. Confirmed refunded
reservations without finalized charges are distinct from unknown liability. The supported meter window is
at most 31 days. Unknown/open invoice liabilities stay pending without credit.
The complete bounded TEST invoice must match its trusted customer and subscription.
Only one non-prorated usage line with the same meter and period may supply the
quantity. Transformed/tiered pricing and ambiguous usage lines are refused;
fixed subscription charges never substitute for usage. Provider observations are
sampled again to refuse a changed aggregate or invoice during the read.

Invoice observations additionally require the original bound price/line/item to
be the selected metered usage line. A fixed-price entitlement invoice without this
metered attribution remains unavailable; separate usage-item attribution is not
guessed. The final local transaction locks and rechecks customer, policy, original
invoice identity and exact attribution after network reads, then appends immutable
period/snapshot evidence. Reusing a snapshot with a different identity or provider
quantity conflicts. API replay returns the original recorded counters and state
even after local accounting advances; this is not network response-loss proof.
No network request occurs in that transaction. At most 10,000
observations per account are retained; bounded retention removes evidence older
than 180 days. A period with more than 10,000 attributed messages is unavailable
instead of making an unbounded lock/read attempt. Retention preserves original
periods and unknown liabilities.

The worker alternates bounded calendar and invoice lanes with independent cursors;
an unavailable invoice does not starve calendar observations. Owner takeout exposes
20 observations per page through `invoice_observations_after`, with a tenant-checked
cursor. Existing owner erasure removes observations before invoice/policy parents
in the same transaction. Neither retention nor erasure is a monetary correction.

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
