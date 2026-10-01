# Invoice-bound TEST billing candidate

This source candidate is disabled by default. Migration 081 installs an
`invoice_bound_test=false` account policy; installation does not enable it.
It extends the verified TEST event inbox and existing subscription, payment-risk
and usage ledgers. It introduces no live payment calls, prices, accounts,
entitlement activation endpoint or hosted launch approval. Operator-provisioned
self-host usage policies retain their existing behavior.

## Current provider identity

Webhook signatures cover the original bytes before parsing. Duplicate events
remain durable inbox replays; events request a current provider read rather than
projecting their historical invoice payload. Connected-account/context events
and explicit unsupported API versions are stored as unsupported without tenant
or risk effects. Subscription and invoice reads use the existing
`2025-07-30.basil` API pin and configured TEST key.

The reader accepts one complete quantity-one subscription item and its current
invoice. Customer, subscription, item, price and period identities must match.
It repeats both reads and refuses mixed observations, truncated lists,
substitution, unrecognized statuses, transport failures and missing invoices.
A bounded timeout leaves reconciliation retryable. A missing invoice is not a
deleted subscription.

The period comes from the subscription item's current period fields and the
exact non-prorated invoice line, with an exclusive end. Invoice-level dates,
webhook arrival dates and calendar guesses are not period authority. Only a
current paid creation or renewal invoice can establish a new period. This
follows the [Basil item-period change](https://docs.stripe.com/changelog/basil/2025-03-31/deprecate-subscription-current-period-start-and-end)
and [pinned invoice contract](https://docs.stripe.com/api/invoices/object?api-version=2025-07-30.basil).

## Recovery and effective policy

The period marker, current entitlement, existing subscription/quota projection,
audit and processed reconciliation generation commit in one transaction. An
audit or storage failure rolls all of them back. A unique account/subscription/
period and account/invoice identity prevents duplicate renewal markers.
Historical observations cannot replace a newer applied period.

Current active paid state permits the recognized configured allowance. A
current paid proration can change the effective allowance only within an
already established period; it cannot mint a new period. An upgrade affects
the current configured ceiling after a verified paid observation, without
resetting consumption. A downgrade immediately reduces the effective ceiling;
already consumed units remain recorded. Future subscription schedules are not
projected ahead of their actual current item state.

Past-due recovery uses the existing verified payment-failure anchor and seven-day
grace, bounded by the original paid period. An unpaid upgrade cannot enlarge
the previous allowance. Missing anchors, unpaid/incomplete/paused states,
ambiguous subscriptions and expired periods refuse new discretionary spend.
Recovery and repeated paid reads never replenish consumed budget.

Period-end cancellation is bounded by the current period end and any earlier
actual cancellation time. Immediate cancellation and confirmed subscription
deletion refuse new spend. Payment-risk holds remain subject to the existing
explicit operator review; partial/full refunds and disputes do not automatically
release holds or reset invoice consumption. Authenticated billing, portal,
export/deletion and safety controls do not require a spend allowance.

## Usage and exposure boundaries

The existing immutable usage ledger remains the canonical outbound reservation
and refund history. Supplemental invoice attribution records its original
period identity and counters. Calendar usage history remains intact, while an
enabled invoice policy enforces its actual period ceiling in the same message,
job, idempotency and usage transaction. A partial guard installation fails
closed. Concurrent admissions serialize the last available unit.

Outstanding work from older invoice periods carries into later allowances.
Silence, lease expiry, submission or unknown delivery does not release that
liability. Existing confirmed terminal transitions and legitimate pre-grant
refunds update it once. Recovery does not rewrite original identities or
counters. Periods are bounded to 370 days and an account retains at most 1,000
period markers; exceeding a bound requires review rather than invented credit.

The separate TEST exposure engine retains its own immutable policies,
outstanding/finalized counters and deployment-global epoch. For an enabled
invoice account, its tenant policy window must exactly match the independently
verified current invoice period at reservation and first intent, including
fresh post-wait checks. A budget receipt, synthetic settlement or model output
cannot establish payment authority. This integration does not enable a provider
or model adapter or create an invoice from an operator-defined epoch.

## Owner lifecycle and limitations

The owner billing status labels stored phase and allowance as
`lastObservedPhase` and `lastObservedEffectiveLimit`. `currentPeriodEligible`
and `effectiveLimit` independently recheck the current invoice fence, including
deadlines, dirty generations and risk holds. An ineligible period reports a
zero current ceiling; missing observations remain null. Enabled accounts also
use that current ceiling for `projectedEntitlement`, rather than the legacy
calendar projection. These readings remain informational and do not authorize
admission, establish remaining capacity or bypass any other fence.
Owner takeout provides
three independent 20-row pages using `invoice_periods_after`,
`invoice_usage_after` and `invoice_audit_after`. Cursors must belong to the same
account. Export rechecks the actual live owner session before committing.
Existing account erasure removes audit, attribution, entitlement and period
rows atomically under the established owner/MFA fence.

Retention prunes only audit entries older than 180 days in bounded indexed
batches. Period identities, consumption and unknown liabilities survive normal
message retention until owner erasure. Audit growth is bounded at 8,192 entries
per account; reaching the limit refuses further projection until review or
retention creates room.

Synthetic PostgreSQL and provider fixtures verify the restricted candidate.
They do not verify a live Stripe account, production proration policy, physical
SMS delivery or hosted readiness. Deployment requires the contiguous reviewed
migration train, separately configured policy and existing launch gates.
