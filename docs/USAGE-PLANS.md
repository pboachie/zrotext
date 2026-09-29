# Usage-limit plans

Usage-limit plans are a first, disabled-by-default slice of the roadmap item
"Live payments, usage limits and plans" ([hosted accounts and
subscriptions](ROADMAP.md#cap-hosted)). A plan is a **quota-only definition**:
a named monthly outbound-message limit. Plans deliberately carry no price, no
currency, no trial length and no payment-provider pointer. Anything commercial
is a founder decision; this slice invents none.

- Nothing is enabled by default. Without `USAGE_LIMITS_ENABLED=true` the
  server projects no plan policies, an existing projection is reset to zero,
  and admission behaves exactly as before this feature existed.
- No live payment path exists. The only payment integration remains Stripe
  TEST mode ([Stripe test billing](STRIPE-TEST-BILLING.md)), which this slice
  does not modify or extend.
- The values are operator configuration, not commercial defaults. This
  document and the code contain no recommended plan catalog.

## Configuration

```text
USAGE_LIMITS_ENABLED=false
USAGE_LIMIT_PLANS=starter:100,standard:2500
```

The plan keys and numbers above are **placeholder examples, not
recommendations**; nothing in this repository chooses a catalog for you. Each
entry is `plan_key:monthly_outbound_limit`. A plan key is 1–32 characters of
lowercase letters, digits and hyphens, starting with a letter or digit. Limits
are positive integers counting accepted outbound messages per UTC calendar
month. Enabling without a catalog, or configuring a catalog without enabling,
fails startup: stale configuration must not silently change limits. There is
no device-cap field in this slice; the existing device-cap machinery is
coupled to Stripe reconciliation and extending it to plans is a separate,
undecided step.

Apply migration 059 (`059_usage_limit_plans.sql`) before enabling.

## Assignment and projection

An operator assigns a plan to an account by inserting one row per account:

```sql
INSERT INTO usage_plan_assignments(account_id, plan_key)
VALUES ('00000000-0000-0000-0000-000000000000', 'starter')
ON CONFLICT (account_id) DO UPDATE
  SET plan_key = EXCLUDED.plan_key, updated_at = now();
```

At every startup while usage limits are enabled, the server reprojects every
assignment into the shared quota policy (`usage_quota_policies` with
`source='usage_plan'`) and the current period's limit, recording each **actual
change** in `usage_plan_audit`. Consequences:

- Assignment changes take effect at the next startup, without any catalog
  change: a newly assigned account gains its limit, and a deleted assignment
  loses its allowance. There is no request-time write path into quota policy.
- Removing a plan from the catalog projects zero for its assignments
  (`plan_removed`); deleting an assignment row zeroes its policy at the next
  startup (`assignment_removed`). A lower limit or zero never removes
  existing reservations, matching Stripe test projection.
- An account with a Stripe billing-customer binding is skipped
  (`skipped_billed`): a bound tenant's quota is owned by Stripe
  reconciliation and an operator plan must not overwrite it. While such an
  account is bound, metered admission follows the Stripe test rules.
- A restart with nothing changed writes no audit rows; a rolling restart
  serializes on a database advisory lock. Disabling the feature zeroes every
  `usage_plan` policy (`disabled` audit), so a downgrade cannot leave stale
  allowances.
- Deleting an account removes its assignment and audit history with it
  (`ON DELETE CASCADE`).
- On a database without migration 059, enabling fails startup with an
  explicit schema error; disabling is a no-op.

## Enforcement and honest over-limit responses

When `USAGE_LIMITS_ENABLED=true` (with or without Stripe test billing), the
allowlisted synthetic route `POST /v1/alpha/messages` uses metered admission.
Accepted messages reserve one unit in the current UTC month; cancelled
pre-grant messages refund theirs; an exact idempotent replay reserves nothing
extra. Responses are the existing honest codes:

| Condition | Response |
|---|---|
| Monthly limit reached or projected to zero | HTTP 429 `quota_exceeded`, `Retry-After: 60` |
| Limits enabled but the account has no policy | HTTP 503 `billing_pending`, `Retry-After: 10` |
| Queued/held payment risk (bound tenants) | HTTP 402 `payment_hold` |

Fail-closed behavior is intentional: enabling usage limits means every
sending account must have an assigned plan, otherwise its sends return
`billing_pending` rather than passing unmetered. Plan limits apply only to
accounts without a Stripe billing-customer binding.

## What this slice does not decide

These remain open for the founder; none has a default in code:

- Any pricing, plan names, limit values or tier structure.
- Over-limit policy beyond honest rejection (no overage, no grace, no
  soft warnings; a usage readout API such as `/v1/usage` is future work).
- Device caps or other quota dimensions for plans.
- Any live-mode Stripe support: live keys, live charges and live entitlement
  reconciliation are explicitly out of scope for this slice.

Consult the [server implementation](../crates/server/src/billing/plans.rs)
and its tests for the exact behavior.
