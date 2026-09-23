-- SPDX-License-Identifier: AGPL-3.0-only
-- Test-mode Stripe price-to-outbound quota projection. Migration 009 is
-- reserved by this isolated stack; renumber when combined with webhook replay.

ALTER TABLE usage_quota_policies
    ADD COLUMN source text NOT NULL DEFAULT 'operator'
        CHECK (source IN ('operator', 'stripe_test'));

CREATE TABLE billing_quota_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    stripe_subscription_id text REFERENCES billing_subscriptions(stripe_subscription_id),
    reconciliation_generation bigint NOT NULL CHECK (reconciliation_generation >= 0),
    previous_limit_units bigint,
    limit_units bigint NOT NULL CHECK (limit_units >= 0),
    reason text NOT NULL CHECK (reason IN ('active', 'inactive', 'ambiguous', 'unmapped', 'startup_reset')),
    changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX billing_quota_audit_account ON billing_quota_audit(account_id, changed_at DESC);
