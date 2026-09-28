-- SPDX-License-Identifier: AGPL-3.0-only
-- Named usage-limit plans. A plan is a quota-only definition an operator
-- assigns to an account; no price, currency or payment-provider data lives
-- here. Projection into usage_quota_policies happens only in trusted server
-- startup code (billing::plans), never from request data.

ALTER TABLE usage_quota_policies
    DROP CONSTRAINT usage_quota_policies_source_check,
    ADD CONSTRAINT usage_quota_policies_source_check
        CHECK (source IN ('operator', 'stripe_test', 'usage_plan'));

CREATE TABLE usage_plan_assignments (
    account_id uuid NOT NULL REFERENCES accounts(id),
    plan_key text NOT NULL
        CHECK (plan_key ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
    assigned_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id)
);

CREATE TABLE usage_plan_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    plan_key text,
    previous_limit_units bigint,
    limit_units bigint NOT NULL CHECK (limit_units >= 0),
    reason text NOT NULL CHECK (reason IN
        ('assigned', 'reprojected', 'plan_removed', 'assignment_removed',
         'skipped_billed', 'disabled')),
    changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX usage_plan_audit_account ON usage_plan_audit(account_id, changed_at DESC);

-- Mirrors billing_test_config: a one-way digest of the effective plan catalog
-- so an unchanged configuration keeps projections across restarts and a
-- changed catalog forces one reprojection.
CREATE TABLE usage_plan_config (
    singleton boolean PRIMARY KEY CHECK (singleton),
    configuration_sha256 bytea NOT NULL CHECK (octet_length(configuration_sha256) = 32),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
