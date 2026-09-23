-- SPDX-License-Identifier: AGPL-3.0-only
-- An explicit test-price device cap is distinct from monthly message usage.
-- Existing enrolled devices are never removed by a billing projection.
CREATE TABLE billing_device_cap_config (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    enabled boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO billing_device_cap_config(singleton,enabled) VALUES(true,false);

CREATE TABLE billing_device_caps (
    account_id uuid PRIMARY KEY REFERENCES accounts(id),
    limit_devices bigint NOT NULL CHECK (limit_devices >= 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE billing_device_cap_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    stripe_subscription_id text REFERENCES billing_subscriptions(stripe_subscription_id),
    reconciliation_generation bigint NOT NULL CHECK (reconciliation_generation >= 0),
    previous_limit_devices bigint,
    limit_devices bigint NOT NULL CHECK (limit_devices >= 0),
    reason text NOT NULL CHECK (reason IN ('active', 'inactive', 'ambiguous', 'unmapped', 'startup_reset')),
    changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX billing_device_cap_audit_account ON billing_device_cap_audit(account_id, changed_at DESC);
