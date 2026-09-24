-- SPDX-License-Identifier: AGPL-3.0-only
-- Remember the effective Stripe TEST entitlement configuration across starts.
-- Never store API keys or signing secrets here.
CREATE TABLE billing_test_config (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    configuration_sha256 bytea NOT NULL CHECK (octet_length(configuration_sha256) = 32),
    updated_at timestamptz NOT NULL DEFAULT now()
);
