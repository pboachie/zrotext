-- SPDX-License-Identifier: AGPL-3.0-only
-- Read-only TEST evidence, never another charge ledger or correction authority.
CREATE TABLE billing_invoice_usage_observations (
    account_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    period_id uuid NOT NULL,
    policy_version bigint NOT NULL,
    identity_digest bytea NOT NULL CHECK(octet_length(identity_digest)=32),
    snapshot_digest bytea NOT NULL CHECK(octet_length(snapshot_digest)=32),
    finalized_units bigint NOT NULL CHECK(finalized_units>=0),
    acknowledged_units bigint NOT NULL CHECK(acknowledged_units>=0 AND acknowledged_units<=finalized_units),
    pending_units bigint NOT NULL CHECK(pending_units>=0),
    review_units bigint NOT NULL CHECK(review_units>=0),
    open_units bigint NOT NULL CHECK(open_units>=0),
    provider_units bigint NOT NULL CHECK(provider_units>=0),
    invoice_units bigint NOT NULL CHECK(invoice_units>=0),
    state text NOT NULL CHECK(state IN ('pending','diverged','observed_equal')),
    observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,snapshot_id),
    FOREIGN KEY(account_id,period_id) REFERENCES billing_invoice_periods(account_id,id),
    FOREIGN KEY(account_id,policy_version) REFERENCES billing_usage_test_policies(account_id,policy_version)
);
CREATE INDEX billing_invoice_observation_period
    ON billing_invoice_usage_observations(account_id,period_id,observed_at);
CREATE INDEX billing_invoice_observation_retention
    ON billing_invoice_usage_observations(observed_at,account_id,snapshot_id);
CREATE INDEX billing_invoice_observation_policy
    ON billing_invoice_usage_observations(account_id,policy_version);
CREATE TRIGGER billing_invoice_observation_immutable
    BEFORE UPDATE ON billing_invoice_usage_observations
    FOR EACH ROW EXECUTE FUNCTION billing_usage_freeze();
