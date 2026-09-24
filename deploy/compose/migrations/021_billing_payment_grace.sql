-- SPDX-License-Identifier: AGPL-3.0-only
-- A signed failure event anchors one bounded grace interval. The current
-- provider subscription remains authoritative for whether grace applies.
ALTER TABLE billing_events
    ADD COLUMN payment_failed_at timestamptz;
ALTER TABLE billing_events
    ADD CONSTRAINT billing_events_failure_time CHECK
        (payment_failed_at IS NULL OR event_type = 'invoice.payment_failed');
CREATE INDEX billing_events_failure_anchor
    ON billing_events(stripe_subscription_id, payment_failed_at)
    WHERE payment_failed_at IS NOT NULL;

ALTER TABLE billing_subscriptions
    ADD COLUMN payment_grace_started_at timestamptz;
-- Unlike reconciled_at, this boundary does not advance on repeated past_due
-- reads while a matching failure webhook is delayed.
ALTER TABLE billing_subscriptions
    ADD COLUMN last_non_past_due_at timestamptz;
ALTER TABLE billing_subscriptions
    ADD COLUMN latest_invoice_id text CHECK (latest_invoice_id ~ '^in_[A-Za-z0-9]+$');
ALTER TABLE billing_subscriptions
    ADD COLUMN payment_grace_invoice_id text CHECK (payment_grace_invoice_id ~ '^in_[A-Za-z0-9]+$');
ALTER TABLE billing_subscriptions
    ADD CONSTRAINT billing_payment_grace_binding CHECK
        ((payment_grace_started_at IS NULL) = (payment_grace_invoice_id IS NULL));

ALTER TABLE billing_quota_audit DROP CONSTRAINT billing_quota_audit_reason_check;
ALTER TABLE billing_quota_audit ADD CONSTRAINT billing_quota_audit_reason_check CHECK
    (reason IN ('active', 'grace', 'inactive', 'ambiguous', 'unmapped', 'startup_reset'));
ALTER TABLE billing_device_cap_audit DROP CONSTRAINT billing_device_cap_audit_reason_check;
ALTER TABLE billing_device_cap_audit ADD CONSTRAINT billing_device_cap_audit_reason_check CHECK
    (reason IN ('active', 'grace', 'inactive', 'ambiguous', 'unmapped', 'startup_reset'));
