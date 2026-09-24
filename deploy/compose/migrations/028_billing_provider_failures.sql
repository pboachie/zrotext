-- SPDX-License-Identifier: AGPL-3.0-only
-- Keep failed provider reads visible and bounded without trusting webhook data.
ALTER TABLE billing_reconciliations ADD COLUMN state text NOT NULL DEFAULT 'queued'
    CHECK (state IN ('queued', 'needs_review'));
ALTER TABLE billing_reconciliations ADD COLUMN last_failure_class text;
ALTER TABLE billing_reconciliations ADD CONSTRAINT billing_reconciliation_failure_class CHECK
    (last_failure_class IS NULL OR last_failure_class IN ('authorization', 'missing', 'http', 'transport', 'invalid_response', 'local'));
CREATE INDEX billing_reconciliations_review ON billing_reconciliations(account_id)
    WHERE state='needs_review';

ALTER TABLE billing_risk_events ADD COLUMN last_failure_class text;
ALTER TABLE billing_risk_events ADD CONSTRAINT billing_risk_failure_class CHECK
    (last_failure_class IS NULL OR last_failure_class IN ('authorization', 'missing', 'http', 'transport', 'invalid_response', 'local'));

ALTER TABLE billing_quota_audit DROP CONSTRAINT billing_quota_audit_reason_check;
ALTER TABLE billing_quota_audit ADD CONSTRAINT billing_quota_audit_reason_check CHECK
    (reason IN ('active', 'grace', 'inactive', 'ambiguous', 'unmapped', 'startup_reset', 'provider_deleted'));
ALTER TABLE billing_device_cap_audit DROP CONSTRAINT billing_device_cap_audit_reason_check;
ALTER TABLE billing_device_cap_audit ADD CONSTRAINT billing_device_cap_audit_reason_check CHECK
    (reason IN ('active', 'grace', 'inactive', 'ambiguous', 'unmapped', 'startup_reset', 'provider_deleted'));
