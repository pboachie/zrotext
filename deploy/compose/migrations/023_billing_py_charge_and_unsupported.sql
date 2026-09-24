-- SPDX-License-Identifier: AGPL-3.0-only
-- Non-card payment methods (SEPA Direct Debit, ACH, Bacs) create
-- PaymentIntent-scoped charges with `py_` IDs. Refunds and disputes on those
-- charges follow the same payment-risk hold path as card charges. Existing
-- rows already satisfy the relaxed constraints; no row is rewritten.

ALTER TABLE billing_risk_events
    DROP CONSTRAINT billing_risk_events_stripe_charge_id_check;
ALTER TABLE billing_risk_events
    ADD CONSTRAINT billing_risk_events_stripe_charge_id_check
        CHECK (stripe_charge_id ~ '^(ch|py)_[A-Za-z0-9]+$');
-- Stripe documents Refund.charge as nullable. Keep a PaymentIntent pointer
-- until a bounded provider read resolves the associated Charge.
ALTER TABLE billing_risk_events
    ALTER COLUMN stripe_charge_id DROP NOT NULL;
ALTER TABLE billing_risk_events
    ADD COLUMN stripe_payment_intent_id text
        CHECK (stripe_payment_intent_id ~ '^pi_[A-Za-z0-9]+$');
ALTER TABLE billing_risk_events
    ADD CONSTRAINT billing_risk_events_pointer_or_review_check
        CHECK (stripe_charge_id IS NOT NULL OR stripe_payment_intent_id IS NOT NULL OR state='needs_review');
ALTER TABLE billing_payment_holds
    DROP CONSTRAINT billing_payment_holds_stripe_charge_id_check;
ALTER TABLE billing_payment_holds
    ADD CONSTRAINT billing_payment_holds_stripe_charge_id_check
        CHECK (stripe_charge_id ~ '^(ch|py)_[A-Za-z0-9]+$');

-- A correctly signed test-mode event with an unexpected object shape is
-- acknowledged with 2xx and durably recorded instead of being dropped.
ALTER TABLE billing_events
    DROP CONSTRAINT billing_events_disposition_check;
ALTER TABLE billing_events
    ADD CONSTRAINT billing_events_disposition_check
        CHECK (disposition IN ('queued', 'unbound', 'ignored', 'conflict', 'unsupported'));
