-- SPDX-License-Identifier: AGPL-3.0-only
-- Operator decisions for signed TEST-mode risk events that require review.
-- A failed/canceled refund can be closed only after a fresh provider read;
-- other risks remain review-required until a paid subscription hold is proven.

ALTER TABLE billing_risk_events
    DROP CONSTRAINT billing_risk_events_state_check;
ALTER TABLE billing_risk_events
    ADD CONSTRAINT billing_risk_events_state_check
        CHECK (state IN ('queued','held','needs_review','closed_failed_refund'));

CREATE TABLE billing_risk_review_actions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    stripe_event_id text NOT NULL REFERENCES billing_risk_events(stripe_event_id),
    operator_id text NOT NULL CHECK (operator_id ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$'),
    action text NOT NULL CHECK (action IN ('attributed_unbound','held','closed_failed_refund')),
    stripe_object_id text NOT NULL,
    stripe_charge_id text CHECK (stripe_charge_id ~ '^(ch|py)_[A-Za-z0-9]+$'),
    stripe_payment_intent_id text CHECK (stripe_payment_intent_id ~ '^pi_[A-Za-z0-9]+$'),
    stripe_customer_id text CHECK (stripe_customer_id ~ '^cus_[A-Za-z0-9]+$'),
    stripe_subscription_id text CHECK (stripe_subscription_id ~ '^sub_[A-Za-z0-9]+$'),
    reviewed_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (stripe_event_id, action)
);
CREATE INDEX billing_risk_review_actions_recent
    ON billing_risk_review_actions(reviewed_at DESC, id DESC);
CREATE UNIQUE INDEX billing_risk_review_actions_one_final
    ON billing_risk_review_actions(stripe_event_id)
    WHERE action IN ('held','closed_failed_refund');
