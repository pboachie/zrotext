-- SPDX-License-Identifier: AGPL-3.0-only
-- Isolated test-mode payment-risk slice after entitlement migration 009.
-- Combined stack already uses 010 and 011; renumber this migration to 012.

CREATE TABLE billing_risk_events (
    stripe_event_id text PRIMARY KEY REFERENCES billing_events(stripe_event_id),
    stripe_charge_id text NOT NULL CHECK (stripe_charge_id ~ '^ch_[A-Za-z0-9]+$'),
    risk_kind text NOT NULL CHECK (risk_kind IN ('refund', 'dispute')),
    state text NOT NULL DEFAULT 'queued'
        CHECK (state IN ('queued', 'held', 'needs_review')),
    account_id uuid REFERENCES accounts(id),
    stripe_subscription_id text,
    failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    processed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX billing_risk_events_pending ON billing_risk_events(next_attempt_at, stripe_event_id)
    WHERE state='queued';

-- Append-only evidence of a hold. There is deliberately no automatic release:
-- refund amount and dispute outcome policies require operator review.
CREATE TABLE billing_payment_holds (
    stripe_event_id text PRIMARY KEY REFERENCES billing_risk_events(stripe_event_id),
    account_id uuid NOT NULL REFERENCES accounts(id),
    stripe_subscription_id text NOT NULL CHECK (stripe_subscription_id ~ '^sub_[A-Za-z0-9]+$'),
    stripe_charge_id text NOT NULL CHECK (stripe_charge_id ~ '^ch_[A-Za-z0-9]+$'),
    reason text NOT NULL CHECK (reason IN ('refund', 'dispute')),
    held_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX billing_payment_holds_account ON billing_payment_holds(account_id, held_at DESC);
