-- SPDX-License-Identifier: AGPL-3.0-only
-- Verification mail is queued in the same transaction as its challenge.
-- The raw code is never stored: it is derived from the unpredictable
-- challenge UUID and the operational auth pepper by the delivery worker.
CREATE TABLE verification_mail_outbox (
    verification_id uuid PRIMARY KEY REFERENCES email_verifications(id) ON DELETE CASCADE,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 6),
    lease_id uuid,
    leased_until timestamptz,
    delivered_at timestamptz,
    canceled_at timestamptz,
    dead_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((lease_id IS NULL) = (leased_until IS NULL))
);
CREATE INDEX verification_mail_due ON verification_mail_outbox(next_attempt_at, verification_id)
    WHERE delivered_at IS NULL AND canceled_at IS NULL AND dead_at IS NULL;

ALTER TABLE users
    ADD COLUMN verification_resend_window_at timestamptz,
    ADD COLUMN verification_resend_last_at timestamptz,
    ADD COLUMN verification_resend_count integer NOT NULL DEFAULT 0
        CHECK (verification_resend_count BETWEEN 0 AND 3);
