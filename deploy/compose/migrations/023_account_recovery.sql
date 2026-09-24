-- SPDX-License-Identifier: AGPL-3.0-only
-- One-use, one-hour password reset codes. The raw code is derived from the
-- operational token pepper only while a live outbox claim is being sent.
CREATE TABLE password_resets (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (account_id, user_id) REFERENCES memberships(account_id, user_id) ON DELETE CASCADE
);
CREATE INDEX password_resets_owner_live ON password_resets(account_id, user_id, created_at DESC)
    WHERE used_at IS NULL;

CREATE TABLE password_reset_mail_outbox (
    reset_id uuid PRIMARY KEY REFERENCES password_resets(id) ON DELETE CASCADE,
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
CREATE INDEX password_reset_mail_due ON password_reset_mail_outbox(next_attempt_at, reset_id)
    WHERE delivered_at IS NULL AND canceled_at IS NULL AND dead_at IS NULL;

CREATE TABLE password_reset_notice_outbox (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    user_id uuid NOT NULL,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 6),
    lease_id uuid,
    leased_until timestamptz,
    delivered_at timestamptz,
    dead_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (account_id, user_id) REFERENCES memberships(account_id, user_id) ON DELETE CASCADE,
    CHECK ((lease_id IS NULL) = (leased_until IS NULL))
);
CREATE INDEX password_reset_notice_due ON password_reset_notice_outbox(next_attempt_at, id)
    WHERE delivered_at IS NULL AND dead_at IS NULL;
