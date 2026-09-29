-- SPDX-License-Identifier: AGPL-3.0-only
-- Owner-issued device-status observer invitations. The database stores only
-- the HMAC of the opaque invitation token; the raw token is shown once to the
-- owner and handed to the invitee out of band. An account holds at most one
-- open invitation per address; other accounts are deliberately not blocked, so
-- inviting an address never reveals whether it is registered or invited
-- elsewhere. Acceptance is single-use and bound to the stored address, and a
-- token whose address already belongs to a user is refused at acceptance; the
-- resulting membership uses the observer role added in 048.
CREATE TABLE seat_invitations (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email text NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    canceled_at timestamptz,
    accepted_user_id uuid REFERENCES users(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX seat_invitations_one_open_per_account_address
    ON seat_invitations(account_id, email) WHERE accepted_at IS NULL AND canceled_at IS NULL;
CREATE INDEX seat_invitations_account_recent
    ON seat_invitations(account_id, created_at DESC, id DESC);
CREATE INDEX seat_invitations_expiry
    ON seat_invitations(expires_at) WHERE accepted_at IS NULL AND canceled_at IS NULL;
