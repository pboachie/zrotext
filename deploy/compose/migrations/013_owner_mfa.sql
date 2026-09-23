-- SPDX-License-Identifier: AGPL-3.0-only
-- Existing owners remain password-only until they confirm enrollment.
ALTER TABLE users ADD COLUMN mfa_enabled boolean NOT NULL DEFAULT false;

CREATE TABLE owner_mfa (
    account_id uuid PRIMARY KEY,
    user_id uuid NOT NULL UNIQUE,
    secret_nonce bytea NOT NULL CHECK (octet_length(secret_nonce) = 12),
    secret_ciphertext bytea NOT NULL CHECK (octet_length(secret_ciphertext) = 36),
    enabled_at timestamptz,
    pending_expires_at timestamptz,
    pending_session_id uuid,
    last_accepted_step bigint NOT NULL DEFAULT -1,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (account_id, user_id) REFERENCES memberships(account_id, user_id) ON DELETE CASCADE,
    UNIQUE (account_id, user_id),
    CHECK ((enabled_at IS NULL) = (pending_expires_at IS NOT NULL)),
    CHECK ((enabled_at IS NULL) = (pending_session_id IS NOT NULL))
);

CREATE TABLE owner_mfa_recovery_codes (
    account_id uuid NOT NULL,
    user_id uuid NOT NULL,
    code_hash bytea NOT NULL CHECK (octet_length(code_hash) = 32),
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, code_hash),
    FOREIGN KEY (account_id, user_id) REFERENCES owner_mfa(account_id, user_id) ON DELETE CASCADE
);

CREATE TABLE owner_mfa_login_challenges (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 5),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (account_id, user_id) REFERENCES memberships(account_id, user_id) ON DELETE CASCADE
);
CREATE INDEX owner_mfa_login_challenges_expiry ON owner_mfa_login_challenges(expires_at);
