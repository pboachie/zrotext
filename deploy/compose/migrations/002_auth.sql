-- SPDX-License-Identifier: AGPL-3.0-only
-- Apply once under the deployment migration lock. This file is not loaded by
-- docker-entrypoint-initdb.d and is safe for an existing M0 database.
CREATE TABLE accounts (
    id uuid PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz
);

CREATE TABLE users (
    id uuid PRIMARY KEY,
    email text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    email_verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (email = lower(email)),
    CHECK (length(email) BETWEEN 3 AND 254)
);

CREATE TABLE memberships (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, user_id),
    UNIQUE (account_id),
    UNIQUE (user_id)
);

CREATE TABLE email_verifications (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (account_id, user_id) REFERENCES memberships(account_id, user_id) ON DELETE CASCADE
);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash) = 32),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    FOREIGN KEY (account_id, user_id) REFERENCES memberships(account_id, user_id) ON DELETE CASCADE
);
CREATE INDEX sessions_owner_active ON sessions(account_id, user_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE api_keys (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    created_by_user_id uuid NOT NULL,
    public_prefix text NOT NULL UNIQUE,
    token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
    scopes text[] NOT NULL,
    bound_device_id uuid,
    expires_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    FOREIGN KEY (account_id, created_by_user_id) REFERENCES memberships(account_id, user_id) ON DELETE CASCADE,
    CHECK (cardinality(scopes) BETWEEN 1 AND 8),
    CHECK (scopes <@ ARRAY['messages:send', 'messages:read', 'devices:read', 'devices:manage', 'webhooks:read', 'webhooks:manage', 'billing:read']::text[])
);
CREATE INDEX api_keys_owner ON api_keys(account_id, created_at DESC, id);
