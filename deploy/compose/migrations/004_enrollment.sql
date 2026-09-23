-- SPDX-License-Identifier: AGPL-3.0-only
-- M1 enrollment. Apply once under the migration lock after 003_delivery.
-- Pairing secrets and authentication challenges are never stored in plaintext.
CREATE TABLE pairing_requests (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    created_by_user_id uuid NOT NULL,
    token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 64),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    claimed_at timestamptz,
    signing_key_sec1 bytea,
    key_fingerprint bytea CHECK (key_fingerprint IS NULL OR octet_length(key_fingerprint) = 32),
    comparison_code text CHECK (comparison_code IS NULL OR comparison_code ~ '^[0-9]{8}$'),
    challenge_digest bytea CHECK (challenge_digest IS NULL OR octet_length(challenge_digest) = 32),
    challenge_consumed_at timestamptz,
    proof_verified_at timestamptz,
    approval_failures smallint NOT NULL DEFAULT 0 CHECK (approval_failures BETWEEN 0 AND 5),
    approved_at timestamptz,
    device_id uuid,
    cancelled_at timestamptz,
    FOREIGN KEY (account_id, created_by_user_id) REFERENCES memberships(account_id, user_id),
    FOREIGN KEY (account_id, device_id) REFERENCES devices(account_id, id),
    CHECK (expires_at > created_at),
    CHECK ((claimed_at IS NULL) = (signing_key_sec1 IS NULL)),
    CHECK ((claimed_at IS NULL) = (key_fingerprint IS NULL)),
    CHECK ((claimed_at IS NULL) = (comparison_code IS NULL)),
    CHECK ((claimed_at IS NULL) = (challenge_digest IS NULL)),
    CHECK (proof_verified_at IS NULL OR challenge_consumed_at IS NOT NULL),
    CHECK (approved_at IS NULL OR (proof_verified_at IS NOT NULL AND device_id IS NOT NULL))
);
CREATE INDEX pairing_requests_owner ON pairing_requests(account_id, created_at DESC, id);

CREATE TABLE device_keys (
    device_id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    signing_key_sec1 bytea NOT NULL CHECK (octet_length(signing_key_sec1) = 65),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    FOREIGN KEY (account_id, device_id) REFERENCES devices(account_id, id),
    UNIQUE (account_id, device_id)
);

CREATE TABLE device_auth_challenges (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    device_id uuid NOT NULL,
    nonce_digest bytea NOT NULL UNIQUE CHECK (octet_length(nonce_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    FOREIGN KEY (account_id, device_id) REFERENCES device_keys(account_id, device_id),
    CHECK (expires_at > created_at)
);
CREATE INDEX device_auth_challenges_expiry ON device_auth_challenges(expires_at);
