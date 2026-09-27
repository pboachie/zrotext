-- SPDX-License-Identifier: AGPL-3.0-only
-- Dormant generation-one ceremony. Account-scoped replacement bounds storage;
-- public receipts and the independent044 marker survive ordinary cleanup.
CREATE TABLE sealed_root_challenges (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    challenge_id uuid NOT NULL UNIQUE,
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    root_pin bytea NOT NULL CHECK (octet_length(root_pin)=94),
    root_fingerprint bytea NOT NULL CHECK (octet_length(root_fingerprint)=32),
    nonce_digest bytea NOT NULL CHECK (octet_length(nonce_digest)=32),
    origin text NOT NULL CHECK (octet_length(origin) BETWEEN 1 AND 512),
    issued_ms bigint NOT NULL CHECK (issued_ms>0),
    expires_ms bigint NOT NULL,
    consumed_ms bigint,
    CHECK (expires_ms>issued_ms AND expires_ms-issued_ms<=300000),
    CHECK (consumed_ms IS NULL OR consumed_ms>=issued_ms)
);

-- Actor identifiers are historical copies, not foreign keys whose ordinary
-- session/user cleanup could delete a receipt or prevent account erasure.
CREATE TABLE sealed_root_receipts (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    challenge_id uuid NOT NULL UNIQUE,
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    root_pin bytea NOT NULL CHECK (octet_length(root_pin)=94),
    root_fingerprint bytea NOT NULL CHECK (octet_length(root_fingerprint)=32),
    completed_ms bigint NOT NULL CHECK (completed_ms>0)
);
CREATE TRIGGER sealed_root_receipt_before_update_or_delete
    BEFORE UPDATE OR DELETE ON sealed_root_receipts
    FOR EACH ROW EXECUTE FUNCTION sealed_trust_history_immutable();
CREATE TRIGGER sealed_root_receipt_before_truncate
    BEFORE TRUNCATE ON sealed_root_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION sealed_trust_history_immutable();
