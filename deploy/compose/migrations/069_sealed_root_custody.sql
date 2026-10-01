-- SPDX-License-Identifier: AGPL-3.0-only
-- Generation-one encrypted-only custody. An enrollment and its immutable bundle
-- are committed by one authenticated ceremony transaction, never by login.
CREATE TABLE sealed_root_custody (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    challenge_id uuid NOT NULL UNIQUE,
    backup_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation=1),
    root_pin bytea NOT NULL CHECK (octet_length(root_pin)=94),
    root_fingerprint bytea NOT NULL CHECK (octet_length(root_fingerprint)=32),
    encrypted_backup bytea NOT NULL CHECK (octet_length(encrypted_backup) BETWEEN 237 AND 748),
    public_card bytea NOT NULL CHECK (octet_length(public_card) BETWEEN 134 AND 645),
    backup_sha256 bytea NOT NULL CHECK (octet_length(backup_sha256)=32),
    card_sha256 bytea NOT NULL CHECK (octet_length(card_sha256)=32),
    unsigned_enrollment bytea NOT NULL CHECK (octet_length(unsigned_enrollment) BETWEEN 152 AND 663),
    custody_signature bytea NOT NULL CHECK (octet_length(custody_signature)=64),
    committed_ms bigint NOT NULL CHECK (committed_ms>0),
    FOREIGN KEY (account_id) REFERENCES sealed_root_receipts(account_id) ON DELETE CASCADE,
    UNIQUE (account_id,backup_id)
);
CREATE FUNCTION sealed_root_custody_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM sealed_root_receipts r
        JOIN sealed_manifest_authorities a USING (account_id)
        WHERE r.account_id=NEW.account_id AND r.challenge_id=NEW.challenge_id
        AND r.root_pin=NEW.root_pin AND r.root_fingerprint=NEW.root_fingerprint
        AND r.completed_ms=NEW.committed_ms AND a.generation=NEW.generation
        AND a.root_pin=NEW.root_pin AND a.root_fingerprint=NEW.root_fingerprint
    ) THEN
        RAISE EXCEPTION 'custody must match current enrollment' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sealed_root_custody_before_insert
    BEFORE INSERT ON sealed_root_custody
    FOR EACH ROW EXECUTE FUNCTION sealed_root_custody_insert_guard();
CREATE TRIGGER sealed_root_custody_before_update_or_delete
    BEFORE UPDATE OR DELETE ON sealed_root_custody
    FOR EACH ROW EXECUTE FUNCTION sealed_trust_history_immutable();
CREATE TRIGGER sealed_root_custody_before_truncate
    BEFORE TRUNCATE ON sealed_root_custody
    FOR EACH STATEMENT EXECUTE FUNCTION sealed_trust_history_immutable();
