-- SPDX-License-Identifier: AGPL-3.0-only
-- Dormant trust-lifecycle prerequisite. No enrollment endpoint is introduced.
-- Known points stay reserved after revocation, deletion or identity replacement.
-- This cannot recover keys deleted before this migration or classify unseen keys.
-- Fence concurrent key writers across the backfill/trigger installation boundary.
-- The migrator owns this transaction; lock failure rolls back the entire change.
LOCK TABLE sealed_manifest_authorities, device_keys,
    line_owner_approval_keys, sms_line_owner_approval_keys IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE known_signing_role_claims (
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    signing_key_sec1 bytea NOT NULL CHECK (octet_length(signing_key_sec1)=65),
    role text NOT NULL CHECK (role IN ('sealed_root','sms_approval','line_approval','device_auth')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (account_id,signing_key_sec1,role)
);

CREATE TABLE sealed_root_enrollments (
    account_id uuid PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    root_pin bytea NOT NULL CHECK (octet_length(root_pin)=94),
    root_fingerprint bytea NOT NULL CHECK (octet_length(root_fingerprint)=32),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Account serialization is shared with existing SMS/device registration. Never
-- lock an existing authority row here: admission holds authority before account.
CREATE FUNCTION known_signing_role_claim_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    PERFORM 1 FROM accounts WHERE id=NEW.account_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'signing role account is absent' USING ERRCODE='23503';
    END IF;
    IF EXISTS (
        SELECT 1 FROM known_signing_role_claims c
        WHERE c.account_id=NEW.account_id AND c.signing_key_sec1=NEW.signing_key_sec1
          AND c.role<>NEW.role
          AND (c.role IN ('sealed_root','sms_approval') OR
               NEW.role IN ('sealed_root','sms_approval'))
    ) THEN
        RAISE EXCEPTION 'public point is reserved for another signing role'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER known_signing_role_before_insert
    BEFORE INSERT ON known_signing_role_claims
    FOR EACH ROW EXECUTE FUNCTION known_signing_role_claim_guard();

-- Ordinary deletion must not erase trust history. Account erasure cascades only
-- after the parent is gone in the same transaction. Do not use trigger depth or
-- a caller-controlled session flag to grant an erasure exception.
CREATE FUNCTION sealed_trust_history_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        IF NOT EXISTS(SELECT 1 FROM accounts WHERE id=OLD.account_id) THEN
            RETURN OLD;
        END IF;
    END IF;
    RAISE EXCEPTION 'sealed trust history is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER known_signing_role_before_update_or_delete
    BEFORE UPDATE OR DELETE ON known_signing_role_claims
    FOR EACH ROW EXECUTE FUNCTION sealed_trust_history_immutable();
CREATE TRIGGER known_signing_role_before_truncate
    BEFORE TRUNCATE ON known_signing_role_claims
    FOR EACH STATEMENT EXECUTE FUNCTION sealed_trust_history_immutable();
CREATE TRIGGER sealed_root_enrollment_before_update_or_delete
    BEFORE UPDATE OR DELETE ON sealed_root_enrollments
    FOR EACH ROW EXECUTE FUNCTION sealed_trust_history_immutable();
CREATE TRIGGER sealed_root_enrollment_before_truncate
    BEFORE TRUNCATE ON sealed_root_enrollments
    FOR EACH STATEMENT EXECUTE FUNCTION sealed_trust_history_immutable();

CREATE FUNCTION reserve_known_signing_role() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    INSERT INTO known_signing_role_claims(account_id,signing_key_sec1,role)
    VALUES(NEW.account_id,NEW.signing_key_sec1,TG_ARGV[0])
    ON CONFLICT DO NOTHING;
    -- On device identity updates the OLD reservation already exists, from
    -- backfill or insertion. Never delete it or acquire an old-account lock.
    RETURN NEW;
END;
$$;
CREATE TRIGGER reserve_sms_signing_role_before_insert
    BEFORE INSERT ON sms_line_owner_approval_keys
    FOR EACH ROW EXECUTE FUNCTION reserve_known_signing_role('sms_approval');
CREATE TRIGGER reserve_line_signing_role_before_insert
    BEFORE INSERT ON line_owner_approval_keys
    FOR EACH ROW EXECUTE FUNCTION reserve_known_signing_role('line_approval');
CREATE TRIGGER reserve_device_signing_role_before_insert_or_identity_update
    BEFORE INSERT OR UPDATE OF account_id,signing_key_sec1 ON device_keys
    FOR EACH ROW EXECUTE FUNCTION reserve_known_signing_role('device_auth');

CREATE FUNCTION sealed_root_enrollment_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    PERFORM 1 FROM accounts WHERE id=NEW.account_id FOR UPDATE;
    -- Plain SELECT deliberately does not wait on the authority tuple lock.
    IF NOT EXISTS(SELECT 1 FROM sealed_manifest_authorities a
        WHERE a.account_id=NEW.account_id AND a.root_pin=NEW.root_pin
          AND a.root_fingerprint=NEW.root_fingerprint) THEN
        RAISE EXCEPTION 'root marker requires matching authority'
            USING ERRCODE='23514';
    END IF;
    INSERT INTO known_signing_role_claims(account_id,signing_key_sec1,role)
    VALUES(NEW.account_id,substring(NEW.root_pin from 30 for 65),'sealed_root')
    ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sealed_root_enrollment_before_insert
    BEFORE INSERT ON sealed_root_enrollments
    FOR EACH ROW EXECUTE FUNCTION sealed_root_enrollment_insert_guard();

-- Backfill every known row, including revoked keys and authorities. Conflicting
-- preexisting aliases fail the migration transaction; none are silently repinned.
INSERT INTO known_signing_role_claims(account_id,signing_key_sec1,role)
    SELECT account_id,signing_key_sec1,'device_auth' FROM device_keys
    ON CONFLICT DO NOTHING;
INSERT INTO known_signing_role_claims(account_id,signing_key_sec1,role)
    SELECT account_id,signing_key_sec1,'line_approval' FROM line_owner_approval_keys
    ON CONFLICT DO NOTHING;
INSERT INTO known_signing_role_claims(account_id,signing_key_sec1,role)
    SELECT account_id,signing_key_sec1,'sms_approval' FROM sms_line_owner_approval_keys
    ON CONFLICT DO NOTHING;
INSERT INTO sealed_root_enrollments(account_id,root_pin,root_fingerprint)
    SELECT account_id,root_pin,root_fingerprint FROM sealed_manifest_authorities;

CREATE FUNCTION sealed_authority_genesis_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    PERFORM 1 FROM accounts WHERE id=NEW.account_id FOR UPDATE;
    -- Serialize absent genesis, then re-read committed history. Do not lock an
    -- existing authority after account, including a revoked or expired one.
    IF EXISTS(SELECT 1 FROM sealed_root_enrollments WHERE account_id=NEW.account_id)
       OR EXISTS(SELECT 1 FROM sealed_manifest_authorities WHERE account_id=NEW.account_id) THEN
        RAISE EXCEPTION 'account already has root enrollment history'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sealed_authority_before_insert
    BEFORE INSERT ON sealed_manifest_authorities
    FOR EACH ROW EXECUTE FUNCTION sealed_authority_genesis_guard();

CREATE FUNCTION record_sealed_root_enrollment() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    INSERT INTO sealed_root_enrollments(account_id,root_pin,root_fingerprint)
    VALUES(NEW.account_id,NEW.root_pin,NEW.root_fingerprint);
    RETURN NEW;
END;
$$;
CREATE TRIGGER sealed_authority_after_insert
    AFTER INSERT ON sealed_manifest_authorities
    FOR EACH ROW EXECUTE FUNCTION record_sealed_root_enrollment();
-- Existing035 guards and authority UPDATE behavior remain intact. These tables
-- record database-known history only, not human comparison or root possession.
