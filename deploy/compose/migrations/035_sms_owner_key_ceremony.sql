-- SPDX-License-Identifier: AGPL-3.0-only
-- Public-key possession challenges for the SMS-only owner approval role.
-- The server never stores or handles an owner private signing key.
CREATE TABLE sms_owner_key_challenges (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    user_id uuid NOT NULL,
    session_id uuid NOT NULL REFERENCES sessions(id),
    signing_key_sec1 bytea NOT NULL CHECK (octet_length(signing_key_sec1)=65),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint)=32),
    nonce_digest bytea NOT NULL UNIQUE CHECK (octet_length(nonce_digest)=32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    FOREIGN KEY (account_id,user_id) REFERENCES memberships(account_id,user_id),
    CHECK (expires_at>created_at)
);
CREATE INDEX sms_owner_key_challenges_expiry
    ON sms_owner_key_challenges(expires_at) WHERE consumed_at IS NULL;

CREATE FUNCTION sms_owner_key_challenge_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        IF OLD.expires_at<clock_timestamp()-interval '1 hour' THEN
            RETURN OLD;
        END IF;
        RAISE EXCEPTION 'live SMS owner key challenge cannot be deleted' USING ERRCODE='23514';
    END IF;
    IF NEW.id<>OLD.id OR NEW.account_id<>OLD.account_id OR
       NEW.user_id<>OLD.user_id OR NEW.session_id<>OLD.session_id OR
       NEW.signing_key_sec1<>OLD.signing_key_sec1 OR
       NEW.fingerprint<>OLD.fingerprint OR NEW.nonce_digest<>OLD.nonce_digest OR
       NEW.created_at<>OLD.created_at OR NEW.expires_at<>OLD.expires_at OR
       (OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at) THEN
        RAISE EXCEPTION 'SMS owner key challenge cannot change identity or replay' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sms_owner_key_challenge_before_update
    BEFORE UPDATE ON sms_owner_key_challenges
    FOR EACH ROW EXECUTE FUNCTION sms_owner_key_challenge_guard();
CREATE TRIGGER sms_owner_key_challenge_before_delete
    BEFORE DELETE ON sms_owner_key_challenges
    FOR EACH ROW EXECUTE FUNCTION sms_owner_key_challenge_guard();

CREATE TABLE sms_owner_key_audit (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id),
    user_id uuid NOT NULL REFERENCES users(id),
    session_id uuid NOT NULL REFERENCES sessions(id),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint)=32),
    event text NOT NULL CHECK (event IN ('registered','revoked')),
    affected_sms_bindings bigint NOT NULL DEFAULT 0 CHECK (affected_sms_bindings>=0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION sms_owner_key_audit_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    RAISE EXCEPTION 'SMS owner key audit is append-only' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER sms_owner_key_audit_before_update_or_delete
    BEFORE UPDATE OR DELETE ON sms_owner_key_audit
    FOR EACH ROW EXECUTE FUNCTION sms_owner_key_audit_immutable();

-- Keep the three signing roles distinct even for direct database writers.
-- The account lock serializes this with owner registration and device approval.
DO $$
BEGIN
    IF EXISTS(
        SELECT 1 FROM sms_line_owner_approval_keys s
        WHERE EXISTS(SELECT 1 FROM line_owner_approval_keys o WHERE o.account_id=s.account_id AND o.signing_key_sec1=s.signing_key_sec1)
           OR EXISTS(SELECT 1 FROM device_keys d WHERE d.account_id=s.account_id AND d.signing_key_sec1=s.signing_key_sec1)
    ) THEN
        RAISE EXCEPTION 'existing SMS owner key aliases another signing role' USING ERRCODE='23514';
    END IF;
END;
$$;
CREATE FUNCTION sms_owner_key_role_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    PERFORM 1 FROM accounts WHERE id=NEW.account_id FOR UPDATE;
    IF TG_TABLE_NAME='sms_line_owner_approval_keys' THEN
        IF EXISTS(SELECT 1 FROM line_owner_approval_keys WHERE account_id=NEW.account_id AND signing_key_sec1=NEW.signing_key_sec1)
           OR EXISTS(SELECT 1 FROM device_keys WHERE account_id=NEW.account_id AND signing_key_sec1=NEW.signing_key_sec1) THEN
            RAISE EXCEPTION 'SMS owner key aliases another signing role' USING ERRCODE='23514';
        END IF;
    ELSIF TG_TABLE_NAME='line_owner_approval_keys' OR TG_TABLE_NAME='device_keys' THEN
        IF EXISTS(SELECT 1 FROM sms_line_owner_approval_keys WHERE account_id=NEW.account_id AND signing_key_sec1=NEW.signing_key_sec1) THEN
            RAISE EXCEPTION 'signing key aliases SMS owner role' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER sms_owner_key_role_before_insert
    BEFORE INSERT ON sms_line_owner_approval_keys
    FOR EACH ROW EXECUTE FUNCTION sms_owner_key_role_guard();
CREATE TRIGGER sealed_owner_key_role_before_insert
    BEFORE INSERT ON line_owner_approval_keys
    FOR EACH ROW EXECUTE FUNCTION sms_owner_key_role_guard();
CREATE TRIGGER device_key_sms_role_before_insert
    BEFORE INSERT OR UPDATE OF account_id,signing_key_sec1 ON device_keys
    FOR EACH ROW EXECUTE FUNCTION sms_owner_key_role_guard();
