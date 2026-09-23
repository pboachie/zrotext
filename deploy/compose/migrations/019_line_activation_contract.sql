-- SPDX-License-Identifier: AGPL-3.0-only
-- M2 internal line-activation prerequisite. No API provisions owner keys or
-- accepts activation proofs yet. A future signed-manifest/root-pin ceremony
-- must establish an owner key before this transaction can be exposed.

-- Keep an issuance high-water mark separate from the active generation. A
-- lost/revoked pending device burns its generation without interrupting the
-- current active binding. Its tombstone and challenge remain auditable.
ALTER TABLE phone_lines ADD COLUMN last_issued_generation bigint NOT NULL DEFAULT 0
    CHECK (last_issued_generation >= 0);
UPDATE phone_lines SET last_issued_generation=current_binding_generation;
ALTER TABLE phone_lines ADD CONSTRAINT phone_lines_issued_at_least_active
    CHECK (last_issued_generation >= current_binding_generation);

CREATE FUNCTION phone_line_issued_generation_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.last_issued_generation < OLD.last_issued_generation THEN
        RAISE EXCEPTION 'issued line generation cannot roll back'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER phone_line_issued_generation_before_update
    BEFORE UPDATE ON phone_lines
    FOR EACH ROW EXECUTE FUNCTION phone_line_issued_generation_guard();

CREATE TABLE line_owner_approval_keys (
    account_id uuid NOT NULL REFERENCES accounts(id),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    signing_key_sec1 bytea NOT NULL CHECK (octet_length(signing_key_sec1) = 65),
    installed_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    PRIMARY KEY (account_id, fingerprint)
);
CREATE UNIQUE INDEX line_owner_approval_keys_one_active
    ON line_owner_approval_keys(account_id) WHERE revoked_at IS NULL;

CREATE FUNCTION line_owner_key_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'line owner key cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF NEW.account_id <> OLD.account_id OR
       NEW.fingerprint <> OLD.fingerprint OR
       NEW.signing_key_sec1 <> OLD.signing_key_sec1 OR
       NEW.installed_at <> OLD.installed_at OR
       (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
        RAISE EXCEPTION 'line owner key identity or revocation cannot roll back'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER line_owner_key_before_update
    BEFORE UPDATE ON line_owner_approval_keys
    FOR EACH ROW EXECUTE FUNCTION line_owner_key_guard();
CREATE TRIGGER line_owner_key_before_delete
    BEFORE DELETE ON line_owner_approval_keys
    FOR EACH ROW EXECUTE FUNCTION line_owner_key_guard();

CREATE TABLE line_activation_challenges (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL,
    line_id uuid NOT NULL,
    device_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    nonce_digest bytea NOT NULL UNIQUE CHECK (octet_length(nonce_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    FOREIGN KEY (account_id, line_id, device_id, generation)
        REFERENCES device_line_bindings(account_id, line_id, device_id, generation),
    CHECK (expires_at > created_at)
);
CREATE INDEX line_activation_challenges_expiry
    ON line_activation_challenges(expires_at) WHERE consumed_at IS NULL;

CREATE FUNCTION line_activation_challenge_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'line activation challenge cannot be deleted'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.id <> OLD.id OR NEW.account_id <> OLD.account_id OR
       NEW.line_id <> OLD.line_id OR NEW.device_id <> OLD.device_id OR
       NEW.generation <> OLD.generation OR NEW.nonce_digest <> OLD.nonce_digest OR
       NEW.created_at <> OLD.created_at OR NEW.expires_at <> OLD.expires_at OR
       (OLD.consumed_at IS NOT NULL AND
        NEW.consumed_at IS DISTINCT FROM OLD.consumed_at) THEN
        RAISE EXCEPTION 'line activation challenge cannot change or replay'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER line_activation_challenge_before_update
    BEFORE UPDATE ON line_activation_challenges
    FOR EACH ROW EXECUTE FUNCTION line_activation_challenge_guard();
CREATE TRIGGER line_activation_challenge_before_delete
    BEFORE DELETE ON line_activation_challenges
    FOR EACH ROW EXECUTE FUNCTION line_activation_challenge_guard();
