-- SPDX-License-Identifier: AGPL-3.0-only
-- Requires the complete numbered predecessor train. This is pending-owner
-- authentication metadata; it grants no content, device, or root authority.
CREATE TABLE registration_browser_intents (
    intent_hash bytea PRIMARY KEY CHECK (octet_length(intent_hash) = 32),
    csrf_hash bytea NOT NULL CHECK (octet_length(csrf_hash) = 32),
    account_id uuid NOT NULL,
    user_id uuid NOT NULL UNIQUE,
    email text NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
    password_binding bytea NOT NULL CHECK (octet_length(password_binding) = 32),
    verification_id uuid NOT NULL REFERENCES email_verifications(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    verification_attempts integer NOT NULL DEFAULT 0 CHECK (verification_attempts BETWEEN 0 AND 8),
    consumed_at timestamptz,
    retired_at timestamptz,
    FOREIGN KEY (account_id, user_id) REFERENCES memberships(account_id, user_id) ON DELETE CASCADE,
    CHECK (expires_at = created_at + interval '15 minutes'),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    CHECK (retired_at IS NULL OR retired_at >= created_at)
);

CREATE INDEX registration_browser_intents_expiry ON registration_browser_intents(expires_at);

CREATE FUNCTION registration_browser_intent_binding_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
DECLARE
    generation_matches boolean;
BEGIN
    IF TG_OP = 'UPDATE' AND (
        NEW.intent_hash IS DISTINCT FROM OLD.intent_hash OR
        NEW.csrf_hash IS DISTINCT FROM OLD.csrf_hash OR
        NEW.account_id IS DISTINCT FROM OLD.account_id OR
        NEW.user_id IS DISTINCT FROM OLD.user_id OR
        NEW.email IS DISTINCT FROM OLD.email OR
        NEW.password_binding IS DISTINCT FROM OLD.password_binding OR
        NEW.created_at IS DISTINCT FROM OLD.created_at OR
        NEW.expires_at IS DISTINCT FROM OLD.expires_at OR
        NEW.verification_attempts < OLD.verification_attempts OR
        (OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at) OR
        (OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at)
    ) THEN
        RAISE EXCEPTION 'registration intent binding is immutable' USING ERRCODE = '23514';
    END IF;
    EXECUTE pg_catalog.format(
        'SELECT EXISTS (SELECT 1 FROM %I.email_verifications WHERE id=$1 AND account_id=$2 AND user_id=$3)',
        TG_TABLE_SCHEMA
    ) INTO generation_matches USING NEW.verification_id,NEW.account_id,NEW.user_id;
    IF NOT generation_matches THEN
        RAISE EXCEPTION 'registration intent generation ownership mismatch' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER registration_browser_intent_binding_guard
BEFORE INSERT OR UPDATE ON registration_browser_intents
FOR EACH ROW EXECUTE FUNCTION registration_browser_intent_binding_guard();

REVOKE ALL ON FUNCTION registration_browser_intent_binding_guard() FROM PUBLIC;
DO $$
BEGIN
    IF current_schema()='public' AND EXISTS (
        SELECT FROM pg_catalog.pg_roles WHERE rolname='zrotext_runtime'
    ) THEN
        REVOKE ALL ON FUNCTION registration_browser_intent_binding_guard() FROM zrotext_runtime;
    END IF;
END;
$$;
