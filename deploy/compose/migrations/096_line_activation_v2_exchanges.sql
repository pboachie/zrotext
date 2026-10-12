-- SPDX-License-Identifier: AGPL-3.0-only
-- Keep removable pending nonces separate from durable observation provenance.
-- Existing v1 exchange tables and their count-one constraints stay unchanged.
CREATE TABLE line_activation_v2_pending (
    challenge_id uuid PRIMARY KEY REFERENCES line_activation_challenges(id),
    protocol_version smallint NOT NULL DEFAULT 2 CHECK (protocol_version = 2),
    purpose text NOT NULL CHECK (purpose IN ('sms', 'sealed')),
    opening_id uuid NOT NULL,
    account_id uuid NOT NULL,
    line_id uuid NOT NULL,
    device_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    initiating_user_id uuid NOT NULL,
    initiating_session_id uuid NOT NULL REFERENCES sessions(id),
    registration_id uuid,
    site_id text NOT NULL,
    instance_id text NOT NULL,
    connection_epoch bigint NOT NULL CHECK (connection_epoch > 0),
    deployment_epoch bigint NOT NULL CHECK (deployment_epoch > 0),
    device_fingerprint bytea NOT NULL CHECK (octet_length(device_fingerprint) = 32),
    owner_fingerprint bytea NOT NULL CHECK (octet_length(owner_fingerprint) = 32),
    nonce bytea CHECK (nonce IS NULL OR octet_length(nonce) = 32),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    owner_signature_sha256 bytea CHECK (owner_signature_sha256 IS NULL OR octet_length(owner_signature_sha256) = 32),
    approved_at timestamptz,
    installed_at timestamptz,
    retired_at timestamptz,
    UNIQUE (account_id, purpose, opening_id),
    UNIQUE (challenge_id, account_id, line_id, device_id, generation, purpose),
    FOREIGN KEY (account_id, line_id, device_id, generation)
        REFERENCES device_line_bindings(account_id, line_id, device_id, generation),
    FOREIGN KEY (account_id, registration_id)
        REFERENCES sealed_line_key_receipts(account_id, registration_id),
    CHECK ((purpose = 'sealed') = (registration_id IS NOT NULL)),
    CHECK ((approved_at IS NULL) = (owner_signature_sha256 IS NULL)),
    CHECK (installed_at IS NULL OR (purpose = 'sealed' AND approved_at IS NOT NULL AND nonce IS NULL)),
    CHECK (retired_at IS NULL OR nonce IS NULL),
    CHECK (nonce IS NOT NULL OR installed_at IS NOT NULL OR retired_at IS NOT NULL)
);
CREATE INDEX line_activation_v2_pending_device
    ON line_activation_v2_pending(account_id, device_id, purpose, created_at)
    WHERE installed_at IS NULL AND retired_at IS NULL;
CREATE INDEX line_activation_v2_pending_registration
    ON line_activation_v2_pending(account_id, registration_id) WHERE nonce IS NOT NULL;

CREATE FUNCTION line_activation_v2_pending_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'v2 pending identity cannot be deleted' USING ERRCODE = '23514';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.nonce IS NULL OR NEW.approved_at IS NOT NULL OR NEW.installed_at IS NOT NULL
           OR NEW.retired_at IS NOT NULL OR NOT EXISTS (
            SELECT 1 FROM line_activation_challenges c JOIN device_line_bindings b
                ON (b.account_id,b.line_id,b.device_id,b.generation) =
                   (c.account_id,c.line_id,c.device_id,c.generation)
            WHERE c.id=NEW.challenge_id AND c.protocol_version=2 AND c.consumed_at IS NULL
                AND (c.account_id,c.line_id,c.device_id,c.generation) =
                    (NEW.account_id,NEW.line_id,NEW.device_id,NEW.generation)
                AND b.purpose=NEW.purpose AND c.expires_at=NEW.expires_at) THEN
            RAISE EXCEPTION 'v2 pending challenge scope differs' USING ERRCODE = '23514';
        END IF;
    ELSIF (to_jsonb(NEW) - ARRAY['nonce','owner_signature_sha256','approved_at','installed_at','retired_at'])
            IS DISTINCT FROM
          (to_jsonb(OLD) - ARRAY['nonce','owner_signature_sha256','approved_at','installed_at','retired_at'])
        OR (OLD.nonce IS NULL AND NEW.nonce IS NOT NULL)
        OR (OLD.nonce IS NOT NULL AND NEW.nonce IS NOT NULL AND NEW.nonce<>OLD.nonce)
        OR (OLD.owner_signature_sha256 IS NOT NULL AND NEW.owner_signature_sha256 IS DISTINCT FROM OLD.owner_signature_sha256)
        OR (OLD.approved_at IS NOT NULL AND NEW.approved_at IS DISTINCT FROM OLD.approved_at)
        OR (OLD.installed_at IS NOT NULL AND NEW.installed_at IS DISTINCT FROM OLD.installed_at)
        OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at) THEN
        RAISE EXCEPTION 'v2 pending identity or terminal state cannot change' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER line_activation_v2_pending_before_insert_or_update
    BEFORE INSERT OR UPDATE ON line_activation_v2_pending
    FOR EACH ROW EXECUTE FUNCTION line_activation_v2_pending_guard();
CREATE TRIGGER line_activation_v2_pending_before_delete
    BEFORE DELETE ON line_activation_v2_pending
    FOR EACH ROW EXECUTE FUNCTION line_activation_v2_pending_guard();

CREATE TABLE line_activation_v2_observations (
    challenge_id uuid PRIMARY KEY,
    protocol_version smallint NOT NULL DEFAULT 2 CHECK (protocol_version = 2),
    purpose text NOT NULL CHECK (purpose IN ('sms', 'sealed')),
    account_id uuid NOT NULL,
    line_id uuid NOT NULL,
    device_id uuid NOT NULL,
    generation bigint NOT NULL CHECK (generation > 0),
    observation bytea NOT NULL CHECK (octet_length(observation) = 121),
    device_signature_der bytea NOT NULL CHECK (octet_length(device_signature_der) BETWEEN 8 AND 80),
    device_statement_sha256 bytea NOT NULL CHECK (octet_length(device_statement_sha256) = 32),
    device_signature_sha256 bytea NOT NULL CHECK (octet_length(device_signature_sha256) = 32),
    confirmation_digest bytea NOT NULL CHECK (octet_length(confirmation_digest) = 32),
    device_fingerprint bytea NOT NULL CHECK (octet_length(device_fingerprint) = 32),
    proof_site_id text NOT NULL,
    proof_instance_id text NOT NULL,
    proof_connection_epoch bigint NOT NULL CHECK (proof_connection_epoch > 0),
    proof_deployment_epoch bigint NOT NULL CHECK (proof_deployment_epoch > 0),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (challenge_id, account_id, line_id, device_id, generation, purpose)
        REFERENCES line_activation_v2_pending(challenge_id, account_id, line_id, device_id, generation, purpose)
);
CREATE FUNCTION line_activation_v2_observation_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'v2 observation provenance is immutable' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM line_activation_v2_pending p JOIN line_activation_challenges c
        ON c.id=p.challenge_id WHERE p.challenge_id=NEW.challenge_id
        AND p.nonce IS NOT NULL AND p.retired_at IS NULL AND p.approved_at IS NULL
        AND c.protocol_version=2 AND c.consumed_at IS NULL AND c.expires_at>clock_timestamp()
        AND (p.device_fingerprint,p.site_id,p.instance_id,p.connection_epoch,p.deployment_epoch)=
            (NEW.device_fingerprint,NEW.proof_site_id,NEW.proof_instance_id,NEW.proof_connection_epoch,NEW.proof_deployment_epoch)) THEN
        RAISE EXCEPTION 'v2 proof admission differs' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER line_activation_v2_observation_before_insert_or_update_or_delete
    BEFORE INSERT OR UPDATE OR DELETE ON line_activation_v2_observations
    FOR EACH ROW EXECUTE FUNCTION line_activation_v2_observation_guard();
