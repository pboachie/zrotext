-- SPDX-License-Identifier: AGPL-3.0-only
-- Dormant exact conversation activation and original verified ingest provenance.
ALTER TABLE sessions ADD CONSTRAINT sessions_account_identity UNIQUE(account_id,id);
CREATE TABLE conversation_intervals (
    account_id uuid NOT NULL REFERENCES accounts(id),
    id uuid NOT NULL,
    receipt_id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    device_id uuid NOT NULL,
    line_id uuid NOT NULL,
    binding_generation bigint NOT NULL CHECK(binding_generation>0),
    initiating_session_id uuid NOT NULL,
    statement bytea CHECK(octet_length(statement) BETWEEN 380 AND 1024),
    statement_digest bytea NOT NULL CHECK(octet_length(statement_digest)=32),
    manifest bytea NOT NULL CHECK(octet_length(manifest) BETWEEN 364 AND 9751),
    trust_generation bigint NOT NULL CHECK(trust_generation>0),
    activation_version bigint NOT NULL CHECK(activation_version>1),
    activation_digest bytea NOT NULL CHECK(octet_length(activation_digest)=32),
    expires_at_ms bigint NOT NULL CHECK(expires_at_ms>0),
    phase text NOT NULL DEFAULT 'pending' CHECK(phase IN ('pending','install_pending','active','history','withdrawn','expired')),
    accepted_at_ms bigint CHECK(accepted_at_ms>0),
    approval_signature bytea CHECK(octet_length(approval_signature)=64),
    installation_signature bytea CHECK(octet_length(installation_signature)=64),
    closed_at timestamptz,
    PRIMARY KEY(account_id,id),
    FOREIGN KEY(account_id,initiating_session_id) REFERENCES sessions(account_id,id),
    FOREIGN KEY(account_id,line_id,device_id,binding_generation)
        REFERENCES device_line_bindings(account_id,line_id,device_id,generation),
    CHECK((phase IN ('withdrawn','expired') AND statement IS NULL AND closed_at IS NOT NULL)
        OR (phase NOT IN ('withdrawn','expired') AND statement IS NOT NULL)),
    CHECK((accepted_at_ms IS NULL AND approval_signature IS NULL)
        OR (accepted_at_ms IS NOT NULL AND approval_signature IS NOT NULL)),
    CHECK(phase NOT IN ('install_pending','active','history') OR accepted_at_ms IS NOT NULL),
    CHECK(phase NOT IN ('active','history') OR installation_signature IS NOT NULL),
    CHECK(phase<>'history' OR closed_at IS NOT NULL),
    CHECK(phase<>'pending' OR (accepted_at_ms IS NULL AND installation_signature IS NULL)),
    CHECK(phase<>'install_pending' OR installation_signature IS NULL),
    CHECK(phase NOT IN ('pending','install_pending','active') OR closed_at IS NULL)
);
CREATE UNIQUE INDEX conversation_one_admitting_interval ON conversation_intervals(account_id)
    WHERE phase IN ('pending','install_pending','active');
CREATE INDEX conversation_interval_cleanup ON conversation_intervals(closed_at,account_id,id)
    WHERE closed_at IS NOT NULL;
CREATE FUNCTION conversation_interval_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (to_jsonb(NEW)-ARRAY['statement','phase','accepted_at_ms','approval_signature','installation_signature','closed_at']) <>
       (to_jsonb(OLD)-ARRAY['statement','phase','accepted_at_ms','approval_signature','installation_signature','closed_at']) OR
       (NEW.statement IS DISTINCT FROM OLD.statement AND NOT
            (OLD.statement IS NOT NULL AND NEW.statement IS NULL AND NEW.phase IN ('withdrawn','expired'))) OR
       (ROW(NEW.accepted_at_ms,NEW.approval_signature) IS DISTINCT FROM ROW(OLD.accepted_at_ms,OLD.approval_signature)
            AND NOT (OLD.phase='pending' AND NEW.phase='install_pending' AND OLD.accepted_at_ms IS NULL)) OR
       (NEW.installation_signature IS DISTINCT FROM OLD.installation_signature AND NOT
            (OLD.phase='install_pending' AND NEW.phase='active' AND OLD.installation_signature IS NULL)) OR
       (OLD.closed_at IS NOT NULL AND NEW.closed_at IS DISTINCT FROM OLD.closed_at) OR
       (NEW.closed_at IS DISTINCT FROM OLD.closed_at AND NEW.phase NOT IN ('history','withdrawn','expired')) OR
       NOT (NEW.phase=OLD.phase OR
            (OLD.phase='pending' AND NEW.phase IN ('install_pending','withdrawn','expired')) OR
            (OLD.phase='install_pending' AND NEW.phase IN ('active','withdrawn','expired')) OR
            (OLD.phase='active' AND NEW.phase IN ('history','withdrawn')) OR
            (OLD.phase='history' AND NEW.phase='withdrawn')) THEN
        RAISE EXCEPTION 'conversation scope or state cannot roll back' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER conversation_interval_before_update BEFORE UPDATE ON conversation_intervals
    FOR EACH ROW EXECUTE FUNCTION conversation_interval_guard();

CREATE TABLE conversation_inbound_provenance (
    account_id uuid NOT NULL,
    event_id uuid NOT NULL,
    interval_id uuid NOT NULL,
    trust_generation bigint NOT NULL CHECK(trust_generation>0),
    manifest_version bigint NOT NULL CHECK(manifest_version>0),
    manifest_digest bytea NOT NULL CHECK(octet_length(manifest_digest)=32),
    verified_manifest bytea NOT NULL CHECK(octet_length(verified_manifest) BETWEEN 364 AND 9751),
    accepted_at_ms bigint NOT NULL CHECK(accepted_at_ms>0),
    PRIMARY KEY(account_id,event_id),
    FOREIGN KEY(account_id,event_id) REFERENCES sealed_inbound_events(account_id,id) ON DELETE CASCADE,
    FOREIGN KEY(account_id,interval_id) REFERENCES conversation_intervals(account_id,id)
);
CREATE INDEX conversation_provenance_interval ON conversation_inbound_provenance(account_id,interval_id);
CREATE FUNCTION conversation_provenance_no_update() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    RAISE EXCEPTION 'verified conversation provenance is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER conversation_provenance_before_update BEFORE UPDATE ON conversation_inbound_provenance
    FOR EACH ROW EXECUTE FUNCTION conversation_provenance_no_update();
