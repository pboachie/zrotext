-- SPDX-License-Identifier: AGPL-3.0-only
-- Proposed candidate: owner-entered ciphertext only; no route activation.
CREATE TABLE encrypted_templates (
    account_id uuid NOT NULL REFERENCES accounts(id), id uuid NOT NULL,
    interval_id uuid NOT NULL, device_id uuid NOT NULL, line_id uuid NOT NULL,
    binding_generation bigint NOT NULL CHECK(binding_generation>0),
    peer_digest bytea NOT NULL CHECK(octet_length(peer_digest)=32),
    reader_key_id bytea NOT NULL CHECK(octet_length(reader_key_id)=32),
    trust_generation bigint NOT NULL CHECK(trust_generation>0),
    revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 128),
    expires_at_ms bigint NOT NULL CHECK(expires_at_ms>0),
    purged_at timestamptz, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,id),
    FOREIGN KEY(account_id,line_id,device_id,binding_generation)
        REFERENCES device_line_bindings(account_id,line_id,device_id,generation)
);
CREATE INDEX encrypted_template_expiry ON encrypted_templates(expires_at_ms,account_id,id) WHERE purged_at IS NULL;
CREATE TABLE encrypted_template_versions (
    account_id uuid NOT NULL, template_id uuid NOT NULL, id uuid NOT NULL UNIQUE,
    revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 128),
    expires_at_ms bigint NOT NULL CHECK(expires_at_ms>0),
    request_id uuid NOT NULL, request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    envelope bytea CHECK(octet_length(envelope) BETWEEN 308 AND 33075),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,template_id,revision), UNIQUE(account_id,request_id),
    FOREIGN KEY(account_id,template_id) REFERENCES encrypted_templates(account_id,id)
);
ALTER TABLE encrypted_templates ADD CONSTRAINT encrypted_template_head FOREIGN KEY(account_id,id,revision) REFERENCES encrypted_template_versions(account_id,template_id,revision) DEFERRABLE INITIALLY DEFERRED;
CREATE FUNCTION encrypted_template_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (to_jsonb(NEW)-ARRAY['revision','expires_at_ms','purged_at']) <>
       (to_jsonb(OLD)-ARRAY['revision','expires_at_ms','purged_at'])
       OR (NEW.revision<>OLD.revision AND NEW.revision<>OLD.revision+1)
       OR (NEW.expires_at_ms<>OLD.expires_at_ms AND NEW.revision<>OLD.revision+1)
       OR (OLD.purged_at IS NOT NULL AND NEW IS DISTINCT FROM OLD)
       OR (NEW.purged_at IS NOT NULL AND (NEW.revision<>OLD.revision OR NEW.expires_at_ms<>OLD.expires_at_ms)) THEN
        RAISE EXCEPTION 'encrypted template binding is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER encrypted_template_before_update BEFORE UPDATE ON encrypted_templates FOR EACH ROW EXECUTE FUNCTION encrypted_template_guard();
CREATE FUNCTION encrypted_template_version_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (to_jsonb(NEW)-'envelope')<>(to_jsonb(OLD)-'envelope') OR
       NOT (NEW.envelope IS NOT DISTINCT FROM OLD.envelope OR (OLD.envelope IS NOT NULL AND NEW.envelope IS NULL)) THEN
        RAISE EXCEPTION 'encrypted template version cannot be rewritten or rehydrated' USING ERRCODE='23514';
    END IF; RETURN NEW;
END; $$;
CREATE TRIGGER encrypted_template_version_before_update BEFORE UPDATE ON encrypted_template_versions FOR EACH ROW EXECUTE FUNCTION encrypted_template_version_guard();
