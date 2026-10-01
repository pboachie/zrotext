-- SPDX-License-Identifier: AGPL-3.0-only
-- Explicit integration authority for the shared workflow service. Dormant.
-- A workflow credential is a separate realm, not an ordinary API key or owner.
CREATE TABLE workflow_integration_grants (
    account_id uuid NOT NULL REFERENCES accounts(id),
    grant_id uuid NOT NULL,
    credential_hash bytea NOT NULL UNIQUE CHECK(octet_length(credential_hash)=32),
    connector_id uuid NOT NULL,
    reader_key_id bytea NOT NULL CHECK(octet_length(reader_key_id)=32),
    signer_key_id bytea CHECK(octet_length(signer_key_id)=32),
    device_id uuid NOT NULL,
    line_id uuid NOT NULL,
    binding_generation bigint NOT NULL CHECK(binding_generation>0),
    trust_generation bigint NOT NULL CHECK(trust_generation>0),
    manifest_version bigint NOT NULL CHECK(manifest_version>0),
    manifest_digest bytea NOT NULL CHECK(octet_length(manifest_digest)=32),
    context_id uuid NOT NULL,
    context_revision bigint NOT NULL CHECK(context_revision BETWEEN 1 AND 128),
    contact_id uuid NOT NULL,
    purpose text NOT NULL CHECK(purpose IN ('transactional','operational','marketing')),
    permissions smallint NOT NULL CHECK(permissions BETWEEN 1 AND 127),
    created_by_user uuid NOT NULL,
    created_session uuid NOT NULL,
    created_ms bigint NOT NULL CHECK(created_ms>0),
    expires_ms bigint NOT NULL CHECK(expires_ms>created_ms AND expires_ms-created_ms<=86400000),
    revoked_ms bigint CHECK(revoked_ms>0),
    PRIMARY KEY(account_id,grant_id),
    FOREIGN KEY(account_id,connector_id) REFERENCES connector_registrations(account_id,connector_id),
    FOREIGN KEY(account_id,line_id,device_id,binding_generation)
        REFERENCES device_line_bindings(account_id,line_id,device_id,generation),
    FOREIGN KEY(account_id,context_id,context_revision)
        REFERENCES workflow_context_versions(account_id,context_id,revision),
    FOREIGN KEY(account_id,contact_id) REFERENCES contacts(account_id,id),
    FOREIGN KEY(account_id,created_by_user) REFERENCES memberships(account_id,user_id),
    CHECK(signer_key_id IS NULL OR signer_key_id<>reader_key_id),
    CHECK((permissions & 72)=0 OR signer_key_id IS NOT NULL)
);
CREATE INDEX workflow_integration_grants_owner
    ON workflow_integration_grants(account_id,created_ms DESC,grant_id DESC);
CREATE FUNCTION workflow_integration_grant_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (to_jsonb(NEW)-'revoked_ms')<>(to_jsonb(OLD)-'revoked_ms') OR
       (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS DISTINCT FROM OLD.revoked_ms) THEN
        RAISE EXCEPTION 'workflow grant cannot widen or resurrect' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_integration_grants_before_update
    BEFORE UPDATE ON workflow_integration_grants
    FOR EACH ROW EXECUTE FUNCTION workflow_integration_grant_guard();

-- A client must actually encrypt a separate envelope for the selected role-3
-- reader. The existing archive-reader envelope is never relabeled or returned.
CREATE TABLE workflow_connector_context_envelopes (
    account_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    context_revision bigint NOT NULL,
    request_id uuid NOT NULL,
    envelope_digest bytea NOT NULL CHECK(octet_length(envelope_digest)=32),
    envelope bytea CHECK(octet_length(envelope) BETWEEN 308 AND 33075),
    created_by_user uuid NOT NULL,
    created_ms bigint NOT NULL CHECK(created_ms>0),
    PRIMARY KEY(account_id,grant_id,context_id,context_revision),
    UNIQUE(account_id,request_id),
    FOREIGN KEY(account_id,grant_id) REFERENCES workflow_integration_grants(account_id,grant_id),
    FOREIGN KEY(account_id,context_id,context_revision)
        REFERENCES workflow_context_versions(account_id,context_id,revision),
    FOREIGN KEY(account_id,created_by_user) REFERENCES memberships(account_id,user_id)
);
CREATE FUNCTION workflow_connector_envelope_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (to_jsonb(NEW)-'envelope')<>(to_jsonb(OLD)-'envelope') OR
       NOT (NEW.envelope IS NOT DISTINCT FROM OLD.envelope OR
            (OLD.envelope IS NOT NULL AND NEW.envelope IS NULL)) THEN
        RAISE EXCEPTION 'workflow reader envelope cannot change or rehydrate' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_connector_envelopes_before_update
    BEFORE UPDATE ON workflow_connector_context_envelopes
    FOR EACH ROW EXECUTE FUNCTION workflow_connector_envelope_guard();

-- Content-free access records. Action idempotency and outcomes remain in the
-- shared action service, and scheduling remains in the shared scheduler.
CREATE TABLE workflow_integration_access (
    account_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    request_id uuid NOT NULL,
    operation smallint NOT NULL CHECK(operation IN (1,2,4,8,16,32,64)),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    subject_id uuid NOT NULL,
    outcome text NOT NULL CHECK(outcome IN ('accepted','refused')),
    recorded_ms bigint NOT NULL CHECK(recorded_ms>0),
    PRIMARY KEY(account_id,grant_id,request_id),
    FOREIGN KEY(account_id,grant_id) REFERENCES workflow_integration_grants(account_id,grant_id)
);
CREATE INDEX workflow_integration_access_retention
    ON workflow_integration_access(recorded_ms,account_id,grant_id,request_id);
CREATE FUNCTION workflow_integration_access_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'workflow access fact is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_integration_access_before_update
    BEFORE UPDATE ON workflow_integration_access
    FOR EACH ROW EXECUTE FUNCTION workflow_integration_access_guard();
