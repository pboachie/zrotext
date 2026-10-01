-- SPDX-License-Identifier: AGPL-3.0-only
-- Proposed candidate: owner-entered ciphertext only; no route activation.
CREATE TABLE workflow_contexts (
    account_id uuid NOT NULL REFERENCES accounts(id), id uuid NOT NULL,
    interval_id uuid NOT NULL, device_id uuid NOT NULL, line_id uuid NOT NULL,
    binding_generation bigint NOT NULL CHECK(binding_generation>0),
    peer_digest bytea NOT NULL CHECK(octet_length(peer_digest)=32),
    reader_key_id bytea NOT NULL CHECK(octet_length(reader_key_id)=32),
    trust_generation bigint NOT NULL CHECK(trust_generation>0),
    kind smallint NOT NULL CHECK(kind BETWEEN 1 AND 3),
    revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 128),
    expires_at_ms bigint NOT NULL CHECK(expires_at_ms>0),
    purged_at timestamptz, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,id),
    FOREIGN KEY(account_id,interval_id) REFERENCES conversation_intervals(account_id,id),
    FOREIGN KEY(account_id,line_id,device_id,binding_generation)
        REFERENCES device_line_bindings(account_id,line_id,device_id,generation)
);
CREATE INDEX workflow_context_expiry ON workflow_contexts(expires_at_ms,account_id,id) WHERE purged_at IS NULL;
CREATE TABLE workflow_context_versions (
    account_id uuid NOT NULL, context_id uuid NOT NULL, id uuid NOT NULL UNIQUE,
    revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 128),
    request_id uuid NOT NULL, request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    envelope bytea CHECK(octet_length(envelope) BETWEEN 308 AND 33075),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,context_id,revision), UNIQUE(account_id,request_id),
    FOREIGN KEY(account_id,context_id) REFERENCES workflow_contexts(account_id,id)
);
CREATE TABLE workflow_exceptions (
    account_id uuid NOT NULL, context_id uuid NOT NULL, id uuid NOT NULL,
    context_revision bigint NOT NULL,
    source_kind smallint NOT NULL CHECK(source_kind IN (1,2)), source_id uuid NOT NULL,
    reason smallint NOT NULL CHECK(reason BETWEEN 1 AND 5),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    revision bigint NOT NULL DEFAULT 1 CHECK(revision IN (1,2)),
    state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','resolved')),
    resolution_request_id uuid, resolved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,id), UNIQUE(account_id,context_id,source_kind,source_id,reason),
    FOREIGN KEY(account_id,context_id,context_revision)
        REFERENCES workflow_context_versions(account_id,context_id,revision),
    CHECK((revision=1 AND state='pending' AND resolution_request_id IS NULL AND resolved_at IS NULL)
        OR (revision=2 AND state='resolved' AND resolution_request_id IS NOT NULL AND resolved_at IS NOT NULL))
);
ALTER TABLE workflow_contexts ADD CONSTRAINT workflow_context_head
    FOREIGN KEY(account_id,id,revision) REFERENCES workflow_context_versions(account_id,context_id,revision)
    DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE workflow_context_audit (
    account_id uuid NOT NULL, context_id uuid NOT NULL, id uuid NOT NULL,
    operation smallint NOT NULL CHECK(operation BETWEEN 1 AND 3),
    subject_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision>0),
    request_id uuid NOT NULL, request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    actor_user_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,id), UNIQUE(account_id,request_id,operation),
    FOREIGN KEY(account_id,context_id) REFERENCES workflow_contexts(account_id,id)
);
CREATE FUNCTION workflow_context_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (to_jsonb(NEW)-ARRAY['revision','expires_at_ms','purged_at']) <>
       (to_jsonb(OLD)-ARRAY['revision','expires_at_ms','purged_at'])
       OR (NEW.revision<>OLD.revision AND NEW.revision<>OLD.revision+1)
       OR (NEW.expires_at_ms<>OLD.expires_at_ms AND NEW.revision<>OLD.revision+1)
       OR (OLD.purged_at IS NOT NULL AND NEW IS DISTINCT FROM OLD)
       OR (NEW.purged_at IS NOT NULL AND (NEW.revision<>OLD.revision OR NEW.expires_at_ms<>OLD.expires_at_ms)) THEN
        RAISE EXCEPTION 'workflow context binding is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_context_before_update BEFORE UPDATE ON workflow_contexts FOR EACH ROW EXECUTE FUNCTION workflow_context_guard();
CREATE FUNCTION workflow_version_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (to_jsonb(NEW)-'envelope')<>(to_jsonb(OLD)-'envelope') OR
       NOT (NEW.envelope IS NOT DISTINCT FROM OLD.envelope OR (OLD.envelope IS NOT NULL AND NEW.envelope IS NULL)) THEN
        RAISE EXCEPTION 'workflow version cannot be rewritten or rehydrated' USING ERRCODE='23514';
    END IF; RETURN NEW;
END; $$;
CREATE TRIGGER workflow_version_before_update BEFORE UPDATE ON workflow_context_versions FOR EACH ROW EXECUTE FUNCTION workflow_version_guard();
CREATE FUNCTION workflow_exception_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (to_jsonb(NEW)-ARRAY['revision','state','resolution_request_id','resolved_at'])<>
       (to_jsonb(OLD)-ARRAY['revision','state','resolution_request_id','resolved_at']) OR
       NOT (NEW IS NOT DISTINCT FROM OLD OR (OLD.revision=1 AND NEW.revision=2)) THEN
        RAISE EXCEPTION 'workflow exception cannot roll back or change source' USING ERRCODE='23514';
    END IF; RETURN NEW;
END; $$;
CREATE TRIGGER workflow_exception_before_update BEFORE UPDATE ON workflow_exceptions FOR EACH ROW EXECUTE FUNCTION workflow_exception_guard();
CREATE FUNCTION workflow_audit_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN RAISE EXCEPTION 'workflow audit is immutable' USING ERRCODE='23514'; END; $$;
CREATE TRIGGER workflow_audit_before_update BEFORE UPDATE ON workflow_context_audit FOR EACH ROW EXECUTE FUNCTION workflow_audit_guard();
