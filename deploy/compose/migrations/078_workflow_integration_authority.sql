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
    UNIQUE(account_id,grant_id,context_id,context_revision),
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
    id uuid NOT NULL DEFAULT gen_random_uuid(),
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
    UNIQUE(account_id,id),
    UNIQUE(account_id,request_id),
    FOREIGN KEY(account_id,grant_id) REFERENCES workflow_integration_grants(account_id,grant_id),
    FOREIGN KEY(account_id,grant_id,context_id,context_revision)
        REFERENCES workflow_integration_grants(account_id,grant_id,context_id,context_revision),
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
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    account_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    request_id uuid NOT NULL,
    operation smallint NOT NULL CHECK(operation IN (1,2,4,8,16,32,64)),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    subject_id uuid NOT NULL,
    outcome text NOT NULL CHECK(outcome IN ('accepted','refused')),
    recorded_ms bigint NOT NULL CHECK(recorded_ms>0),
    PRIMARY KEY(account_id,grant_id,request_id),
    UNIQUE(account_id,id),
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

-- Actor identities are immutable metadata, retained if their grant is erased.
-- Missing real grants will fail effect checks; these tombstones never authorize.
ALTER TABLE workflow_actions ADD COLUMN integration_origin_grant uuid;
CREATE FUNCTION workflow_integration_origin_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.integration_origin_grant IS DISTINCT FROM OLD.integration_origin_grant THEN
        RAISE EXCEPTION 'workflow origin cannot change' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_integration_origin_guard BEFORE UPDATE ON workflow_actions
    FOR EACH ROW EXECUTE FUNCTION workflow_integration_origin_immutable();
ALTER TABLE workflow_action_mutations ALTER COLUMN actor_user_id DROP NOT NULL;
ALTER TABLE workflow_action_mutations ADD COLUMN actor_kind text NOT NULL DEFAULT 'owner';
ALTER TABLE workflow_action_mutations ADD COLUMN actor_grant_id uuid;
ALTER TABLE workflow_action_mutations ADD CONSTRAINT workflow_mutation_actor
    CHECK((actor_kind='owner' AND actor_user_id IS NOT NULL AND actor_grant_id IS NULL)
       OR (actor_kind='integration' AND actor_user_id IS NULL AND actor_grant_id IS NOT NULL));

-- Require the independently reviewed schedule predicate; never replace a
-- decision-only predecessor and silently omit its schedule/time fences.
DO $$ BEGIN
    IF to_regprocedure('workflow_schedule_actor_current(uuid,uuid)') IS NULL THEN
        RAISE EXCEPTION 'workflow integration requires the shared schedule migration';
    END IF;
END; $$;

-- Issuance bounds expires_ms by verified manifest, context-key, role-3 and
-- (when required) role-5 deadlines. Exact immutable root triples below keep
-- that proof bound to the same cryptographic manifest at every SQL effect.
CREATE FUNCTION workflow_integration_grant_current(wanted_account uuid,wanted_grant uuid,wanted_action uuid,wanted_permission integer) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT wanted_permission IN (8,32,64) AND EXISTS(
    SELECT 1 FROM workflow_integration_grants g
    JOIN accounts tenant ON tenant.id=g.account_id
    JOIN sessions creator ON (creator.account_id,creator.user_id,creator.id)=(g.account_id,g.created_by_user,g.created_session)
    JOIN memberships membership ON (membership.account_id,membership.user_id)=(g.account_id,g.created_by_user)
    JOIN users owner ON owner.id=g.created_by_user
    JOIN sealed_manifest_authorities root ON root.account_id=g.account_id
    JOIN connector_registrations registration ON (registration.account_id,registration.connector_id,registration.key_id)=(g.account_id,g.connector_id,g.reader_key_id)
    JOIN connector_keys reader ON (reader.account_id,reader.connector_id,reader.key_id)=(g.account_id,g.connector_id,g.reader_key_id)
    JOIN workflow_actions action ON action.account_id=g.account_id AND action.id=wanted_action
    JOIN workflow_action_versions version ON (version.account_id,version.action_id,version.revision,version.binding_digest)=(action.account_id,action.id,action.revision,action.binding_digest)
    JOIN workflow_contexts context ON (context.account_id,context.id,context.revision)=(g.account_id,g.context_id,g.context_revision)
    JOIN workflow_context_versions source ON (source.account_id,source.context_id,source.revision)=(g.account_id,g.context_id,g.context_revision)
    JOIN contacts contact ON (contact.account_id,contact.id)=(g.account_id,g.contact_id)
    JOIN conversation_intervals interval ON (interval.account_id,interval.id)=(context.account_id,context.interval_id)
    JOIN sessions origin ON (origin.account_id,origin.id)=(interval.account_id,interval.initiating_session_id)
    JOIN memberships origin_membership ON (origin_membership.account_id,origin_membership.user_id)=(origin.account_id,origin.user_id)
    JOIN users origin_owner ON origin_owner.id=origin.user_id
    JOIN devices device ON (device.account_id,device.id)=(g.account_id,g.device_id)
    JOIN device_keys device_key ON (device_key.account_id,device_key.device_id)=(g.account_id,g.device_id)
    JOIN phone_lines line ON (line.account_id,line.id)=(g.account_id,g.line_id)
    JOIN device_line_bindings binding ON (binding.account_id,binding.line_id,binding.device_id,binding.generation)=(g.account_id,g.line_id,g.device_id,g.binding_generation)
    WHERE g.account_id=wanted_account AND g.grant_id=wanted_grant
      AND g.revoked_ms IS NULL AND g.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
      AND (g.permissions::integer & wanted_permission)=wanted_permission
      AND (wanted_permission=32 OR g.signer_key_id IS NOT NULL)
      AND tenant.disabled_at IS NULL AND membership.role='owner' AND membership.revoked_at IS NULL
      AND owner.email_verified_at IS NOT NULL AND owner.mfa_enabled
      AND creator.revoked_at IS NULL AND creator.expires_at>clock_timestamp()
      AND origin.revoked_at IS NULL AND origin.expires_at>clock_timestamp()
      AND origin_membership.role='owner' AND origin_membership.revoked_at IS NULL AND origin_owner.email_verified_at IS NOT NULL
      AND root.revoked_at IS NULL AND (root.generation,root.version,root.semantic_digest)=(g.trust_generation,g.manifest_version,g.manifest_digest)
      AND registration.state='active' AND registration.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
      AND (registration.manifest_generation,registration.manifest_version,registration.manifest_digest)=(g.trust_generation,g.manifest_version,g.manifest_digest)
      AND reader.retired_ms IS NULL AND reader.valid_from_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
      AND reader.valid_until_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
      AND device.revoked_at IS NULL AND device_key.revoked_at IS NULL
      AND line.state='active' AND line.approved_at IS NOT NULL AND line.current_binding_generation=g.binding_generation
      AND binding.state='active' AND binding.purpose='sealed' AND binding.activated_at IS NOT NULL
      AND binding.owner_approval_digest IS NOT NULL AND binding.device_confirmation_digest IS NOT NULL
      AND context.purged_at IS NULL AND context.expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
      AND (context.device_id,context.line_id,context.binding_generation,context.trust_generation)=(g.device_id,g.line_id,g.binding_generation,g.trust_generation)
      AND interval.phase='active' AND interval.statement IS NOT NULL AND sha256(convert_to('zrotext/conversation/approve/v1','UTF8')||decode('00','hex')||int4send(octet_length(interval.statement))||interval.statement)=interval.statement_digest
      AND interval.expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
      AND (interval.device_id,interval.line_id,interval.binding_generation,interval.trust_generation)=(g.device_id,g.line_id,g.binding_generation,g.trust_generation)
      AND source.envelope IS NOT NULL AND sha256(convert_to(contact.recipient_e164,'UTF8'))=context.peer_digest
      AND (version.context_id,version.content_version)=(g.context_id,g.context_revision)
      AND convert_from(version.descriptor,'UTF8')::jsonb->>'line_id'=g.line_id::text
      AND convert_from(version.descriptor,'UTF8')::jsonb->>'recipient_id'=g.contact_id::text
      AND convert_from(version.descriptor,'UTF8')::jsonb->>'content_digest'=encode(sha256(source.envelope),'hex')
      AND g.purpose=CASE convert_from(version.descriptor,'UTF8')::jsonb->>'purpose_id'
          WHEN '00000000-0000-0000-0000-000000000001' THEN 'transactional'
          WHEN '00000000-0000-0000-0000-000000000002' THEN 'operational'
          WHEN '00000000-0000-0000-0000-000000000003' THEN 'marketing' END
      AND (wanted_permission=8 OR EXISTS(SELECT 1 FROM connector_grants cg
          WHERE (cg.account_id,cg.connector_id,cg.line_id)=(g.account_id,g.connector_id,g.line_id)
            AND cg.kind='send' AND cg.revoked_ms IS NULL AND cg.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
            AND (cardinality(cg.conversation_restriction)=0 OR context.interval_id=ANY(cg.conversation_restriction))))
);
$$;
CREATE FUNCTION workflow_action_origin_current(wanted_account uuid,wanted_action uuid) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT EXISTS(SELECT 1 FROM workflow_actions a WHERE a.account_id=wanted_account AND a.id=wanted_action
    AND (a.integration_origin_grant IS NULL OR workflow_integration_grant_current(a.account_id,a.integration_origin_grant,a.id,8)));
$$;

-- Preserve executor identity when its grant is erased; absence of the grant
-- must refuse effects rather than converting an integration send into owner send.
ALTER TABLE messages ADD COLUMN workflow_executor_grant uuid;
CREATE FUNCTION workflow_executor_marker_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF OLD.workflow_executor_grant IS NOT NULL AND NEW.workflow_executor_grant IS DISTINCT FROM OLD.workflow_executor_grant THEN
        RAISE EXCEPTION 'workflow executor cannot change' USING ERRCODE='23514';
    END IF;
    IF OLD.workflow_executor_grant IS NULL AND NEW.workflow_executor_grant IS NOT NULL AND
       (NEW.workflow_action_id IS NULL OR NEW.state NOT IN ('queued','claimed') OR EXISTS(SELECT 1 FROM message_attempts a WHERE a.account_id=NEW.account_id AND a.message_id=NEW.id)) THEN
        RAISE EXCEPTION 'workflow executor requires an unissued action message' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_executor_marker BEFORE UPDATE ON messages FOR EACH ROW EXECUTE FUNCTION workflow_executor_marker_immutable();

CREATE OR REPLACE FUNCTION workflow_schedule_actor_current(wanted_account uuid,wanted_occurrence uuid) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT workflow_schedule_owner_actor_current(wanted_account,wanted_occurrence) OR EXISTS(
    SELECT 1 FROM workflow_schedule_occurrences o WHERE o.account_id=wanted_account AND o.id=wanted_occurrence
      AND o.actor_kind='integration' AND o.owner_session_id IS NULL
      AND workflow_integration_grant_current(o.account_id,o.actor_id,o.action_id,32)
);
$$;
ALTER FUNCTION workflow_effect_current(uuid,uuid) RENAME TO workflow_schedule_effect_current;
CREATE FUNCTION workflow_effect_current(wanted_account uuid,wanted_message uuid) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT workflow_schedule_effect_current(wanted_account,wanted_message) AND EXISTS(
    SELECT 1 FROM messages m WHERE m.account_id=wanted_account AND m.id=wanted_message
      AND workflow_action_origin_current(m.account_id,m.workflow_action_id)
      AND (m.workflow_executor_grant IS NULL OR workflow_integration_grant_current(m.account_id,m.workflow_executor_grant,m.workflow_action_id,64))
);
$$;
CREATE OR REPLACE FUNCTION workflow_effect_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_TABLE_NAME='message_events' THEN
        IF NEW.evidence_code IS DISTINCT FROM 'durable_intent' THEN RETURN NEW; END IF;
    END IF;
    IF EXISTS(SELECT 1 FROM messages WHERE account_id=NEW.account_id AND id=NEW.message_id AND workflow_action_id IS NOT NULL)
       AND NOT workflow_effect_current(NEW.account_id,NEW.message_id) THEN
        RAISE EXCEPTION 'workflow automation is fenced' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
