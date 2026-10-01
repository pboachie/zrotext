-- SPDX-License-Identifier: AGPL-3.0-only
-- Dormant candidate. Workflow metadata never authorizes an owner decision.
CREATE TABLE workflow_context_fences (
    account_id uuid NOT NULL, context_id uuid NOT NULL,
    stopped_at timestamptz, actor_user_id uuid,
    PRIMARY KEY(account_id,context_id),
    FOREIGN KEY(account_id,context_id) REFERENCES workflow_contexts(account_id,id)
);
CREATE TABLE workflow_routines (
    account_id uuid NOT NULL, id uuid NOT NULL, context_id uuid NOT NULL,
    generation bigint NOT NULL CHECK(generation>0), stopped_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,id),
    FOREIGN KEY(account_id,context_id) REFERENCES workflow_contexts(account_id,id)
);
CREATE TABLE workflow_actions (
    account_id uuid NOT NULL, id uuid NOT NULL, context_id uuid NOT NULL,
    routine_id uuid NOT NULL, revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 128),
    binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
    record_version bigint NOT NULL CHECK(record_version>0),
    phase text NOT NULL CHECK(phase IN ('proposed','approved','invalidated','cancelled',
        'expired','dispatching','unknown','succeeded','failed')),
    approved_by uuid, approved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,id),
    FOREIGN KEY(account_id,context_id) REFERENCES workflow_contexts(account_id,id),
    FOREIGN KEY(account_id,routine_id) REFERENCES workflow_routines(account_id,id),
    CHECK((phase IN ('approved','dispatching','unknown','succeeded','failed'))=
        (approved_by IS NOT NULL AND approved_at IS NOT NULL))
);
CREATE INDEX workflow_actions_context ON workflow_actions(account_id,context_id,id);
CREATE INDEX workflow_actions_routine ON workflow_actions(account_id,routine_id,id);
CREATE FUNCTION workflow_stop_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.account_id IS DISTINCT FROM OLD.account_id OR
       (OLD.stopped_at IS NOT NULL AND NEW.stopped_at IS DISTINCT FROM OLD.stopped_at) THEN
        RAISE EXCEPTION 'workflow fence cannot reopen' USING ERRCODE='23514';
    END IF;
    IF TG_TABLE_NAME='workflow_routines' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.context_id IS DISTINCT FROM OLD.context_id OR
           NEW.generation IS DISTINCT FROM OLD.generation THEN
            RAISE EXCEPTION 'workflow routine binding is immutable' USING ERRCODE='23514';
        END IF;
    ELSIF NEW.context_id IS DISTINCT FROM OLD.context_id OR
          (OLD.actor_user_id IS NOT NULL AND NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id) THEN
        RAISE EXCEPTION 'workflow takeover identity is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_routine_stop BEFORE UPDATE ON workflow_routines
    FOR EACH ROW EXECUTE FUNCTION workflow_stop_immutable();
CREATE TRIGGER workflow_context_stop BEFORE UPDATE ON workflow_context_fences
    FOR EACH ROW EXECUTE FUNCTION workflow_stop_immutable();
CREATE TABLE workflow_action_versions (
    account_id uuid NOT NULL, action_id uuid NOT NULL, revision bigint NOT NULL,
    binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
    descriptor bytea NOT NULL CHECK(octet_length(descriptor) BETWEEN 2 AND 4096),
    context_id uuid NOT NULL, content_version bigint NOT NULL,
    routine_id uuid NOT NULL, authority_generation bigint NOT NULL CHECK(authority_generation>0),
    not_before_ms bigint NOT NULL CHECK(not_before_ms>=0), expires_at_ms bigint NOT NULL,
    context_trust_generation bigint NOT NULL CHECK(context_trust_generation>0),
    context_manifest_version bigint NOT NULL CHECK(context_manifest_version>0),
    context_manifest_digest bytea NOT NULL CHECK(octet_length(context_manifest_digest)=32),
    context_authority_deadline_ms bigint NOT NULL CHECK(context_authority_deadline_ms>0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,action_id,revision),
    UNIQUE(account_id,action_id,revision,binding_digest),
    FOREIGN KEY(account_id,action_id) REFERENCES workflow_actions(account_id,id),
    FOREIGN KEY(account_id,context_id,content_version)
        REFERENCES workflow_context_versions(account_id,context_id,revision),
    FOREIGN KEY(account_id,routine_id) REFERENCES workflow_routines(account_id,id),
    CHECK(revision BETWEEN 1 AND 128 AND expires_at_ms>not_before_ms)
);
ALTER TABLE workflow_actions ADD CONSTRAINT workflow_action_head
    FOREIGN KEY(account_id,id,revision,binding_digest)
    REFERENCES workflow_action_versions(account_id,action_id,revision,binding_digest)
    DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE workflow_action_mutations (
    account_id uuid NOT NULL REFERENCES accounts(id), request_id uuid NOT NULL,
    context_id uuid NOT NULL, subject_id uuid NOT NULL,
    operation smallint NOT NULL CHECK(operation BETWEEN 1 AND 8),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    result bytea NOT NULL CHECK(octet_length(result) BETWEEN 2 AND 4096),
    actor_user_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,request_id),
    FOREIGN KEY(account_id,context_id) REFERENCES workflow_contexts(account_id,id)
);
CREATE INDEX workflow_mutations_context ON workflow_action_mutations(account_id,context_id,request_id);
CREATE TABLE workflow_reply_correlations (
    account_id uuid NOT NULL, event_id uuid NOT NULL, context_id uuid NOT NULL,
    action_id uuid, action_revision bigint, binding_digest bytea,
    disposition text NOT NULL CHECK(disposition IN ('qualifying','ambiguous','late','unrelated')),
    request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
    request_id uuid NOT NULL, actor_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,event_id), UNIQUE(account_id,request_id),
    FOREIGN KEY(account_id,context_id) REFERENCES workflow_contexts(account_id,id),
    FOREIGN KEY(account_id,event_id) REFERENCES conversation_inbound_provenance(account_id,event_id),
    FOREIGN KEY(account_id,action_id,action_revision,binding_digest)
        REFERENCES workflow_action_versions(account_id,action_id,revision,binding_digest),
    CHECK((action_id IS NULL AND action_revision IS NULL AND binding_digest IS NULL)
        OR (action_id IS NOT NULL AND action_revision IS NOT NULL AND octet_length(binding_digest)=32))
);
CREATE TABLE workflow_message_links (
    account_id uuid NOT NULL, action_id uuid NOT NULL, revision bigint NOT NULL,
    binding_digest bytea NOT NULL, message_id uuid NOT NULL, dispatch_id uuid NOT NULL,
    message_digest bytea NOT NULL CHECK(octet_length(message_digest)=32),
    confirmed_by uuid NOT NULL, confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(account_id,action_id,revision), UNIQUE(account_id,message_id),
    UNIQUE(account_id,dispatch_id),
    FOREIGN KEY(account_id,action_id,revision,binding_digest)
        REFERENCES workflow_action_versions(account_id,action_id,revision,binding_digest),
    FOREIGN KEY(account_id,message_id) REFERENCES messages(account_id,id)
);
ALTER TABLE messages ADD COLUMN workflow_action_id uuid;
ALTER TABLE messages ADD CONSTRAINT workflow_message_action
    FOREIGN KEY(account_id,workflow_action_id) REFERENCES workflow_actions(account_id,id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION workflow_record_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN RAISE EXCEPTION 'workflow record is immutable' USING ERRCODE='23514'; END; $$;
CREATE TRIGGER workflow_version_immutable BEFORE UPDATE ON workflow_action_versions
    FOR EACH ROW EXECUTE FUNCTION workflow_record_immutable();
CREATE TRIGGER workflow_mutation_immutable BEFORE UPDATE ON workflow_action_mutations
    FOR EACH ROW EXECUTE FUNCTION workflow_record_immutable();
CREATE TRIGGER workflow_reply_immutable BEFORE UPDATE ON workflow_reply_correlations
    FOR EACH ROW EXECUTE FUNCTION workflow_record_immutable();
CREATE TRIGGER workflow_link_immutable BEFORE UPDATE ON workflow_message_links
    FOR EACH ROW EXECUTE FUNCTION workflow_record_immutable();
CREATE FUNCTION workflow_message_marker_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF OLD.workflow_action_id IS NOT NULL AND NEW.workflow_action_id IS DISTINCT FROM OLD.workflow_action_id THEN
        RAISE EXCEPTION 'workflow message identity cannot change' USING ERRCODE='23514';
    END IF;
    IF OLD.workflow_action_id IS NULL AND NEW.workflow_action_id IS NOT NULL AND
        (NEW.state NOT IN ('queued','claimed') OR EXISTS(SELECT 1 FROM message_attempts a
            WHERE a.account_id=NEW.account_id AND a.message_id=NEW.id)) THEN
        RAISE EXCEPTION 'workflow binding requires an unissued message' USING ERRCODE='23514';
    END IF;
    IF NEW.workflow_action_id IS NOT NULL AND
        (NEW.transport_mode<>'sealed_candidate02' OR
        (NEW.transport_payload IS DISTINCT FROM OLD.transport_payload AND NOT
            (OLD.transport_payload IS NOT NULL AND NEW.transport_payload IS NULL AND
             (NEW.state IN ('submitted','failed','expired','cancelled','unknown') OR NEW.expires_at<=clock_timestamp())))) THEN
        RAISE EXCEPTION 'workflow ciphertext is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_message_marker BEFORE UPDATE ON messages
    FOR EACH ROW EXECUTE FUNCTION workflow_message_marker_guard();

-- Callers hold canonical root/account locks before effects. These independent
-- guards never acquire those locks backwards after message/attempt locks.
CREATE FUNCTION workflow_effect_current(wanted_account uuid,wanted_message uuid) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT EXISTS(SELECT 1 FROM workflow_message_links l
    JOIN workflow_actions a ON (a.account_id,a.id,a.revision,a.binding_digest)=
        (l.account_id,l.action_id,l.revision,l.binding_digest)
    JOIN workflow_action_versions v ON (v.account_id,v.action_id,v.revision)=
        (a.account_id,a.id,a.revision)
    JOIN workflow_routines r ON (r.account_id,r.id)=(a.account_id,a.routine_id)
    JOIN workflow_contexts c ON (c.account_id,c.id)=(a.account_id,a.context_id)
    JOIN workflow_context_fences f ON (f.account_id,f.context_id)=(c.account_id,c.id)
    JOIN sealed_manifest_authorities root ON root.account_id=a.account_id
    JOIN memberships approver ON (approver.account_id,approver.user_id)=(a.account_id,a.approved_by)
    JOIN users approval_user ON approval_user.id=approver.user_id
    JOIN messages m ON (m.account_id,m.id)=(l.account_id,l.message_id)
    JOIN contacts contact ON contact.account_id=v.account_id AND
        contact.id=(convert_from(v.descriptor,'UTF8')::jsonb->>'recipient_id')::uuid
        AND contact.recipient_e164=m.recipient_e164
    JOIN LATERAL (SELECT action,effective_at,expires_at FROM contact_consent_records cc
        WHERE cc.account_id=contact.account_id AND cc.contact_id=contact.id AND cc.purpose=
        CASE convert_from(v.descriptor,'UTF8')::jsonb->>'purpose_id'
            WHEN '00000000-0000-0000-0000-000000000001' THEN 'transactional'
            WHEN '00000000-0000-0000-0000-000000000002' THEN 'operational'
            WHEN '00000000-0000-0000-0000-000000000003' THEN 'marketing' END
        ORDER BY effective_at DESC,recorded_at DESC,id DESC LIMIT 1) consent ON true
    WHERE l.account_id=wanted_account AND l.message_id=wanted_message
        AND m.workflow_action_id=a.id AND a.phase='dispatching'
        AND approver.role='owner' AND approver.revoked_at IS NULL AND approval_user.email_verified_at IS NOT NULL
        AND r.generation=v.authority_generation AND r.stopped_at IS NULL AND f.stopped_at IS NULL
        AND c.purged_at IS NULL AND c.expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
        AND root.revoked_at IS NULL AND root.generation=v.context_trust_generation
        AND root.version=v.context_manifest_version AND root.semantic_digest=v.context_manifest_digest
        AND v.context_authority_deadline_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
        AND v.not_before_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
        AND v.expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
        AND consent.action='grant' AND consent.effective_at<=clock_timestamp()
        AND (consent.expires_at IS NULL OR consent.expires_at>clock_timestamp())
        AND NOT EXISTS(SELECT 1 FROM recipient_suppressions s WHERE s.account_id=m.account_id
            AND s.recipient_e164=m.recipient_e164 AND s.active)
        AND NOT EXISTS(SELECT 1 FROM owner_recipient_holds h WHERE h.account_id=m.account_id
            AND h.recipient_e164=m.recipient_e164 AND h.released_at IS NULL)
        AND m.transport_mode='sealed_candidate02' AND m.transport_payload IS NOT NULL);
$$;
CREATE FUNCTION workflow_effect_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_TABLE_NAME='message_events' THEN
        IF NEW.evidence_code IS DISTINCT FROM 'durable_intent' THEN RETURN NEW; END IF;
    END IF;
    IF EXISTS(SELECT 1 FROM messages WHERE account_id=NEW.account_id AND id=NEW.message_id
        AND workflow_action_id IS NOT NULL) AND
       NOT workflow_effect_current(NEW.account_id,NEW.message_id) THEN
        RAISE EXCEPTION 'workflow automation is fenced' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END; $$;
CREATE TRIGGER workflow_attempt_guard BEFORE INSERT ON message_attempts
    FOR EACH ROW EXECUTE FUNCTION workflow_effect_guard();
CREATE TRIGGER workflow_dispatch_guard BEFORE INSERT ON dispatch_fences
    FOR EACH ROW EXECUTE FUNCTION workflow_effect_guard();
CREATE TRIGGER workflow_intent_guard BEFORE INSERT ON message_events
    FOR EACH ROW EXECUTE FUNCTION workflow_effect_guard();
