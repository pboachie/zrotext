-- SPDX-License-Identifier: AGPL-3.0-only
-- Independent, owner-confirmed authority for the bounded self-notification pilot.
-- No route or production send gate is enabled by installing these tables.
CREATE TABLE agent_authority_grants (
    account_id uuid NOT NULL REFERENCES accounts(id),
    grant_id uuid NOT NULL,
    api_key_id uuid NOT NULL UNIQUE REFERENCES api_keys(id),
    connector_id uuid NOT NULL,
    connector_key_id bytea NOT NULL CHECK (octet_length(connector_key_id)=32),
    signer_key_id bytea NOT NULL CHECK (octet_length(signer_key_id)=32),
    device_id uuid NOT NULL,
    line_id uuid NOT NULL,
    binding_generation bigint NOT NULL CHECK (binding_generation>0),
    recipient_digest bytea NOT NULL CHECK (octet_length(recipient_digest)=32),
    metadata_allowed boolean NOT NULL,
    content_allowed boolean NOT NULL,
    draft_allowed boolean NOT NULL,
    send_allowed boolean NOT NULL,
    reader_identity uuid,
    model_provider_identity uuid,
    model_reads_content boolean NOT NULL DEFAULT false,
    owner_self_notification boolean NOT NULL CHECK (owner_self_notification),
    created_by_user uuid NOT NULL,
    created_session uuid NOT NULL,
    created_ms bigint NOT NULL CHECK (created_ms>0),
    expires_ms bigint NOT NULL CHECK (expires_ms>created_ms AND expires_ms-created_ms<=86400000),
    message_limit integer NOT NULL CHECK (message_limit BETWEEN 1 AND 100),
    turn_limit integer NOT NULL CHECK (turn_limit BETWEEN 1 AND 3),
    messages_reserved integer NOT NULL DEFAULT 0 CHECK (messages_reserved BETWEEN 0 AND message_limit),
    turns_consumed integer NOT NULL DEFAULT 0 CHECK (turns_consumed BETWEEN 0 AND turn_limit),
    revoked_ms bigint CHECK (revoked_ms>0),
    taken_over_ms bigint CHECK (taken_over_ms>0),
    PRIMARY KEY (account_id,grant_id),
    FOREIGN KEY (account_id,connector_id) REFERENCES connector_registrations(account_id,connector_id),
    FOREIGN KEY (account_id,line_id,device_id,binding_generation)
        REFERENCES device_line_bindings(account_id,line_id,device_id,generation),
    FOREIGN KEY (account_id,created_by_user) REFERENCES memberships(account_id,user_id),
    CHECK (metadata_allowed OR content_allowed OR draft_allowed OR send_allowed),
    CHECK (NOT content_allowed OR reader_identity IS NOT NULL),
    -- The first pilot cannot authorize an unimplemented managed-model service.
    CHECK (model_provider_identity IS NULL AND NOT model_reads_content)
);
CREATE INDEX agent_authority_grants_owner ON agent_authority_grants(account_id,created_ms DESC,grant_id DESC);

CREATE FUNCTION agent_authority_grant_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF ROW(NEW.account_id,NEW.grant_id,NEW.api_key_id,NEW.connector_id,NEW.connector_key_id,NEW.signer_key_id,
        NEW.device_id,NEW.line_id,NEW.binding_generation,NEW.recipient_digest,
        NEW.metadata_allowed,NEW.content_allowed,NEW.draft_allowed,NEW.send_allowed,
        NEW.reader_identity,NEW.model_provider_identity,NEW.model_reads_content,
        NEW.owner_self_notification,NEW.created_by_user,NEW.created_session,NEW.created_ms,
        NEW.expires_ms,NEW.message_limit,NEW.turn_limit)
       IS DISTINCT FROM ROW(OLD.account_id,OLD.grant_id,OLD.api_key_id,OLD.connector_id,OLD.connector_key_id,OLD.signer_key_id,
        OLD.device_id,OLD.line_id,OLD.binding_generation,OLD.recipient_digest,
        OLD.metadata_allowed,OLD.content_allowed,OLD.draft_allowed,OLD.send_allowed,
        OLD.reader_identity,OLD.model_provider_identity,OLD.model_reads_content,
        OLD.owner_self_notification,OLD.created_by_user,OLD.created_session,OLD.created_ms,
        OLD.expires_ms,OLD.message_limit,OLD.turn_limit)
       OR NEW.messages_reserved<OLD.messages_reserved OR NEW.turns_consumed<OLD.turns_consumed
       OR (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS DISTINCT FROM OLD.revoked_ms)
       OR (OLD.taken_over_ms IS NOT NULL AND NEW.taken_over_ms IS DISTINCT FROM OLD.taken_over_ms) THEN
        RAISE EXCEPTION 'agent scope and consumed authority cannot be rewritten' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER agent_authority_grant_before_update BEFORE UPDATE ON agent_authority_grants
    FOR EACH ROW EXECUTE FUNCTION agent_authority_grant_guard();

CREATE TABLE agent_authority_approvals (
    account_id uuid NOT NULL,
    action_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    message_id uuid NOT NULL,
    device_id uuid NOT NULL,
    line_id uuid NOT NULL,
    binding_generation bigint NOT NULL CHECK (binding_generation>0),
    recipient_digest bytea NOT NULL CHECK (octet_length(recipient_digest)=32),
    unsigned_digest bytea NOT NULL CHECK (octet_length(unsigned_digest)=32),
    action_digest bytea NOT NULL CHECK (octet_length(action_digest)=32),
    not_before_ms bigint NOT NULL CHECK (not_before_ms>0),
    expires_ms bigint NOT NULL CHECK (expires_ms>not_before_ms),
    approved_by_user uuid NOT NULL,
    approved_session uuid NOT NULL,
    approved_ms bigint NOT NULL CHECK (approved_ms>0),
    revoked_ms bigint CHECK (revoked_ms>0),
    PRIMARY KEY (account_id,action_id),
    FOREIGN KEY (account_id,grant_id) REFERENCES agent_authority_grants(account_id,grant_id),
    FOREIGN KEY (account_id,approved_by_user) REFERENCES memberships(account_id,user_id)
);
CREATE FUNCTION agent_authority_approval_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (to_jsonb(NEW)-'revoked_ms') IS DISTINCT FROM (to_jsonb(OLD)-'revoked_ms')
       OR (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS DISTINCT FROM OLD.revoked_ms) THEN
        RAISE EXCEPTION 'exact agent approval cannot change' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER agent_authority_approval_before_update BEFORE UPDATE ON agent_authority_approvals
    FOR EACH ROW EXECUTE FUNCTION agent_authority_approval_guard();

CREATE TABLE agent_authority_actions (
    account_id uuid NOT NULL,
    action_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    message_id uuid NOT NULL UNIQUE REFERENCES messages(id),
    action_digest bytea NOT NULL CHECK (octet_length(action_digest)=32),
    reserved_ms bigint NOT NULL CHECK (reserved_ms>0),
    PRIMARY KEY (account_id,action_id),
    FOREIGN KEY (account_id,action_id) REFERENCES agent_authority_approvals(account_id,action_id),
    FOREIGN KEY (account_id,grant_id) REFERENCES agent_authority_grants(account_id,grant_id)
);
CREATE FUNCTION agent_authority_action_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    RAISE EXCEPTION 'agent action identity is immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER agent_authority_action_before_update BEFORE UPDATE ON agent_authority_actions
    FOR EACH ROW EXECUTE FUNCTION agent_authority_action_guard();

-- Retain provenance after revocation or access-record erasure. Missing authority
-- must stop dispatch, rather than turning an agent message into owner work.
ALTER TABLE messages ADD COLUMN agent_grant_id uuid;
ALTER TABLE messages ADD CONSTRAINT messages_agent_grant FOREIGN KEY (account_id,agent_grant_id)
    REFERENCES agent_authority_grants(account_id,grant_id);
ALTER TABLE messages ADD CONSTRAINT messages_agent_transport CHECK
    (agent_grant_id IS NULL OR transport_mode='sealed_candidate02');
CREATE FUNCTION agent_message_provenance_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF OLD.agent_grant_id IS NOT NULL AND NEW.agent_grant_id IS DISTINCT FROM OLD.agent_grant_id THEN
        RAISE EXCEPTION 'agent message provenance cannot change' USING ERRCODE='23514';
    END IF;
    IF NEW.agent_grant_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM agent_authority_actions a WHERE a.account_id=NEW.account_id
            AND a.message_id=NEW.id AND a.grant_id=NEW.agent_grant_id) THEN
        RAISE EXCEPTION 'agent message requires its exact durable action' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER agent_message_provenance_before_update BEFORE UPDATE ON messages
    FOR EACH ROW EXECUTE FUNCTION agent_message_provenance_guard();

-- Additional gates compose with the sealed radio-authority guards. Historical
-- callbacks remain recordable after withdrawal; only a new grant/intent or
-- transition toward a new effect requires currently live agent authority.
CREATE FUNCTION require_live_agent_action(wanted_account uuid,wanted_message uuid) RETURNS void
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    wanted_grant uuid;
    current_ms bigint := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
BEGIN
    SELECT agent_grant_id INTO wanted_grant FROM messages
        WHERE account_id=wanted_account AND id=wanted_message;
    IF wanted_grant IS NULL THEN RETURN; END IF;
    -- Revocation/takeover updates serialize on this row, without acquiring
    -- dispatch-job locks in the reverse order.
    PERFORM 1 FROM agent_authority_grants WHERE account_id=wanted_account
        AND grant_id=wanted_grant FOR SHARE;
    current_ms := floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
    IF NOT EXISTS (
        SELECT 1 FROM agent_authority_grants g
        JOIN api_keys k ON k.id=g.api_key_id AND k.account_id=g.account_id
        JOIN memberships owner_member ON owner_member.account_id=k.account_id
            AND owner_member.user_id=k.created_by_user_id
        JOIN users owner_user ON owner_user.id=owner_member.user_id
        JOIN accounts tenant ON tenant.id=g.account_id
        JOIN connector_registrations c ON c.account_id=g.account_id AND c.connector_id=g.connector_id
        JOIN sealed_manifest_authorities ma ON ma.account_id=c.account_id AND ma.generation=c.manifest_generation
        JOIN connector_keys ck ON ck.account_id=c.account_id AND ck.connector_id=c.connector_id
            AND ck.key_id=g.connector_key_id AND ck.key_id=c.key_id
        JOIN connector_grants cg ON cg.account_id=c.account_id AND cg.connector_id=c.connector_id
            AND cg.line_id=g.line_id AND cg.kind='send'
        JOIN messages m ON m.account_id=g.account_id AND m.id=wanted_message
        JOIN agent_authority_actions a ON a.account_id=m.account_id AND a.message_id=m.id
            AND a.grant_id=g.grant_id
        JOIN agent_authority_approvals p ON p.account_id=a.account_id AND p.action_id=a.action_id
            AND p.grant_id=a.grant_id AND p.action_digest=a.action_digest
        JOIN memberships approver ON approver.account_id=p.account_id AND approver.user_id=p.approved_by_user
        JOIN phone_lines l ON l.account_id=g.account_id AND l.id=g.line_id
        JOIN device_line_bindings b ON b.account_id=l.account_id AND b.line_id=l.id
            AND b.device_id=g.device_id AND b.generation=g.binding_generation
        WHERE g.account_id=wanted_account AND g.grant_id=wanted_grant
            AND g.send_allowed AND g.owner_self_notification
            AND g.revoked_ms IS NULL AND g.taken_over_ms IS NULL AND g.expires_ms>current_ms
            AND g.messages_reserved BETWEEN 1 AND g.message_limit
            AND g.turns_consumed BETWEEN 1 AND g.turn_limit
            AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at>clock_timestamp())
            AND k.bound_device_id=g.device_id AND 'messages:send'=ANY(k.scopes)
            AND owner_member.role='owner' AND owner_member.revoked_at IS NULL
            AND owner_user.email_verified_at IS NOT NULL AND tenant.disabled_at IS NULL
            AND c.state='active' AND c.expires_ms>current_ms
            AND ma.revoked_at IS NULL AND ma.version>0
            AND ck.retired_ms IS NULL AND ck.valid_from_ms<=current_ms AND ck.valid_until_ms>current_ms
            AND cg.revoked_ms IS NULL AND cg.expires_ms>current_ms
            AND approver.role='owner' AND approver.revoked_at IS NULL
            AND p.revoked_ms IS NULL AND p.not_before_ms<=current_ms AND p.expires_ms>current_ms
            AND p.expires_ms<=g.expires_ms AND p.message_id=m.id
            AND p.device_id=m.device_id AND p.line_id=m.sealed_line_id
            AND p.binding_generation=m.sealed_binding_generation
            AND p.recipient_digest=g.recipient_digest AND p.unsigned_digest=m.request_digest
            AND p.expires_ms=(extract(epoch FROM m.expires_at)*1000)::bigint
            AND m.agent_grant_id=g.grant_id AND m.device_id=g.device_id
            AND m.sealed_line_id=g.line_id AND m.sealed_binding_generation=g.binding_generation
            AND m.sealed_signer_key_id=g.signer_key_id AND m.transport_mode='sealed_candidate02'
            AND m.recipient_e164 IS NOT NULL AND m.transport_payload IS NOT NULL
            AND l.current_binding_generation=g.binding_generation AND l.state='active'
            AND b.state='active' AND b.purpose='sealed'
            AND NOT EXISTS (SELECT 1 FROM recipient_suppressions s
                WHERE s.account_id=m.account_id AND s.recipient_e164=m.recipient_e164 AND s.active)
            AND NOT EXISTS (SELECT 1 FROM owner_recipient_holds h
                WHERE h.account_id=m.account_id AND h.recipient_e164=m.recipient_e164 AND h.released_at IS NULL)
    ) THEN
        RAISE EXCEPTION 'current exact agent action authority is unavailable' USING ERRCODE='23514';
    END IF;
END;
$$;

CREATE FUNCTION agent_effect_authority_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    PERFORM require_live_agent_action(NEW.account_id,NEW.message_id);
    RETURN NEW;
END;
$$;
CREATE TRIGGER agent_attempt_before_insert BEFORE INSERT ON message_attempts
    FOR EACH ROW EXECUTE FUNCTION agent_effect_authority_guard();
CREATE TRIGGER agent_fence_before_insert BEFORE INSERT ON dispatch_fences
    FOR EACH ROW EXECUTE FUNCTION agent_effect_authority_guard();

CREATE FUNCTION agent_intent_authority_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.evidence_code='durable_intent' THEN
        PERFORM require_live_agent_action(NEW.account_id,NEW.message_id);
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER agent_intent_before_insert BEFORE INSERT ON message_events
    FOR EACH ROW EXECUTE FUNCTION agent_intent_authority_guard();

CREATE FUNCTION agent_message_effect_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF NEW.agent_grant_id IS NOT NULL AND NEW.state IN ('claimed','submitting')
       AND NEW.state IS DISTINCT FROM OLD.state THEN
        PERFORM require_live_agent_action(NEW.account_id,NEW.id);
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER agent_message_effect_before_update BEFORE UPDATE ON messages
    FOR EACH ROW EXECUTE FUNCTION agent_message_effect_guard();
