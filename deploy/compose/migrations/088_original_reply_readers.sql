-- SPDX-License-Identifier: AGPL-3.0-only
-- Version-two phone statements retain the immutable existing interval schema.
ALTER TABLE conversation_intervals DROP CONSTRAINT conversation_intervals_statement_check;
ALTER TABLE conversation_intervals ADD CONSTRAINT conversation_intervals_statement_check
 CHECK(octet_length(statement) BETWEEN 380 AND 1536);
-- Accepted signed manifest bytes, never a fabricated historical trust assertion.
CREATE TABLE original_reply_manifest_history (
 account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 root_generation bigint NOT NULL CHECK(root_generation>0),
 version bigint NOT NULL CHECK(version>0),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 manifest bytea NOT NULL CHECK(octet_length(manifest) BETWEEN 364 AND 9751),
 accepted_at_ms bigint NOT NULL CHECK(accepted_at_ms>0),
 PRIMARY KEY(account_id,root_generation,version)
);
INSERT INTO original_reply_manifest_history
 SELECT account_id,generation,version,semantic_digest,manifest,accepted_at_ms
 FROM sealed_manifest_authorities WHERE version>0 AND manifest IS NOT NULL;
CREATE FUNCTION original_reply_manifest_acceptance() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF NEW.version>0 AND NEW.manifest IS NOT NULL THEN
  INSERT INTO original_reply_manifest_history VALUES(NEW.account_id,NEW.generation,NEW.version,NEW.semantic_digest,NEW.manifest,NEW.accepted_at_ms)
   ON CONFLICT DO NOTHING;
  IF NOT EXISTS(SELECT 1 FROM original_reply_manifest_history WHERE account_id=NEW.account_id
      AND root_generation=NEW.generation AND version=NEW.version AND digest=NEW.semantic_digest AND manifest=NEW.manifest) THEN
   RAISE EXCEPTION 'accepted manifest identity conflict' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER original_reply_manifest_acceptance AFTER INSERT OR UPDATE OF version,manifest
 ON sealed_manifest_authorities FOR EACH ROW EXECUTE FUNCTION original_reply_manifest_acceptance();

-- Original phone-event access inherits a phone-approved interval and exact
-- existing connector read grant. It grants neither sending nor approval.
CREATE TABLE original_reply_grants (
 account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 grant_id uuid NOT NULL,
 credential_hash bytea NOT NULL CHECK(octet_length(credential_hash)=32),
 interval_id uuid NOT NULL,
 connector_id uuid NOT NULL,
 read_grant_id uuid NOT NULL,
 reader_key_id bytea NOT NULL CHECK(octet_length(reader_key_id)=32),
 trust_generation bigint NOT NULL CHECK(trust_generation>0),
 manifest_version bigint NOT NULL CHECK(manifest_version>0),
 manifest_digest bytea NOT NULL CHECK(octet_length(manifest_digest)=32),
 created_by_user uuid NOT NULL,
 created_session uuid NOT NULL,
 created_ms bigint NOT NULL CHECK(created_ms>0),
 expires_ms bigint NOT NULL CHECK(expires_ms>created_ms AND expires_ms-created_ms<=86400000),
 revoked_ms bigint,
 PRIMARY KEY(account_id,grant_id), UNIQUE(credential_hash)
);
CREATE TABLE original_reply_requests (
 account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 request_id uuid NOT NULL,
 interval_id uuid NOT NULL,
 action_id uuid NOT NULL,
 revision bigint NOT NULL,
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 message_id uuid NOT NULL,
 created_by_user uuid NOT NULL,
 created_session uuid NOT NULL,
 starts_ms bigint NOT NULL CHECK(starts_ms>0),
 expires_ms bigint NOT NULL CHECK(expires_ms>starts_ms AND expires_ms-starts_ms<=86400000),
 maximum_turns integer NOT NULL CHECK(maximum_turns BETWEEN 1 AND 8),
 consumed_turns integer NOT NULL DEFAULT 0 CHECK(consumed_turns BETWEEN 0 AND maximum_turns),
 stopped_ms bigint,
 PRIMARY KEY(account_id,request_id),
 UNIQUE(account_id,action_id,revision,binding_digest)
);
CREATE TABLE original_reply_consumptions (
 account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 consumption_id uuid NOT NULL,
 consumer_id uuid NOT NULL,
 event_id uuid NOT NULL,
 interval_id uuid NOT NULL,
 request_id uuid,
 proposed_action_id uuid,
 revision bigint,
 binding_digest bytea,
 disposition text NOT NULL CHECK(disposition IN('proposal','owner_review')),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 created_ms bigint NOT NULL CHECK(created_ms>0),
 PRIMARY KEY(account_id,consumption_id), UNIQUE(account_id,consumer_id,event_id),
 CHECK((disposition='proposal' AND request_id IS NOT NULL AND proposed_action_id IS NOT NULL AND revision IS NOT NULL AND octet_length(binding_digest)=32)
    OR (disposition='owner_review' AND proposed_action_id IS NULL AND revision IS NULL AND binding_digest IS NULL))
);
CREATE TABLE original_reply_access (
 account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 id uuid NOT NULL,
 grant_id uuid NOT NULL,
 event_id uuid,
 operation text NOT NULL CHECK(operation IN('current','page','read','consume','withdraw','status')),
 recorded_ms bigint NOT NULL CHECK(recorded_ms>0),
 PRIMARY KEY(account_id,id)
);
CREATE FUNCTION original_reply_grant_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF (to_jsonb(NEW)-'revoked_ms') IS DISTINCT FROM (to_jsonb(OLD)-'revoked_ms')
    OR (OLD.revoked_ms IS NOT NULL AND NEW.revoked_ms IS DISTINCT FROM OLD.revoked_ms) THEN
  RAISE EXCEPTION 'original reply grant immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER original_reply_grant_guard BEFORE UPDATE ON original_reply_grants FOR EACH ROW EXECUTE FUNCTION original_reply_grant_immutable();
CREATE FUNCTION original_reply_consumption_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 RAISE EXCEPTION 'original reply consumption immutable' USING ERRCODE='23514';
END;
$$;
CREATE TRIGGER original_reply_consumption_guard BEFORE UPDATE ON original_reply_consumptions FOR EACH ROW EXECUTE FUNCTION original_reply_consumption_immutable();

-- Minimal source identities survive content/request metadata pruning. A missing
-- markers persist for the account lifetime; ordinary actions have no marker.
CREATE TABLE original_reply_sources (
 account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 action_id uuid NOT NULL,revision bigint NOT NULL CHECK(revision>0),
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 source_grant_id uuid NOT NULL,source_event_id uuid NOT NULL,request_id uuid NOT NULL,
 expires_at_ms bigint NOT NULL CHECK(expires_at_ms>0),
 PRIMARY KEY(account_id,action_id,revision)
);
CREATE TRIGGER original_reply_source_guard BEFORE UPDATE ON original_reply_sources
 FOR EACH ROW EXECUTE FUNCTION original_reply_consumption_immutable();
-- A deferred account-lifetime constraint allows only genuine full-account erase,
-- including FK cascades, regardless of the order of individual table deletes.
CREATE FUNCTION original_reply_source_delete_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM accounts WHERE id=OLD.account_id) THEN
  RAISE EXCEPTION 'original source retained for account lifetime' USING ERRCODE='23514';
 END IF;
 RETURN OLD;
END;
$$;
CREATE CONSTRAINT TRIGGER original_reply_source_lifetime AFTER DELETE ON original_reply_sources
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION original_reply_source_delete_guard();
CREATE FUNCTION original_reply_request_guard() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['consumed_turns','stopped_ms']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['consumed_turns','stopped_ms'])
 OR NEW.consumed_turns<OLD.consumed_turns OR NEW.consumed_turns>OLD.consumed_turns+1
 OR (OLD.stopped_ms IS NOT NULL AND NEW.stopped_ms IS DISTINCT FROM OLD.stopped_ms) THEN
  RAISE EXCEPTION 'original request binding immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER original_reply_request_guard BEFORE UPDATE ON original_reply_requests
 FOR EACH ROW EXECUTE FUNCTION original_reply_request_guard();

-- Preserve all existing 641 fences for both exact signed statement versions.
CREATE OR REPLACE FUNCTION workflow_integration_grant_current(wanted_account uuid,wanted_grant uuid,wanted_action uuid,wanted_permission integer) RETURNS boolean
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
      AND interval.phase='active' AND interval.statement IS NOT NULL AND sha256(convert_to(CASE substring(interval.statement from 1 for 5) WHEN decode('5a54434101','hex') THEN 'zrotext/conversation/approve/v1' WHEN decode('5a54434102','hex') THEN 'zrotext/conversation/approve/v2' ELSE NULL END,'UTF8')||decode('00','hex')||int4send(octet_length(interval.statement))||interval.statement)=interval.statement_digest
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

CREATE FUNCTION original_reply_grant_current(wanted_account uuid,wanted_grant uuid) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT EXISTS(SELECT 1 FROM original_reply_grants g
 JOIN accounts a ON a.id=g.account_id
 JOIN sessions creator ON (creator.account_id,creator.user_id,creator.id)=(g.account_id,g.created_by_user,g.created_session)
 JOIN memberships membership ON (membership.account_id,membership.user_id)=(g.account_id,g.created_by_user)
 JOIN users owner ON owner.id=g.created_by_user
 JOIN conversation_intervals i ON (i.account_id,i.id)=(g.account_id,g.interval_id)
 JOIN sessions origin ON (origin.account_id,origin.id)=(i.account_id,i.initiating_session_id)
 JOIN memberships origin_owner ON (origin_owner.account_id,origin_owner.user_id)=(origin.account_id,origin.user_id)
 JOIN users origin_user ON origin_user.id=origin.user_id
 JOIN sealed_manifest_authorities root ON root.account_id=g.account_id
 JOIN connector_registrations registration ON (registration.account_id,registration.connector_id,registration.key_id)=(g.account_id,g.connector_id,g.reader_key_id)
 JOIN connector_keys reader ON (reader.account_id,reader.connector_id,reader.key_id)=(g.account_id,g.connector_id,g.reader_key_id)
 JOIN connector_grants permission ON (permission.account_id,permission.connector_id,permission.grant_id)=(g.account_id,g.connector_id,g.read_grant_id)
 JOIN devices d ON (d.account_id,d.id)=(i.account_id,i.device_id)
 JOIN device_keys device_key ON (device_key.account_id,device_key.device_id)=(d.account_id,d.id)
 JOIN phone_lines line ON (line.account_id,line.id)=(i.account_id,i.line_id)
 JOIN device_line_bindings binding ON (binding.account_id,binding.line_id,binding.device_id,binding.generation)=(i.account_id,i.line_id,i.device_id,i.binding_generation)
 WHERE g.account_id=wanted_account AND g.grant_id=wanted_grant AND g.revoked_ms IS NULL
 AND a.disabled_at IS NULL AND membership.role='owner' AND membership.revoked_at IS NULL
 AND owner.email_verified_at IS NOT NULL AND owner.mfa_enabled AND creator.revoked_at IS NULL AND creator.expires_at>clock_timestamp()
 AND g.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 AND root.revoked_at IS NULL AND (root.generation,root.version,root.semantic_digest)=(g.trust_generation,g.manifest_version,g.manifest_digest)
 AND i.phase='active' AND i.statement IS NOT NULL AND i.trust_generation=g.trust_generation
 AND substring(i.statement from 1 for 5)=decode('5a54434102','hex')
 AND sha256(convert_to('zrotext/conversation/approve/v2','UTF8')||decode('00','hex')||int4send(octet_length(i.statement))||i.statement)=i.statement_digest
 AND origin.revoked_at IS NULL AND origin.expires_at>clock_timestamp()
 AND origin_owner.role='owner' AND origin_owner.revoked_at IS NULL AND origin_user.email_verified_at IS NOT NULL
 AND registration.state='active' AND registration.revoked_ms IS NULL AND registration.manifest_generation=g.trust_generation
 AND registration.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 AND reader.retired_ms IS NULL AND reader.valid_from_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 AND reader.valid_until_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 AND permission.kind='read' AND (permission.read_directions::integer & 8)=8 AND permission.line_id=i.line_id AND permission.revoked_ms IS NULL
 AND permission.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 AND (cardinality(permission.conversation_restriction)=0 OR i.id=ANY(permission.conversation_restriction))
 AND d.revoked_at IS NULL AND device_key.revoked_at IS NULL AND line.state='active' AND line.approved_at IS NOT NULL
 AND line.current_binding_generation=i.binding_generation AND binding.state='active' AND binding.purpose='sealed'
 AND binding.activated_at IS NOT NULL AND binding.owner_approval_digest IS NOT NULL AND binding.device_confirmation_digest IS NOT NULL);
$$;
CREATE FUNCTION original_reply_source_one_current(wanted_account uuid,wanted_action uuid) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT NOT EXISTS(SELECT 1 FROM original_reply_sources WHERE account_id=wanted_account AND action_id=wanted_action)
 OR EXISTS(SELECT 1 FROM original_reply_sources s
 JOIN workflow_actions output ON (output.account_id,output.id,output.revision,output.binding_digest)=(s.account_id,s.action_id,s.revision,s.binding_digest)
 JOIN original_reply_grants g ON (g.account_id,g.grant_id)=(s.account_id,s.source_grant_id)
 JOIN conversation_inbound_provenance event ON (event.account_id,event.event_id,event.interval_id)=(g.account_id,s.source_event_id,g.interval_id)
 JOIN sealed_inbound_events opaque ON (opaque.account_id,opaque.id)=(event.account_id,event.event_id)
 JOIN original_reply_requests request ON (request.account_id,request.request_id,request.interval_id)=(s.account_id,s.request_id,g.interval_id)
 JOIN sessions owner_session ON (owner_session.account_id,owner_session.user_id,owner_session.id)=(request.account_id,request.created_by_user,request.created_session)
 JOIN memberships owner_membership ON (owner_membership.account_id,owner_membership.user_id)=(request.account_id,request.created_by_user)
 JOIN users owner_user ON owner_user.id=request.created_by_user
 JOIN workflow_actions source ON (source.account_id,source.id,source.revision,source.binding_digest)=(request.account_id,request.action_id,request.revision,request.binding_digest)
 JOIN workflow_action_versions version ON (version.account_id,version.action_id,version.revision,version.binding_digest)=(source.account_id,source.id,source.revision,source.binding_digest)
 JOIN workflow_routines routine ON (routine.account_id,routine.id)=(source.account_id,source.routine_id)
 JOIN workflow_context_fences context_fence ON (context_fence.account_id,context_fence.context_id)=(source.account_id,source.context_id)
 JOIN workflow_contexts context ON (context.account_id,context.id)=(source.account_id,source.context_id)
 JOIN memberships approver ON (approver.account_id,approver.user_id)=(source.account_id,source.approved_by)
 JOIN users approver_user ON approver_user.id=approver.user_id
 JOIN workflow_message_links link ON (link.account_id,link.action_id,link.revision,link.binding_digest,link.message_id)=(request.account_id,request.action_id,request.revision,request.binding_digest,request.message_id)
 JOIN dispatch_jobs job ON (job.account_id,job.message_id)=(link.account_id,link.message_id)
 WHERE s.account_id=wanted_account AND s.action_id=wanted_action AND original_reply_grant_current(g.account_id,g.grant_id)
 AND opaque.envelope IS NOT NULL AND event.trust_generation=g.trust_generation
 AND s.expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 AND request.stopped_ms IS NULL AND request.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 AND owner_session.revoked_at IS NULL AND owner_session.expires_at>clock_timestamp()
 AND owner_membership.role='owner' AND owner_membership.revoked_at IS NULL AND owner_user.email_verified_at IS NOT NULL AND owner_user.mfa_enabled
 AND source.phase IN('dispatching','unknown') AND workflow_action_origin_current(source.account_id,source.id)
 AND routine.stopped_at IS NULL AND routine.generation=version.authority_generation AND context_fence.stopped_at IS NULL
 AND context.purged_at IS NULL AND context.expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 AND context.interval_id=g.interval_id AND approver.role='owner' AND approver.revoked_at IS NULL AND approver_user.email_verified_at IS NOT NULL
 AND version.context_authority_deadline_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 AND version.expires_at_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 AND job.grant_issued_at IS NOT NULL);
$$;
CREATE FUNCTION original_reply_source_current(wanted_account uuid,wanted_action uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SET search_path FROM CURRENT AS $$
DECLARE
 current_action uuid := wanted_action;
 current_revision bigint;
 current_digest bytea;
 parent_action uuid;
 parent_revision bigint;
 parent_digest bytea;
 visited uuid[] := ARRAY[]::uuid[];
 links integer := 0;
BEGIN
 LOOP
  -- Only a genuinely ordinary action terminates the retained provenance chain.
  IF NOT EXISTS(SELECT 1 FROM original_reply_sources WHERE account_id=wanted_account AND action_id=current_action) THEN
   RETURN true;
  END IF;
  IF links>=128 OR current_action=ANY(visited) THEN RETURN false; END IF;
  visited := array_append(visited,current_action);
  links := links+1;
  SELECT revision,binding_digest INTO current_revision,current_digest FROM workflow_actions
   WHERE account_id=wanted_account AND id=current_action;
  IF NOT FOUND OR NOT original_reply_source_one_current(wanted_account,current_action) THEN RETURN false; END IF;
  SELECT r.action_id,r.revision,r.binding_digest INTO parent_action,parent_revision,parent_digest
   FROM original_reply_sources s JOIN original_reply_requests r
    ON (r.account_id,r.request_id)=(s.account_id,s.request_id)
   WHERE s.account_id=wanted_account AND s.action_id=current_action
    AND s.revision=current_revision AND s.binding_digest=current_digest;
  IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM workflow_actions
   WHERE account_id=wanted_account AND id=parent_action AND revision=parent_revision AND binding_digest=parent_digest) THEN RETURN false; END IF;
  current_action := parent_action;
 END LOOP;
END;
$$;
-- Keep the existing decision, schedule and integration predicates intact.
ALTER FUNCTION workflow_effect_current(uuid,uuid) RENAME TO workflow_original_predecessor_effect_current;
CREATE FUNCTION workflow_effect_current(wanted_account uuid,wanted_message uuid) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT workflow_original_predecessor_effect_current(wanted_account,wanted_message) AND EXISTS(
 SELECT 1 FROM messages m WHERE m.account_id=wanted_account AND m.id=wanted_message
 AND original_reply_source_current(m.account_id,m.workflow_action_id));
$$;

CREATE TRIGGER original_reply_manifest_guard BEFORE UPDATE ON original_reply_manifest_history
 FOR EACH ROW EXECUTE FUNCTION original_reply_consumption_immutable();
