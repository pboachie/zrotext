-- SPDX-License-Identifier: AGPL-3.0-only
-- Explicit original-event execution policy; legacy policy serialization is unchanged.
ALTER TABLE workflow_routine_policies ADD CONSTRAINT workflow_routine_original_policy_shape CHECK (COALESCE(
    policy->'original_input' IS NULL OR policy->'original_input'='null'::jsonb OR
    (policy->>'executor'='local_process' AND jsonb_typeof(policy->'original_input')='object'
     AND ((policy->'original_input')-'grant_id'::text)='{}'::jsonb
     AND jsonb_typeof(policy->'original_input'->'grant_id')='string'
     AND policy->'original_input'->>'grant_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
     AND policy->'original_input'->>'grant_id'<>'00000000-0000-0000-0000-000000000000')
,false));

-- Minimal account-lifetime provenance. Erasing call/content/grant metadata must
-- never permit replay or reclassify an original-derived action as ordinary.
CREATE TABLE workflow_routine_original_sources (
 account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 call_id uuid NOT NULL, policy_id uuid NOT NULL,
 policy_digest bytea NOT NULL CHECK(octet_length(policy_digest)=32),
 connector_id uuid NOT NULL, original_grant_id uuid NOT NULL, event_id uuid NOT NULL,
 accepted_manifest_version bigint NOT NULL CHECK(accepted_manifest_version>0),
 event_digest bytea NOT NULL CHECK(octet_length(event_digest)=32),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 input_grant_id uuid NOT NULL, context_id uuid NOT NULL,
 input_revision bigint NOT NULL CHECK(input_revision BETWEEN 1 AND 128),
 input_digest bytea NOT NULL CHECK(octet_length(input_digest)=32),
 device_id uuid NOT NULL, line_id uuid NOT NULL, interval_id uuid NOT NULL,
 binding_generation bigint NOT NULL CHECK(binding_generation>0),
 root_generation bigint NOT NULL CHECK(root_generation>0),
 reader_key_id bytea NOT NULL CHECK(octet_length(reader_key_id)=32),
 peer_digest bytea NOT NULL CHECK(octet_length(peer_digest)=32),
 contact_id uuid NOT NULL, purpose text NOT NULL CHECK(purpose IN ('transactional','operational','marketing')),
 expires_ms bigint NOT NULL CHECK(expires_ms>0),
 PRIMARY KEY(account_id,call_id), UNIQUE(account_id,connector_id,event_id)
);
CREATE FUNCTION workflow_routine_original_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF NEW IS DISTINCT FROM OLD THEN
  RAISE EXCEPTION 'original routine source is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER workflow_routine_original_update BEFORE UPDATE ON workflow_routine_original_sources
 FOR EACH ROW EXECUTE FUNCTION workflow_routine_original_immutable();
CREATE FUNCTION workflow_routine_original_delete_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM accounts WHERE id=OLD.account_id) THEN
  RAISE EXCEPTION 'original routine source survives for account lifetime' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END; $$;
CREATE CONSTRAINT TRIGGER workflow_routine_original_delete AFTER DELETE ON workflow_routine_original_sources
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION workflow_routine_original_delete_guard();

-- Sample each volatile original-reader deadline once. Later effects retain the
-- same independently owner-configured input policy and content-read authority.
CREATE FUNCTION workflow_routine_original_deadline(wanted_account uuid,wanted_call uuid) RETURNS bigint
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
WITH candidate AS MATERIALIZED (
 SELECT original_reply_grant_deadline(s.account_id,s.original_grant_id) AS original_deadline,
 workflow_registry_binding_deadline(s.account_id,s.connector_id,s.reader_key_id,s.interval_id,
  g.trust_generation,g.manifest_version,g.manifest_digest,g.supplemental_original_grant_id) AS registry_deadline,
 LEAST(s.expires_ms,p.expires_ms,g.expires_ms,c.expires_at_ms,i.expires_at_ms,
  registration.expires_ms,reader.valid_until_ms,
  COALESCE(floor(extract(epoch FROM consent.expires_at)*1000)::bigint,9223372036854775807),
  floor(extract(epoch FROM policy_session.expires_at)*1000)::bigint,
  floor(extract(epoch FROM input_session.expires_at)*1000)::bigint,
  floor(extract(epoch FROM origin_session.expires_at)*1000)::bigint,
  COALESCE((SELECT max(permission.expires_ms) FROM connector_grants permission
   WHERE permission.account_id=s.account_id AND permission.connector_id=s.connector_id
   AND permission.line_id=s.line_id AND permission.kind='read'
   AND (permission.read_directions::integer & 8)=8 AND permission.revoked_ms IS NULL
   AND (cardinality(permission.conversation_restriction)=0 OR s.interval_id=ANY(permission.conversation_restriction))),0)) AS input_deadline
 FROM workflow_routine_original_sources s
 JOIN workflow_routine_policies p ON (p.account_id,p.id)=(s.account_id,s.policy_id)
 JOIN workflow_integration_grants g ON (g.account_id,g.grant_id)=(s.account_id,s.input_grant_id)
 JOIN original_reply_grants original ON (original.account_id,original.grant_id)=(s.account_id,s.original_grant_id)
 JOIN workflow_contexts c ON (c.account_id,c.id,c.revision)=(s.account_id,s.context_id,s.input_revision)
 JOIN workflow_context_versions v ON (v.account_id,v.context_id,v.revision)=(c.account_id,c.id,c.revision)
 JOIN workflow_connector_context_envelopes projection ON (projection.account_id,projection.grant_id,projection.context_id,projection.context_revision)=(g.account_id,g.grant_id,g.context_id,g.context_revision)
 JOIN workflow_context_fences context_fence ON (context_fence.account_id,context_fence.context_id)=(s.account_id,s.context_id)
 JOIN workflow_routines routine ON (routine.account_id,routine.id,routine.context_id,routine.generation)=(p.account_id,p.routine_id,p.context_id,p.generation)
 JOIN memberships policy_owner ON (policy_owner.account_id,policy_owner.user_id)=(p.account_id,p.created_by_user)
 JOIN users policy_user ON policy_user.id=p.created_by_user
 JOIN sessions policy_session ON (policy_session.account_id,policy_session.user_id,policy_session.id)=(p.account_id,p.created_by_user,p.created_session)
 JOIN memberships input_owner ON (input_owner.account_id,input_owner.user_id)=(g.account_id,g.created_by_user)
 JOIN users input_user ON input_user.id=g.created_by_user
 JOIN sessions input_session ON (input_session.account_id,input_session.user_id,input_session.id)=(g.account_id,g.created_by_user,g.created_session)
 JOIN conversation_intervals i ON (i.account_id,i.id)=(s.account_id,s.interval_id)
 JOIN sessions origin_session ON (origin_session.account_id,origin_session.id)=(i.account_id,i.initiating_session_id)
 JOIN memberships origin_owner ON (origin_owner.account_id,origin_owner.user_id)=(origin_session.account_id,origin_session.user_id)
 JOIN users origin_user ON origin_user.id=origin_session.user_id
 JOIN connector_registrations registration ON (registration.account_id,registration.connector_id,registration.key_id)=(s.account_id,s.connector_id,s.reader_key_id)
 JOIN connector_keys reader ON (reader.account_id,reader.connector_id,reader.key_id)=(registration.account_id,registration.connector_id,registration.key_id)
 JOIN sealed_inbound_events e ON (e.account_id,e.id)=(s.account_id,s.event_id)
 JOIN conversation_inbound_provenance provenance ON (provenance.account_id,provenance.event_id,provenance.interval_id)=(s.account_id,s.event_id,s.interval_id)
 JOIN contacts contact ON (contact.account_id,contact.id)=(s.account_id,s.contact_id)
 JOIN LATERAL (SELECT action,effective_at,expires_at FROM contact_consent_records
  WHERE account_id=s.account_id AND contact_id=s.contact_id AND purpose=s.purpose
  ORDER BY effective_at DESC,recorded_at DESC,id DESC LIMIT 1) consent ON true
 WHERE s.account_id=wanted_account AND s.call_id=wanted_call
 AND p.withdrawn_ms IS NULL AND p.input_grant_id=s.input_grant_id AND p.policy_digest=s.policy_digest
 AND (p.context_id,p.input_revision,p.input_digest)=(s.context_id,s.input_revision,s.input_digest)
 AND p.policy->'original_input'->>'grant_id'=s.original_grant_id::text
 AND p.policy->>'executor'='local_process'
 AND g.revoked_ms IS NULL AND (g.permissions::integer & 4)=4
 AND (g.trust_generation,g.manifest_version,g.manifest_digest)=(original.trust_generation,original.manifest_version,original.manifest_digest)
 AND (g.context_id,g.context_revision,g.device_id,g.line_id,g.connector_id,g.reader_key_id,g.contact_id,g.purpose,g.binding_generation,g.trust_generation)=(s.context_id,s.input_revision,s.device_id,s.line_id,s.connector_id,s.reader_key_id,s.contact_id,s.purpose,s.binding_generation,s.root_generation)
 AND (original.interval_id,original.connector_id,original.reader_key_id,original.trust_generation)=(s.interval_id,s.connector_id,s.reader_key_id,s.root_generation)
 AND c.purged_at IS NULL AND v.envelope IS NOT NULL AND sha256(v.envelope)=s.input_digest
 AND (c.device_id,c.line_id,c.interval_id,c.peer_digest)=(s.device_id,s.line_id,s.interval_id,s.peer_digest)
 AND projection.envelope IS NOT NULL AND sha256(projection.envelope)=projection.envelope_digest
 AND routine.stopped_at IS NULL AND context_fence.stopped_at IS NULL
 AND policy_owner.role='owner' AND policy_owner.revoked_at IS NULL
 AND policy_user.email_verified_at IS NOT NULL AND policy_user.mfa_enabled AND policy_session.revoked_at IS NULL
 AND input_owner.role='owner' AND input_owner.revoked_at IS NULL
 AND input_user.email_verified_at IS NOT NULL AND input_user.mfa_enabled AND input_session.revoked_at IS NULL
 AND origin_owner.role='owner' AND origin_owner.revoked_at IS NULL AND origin_user.email_verified_at IS NOT NULL
 AND origin_session.revoked_at IS NULL AND i.phase='active'
 AND registration.state='active' AND registration.revoked_ms IS NULL
 AND reader.retired_ms IS NULL AND reader.valid_from_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 AND e.envelope IS NOT NULL AND sha256(e.envelope)=s.event_digest
 AND (e.device_id,e.line_id,e.binding_generation)=(s.device_id,s.line_id,s.binding_generation)
 AND provenance.trust_generation=s.root_generation
 AND sha256(convert_to(contact.recipient_e164,'UTF8'))=s.peer_digest
 AND consent.action='grant' AND consent.effective_at<=clock_timestamp()
 AND (consent.expires_at IS NULL OR consent.expires_at>clock_timestamp())
 AND NOT EXISTS(SELECT 1 FROM recipient_suppressions suppression
  WHERE suppression.account_id=s.account_id AND suppression.recipient_e164=contact.recipient_e164 AND suppression.active)
 AND NOT EXISTS(SELECT 1 FROM owner_recipient_holds hold
  WHERE hold.account_id=s.account_id AND hold.recipient_e164=contact.recipient_e164 AND hold.released_at IS NULL)
)
SELECT LEAST(original_deadline,registry_deadline,input_deadline) FROM candidate
 WHERE original_deadline IS NOT NULL AND registry_deadline IS NOT NULL AND input_deadline IS NOT NULL;
$$;
CREATE FUNCTION workflow_routine_original_current(wanted_account uuid,wanted_call uuid) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT COALESCE(workflow_routine_original_deadline(wanted_account,wanted_call)>
 floor(extract(epoch FROM clock_timestamp())*1000)::bigint,false);
$$;

CREATE FUNCTION workflow_routine_original_action_current(wanted_account uuid,wanted_action uuid) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT CASE WHEN EXISTS(SELECT 1 FROM workflow_routine_original_sources WHERE account_id=wanted_account AND call_id=wanted_action)
 THEN workflow_routine_original_current(wanted_account,wanted_action) AND (
  NOT EXISTS(SELECT 1 FROM workflow_actions WHERE account_id=wanted_account AND id=wanted_action)
  OR EXISTS(SELECT 1 FROM workflow_routine_original_sources s
   JOIN workflow_actions action ON (action.account_id,action.id)=(s.account_id,s.call_id)
   JOIN workflow_action_versions version ON (version.account_id,version.action_id,version.revision,version.binding_digest)=(action.account_id,action.id,action.revision,action.binding_digest)
   WHERE s.account_id=wanted_account AND s.call_id=wanted_action
   AND (action.context_id,action.routine_id,version.context_id,version.routine_id)=(s.call_id,s.call_id,s.call_id,s.call_id)
   AND version.expires_at_ms<=s.expires_ms
   AND convert_from(version.descriptor,'UTF8')::jsonb->>'recipient_id'=s.contact_id::text
   AND convert_from(version.descriptor,'UTF8')::jsonb->>'line_id'=s.line_id::text
   AND CASE convert_from(version.descriptor,'UTF8')::jsonb->>'purpose_id'
    WHEN '00000000-0000-0000-0000-000000000001' THEN 'transactional'
    WHEN '00000000-0000-0000-0000-000000000002' THEN 'operational'
    WHEN '00000000-0000-0000-0000-000000000003' THEN 'marketing' END=s.purpose)
 ) ELSE true END;
$$;
ALTER FUNCTION workflow_effect_current(uuid,uuid) RENAME TO workflow_routine_original_predecessor_effect_current;
CREATE FUNCTION workflow_effect_current(wanted_account uuid,wanted_message uuid) RETURNS boolean
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
SELECT workflow_routine_original_predecessor_effect_current(wanted_account,wanted_message) AND EXISTS(
 SELECT 1 FROM messages m WHERE m.account_id=wanted_account AND m.id=wanted_message
 AND workflow_routine_original_action_current(m.account_id,m.workflow_action_id));
$$;

-- Extend the existing lineage additively; migration088 stays immutable.
CREATE OR REPLACE FUNCTION original_reply_source_current(wanted_account uuid,wanted_action uuid) RETURNS boolean
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
 effective_deadline bigint := 9223372036854775807;
 hop_deadline bigint;
BEGIN
 LOOP
  -- A configured-original routine is a retained authority root, not an
  -- ordinary parent. Include its exact effective deadline before traversing
  -- or terminating; preserve the same bounded nonrecursive reply lineage.
  IF EXISTS(SELECT 1 FROM workflow_routine_original_sources WHERE account_id=wanted_account AND call_id=current_action) THEN
   hop_deadline:=workflow_routine_original_deadline(wanted_account,current_action);
   IF hop_deadline IS NULL OR NOT workflow_routine_original_action_current(wanted_account,current_action) THEN RETURN false; END IF;
   effective_deadline:=LEAST(effective_deadline,hop_deadline);
  END IF;
  -- Only a genuinely ordinary action terminates the retained provenance chain.
  IF NOT EXISTS(SELECT 1 FROM original_reply_sources WHERE account_id=wanted_account AND action_id=current_action) THEN
   RETURN effective_deadline>floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
  END IF;
  IF links>=128 OR current_action=ANY(visited) THEN RETURN false; END IF;
  visited := array_append(visited,current_action);
  links := links+1;
  SELECT revision,binding_digest INTO current_revision,current_digest FROM workflow_actions
   WHERE account_id=wanted_account AND id=current_action;
  IF NOT FOUND THEN RETURN false; END IF;
  hop_deadline := original_reply_source_one_deadline(wanted_account,current_action);
  IF hop_deadline IS NULL THEN RETURN false; END IF;
  effective_deadline := LEAST(effective_deadline,hop_deadline);
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
