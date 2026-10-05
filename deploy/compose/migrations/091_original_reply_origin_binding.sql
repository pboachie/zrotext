-- SPDX-License-Identifier: AGPL-3.0-only
-- Propose-origin deadlines use the same exact, live selected-reader binding
-- as grant authorization, including its immutable original-grant association.
CREATE OR REPLACE FUNCTION original_reply_integration_origin_deadline(wanted_account uuid,wanted_grant uuid,wanted_action uuid) RETURNS bigint
LANGUAGE sql VOLATILE SET search_path FROM CURRENT AS $$
    SELECT LEAST(g.expires_ms, floor(extract(epoch FROM creator.expires_at)*1000)::bigint, floor(extract(epoch FROM origin.expires_at)*1000)::bigint, registration.expires_ms, reader.valid_until_ms, context.expires_at_ms, interval.expires_at_ms,
     COALESCE(workflow_registry_binding_deadline(g.account_id,g.connector_id,g.reader_key_id,context.interval_id,g.trust_generation,g.manifest_version,g.manifest_digest,g.supplemental_original_grant_id),0)) FROM workflow_integration_grants g
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
      AND (g.permissions::integer & 8)=8
      AND (8=32 OR g.signer_key_id IS NOT NULL)
      AND tenant.disabled_at IS NULL AND membership.role='owner' AND membership.revoked_at IS NULL
      AND owner.email_verified_at IS NOT NULL AND owner.mfa_enabled
      AND creator.revoked_at IS NULL AND creator.expires_at>clock_timestamp()
      AND origin.revoked_at IS NULL AND origin.expires_at>clock_timestamp()
      AND origin_membership.role='owner' AND origin_membership.revoked_at IS NULL AND origin_owner.email_verified_at IS NOT NULL
      AND root.revoked_at IS NULL AND (root.generation,root.version,root.semantic_digest)=(g.trust_generation,g.manifest_version,g.manifest_digest)
      AND registration.state='active' AND registration.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
      AND workflow_registry_binding_deadline(g.account_id,g.connector_id,g.reader_key_id,context.interval_id,g.trust_generation,g.manifest_version,g.manifest_digest,g.supplemental_original_grant_id)>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
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
      AND (8=8 OR EXISTS(SELECT 1 FROM connector_grants cg
          WHERE (cg.account_id,cg.connector_id,cg.line_id)=(g.account_id,g.connector_id,g.line_id)
            AND cg.kind='send' AND cg.revoked_ms IS NULL AND cg.expires_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint
            AND (cardinality(cg.conversation_restriction)=0 OR context.interval_id=ANY(cg.conversation_restriction))))
;
$$;
