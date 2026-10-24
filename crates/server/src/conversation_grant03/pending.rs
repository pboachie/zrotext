// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only candidate selection under the explicit account mode. These
//! mutable predicates prevent obsolete work starving a genuine later request;
//! they confer no owner, cryptographic, billing or effect authority.
use super::*;

pub(super) async fn next(
    tx: &Transaction<'_>,
    actor: DeviceInterval03<'_>,
    ready: &ReadyFrame03,
) -> Result<Option<Uuid>> {
    let r = ready.claims();
    if r.connection_epoch != actor.session.connection_epoch
        || r.deployment_epoch != sqltime(actor.deployment)?
    {
        return Err(Error::Authentication);
    }
    let row = tx.query_opt(
        r#"SELECT m.id
        FROM public.messages m
        JOIN public.dispatch_jobs job ON(job.account_id,job.message_id,job.device_id)=(m.account_id,m.id,m.device_id)
        JOIN public.conversation_reviewed_sends03 review ON(review.account_id,review.message_id)=(m.account_id,m.id)
        JOIN public.conversation_profile03_intervals c ON(c.account_id,c.interval_id)=(review.account_id,review.interval_id)
        JOIN public.sessions s ON(s.account_id,s.user_id,s.id)=(c.account_id,c.initiating_user_id,c.initiating_session_id)
        JOIN public.memberships member ON(member.account_id,member.user_id)=(s.account_id,s.user_id)
        JOIN public.users u ON u.id=s.user_id
        JOIN public.owner_mfa mfa ON(mfa.account_id,mfa.user_id)=(s.account_id,s.user_id)
        JOIN public.accounts account ON account.id=c.account_id
        JOIN public.payload_profile_account_anchors anchor ON anchor.account_id=c.account_id
        JOIN public.sealed_manifest_authorities authority ON authority.account_id=c.account_id
        JOIN public.phone_lines line ON(line.account_id,line.id)=(c.account_id,c.line_id)
        JOIN public.device_line_bindings binding ON(binding.account_id,binding.line_id,binding.device_id,binding.generation)
            =(c.account_id,c.line_id,c.device_id,c.binding_generation)
        WHERE m.account_id=$1 AND m.device_id=$2 AND c.proof_site_id=$3 AND c.proof_instance_id=$4
            AND c.proof_connection_epoch=$5 AND c.proof_deployment_epoch=$6
            AND c.line_id=$7 AND c.binding_generation=$8 AND c.selected_reader_key_id=$9
            AND c.manifest_version=$10 AND c.manifest_digest=$11
            AND c.root_fingerprint=$12 AND c.election_commitment=$13
            AND m.transport_mode='sealed_profile03' AND m.state='queued' AND m.state_version=1
            AND m.transport_payload IS NOT NULL AND m.recipient_e164 IS NOT NULL
            AND m.expires_at>pg_catalog.clock_timestamp()
            AND review.redacted_ms IS NULL AND review.intent IS NOT NULL AND review.signature IS NOT NULL
            AND review.peer IS NOT NULL AND review.initiating_user_id=c.initiating_user_id
            AND review.initiating_session_id=c.initiating_session_id
            AND review.admitted_ms>=c.installed_ms
            AND review.admitted_ms<=pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint
            AND c.phase='active' AND c.installed_ms IS NOT NULL
            AND c.interval_starts_ms<=pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint
            AND c.interval_expires_ms>pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint
            AND job.generation=0 AND job.lease_owner IS NULL AND job.lease_until IS NULL
            AND job.grant_issued_at IS NULL AND job.finished_at IS NULL
            AND job.next_attempt_at<=pg_catalog.clock_timestamp()
            AND NOT EXISTS(SELECT 1 FROM public.conversation_profile03_grants g WHERE(g.account_id,g.message_id)=(m.account_id,m.id))
            AND NOT EXISTS(SELECT 1 FROM public.message_attempts a WHERE(a.account_id,a.message_id)=(m.account_id,m.id))
            AND NOT EXISTS(SELECT 1 FROM public.dispatch_fences f WHERE(f.account_id,f.message_id)=(m.account_id,m.id))
            AND NOT EXISTS(SELECT 1 FROM public.dispatch_fences f WHERE f.account_id=m.account_id
                AND f.device_id=m.device_id AND f.outcome IN('granted','submitting','unknown'))
            AND NOT EXISTS(SELECT 1 FROM public.recipient_suppressions suppression
                WHERE suppression.account_id=m.account_id AND suppression.recipient_e164=m.recipient_e164 AND suppression.active)
            AND NOT EXISTS(SELECT 1 FROM public.owner_recipient_holds hold
                WHERE hold.account_id=m.account_id AND hold.recipient_e164=m.recipient_e164 AND hold.released_at IS NULL)
            AND s.revoked_at IS NULL AND s.expires_at>pg_catalog.clock_timestamp()
            AND COALESCE(s.last_used_at,s.created_at)>pg_catalog.clock_timestamp()-interval '72 hours'
            AND member.role='owner' AND member.revoked_at IS NULL
            AND u.email_verified_at IS NOT NULL AND u.mfa_enabled AND mfa.enabled_at IS NOT NULL
            AND account.disabled_at IS NULL AND anchor.state='live' AND anchor.selection_epoch=c.selection_epoch
            AND authority.revoked_at IS NULL AND authority.version=c.manifest_version
            AND authority.root_fingerprint=c.root_fingerprint AND authority.manifest=c.signed_manifest
            AND authority.semantic_digest=c.manifest_digest
            AND line.state='active' AND line.approved_at IS NOT NULL AND line.current_binding_generation=c.binding_generation
            AND binding.state='active' AND binding.purpose='sealed' AND binding.activated_at IS NOT NULL
            AND((c.physical_source_kind='original_v2' AND NOT EXISTS(
                SELECT 1 FROM public.payload_profile_selection_challenges fresh
                WHERE(fresh.account_id,fresh.binding_id,fresh.proof_site_id,fresh.proof_instance_id,fresh.proof_connection_epoch,fresh.proof_deployment_epoch)
                    =(c.account_id,c.binding_id,c.proof_site_id,c.proof_instance_id,c.proof_connection_epoch,c.proof_deployment_epoch)
                    AND fresh.device_signature IS NOT NULL))
                OR(c.physical_source_kind='owner_refresh03' AND EXISTS(
                SELECT 1 FROM public.payload_profile_selection_receipts fresh
                WHERE(fresh.account_id,fresh.refresh_id,fresh.binding_id,fresh.proof_site_id,fresh.proof_instance_id,fresh.proof_connection_epoch,fresh.proof_deployment_epoch)
                    =(c.account_id,c.physical_refresh_id,c.binding_id,c.proof_site_id,c.proof_instance_id,c.proof_connection_epoch,c.proof_deployment_epoch)
                    AND fresh.installed_ms IS NOT NULL)))
            AND NOT EXISTS(
                SELECT 1 FROM pg_catalog.generate_series(0,pg_catalog.octet_length(c.integration_readers)/64-1) selected(i)
                WHERE NOT EXISTS(
                    SELECT 1 FROM public.connector_registrations registry
                    JOIN public.connector_keys reader_key ON(reader_key.account_id,reader_key.connector_id,reader_key.key_id)=(registry.account_id,registry.connector_id,registry.key_id)
                    JOIN public.connector_grants read_grant ON(read_grant.account_id,read_grant.connector_id)=(registry.account_id,registry.connector_id)
                    WHERE registry.account_id=c.account_id
                        AND registry.connector_id=pg_catalog.encode(substring(c.integration_readers FROM selected.i*64+1 FOR 16),'hex')::uuid
                        AND read_grant.grant_id=pg_catalog.encode(substring(c.integration_readers FROM selected.i*64+17 FOR 16),'hex')::uuid
                        AND registry.key_id=substring(c.integration_readers FROM selected.i*64+33 FOR 32)
                        AND registry.state='active' AND registry.revoked_ms IS NULL AND registry.manifest_generation=c.vault_generation
                        AND reader_key.retired_ms IS NULL AND reader_key.key_point=registry.key_point
                        AND registry.expires_ms>pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint
                        AND reader_key.valid_from_ms<=pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint
                        AND reader_key.valid_until_ms>pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint
                        AND read_grant.kind='read' AND read_grant.read_directions=12 AND read_grant.line_id=c.line_id AND read_grant.revoked_ms IS NULL
                        AND read_grant.expires_ms>pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint
                        AND(pg_catalog.cardinality(read_grant.conversation_restriction)=0 OR c.interval_id=ANY(read_grant.conversation_restriction))))
        ORDER BY job.next_attempt_at,m.id LIMIT 1"#,
        &[&actor.session.account_id,&actor.session.device_id,&actor.site,&actor.instance,
            &actor.session.connection_epoch,&sqltime(actor.deployment)?,&r.line_id,&r.binding_generation,
            &&r.reader_key_id[..],&r.manifest_version,&&r.manifest_digest[..],&&r.root_fingerprint[..],&&r.election_digest[..]],
    ).await?;
    row.map(|r| r.try_get(0).map_err(Error::Database))
        .transpose()
}
