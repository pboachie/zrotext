// SPDX-License-Identifier: AGPL-3.0-only
//! Accepted03 history plus actual present selection. Device reader availability
//! deliberately has no live owner/session projection or message permission.
use super::*;
use crate::sealed_manifest03 as crypto;
use crate::sealed_payload_election03::{
    self as election, activation_evidence::ActivationEvidence03, activation_records, device_context,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use uuid::Uuid;
mod permission;
mod physical;
pub(crate) use permission::{
    HeldMessageSelection03, hold_interval_selection, hold_owner_selection, hold_step_up_selection,
};

struct Current<'held, 'db> {
    reservation: Reservation,
    accepted: election::DurableAcceptedElection03,
    bundle: Vec<u8>,
    history: activation_records::HistoricalActivation03,
    context: device_context::HeldDeviceContext03<'held, 'db>,
    epoch: u64,
    checked: u64,
    deadline: u64,
    proof: election::VerifiedElection03,
    manifest: crypto::VerifiedManifest03,
    authority: election::CurrentAuthority03,
}
impl<'held, 'db> Current<'held, 'db> {
    async fn lock(
        tx: &'held Transaction<'db>,
        account: Uuid,
        line: Uuid,
        origin: &str,
    ) -> Result<Self> {
        crate::payload_profile_elections::require(tx)
            .await
            .map_err(|_| Error::Unavailable)?;
        tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'").await?;
        let root=tx.query_opt("SELECT root_pin,root_fingerprint,generation,version,semantic_digest,anchor_digest,manifest,accepted_at_ms,last_verified_ms FROM public.sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE NOWAIT",&[&account]).await?.ok_or(Error::Unsupported)?;
        let pin: [u8; 94] = fixed(&root, 0)?;
        let fingerprint: [u8; 32] = fixed(&root, 1)?;
        if positive(root.try_get(2)?)? != 1 || fixed::<32>(&root, 5)? != [0; 32] {
            return Err(Error::Unsupported);
        }
        let key = super::super::adapter_contract::account_fence_key(account.as_bytes())
            .map_err(|_| Error::Unsupported)?;
        if !tx
            .query_one(
                "SELECT pg_catalog.pg_try_advisory_xact_lock_shared($1)",
                &[&key],
            )
            .await?
            .try_get::<_, bool>(0)?
        {
            return Err(Error::Conflict);
        }
        let anchor=tx.query_opt("SELECT selection_epoch FROM public.payload_profile_account_anchors WHERE account_id=$1 AND state='live' FOR SHARE NOWAIT",&[&account]).await?.ok_or(Error::Unsupported)?;
        let epoch = u64::try_from(anchor.try_get::<_, i64>(0)?).map_err(|_| Error::Unsupported)?;
        if epoch == 0 {
            return Err(Error::NotFound);
        }
        tx.query_opt(
            "SELECT id FROM public.accounts WHERE id=$1 AND disabled_at IS NULL FOR SHARE NOWAIT",
            &[&account],
        )
        .await?
        .ok_or(Error::Authentication)?;
        let selected=tx.query_opt("SELECT b.device_id,b.generation,b.owner_approval_digest,b.device_confirmation_digest,e.opening_id FROM public.phone_lines l JOIN public.device_line_bindings b ON (b.account_id,b.line_id,b.generation)=(l.account_id,l.id,l.current_binding_generation) JOIN public.payload_profile_elections e ON (e.account_id,e.line_id,e.device_id,e.new_binding_generation)=(b.account_id,b.line_id,b.device_id,b.generation) WHERE l.account_id=$1 AND l.id=$2 AND l.state='active' AND l.approved_at IS NOT NULL AND b.state='active' AND b.purpose='sealed' AND b.activated_at IS NOT NULL FOR SHARE OF l,b NOWAIT",&[&account,&line]).await?.ok_or(Error::Unsupported)?;
        let device: Uuid = selected.try_get(0)?;
        let generation = positive(selected.try_get(1)?)?;
        let opening: Uuid = selected.try_get(4)?;
        let reservation = Reservation::read(tx, account, opening)
            .await?
            .ok_or(Error::Unsupported)?;
        let row=tx.query_opt("SELECT * FROM public.payload_profile_elections WHERE account_id=$1 AND opening_id=$2",&[&account,&opening]).await?.ok_or(Error::Unsupported)?;
        let accepted = transition::accepted_record(&row)?;
        transition::matches_mapping(&reservation, &accepted)?;
        let bundle: Vec<u8> = row.try_get("bundle")?;
        let receipt_epoch = positive(row.try_get("selection_epoch")?)?;
        if !reservation.accepted
            || reservation.closed.is_some()
            || reservation.line != line
            || reservation.device != device
            || reservation.new_generation != generation
            || receipt_epoch != epoch
            || reservation.pin != pin
            || accepted.root_fingerprint != fingerprint
            || fixed::<32>(&selected, 2)?
                != row
                    .try_get::<_, Vec<u8>>("owner_approval_digest")?
                    .as_slice()
            || fixed::<32>(&selected, 3)?
                != row
                    .try_get::<_, Vec<u8>>("device_confirmation_digest")?
                    .as_slice()
        {
            return Err(Error::Conflict);
        }
        let checkpoint = reservation.checkpoint()?;
        let proof = election::verify_accepted(&election::AcceptedProofInput03 {
            bundle: &bundle,
            expected_core: &reservation.core,
            accepted: &accepted,
            predecessor02: &checkpoint,
            accepted_signed_manifest03: &reservation.successor,
            device_signing_point_at_acceptance: &reservation.device_point,
            owner_approval_point_at_acceptance: &reservation.owner_point,
        })
        .map_err(|_| Error::Unsupported)?;
        let original03 =
            crypto::verify_from_02(&reservation.successor, &checkpoint, accepted.accepted_at_ms)
                .map_err(|_| Error::Unsupported)?;
        let history = activation_records::read_locked(
            tx,
            activation_records::Locator {
                account,
                binding: reservation.old_binding,
                selected_reader_key_id: accepted.selected_reader_key_id,
            },
            origin,
        )
        .await
        .map_err(|_| Error::Unsupported)?;
        let original = ActivationEvidence03::decode(history.canonical_evidence())
            .map_err(|_| Error::Unsupported)?;
        if history.identity().line != line
            || history.identity().device != device
            || history.identity().generation != reservation.old_generation
            || *history.old_binding_proof_digest() != accepted.old_binding_proof_digest
            || original.device_point != reservation.device_point
            || original.owner_point != reservation.owner_point
        {
            return Err(Error::Conflict);
        }
        let lease=tx.query_opt("SELECT site_id,instance_id,connection_epoch,deployment_epoch FROM public.device_sessions WHERE account_id=$1 AND device_id=$2 FOR SHARE NOWAIT",&[&account,&device]).await?.ok_or(Error::Unavailable)?;
        let actual = device_context::Selector {
            account,
            device,
            site: lease.try_get(0)?,
            instance: lease.try_get(1)?,
            connection_epoch: positive(lease.try_get(2)?)?,
            deployment_epoch: positive(lease.try_get(3)?)?,
        };
        let context = device_context::lock(tx, &actual)
            .await
            .map_err(|_| Error::Unavailable)?;
        if context.selection_epoch() != epoch
            || context.root_fingerprint() != &fingerprint
            || context.enrollment_signing_key_id().as_slice() != &reservation.core[288..320]
        {
            return Err(Error::Conflict);
        }
        let now = clock(
            tx,
            context
                .checked_primary_ms()
                .max(positive(root.try_get(8)?)?)
                .max(history.registration().checked_primary_ms()),
        )
        .await?;
        // The bounded first deployment supports the exact accepted03 selection.
        // A later, unproven ancestry or alternate signed packet is not inferred.
        let current_bytes: Vec<u8> = root.try_get(6)?;
        if current_bytes != reservation.successor
            || positive(root.try_get(7)?)? != accepted.accepted_at_ms
        {
            return Err(Error::Unsupported);
        }
        let manifest = crypto::verify_current(&current_bytes, &original03, now)
            .map_err(|_| Error::Unsupported)?;
        let identity = manifest.identity_at(now).map_err(|_| Error::Unsupported)?;
        let roles = manifest
            .profile_election_keys(
                device.as_bytes(),
                line.as_bytes(),
                &reservation.device_point,
                &reservation.owner_point,
                now,
            )
            .map_err(|_| Error::Unsupported)?;
        let approval=tx.query_opt("SELECT signing_key_sec1,fingerprint FROM public.line_owner_approval_keys WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE NOWAIT",&[&account]).await?.ok_or(Error::Unsupported)?;
        if fixed::<65>(&approval, 0)? != reservation.owner_point
            || fixed::<32>(&approval, 1)? != crypto::sha(&reservation.owner_point)
            || roles.reader_id != accepted.selected_reader_key_id
            || roles.device_signer_id != reservation.core[288..320]
            || roles.approval_id != reservation.core[320..352]
            || positive(root.try_get(3)?)? != identity.version
            || fixed::<32>(&root, 4)? != identity.digest
        {
            return Err(Error::Conflict);
        }
        let deadline = context.lease_deadline_ms().min(roles.expires_ms);
        let authority = election::require_current(
            &proof,
            &manifest,
            &election::CurrentAuthority03 {
                profile: 3,
                manifest_profile: 3,
                account_id: *account.as_bytes(),
                device_id: *device.as_bytes(),
                line_id: *line.as_bytes(),
                binding_id: *reservation.new_binding.as_bytes(),
                binding_generation: generation,
                selected_reader_key_id: roles.reader_id,
                root_fingerprint: fingerprint,
                vault_generation: 1,
                manifest_version: identity.version,
                manifest_digest: identity.digest,
                election_commitment: accepted.election_commitment,
                election_bundle_sha256: accepted.election_bundle_sha256,
                compared_at_ms: now,
                permission_expires_at_ms: deadline,
            },
            now,
        )
        .map_err(|_| Error::Expired)?;
        Ok(Self {
            reservation,
            accepted,
            bundle,
            history,
            context,
            epoch,
            checked: now,
            deadline,
            proof,
            manifest,
            authority,
        })
    }
    async fn original_physical(&self, tx: &Transaction<'_>) -> Result<()> {
        let old = self.history.original_proof_lease();
        let current = self.context.selected_identity();
        if old.site_id() != current.site
            || old.instance_id() != current.instance
            || old.connection_epoch() != current.connection_epoch
            || old.deployment_epoch() != current.deployment_epoch
            || self.reservation.core[464..496] != *self.context.identity_digest()
        {
            return Err(Error::Unsupported);
        }
        tx.query_opt("SELECT challenge_id FROM public.line_activation_v2_pending WHERE account_id=$1 AND challenge_id=$2 AND protocol_version=2 AND purpose='sealed' AND approved_at IS NOT NULL AND installed_at IS NOT NULL AND retired_at IS NULL AND nonce IS NULL FOR SHARE NOWAIT",&[&self.reservation.account,&self.history.activation_challenge_id()]).await?.ok_or(Error::Unsupported)?;
        Ok(())
    }
    fn projection(&self, origin: &str) -> Result<serde_json::Value> {
        let r = &self.reservation;
        let a = &self.accepted;
        let device = self.context.selected_identity();
        Ok(
            serde_json::json!({"v":1,"envelope_profile":3,"manifest_profile":3,"account_id":r.account,"device_id":r.device,"line_id":r.line,"selection_epoch":self.epoch.to_string(),"origin_digest":B.encode(super::super::adapter_contract::origin_digest(origin).map_err(|_|Error::Unavailable)?),"device_session_digest":B.encode(self.context.identity_digest()),"site_id":device.site,"instance_id":device.instance,"connection_epoch":device.connection_epoch.to_string(),"deployment_epoch":device.deployment_epoch.to_string(),"old_binding_id":r.old_binding,"old_binding_generation":r.old_generation.to_string(),"old_binding_proof_digest":B.encode(a.old_binding_proof_digest),"binding_id":r.new_binding,"binding_generation":r.new_generation.to_string(),"reader_key_id":B.encode(a.selected_reader_key_id),"device_signing_key_id":B.encode(&r.core[288..320]),"approval_key_id":B.encode(&r.core[320..352]),"root_fingerprint":B.encode(a.root_fingerprint),"trust_generation":"1","manifest_version":a.accepted_manifest_version.to_string(),"manifest_digest":B.encode(a.accepted_manifest_digest),"election_digest":B.encode(a.election_commitment),"election_bundle_sha256":B.encode(a.election_bundle_sha256),"compared_ms":self.checked.to_string(),"evidence":{"root_pin":B.encode(r.pin),"prior_manifest02":B.encode(&r.prior),"prior_accepted_ms":r.prior_accepted.to_string(),"accepted_manifest03":B.encode(&r.successor),"accepted_ms":a.accepted_at_ms.to_string(),"bundle":B.encode(&self.bundle),"device_signing_point":B.encode(r.device_point),"owner_approval_point":B.encode(r.owner_point),"registration_evidence":B.encode(self.history.registration().canonical_evidence()),"activation_evidence":B.encode(self.history.canonical_evidence())}}),
        )
    }
}

pub async fn current(
    tx: &Transaction<'_>,
    owner: &mut HeldOrdinaryOwner03<'_, '_>,
    line: Uuid,
    origin: &str,
) -> Result<serde_json::Value> {
    if !owner.uses_transaction(tx) {
        return Err(Error::Authentication);
    }
    let who = owner.selected_identity();
    let mut current = Current::lock(tx, who.account, line, origin).await?;
    let _physical = current.physical(tx).await?;
    owner
        .revalidate()
        .await
        .map_err(|_| Error::Authentication)?;
    current
        .context
        .revalidate()
        .await
        .map_err(|_| Error::Unavailable)?;
    if owner.selection_epoch() != current.epoch
        || owner.root_fingerprint() != &current.accepted.root_fingerprint
    {
        return Err(Error::Conflict);
    }
    current.checked = clock(
        tx,
        current
            .checked
            .max(owner.checked_at_ms())
            .max(current.context.checked_primary_ms()),
    )
    .await?;
    let deadline = current.deadline.min(owner.session_deadline_ms());
    if current.checked >= deadline {
        return Err(Error::Expired);
    }
    let mut value = current.projection(origin)?;
    let object = value.as_object_mut().ok_or(Error::Unavailable)?;
    object.insert("user_id".into(), serde_json::json!(who.user));
    object.insert("owner_session_id".into(), serde_json::json!(who.session));
    object.insert(
        "owner_session_digest".into(),
        serde_json::json!(B.encode(owner.identity_digest())),
    );
    object.insert(
        "permission_expires_ms".into(),
        serde_json::json!(deadline.to_string()),
    );
    Ok(value)
}

pub(crate) async fn device_current(
    tx: &Transaction<'_>,
    session: crate::device_socket::DeviceSession,
    site: &str,
    instance: &str,
    deployment: u64,
    line: Uuid,
    origin: &str,
) -> Result<serde_json::Value> {
    let mut current = Current::lock(tx, session.account_id, line, origin).await?;
    let actual = current.context.selected_identity();
    if current.reservation.device != session.device_id
        || actual.site != site
        || actual.instance != instance
        || actual.connection_epoch != positive(session.connection_epoch)?
        || actual.deployment_epoch != deployment
    {
        return Err(Error::Authentication);
    }
    let physical = current.physical(tx).await?;
    current
        .context
        .revalidate()
        .await
        .map_err(|_| Error::Unavailable)?;
    current.checked = clock(
        tx,
        current.checked.max(current.context.checked_primary_ms()),
    )
    .await?;
    if current.checked >= current.deadline {
        return Err(Error::Expired);
    }
    let mut value = current.projection(origin)?;
    let object = value.as_object_mut().ok_or(Error::Unavailable)?;
    object.insert("kind".into(), serde_json::json!("device_selection03"));
    object.insert(
        "selection_expires_ms".into(),
        serde_json::json!(current.deadline.to_string()),
    );
    object.insert("physical_selection".into(), physical.projection());
    Ok(value)
}
