// SPDX-License-Identifier: AGPL-3.0-only
//! Original02 selection assembled from actual held rows and genuine signatures.
//! This is the reserve/bootstrap input, not accepted03 or dispatch permission.
use super::*;
use crate::sealed_manifest::{self, ChainPosition, ManifestTrust, ProfileElectionKeys};
use crate::sealed_manifest03::{self, AuthenticatedCheckpoint02, VerifiedCheckpoint02};
use crate::sealed_payload_election03::{
    activation_evidence::ActivationEvidence03,
    activation_records::{self, HistoricalActivation03},
    device_context::{self, HeldDeviceContext03},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use uuid::Uuid;

pub(super) struct Current02<'held, 'db> {
    pub line: Uuid,
    pub device: Uuid,
    pub generation: u64,
    pub last_issued: u64,
    pub pin: [u8; 94],
    pub fingerprint: [u8; 32],
    pub manifest: Vec<u8>,
    pub manifest_version: u64,
    pub manifest_digest: [u8; 32],
    pub prior_accepted_ms: u64,
    pub checkpoint: VerifiedCheckpoint02,
    pub selected: ProfileElectionKeys,
    pub device_point: [u8; 65],
    pub owner_point: [u8; 65],
    pub history: HistoricalActivation03,
    pub context: HeldDeviceContext03<'held, 'db>,
    pub checked_ms: u64,
}
impl<'held, 'db> Current02<'held, 'db> {
    pub(super) async fn lock(
        tx: &'held Transaction<'db>,
        owner: &Owner<'_, '_, '_>,
        line: Uuid,
        origin: &str,
    ) -> Result<Self> {
        if line.is_nil() || !owner.uses(tx) {
            return Err(Error::Authentication);
        }
        crate::payload_profile_v2_receipts::require(tx)
            .await
            .map_err(|_| Error::Unavailable)?;
        let who = owner.selector();
        let root=tx.query_opt("SELECT root_pin,root_fingerprint,generation,version,semantic_digest,anchor_digest,manifest,accepted_at_ms,last_verified_ms FROM public.sealed_manifest_authorities WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE NOWAIT",&[&who.account]).await?.ok_or(Error::Unsupported)?;
        let pin = fixed(&root, 0)?;
        let fingerprint = fixed(&root, 1)?;
        let generation = positive(root.try_get(2)?)?;
        let version = positive(root.try_get(3)?)?;
        let semantic = fixed(&root, 4)?;
        let anchor = fixed(&root, 5)?;
        let manifest: Vec<u8> = root.try_get(6)?;
        let accepted = positive(root.try_get(7)?)?;
        let last_verified = positive(root.try_get(8)?)?;
        if generation != 1 || anchor != [0; 32] || &fingerprint != owner.root() {
            return Err(Error::Unsupported);
        }
        let now = clock(tx, owner.checked().max(last_verified)).await?;
        let trust = ManifestTrust {
            account_id: *who.account.as_bytes(),
            root_fingerprint: fingerprint,
            generation,
            position: ChainPosition::Current {
                version,
                digest: semantic,
            },
        };
        let checkpoint = sealed_manifest03::verify_checkpoint02(
            &pin,
            &manifest,
            &AuthenticatedCheckpoint02 {
                trust: trust.clone(),
                anchor_digest: anchor,
                accepted_at_ms: accepted,
                last_verified_ms: last_verified,
            },
            now,
        )
        .map_err(|_| Error::Unsupported)?;
        let verified = sealed_manifest::verify(&pin, &manifest, &trust, now)
            .map_err(|_| Error::Unsupported)?;
        let row=tx.query_opt("SELECT b.device_id,b.generation,l.last_issued_generation,b.owner_approval_digest,b.device_confirmation_digest FROM public.phone_lines l JOIN public.device_line_bindings b ON (b.account_id,b.line_id,b.generation)=(l.account_id,l.id,l.current_binding_generation) WHERE l.account_id=$1 AND l.id=$2 AND l.state='active' AND l.approved_at IS NOT NULL AND b.state='active' AND b.purpose='sealed' AND b.activated_at IS NOT NULL FOR SHARE OF l,b NOWAIT",&[&who.account,&line]).await?.ok_or(Error::Unsupported)?;
        let device: Uuid = row.try_get(0)?;
        let binding_generation = positive(row.try_get(1)?)?;
        let last_issued = positive(row.try_get(2)?)?;
        if device.is_nil() || last_issued < binding_generation {
            return Err(Error::Unsupported);
        }
        let stored_owner_digest: [u8; 32] = fixed(&row, 3)?;
        let stored_device_digest: [u8; 32] = fixed(&row, 4)?;
        let dev=tx.query_opt("SELECT s.site_id,s.instance_id,s.connection_epoch,s.deployment_epoch,k.signing_key_sec1,k.fingerprint FROM public.device_sessions s JOIN public.device_keys k ON (k.account_id,k.device_id)=(s.account_id,s.device_id) WHERE s.account_id=$1 AND s.device_id=$2 FOR SHARE OF s,k NOWAIT",&[&who.account,&device]).await?.ok_or(Error::Unsupported)?;
        let selector = device_context::Selector {
            account: who.account,
            device,
            site: dev.try_get(0)?,
            instance: dev.try_get(1)?,
            connection_epoch: positive(dev.try_get(2)?)?,
            deployment_epoch: positive(dev.try_get(3)?)?,
        };
        let device_point = fixed(&dev, 4)?;
        let device_fingerprint: [u8; 32] = fixed(&dev, 5)?;
        if crate::sealed_manifest03::sha(&device_point) != device_fingerprint {
            return Err(Error::Unsupported);
        }
        let approval=tx.query_opt("SELECT signing_key_sec1,fingerprint FROM public.line_owner_approval_keys WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE NOWAIT",&[&who.account]).await?.ok_or(Error::Unsupported)?;
        let owner_point = fixed(&approval, 0)?;
        if fixed::<32>(&approval, 1)? != crate::sealed_manifest03::sha(&owner_point) {
            return Err(Error::Unsupported);
        }
        let selected = verified
            .profile_election_keys(
                device.as_bytes(),
                line.as_bytes(),
                &device_point,
                &owner_point,
                now,
            )
            .map_err(|_| Error::Unsupported)?;
        let mapping=tx.query_opt("SELECT binding_id,challenge_id FROM public.payload_profile_v2_activation_receipts WHERE account_id=$1 AND line_id=$2 AND device_id=$3 AND generation=$4",&[&who.account,&line,&device,&(binding_generation as i64)]).await?.ok_or(Error::Unsupported)?;
        let binding: Uuid = mapping.try_get(0)?;
        let challenge: Uuid = mapping.try_get(1)?;
        let history = activation_records::read_locked(
            tx,
            activation_records::Locator {
                account: who.account,
                binding,
                selected_reader_key_id: selected.reader_id,
            },
            origin,
        )
        .await
        .map_err(|_| Error::Unsupported)?;
        if history.identity().user != who.user
            || history.identity().device != device
            || history.identity().line != line
            || history.identity().generation != binding_generation
            || history.activation_challenge_id() != challenge
        {
            return Err(Error::Unsupported);
        }
        let original = ActivationEvidence03::decode(history.canonical_evidence())
            .map_err(|_| Error::Unsupported)?;
        let sha = crate::sealed_manifest03::sha;
        if original.device_point != device_point
            || original.owner_point != owner_point
            || sha(&[
                original.owner_statement.as_slice(),
                original.owner_signature_der.as_slice(),
            ]
            .concat())
                != stored_owner_digest
            || sha(&[
                original.device_statement.as_slice(),
                original.device_signature_der.as_slice(),
            ]
            .concat())
                != stored_device_digest
        {
            return Err(Error::Unsupported);
        }
        // Initial upgrade requires the actual installed original v2 lease, not
        // digest-only legacy history or a guessed restored monitor. The bounded
        // explicit physical-selection refresh remains a separate ceremony.
        let lease = history.original_proof_lease();
        if lease.site_id() != selector.site
            || lease.instance_id() != selector.instance
            || lease.connection_epoch() != selector.connection_epoch
            || lease.deployment_epoch() != selector.deployment_epoch
        {
            return Err(Error::Unsupported);
        }
        tx.query_opt("SELECT p.challenge_id FROM public.line_activation_v2_pending p JOIN public.line_activation_challenges c ON c.id=p.challenge_id WHERE p.account_id=$1 AND p.challenge_id=$2 AND p.line_id=$3 AND p.device_id=$4 AND p.generation=$5 AND p.purpose='sealed' AND p.protocol_version=2 AND p.approved_at IS NOT NULL AND p.installed_at IS NOT NULL AND p.retired_at IS NULL AND p.nonce IS NULL AND c.protocol_version=2 AND c.consumed_at IS NOT NULL FOR SHARE OF p,c NOWAIT",&[&who.account,&challenge,&line,&device,&(binding_generation as i64)]).await?.ok_or(Error::Unsupported)?;
        let context = device_context::lock(tx, &selector)
            .await
            .map_err(|_| Error::Unavailable)?;
        if context.selection_epoch() != owner.epoch()
            || context.enrollment_signing_key_id() != &selected.device_signer_id
            || context.root_fingerprint() != &fingerprint
        {
            return Err(Error::Conflict);
        }
        let checked_ms = clock(tx, now.max(context.checked_primary_ms())).await?;
        if checked_ms
            >= owner
                .deadline()
                .min(context.lease_deadline_ms())
                .min(selected.expires_ms)
        {
            return Err(Error::Expired);
        }
        Ok(Self {
            line,
            device,
            generation: binding_generation,
            last_issued,
            pin,
            fingerprint,
            manifest,
            manifest_version: version,
            manifest_digest: semantic,
            prior_accepted_ms: accepted,
            checkpoint,
            selected,
            device_point,
            owner_point,
            history,
            context,
            checked_ms,
        })
    }
    pub(super) fn projection(&self, owner: &Owner<'_, '_, '_>) -> serde_json::Value {
        let who = owner.selector();
        let device = self.context.selected_identity();
        serde_json::json!({"v":1,"envelope_profile":2,"manifest_profile":2,
            "account_id":who.account,"user_id":who.user,"owner_session_id":who.session,"device_id":self.device,"line_id":self.line,
            "selection_epoch":owner.epoch().to_string(),"origin_digest":B.encode(owner.origin()),"owner_session_digest":B.encode(owner.session()),"device_session_digest":B.encode(self.context.identity_digest()),
            "site_id":device.site,"instance_id":device.instance,"connection_epoch":device.connection_epoch.to_string(),"deployment_epoch":device.deployment_epoch.to_string(),
            "old_binding_id":self.history.binding_id(),"old_binding_generation":self.generation.to_string(),"old_binding_proof_digest":B.encode(self.history.old_binding_proof_digest()),
            "reader_key_id":B.encode(self.selected.reader_id),"device_signing_key_id":B.encode(self.selected.device_signer_id),"approval_key_id":B.encode(self.selected.approval_id),
            "root_fingerprint":B.encode(self.fingerprint),"trust_generation":"1","manifest_version":self.manifest_version.to_string(),"manifest_digest":B.encode(self.manifest_digest),
            "compared_ms":self.checked_ms.to_string(),"permission_expires_ms":owner.deadline().min(self.context.lease_deadline_ms()).min(self.selected.expires_ms).to_string(),
            "evidence":{"root_pin":B.encode(self.pin),"prior_manifest02":B.encode(&self.manifest),"prior_accepted_ms":self.prior_accepted_ms.to_string(),
            "device_signing_point":B.encode(self.device_point),"owner_approval_point":B.encode(self.owner_point),
            "registration_evidence":B.encode(self.history.registration().canonical_evidence()),"activation_evidence":B.encode(self.history.canonical_evidence())}})
    }
}
