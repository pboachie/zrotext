// SPDX-License-Identifier: AGPL-3.0-only
//! Actual retained111 selection plus the present held lease. Historical
//! signature verification never reconstructs the phone's opaque issuer handle.
use super::*;
use crate::conversation_interval03::{self, PhysicalSource03};
use crate::selection_refresh03::{self, ExpectedRefresh03};

pub(super) enum Physical {
    Complete(crate::manifest_install03::SelectedPhysical03),
    Original {
        digest: [u8; 32],
    },
    Refreshed {
        refresh: Uuid,
        bundle: Vec<u8>,
        accepted: u64,
        installed: u64,
        digest: [u8; 32],
    },
}
impl Physical {
    pub(super) fn identity(&self) -> (&'static str, Option<Uuid>) {
        match self {
            Self::Complete(selected) => selected.identity(),
            Self::Original { .. } => ("original_v2", None),
            Self::Refreshed { refresh, .. } => ("owner_refresh03", Some(*refresh)),
        }
    }
    pub(super) fn projection(&self) -> serde_json::Value {
        match self {
            Self::Complete(selected) => selected.projection(),
            Self::Original { .. } => serde_json::json!({"kind":"original_v2"}),
            Self::Refreshed {
                refresh,
                bundle,
                accepted,
                installed,
                ..
            } => {
                serde_json::json!({"kind":"owner_refresh03","refresh_id":refresh,"bundle":B.encode(bundle),"accepted_ms":accepted.to_string(),"installed_ms":installed.to_string()})
            }
        }
    }
    pub(super) fn digest(&self) -> &[u8; 32] {
        match self {
            Self::Complete(selected) => selected.digest(),
            Self::Original { digest } | Self::Refreshed { digest, .. } => digest,
        }
    }
}
impl Current<'_, '_> {
    fn physical_digest(&self, source: PhysicalSource03<'_>) -> Result<[u8; 32]> {
        let r = &self.reservation;
        conversation_interval03::physical_digest(
            r.account,
            r.device,
            r.line,
            r.new_binding,
            &self.accepted.election_commitment,
            self.context.identity_digest(),
            source,
        )
        .map_err(|_| Error::Unsupported)
    }
    pub(super) async fn physical(&self, tx: &Transaction<'_>) -> Result<Physical> {
        if let Some(selected) = &self.selected_manifest {
            return Ok(Physical::Complete(
                selected.physical(tx, &self.context).await?,
            ));
        }
        let r = &self.reservation;
        let lease = self.context.selected_identity();
        if crate::payload_profile_selections::optional(tx)
            .await
            .map_err(|_| Error::Unavailable)?
        {
            crate::payload_profile_selections::require(tx)
                .await
                .map_err(|_| Error::Unavailable)?;
            let row=tx.query_opt("SELECT c.refresh_id,c.initiating_user_id,c.initiating_session_id,s.bundle,s.bundle_sha256,s.accepted_ms,s.installed_ms,s.installed_signature,c.device_point,c.owner_point,c.device_session_digest FROM public.payload_profile_selection_receipts s JOIN public.payload_profile_selection_challenges c ON (c.account_id,c.refresh_id)=(s.account_id,s.refresh_id) WHERE s.account_id=$1 AND s.binding_id=$2 AND s.proof_site_id=$3 AND s.proof_instance_id=$4 AND s.proof_connection_epoch=$5 AND s.proof_deployment_epoch=$6 AND s.installed_ms IS NOT NULL",&[&r.account,&r.new_binding,&lease.site,&lease.instance,&(lease.connection_epoch as i64),&(lease.deployment_epoch as i64)]).await?;
            if let Some(row) = row {
                let refresh: Uuid = row.try_get(0)?;
                let user: Uuid = row.try_get(1)?;
                let session: Uuid = row.try_get(2)?;
                let bundle: Vec<u8> = row.try_get(3)?;
                let accepted = positive(row.try_get(5)?)?;
                let installed = positive(row.try_get(6)?)?;
                let signature: Vec<u8> = row.try_get(7)?;
                if user != r.user
                    || fixed::<65>(&row, 8)? != r.device_point
                    || fixed::<65>(&row, 9)? != r.owner_point
                    || fixed::<32>(&row, 10)? != *self.context.identity_digest()
                    || fixed::<32>(&row, 4)? != crypto::sha(&bundle)
                    || accepted < self.accepted.accepted_at_ms
                {
                    return Err(Error::Conflict);
                }
                let owner_session = super::super::super::adapter_contract::OwnerSessionIdentity03 {
                    account_id: *r.account.as_bytes(),
                    user_id: *user.as_bytes(),
                    session_id: *session.as_bytes(),
                }
                .digest()
                .map_err(|_| Error::Unsupported)?;
                let original = ActivationEvidence03::decode(self.history.canonical_evidence())
                    .map_err(|_| Error::Unsupported)?;
                let subscription =
                    i32::from_be_bytes(original.device_statement[138..142].try_into().unwrap());
                let origin: [u8; 32] = r.core[400..432].try_into().unwrap();
                selection_refresh03::verify_installed(
                    &bundle,
                    accepted,
                    installed,
                    &signature,
                    &ExpectedRefresh03 {
                        account: r.account,
                        device: r.device,
                        line: r.line,
                        binding: r.new_binding,
                        refresh,
                        binding_generation: r.new_generation,
                        manifest_version: self.accepted.accepted_manifest_version,
                        selection_epoch: self.epoch,
                        election: &self.accepted.election_commitment,
                        election_bundle: &self.accepted.election_bundle_sha256,
                        reader: &self.accepted.selected_reader_key_id,
                        device_point: &r.device_point,
                        owner_point: &r.owner_point,
                        root: &self.accepted.root_fingerprint,
                        manifest: &self.accepted.accepted_manifest_digest,
                        device_session: self.context.identity_digest(),
                        owner_session: &owner_session,
                        origin: &origin,
                        original_subscription: subscription,
                    },
                )
                .map_err(|_| Error::Unsupported)?;
                clock(tx, self.checked.max(installed)).await?;
                let digest = self.physical_digest(PhysicalSource03::OwnerRefresh03 {
                    refresh_id: refresh,
                    bundle: &bundle,
                    accepted_ms: accepted,
                    installed_ms: installed,
                })?;
                return Ok(Physical::Refreshed {
                    refresh,
                    bundle,
                    accepted,
                    installed,
                    digest,
                });
            }
            // A signed observation permanently withdraws original_v2 fallback
            // for this exact connection, even after expiry or durable closure.
            let signed:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM public.payload_profile_selection_challenges WHERE account_id=$1 AND binding_id=$2 AND proof_site_id=$3 AND proof_instance_id=$4 AND proof_connection_epoch=$5 AND proof_deployment_epoch=$6 AND device_signature IS NOT NULL)",&[&r.account,&r.new_binding,&lease.site,&lease.instance,&(lease.connection_epoch as i64),&(lease.deployment_epoch as i64)]).await?.try_get(0)?;
            if signed {
                return Err(Error::Unsupported);
            }
        }
        self.original_physical(tx).await?;
        Ok(Physical::Original {
            digest: self.physical_digest(PhysicalSource03::OriginalV2 {
                original_binding: r.old_binding,
                activation_evidence: self.history.canonical_evidence(),
            })?,
        })
    }
}
