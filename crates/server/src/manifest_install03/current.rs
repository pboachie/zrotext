// SPDX-License-Identifier: AGPL-3.0-only
//! Actual independently verified current03 and physical-reader projection.
//! Original10 evidence remains first-election history. New current material
//! never translates any old interval or admitted message into fresh permission.
use super::*;
use crate::sealed_payload_election03::{
    activation_evidence::ActivationEvidence03,
    device_context,
    live::{
        Error,
        manifest_history::{self, History03},
    },
};
use crate::selection_refresh03::{self, ExpectedRefresh03};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use tokio_postgres::{Row, Transaction};
type Result<T> = std::result::Result<T, Error>;
pub(super) fn positive(n: i64) -> Result<u64> {
    u64::try_from(n)
        .ok()
        .filter(|n| *n > 0)
        .ok_or(Error::Unsupported)
}
fn fixed<const N: usize>(row: &Row, at: usize) -> Result<[u8; N]> {
    row.try_get::<_, Vec<u8>>(at)?
        .try_into()
        .map_err(|_| Error::Unsupported)
}
pub(super) async fn context<'held, 'db>(
    tx: &'held Transaction<'db>,
    h: &History03,
) -> Result<device_context::HeldDeviceContext03<'held, 'db>> {
    let row=tx.query_opt("SELECT site_id,instance_id,connection_epoch,deployment_epoch FROM public.device_sessions WHERE account_id=$1 AND device_id=$2 FOR SHARE NOWAIT",&[&h.account,&h.device]).await?.ok_or(Error::Unavailable)?;
    let context = device_context::lock(
        tx,
        &device_context::Selector {
            account: h.account,
            device: h.device,
            site: row.try_get(0)?,
            instance: row.try_get(1)?,
            connection_epoch: positive(row.try_get(2)?)?,
            deployment_epoch: positive(row.try_get(3)?)?,
        },
    )
    .await
    .map_err(|_| Error::Unavailable)?;
    if context.selection_epoch() != h.epoch
        || context.root_fingerprint() != &h.accepted.root_fingerprint
        || context.enrollment_signing_key_id().as_slice() != &h.core[288..320]
    {
        return Err(Error::Conflict);
    }
    Ok(context)
}
async fn material(
    tx: &Transaction<'_>,
    h: &History03,
    version: u64,
    origin: &str,
) -> Result<(Vec<u8>, u64)> {
    if version == h.accepted.accepted_manifest_version {
        return Ok((h.first_signed.clone(), h.accepted.accepted_at_ms));
    }
    let row = records::by_version(tx, h.account, version)
        .await?
        .ok_or(Error::Conflict)?;
    row.scope(h, origin)?;
    Ok((row.signed, row.accepted))
}
pub(super) enum Physical03 {
    Original,
    Refreshed {
        refresh: Uuid,
        bundle: Vec<u8>,
        accepted: u64,
        installed: u64,
    },
}
impl Physical03 {
    pub(super) fn projection(&self) -> serde_json::Value {
        match self {
            Self::Original => serde_json::json!({"kind":"original_v2"}),
            Self::Refreshed {
                refresh,
                bundle,
                accepted,
                installed,
            } => {
                serde_json::json!({"kind":"owner_refresh03","refresh_id":refresh,"bundle":B.encode(bundle),"accepted_ms":accepted.to_string(),"installed_ms":installed.to_string()})
            }
        }
    }
}
pub(super) async fn physical(
    tx: &Transaction<'_>,
    h: &History03,
    context: &device_context::HeldDeviceContext03<'_, '_>,
    origin: &str,
) -> Result<Physical03> {
    crate::payload_profile_selections::require(tx)
        .await
        .map_err(|_| Error::Unavailable)?;
    let lease = context.selected_identity();
    let row=tx.query_opt("SELECT c.refresh_id,c.initiating_user_id,c.initiating_session_id,s.bundle,s.bundle_sha256,s.accepted_ms,s.installed_ms,s.installed_signature,c.device_point,c.owner_point,c.device_session_digest,c.manifest_version,c.manifest_digest,c.signed_manifest,c.manifest_accepted_ms FROM public.payload_profile_selection_receipts s JOIN public.payload_profile_selection_challenges c ON (c.account_id,c.refresh_id)=(s.account_id,s.refresh_id) WHERE s.account_id=$1 AND s.binding_id=$2 AND s.proof_site_id=$3 AND s.proof_instance_id=$4 AND s.proof_connection_epoch=$5 AND s.proof_deployment_epoch=$6 AND s.installed_ms IS NOT NULL",&[&h.account,&h.binding,&lease.site,&lease.instance,&(lease.connection_epoch as i64),&(lease.deployment_epoch as i64)]).await?;
    if let Some(row) = row {
        let refresh: Uuid = row.try_get(0)?;
        let user: Uuid = row.try_get(1)?;
        let session: Uuid = row.try_get(2)?;
        let bundle: Vec<u8> = row.try_get(3)?;
        let accepted = positive(row.try_get(5)?)?;
        let installed = positive(row.try_get(6)?)?;
        let signature: Vec<u8> = row.try_get(7)?;
        let version = positive(row.try_get(11)?)?;
        let digest = fixed(&row, 12)?;
        let signed: Vec<u8> = row.try_get(13)?;
        let manifest_accepted = positive(row.try_get(14)?)?;
        if fixed::<65>(&row, 8)? != h.device_point
            || fixed::<65>(&row, 9)? != h.approval_point
            || fixed::<32>(&row, 10)? != *context.identity_digest()
            || fixed::<32>(&row, 4)? != crypto::sha(&bundle)
            || accepted < h.accepted.accepted_at_ms
            || installed > h.checked_ms.max(context.checked_primary_ms())
            || version > h.tip_version
        {
            return Err(Error::Conflict);
        }
        let actual = material(tx, h, version, origin).await?;
        if actual.0 != signed || actual.1 != manifest_accepted {
            return Err(Error::Conflict);
        }
        let historical = shared::verify_checkpoint(
            &h.pin,
            &signed,
            &shared::Checkpoint03 {
                account_id: *h.account.as_bytes(),
                root_fingerprint: h.accepted.root_fingerprint,
                version,
                digest,
                accepted_ms: manifest_accepted,
            },
            accepted,
        )
        .map_err(|_| Error::Unsupported)?;
        if historical.digest() != &digest {
            return Err(Error::Conflict);
        }
        // A historical checkpoint may be expired now, but this original
        // physical approval/install had to fall inside that exact manifest
        // and selected reader lifetime at the time it actually happened.
        let physical_keys = records(&signed).map_err(|_| Error::Unsupported)?;
        let selected: Vec<_> = physical_keys
            .into_iter()
            .filter(|r| {
                r[0] == 1
                    && r[1..33] == h.accepted.selected_reader_key_id
                    && r[98..114] == *h.device.as_bytes()
                    && r[114..130] == *h.line.as_bytes()
                    && r[148] == 1
            })
            .collect();
        if selected.len() != 1
            || crypto::number(&signed[39..47]).map_err(|_| Error::Unsupported)? > accepted
            || crypto::number(&signed[47..55]).map_err(|_| Error::Unsupported)? <= installed
            || crypto::number(&selected[0][132..140]).map_err(|_| Error::Unsupported)? > accepted
            || crypto::number(&selected[0][140..148]).map_err(|_| Error::Unsupported)? <= installed
        {
            return Err(Error::Expired);
        }
        let owner = crate::sealed_payload_election03::adapter_contract::OwnerSessionIdentity03 {
            account_id: *h.account.as_bytes(),
            user_id: *user.as_bytes(),
            session_id: *session.as_bytes(),
        }
        .digest()
        .map_err(|_| Error::Unsupported)?;
        let original = ActivationEvidence03::decode(h.activation.canonical_evidence())
            .map_err(|_| Error::Unsupported)?;
        let subscription =
            i32::from_be_bytes(original.device_statement[138..142].try_into().unwrap());
        let origin_digest =
            crate::sealed_payload_election03::adapter_contract::origin_digest(origin)
                .map_err(|_| Error::Unsupported)?;
        selection_refresh03::verify_installed(
            &bundle,
            accepted,
            installed,
            &signature,
            &ExpectedRefresh03 {
                account: h.account,
                device: h.device,
                line: h.line,
                binding: h.binding,
                refresh,
                binding_generation: h.generation,
                manifest_version: version,
                selection_epoch: h.epoch,
                election: &h.accepted.election_commitment,
                election_bundle: &h.accepted.election_bundle_sha256,
                reader: &h.accepted.selected_reader_key_id,
                device_point: &h.device_point,
                owner_point: &h.approval_point,
                root: &h.accepted.root_fingerprint,
                manifest: &digest,
                device_session: context.identity_digest(),
                owner_session: &owner,
                origin: &origin_digest,
                original_subscription: subscription,
            },
        )
        .map_err(|_| Error::Unsupported)?;
        return Ok(Physical03::Refreshed {
            refresh,
            bundle,
            accepted,
            installed,
        });
    }
    // A signed refresh is a permanent withdrawal for this full connection,
    // including after expiry/closure. Time alone cannot resurrect old custody.
    if tx.query_one("SELECT EXISTS(SELECT FROM public.payload_profile_selection_challenges WHERE account_id=$1 AND binding_id=$2 AND proof_site_id=$3 AND proof_instance_id=$4 AND proof_connection_epoch=$5 AND proof_deployment_epoch=$6 AND device_signature IS NOT NULL)",&[&h.account,&h.binding,&lease.site,&lease.instance,&(lease.connection_epoch as i64),&(lease.deployment_epoch as i64)]).await?.try_get::<_,bool>(0)? {return Err(Error::Unsupported);}
    let old = h.activation.original_proof_lease();
    if old.site_id() != lease.site
        || old.instance_id() != lease.instance
        || old.connection_epoch() != lease.connection_epoch
        || old.deployment_epoch() != lease.deployment_epoch
        || h.core[464..496] != *context.identity_digest()
    {
        return Err(Error::Unsupported);
    }
    tx.query_opt("SELECT challenge_id FROM public.line_activation_v2_pending WHERE account_id=$1 AND challenge_id=$2 AND protocol_version=2 AND purpose='sealed' AND approved_at IS NOT NULL AND installed_at IS NOT NULL AND retired_at IS NULL AND nonce IS NULL FOR SHARE NOWAIT",&[&h.account,&h.activation.activation_challenge_id()]).await?.ok_or(Error::Unsupported)?;
    Ok(Physical03::Original)
}
pub(super) async fn projection(
    tx: &Transaction<'_>,
    h: &History03,
    context: &mut device_context::HeldDeviceContext03<'_, '_>,
    origin: &str,
) -> Result<(serde_json::Value, u64)> {
    // Every linked root/possession/policy is independently verified before a
    // physical receipt can bridge a historical manifest to this actual tip.
    let progress = verified_history::warm(tx, h, origin).await?;
    context.revalidate().await.map_err(|_| Error::Unavailable)?;
    let now = context.checked_primary_ms().max(h.checked_ms);
    let manifest = crypto::verify_current(&h.tip_signed, &progress.verified, now)
        .map_err(|_| Error::Expired)?;
    let roles = manifest
        .profile_election_keys(
            h.device.as_bytes(),
            h.line.as_bytes(),
            &h.device_point,
            &h.approval_point,
            now,
        )
        .map_err(|_| Error::Unsupported)?;
    if roles.reader_id != h.accepted.selected_reader_key_id {
        return Err(Error::Conflict);
    }
    let physical = physical(tx, h, context, origin).await?.projection();
    context.revalidate().await.map_err(|_| Error::Unavailable)?;
    let now = context.checked_primary_ms().max(now);
    let deadline = roles.expires_ms.min(context.lease_deadline_ms());
    if now >= deadline {
        return Err(Error::Expired);
    }
    let lease = context.selected_identity();
    let value = serde_json::json!({"v":1,"envelope_profile":3,"manifest_profile":3,"account_id":h.account,"device_id":h.device,"line_id":h.line,"selection_epoch":h.epoch.to_string(),"origin_digest":B.encode(crate::sealed_payload_election03::adapter_contract::origin_digest(origin).map_err(|_|Error::Unsupported)?),"device_session_digest":B.encode(context.identity_digest()),"site_id":lease.site,"instance_id":lease.instance,"connection_epoch":lease.connection_epoch.to_string(),"deployment_epoch":lease.deployment_epoch.to_string(),"old_binding_id":Uuid::from_bytes(h.accepted.old_binding_id),"old_binding_generation":h.accepted.old_binding_generation.to_string(),"old_binding_proof_digest":B.encode(h.accepted.old_binding_proof_digest),"binding_id":h.binding,"binding_generation":h.generation.to_string(),"reader_key_id":B.encode(roles.reader_id),"device_signing_key_id":B.encode(roles.device_signer_id),"approval_key_id":B.encode(roles.approval_id),"root_fingerprint":B.encode(h.accepted.root_fingerprint),"trust_generation":"1","manifest_version":h.tip_version.to_string(),"manifest_digest":B.encode(h.tip_digest),"election_digest":B.encode(h.accepted.election_commitment),"election_bundle_sha256":B.encode(h.accepted.election_bundle_sha256),"compared_ms":now.to_string(),"physical_selection":physical,"current_manifest03":B.encode(&h.tip_signed),"manifest_ancestry_sha256":B.encode(progress.prefix),"evidence":h.evidence});
    Ok((value, deadline))
}
