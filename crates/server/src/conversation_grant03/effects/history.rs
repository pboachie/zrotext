// SPDX-License-Identifier: AGPL-3.0-only
//! Current original actor for passive typed history, not content permission.
use super::*;
use crate::device_socket::{DeviceSession, SocketActor};
use crate::enrollment::VerifiedDevice;
use crate::sealed_manifest03 as crypto;
use tokio_postgres::Row;

/// This scope can only be assembled from the real verified session claim.
/// It carries no old owner, physical handle, effect-health flag or permit.
pub(super) struct Scope03 {
    pub(super) session: DeviceSession,
    pub(super) proof: VerifiedDevice,
    pub(super) site: String,
    pub(super) instance: String,
    pub(super) deployment: i64,
}
impl Scope03 {
    pub(super) fn from_socket(
        actor: SocketActor,
        state: &crate::device_socket::DeviceSocketState,
    ) -> Result<Self> {
        let session = actor.session();
        let proof = *actor.proof();
        if proof.identity().account_id != session.account_id
            || proof.identity().device_id != session.device_id
            || session.connection_epoch <= 0
            || state.deployment_epoch <= 0
        {
            return Err(Error::Authentication);
        }
        Ok(Self {
            session,
            proof,
            site: state.site_id.clone(),
            instance: state.instance_id.clone(),
            deployment: state.deployment_epoch,
        })
    }
    pub(super) fn sql_actor(&self) -> [&(dyn tokio_postgres::types::ToSql + Sync); 6] {
        [
            &self.session.account_id,
            &self.session.device_id,
            &self.site,
            &self.instance,
            &self.session.connection_epoch,
            &self.deployment,
        ]
    }
}

pub(super) struct Original03 {
    pub(super) grant: GrantRow03,
    pub(super) point: [u8; 65],
    pub(super) key: [u8; 32],
    pub(super) fetch: [u8; 32],
    pub(super) session: [u8; 32],
    minted: u64,
}
impl Original03 {
    pub(super) async fn read(tx: &Transaction<'_>, scope: &Scope03, attempt: Uuid) -> Result<Self> {
        let row = tx.query_opt(
            "SELECT * FROM public.conversation_profile03_effect_actors WHERE account_id=$1 AND attempt_id=$2",
            &[&scope.session.account_id, &attempt],
        ).await?.ok_or(Error::NotFound)?;
        Self::from_row(tx, scope, attempt, &row).await
    }
    async fn from_row(
        tx: &Transaction<'_>,
        scope: &Scope03,
        attempt: Uuid,
        row: &Row,
    ) -> Result<Self> {
        let grant = tx.query_opt(
            "SELECT * FROM public.conversation_profile03_grants WHERE account_id=$1 AND attempt_id=$2",
            &[&scope.session.account_id, &attempt],
        ).await?.ok_or(Error::NotFound)?;
        let grant = GrantRow03::from_row(&grant)?;
        let original = super::super::actor::RetainedActor03::from_row(&grant, row)?;
        if row.try_get::<_, Uuid>("account_id")? != scope.session.account_id
            || row.try_get::<_, Uuid>("device_id")? != scope.session.device_id
            || row.try_get::<_, Uuid>("attempt_id")? != attempt
            || row.try_get::<_, Uuid>("message_id")? != grant.ids[1]
            || grant.ids[0] != scope.session.account_id
            || grant.ids[2] != attempt
            || grant.ids[7] != scope.session.device_id
            || !scope.proof.matches_point(&original.point)
            || &original.key_id != scope.proof.signing_key_id()
        {
            return Err(Error::Authentication);
        }
        Ok(Self {
            grant,
            point: original.point,
            key: original.key_id,
            fetch: original.fetch,
            session: original.session,
            minted: original.minted,
        })
    }
    pub(super) fn command(
        &self,
        command: &crate::conversation_effect03::SubmitCommand03,
    ) -> Result<()> {
        let ids = command.identities();
        if ids[0] != *self.grant.ids[0].as_bytes()
            || ids[1] != *self.grant.ids[7].as_bytes()
            || ids[3] != *self.grant.ids[1].as_bytes()
            || ids[4] != *self.grant.ids[2].as_bytes()
            || command.fetch_digest() != &self.fetch
            || command.device_session_digest() != &self.session
            || command.segment_count() > self.grant.frame()?.claims().segment_count
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}

/// Root/account/anchor/current actor locks are acquired by the narrow actual
/// SQL helper before any late evidence is read. They supply no socket proof.
pub(super) struct HeldHistory03<'held, 'db> {
    tx: &'held Transaction<'db>,
    pub(super) original: Original03,
    checked: u64,
    pub(super) lease_end: u64,
    pub(super) lease_version: u16,
    pub(super) proof_session: [u8; 32],
}
impl<'held, 'db> HeldHistory03<'held, 'db> {
    pub(super) async fn lock(
        tx: &'held Transaction<'db>,
        scope: &Scope03,
        attempt: Uuid,
    ) -> Result<Self> {
        crate::conversation_profile03_effect_storage::require(tx)
            .await
            .map_err(|_| Error::Unavailable)?;
        tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'").await?;
        let rows = tx.query(
            "SELECT * FROM public.conversation_profile03_effect_history_lock($1,$2,$3,$4,$5,$6,$7)",
            &[&scope.session.account_id,&attempt,&scope.session.device_id,&scope.site,&scope.instance,&scope.session.connection_epoch,&scope.deployment],
        ).await?;
        if rows.len() != 1 {
            return Err(Error::NotFound);
        }
        let original = Original03::from_row(tx, scope, attempt, &rows[0]).await?;
        let checked = original.minted;
        let mut held = Self {
            tx,
            original,
            checked,
            lease_end: 0,
            lease_version: 0,
            proof_session: [0; 32],
        };
        held.revalidate(scope).await?;
        Ok(held)
    }
    pub(super) fn now_ms(&self) -> u64 {
        self.checked
    }
    pub(super) async fn revalidate(&mut self, scope: &Scope03) -> Result<()> {
        // The selected point must STILL be the independently verified original
        // handshake point. History permits ordinary activation-version1 leases;
        // it never widens the existing version2-only content proof parser.
        let row = self.tx.query_opt(
            "SELECT k.signing_key_sec1,k.fingerprint,s.line_activation_version,pg_catalog.floor(extract(epoch FROM s.lease_until)*1000)::bigint AS lease_end FROM public.device_sessions s JOIN public.devices d ON(d.account_id,d.id)=(s.account_id,s.device_id) JOIN public.device_keys k ON(k.account_id,k.device_id)=(d.account_id,d.id) JOIN public.accounts a ON a.id=d.account_id JOIN public.sites t ON t.site_id=s.site_id JOIN public.deployment_authority p ON p.singleton=TRUE WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 AND s.instance_id=$4 AND s.connection_epoch=$5 AND s.deployment_epoch=$6 AND s.lease_until>pg_catalog.clock_timestamp() AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL AND t.enabled=TRUE AND t.draining=FALSE AND p.epoch=$6 AND NOT pg_catalog.pg_is_in_recovery() FOR SHARE OF s,d,k,a,t,p NOWAIT",
            &scope.sql_actor(),
        ).await?.ok_or(Error::Authentication)?;
        let point: Vec<u8> = row.try_get("signing_key_sec1")?;
        let fingerprint: Vec<u8> = row.try_get("fingerprint")?;
        let lease_end = positive(row.try_get("lease_end")?)?;
        let lease_version = u16::try_from(row.try_get::<_, i16>("line_activation_version")?)
            .map_err(|_| Error::Unsupported)?;
        if point.as_slice() != self.original.point
            || !scope.proof.matches_point(&point)
            || fingerprint.as_slice() != crypto::sha(&point)
            || scope.proof.signing_key_id() != &self.original.key
        {
            return Err(Error::Authentication);
        }
        self.proof_session = passive_session_digest(
            crate::sealed_payload_election03::adapter_contract::DeviceSessionIdentity03 {
                account_id: *scope.session.account_id.as_bytes(),
                device_id: *scope.session.device_id.as_bytes(),
                site_id: &scope.site,
                instance_id: &scope.instance,
                connection_epoch: positive(scope.session.connection_epoch)?,
                deployment_epoch: positive(scope.deployment)?,
                line_activation_version: lease_version,
                enrollment_signing_key_id: *scope.proof.signing_key_id(),
            },
        )?;
        // Sample only AFTER the actual locked actor/key/lease lookup and its
        // waits. The retained floor is never reset by a new assertion or clock.
        let clock = self.tx.query_one(
            "SELECT pg_catalog.pg_is_in_recovery(),pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint",
            &[],
        ).await?;
        let checked = positive(clock.try_get(1)?)?;
        if clock.try_get::<_, bool>(0)? || checked < self.checked || checked >= lease_end {
            return Err(Error::Authentication);
        }
        self.checked = checked;
        self.lease_end = lease_end;
        self.lease_version = lease_version;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

pub(super) fn positive(value: i64) -> Result<u64> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(Error::Unsupported)
}

fn passive_session_digest(
    identity: crate::sealed_payload_election03::adapter_contract::DeviceSessionIdentity03<'_>,
) -> Result<[u8; 32]> {
    if !matches!(identity.line_activation_version, 1 | 2)
        || identity.account_id == [0; 16]
        || identity.device_id == [0; 16]
        || identity.enrollment_signing_key_id == [0; 32]
    {
        return Err(Error::Unsupported);
    }
    let mut bytes = Vec::new();
    bytes.extend(identity.account_id);
    bytes.extend(identity.device_id);
    for text in [identity.site_id, identity.instance_id] {
        if text.is_empty() || text.len() > 256 || text.chars().any(char::is_control) {
            return Err(Error::Unsupported);
        }
        bytes.extend((text.len() as u32).to_be_bytes());
        bytes.extend(text.as_bytes());
    }
    crypto::time(identity.connection_epoch).map_err(|_| Error::Unsupported)?;
    crypto::time(identity.deployment_epoch).map_err(|_| Error::Unsupported)?;
    bytes.extend(identity.connection_epoch.to_be_bytes());
    bytes.extend(identity.deployment_epoch.to_be_bytes());
    bytes.extend(identity.line_activation_version.to_be_bytes());
    bytes.extend(identity.enrollment_signing_key_id);
    Ok(crypto::sha(
        &crypto::framed(b"ZTSE/line/payload-profile/device-session/v1\0", &bytes)
            .map_err(|_| Error::Unsupported)?,
    ))
}
