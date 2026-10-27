// SPDX-License-Identifier: AGPL-3.0-only
//! Actual one-attempt profile03 grant and exact signed ciphertext fetch.
//! The optional caller must authenticate its socket/configuration separately;
//! no received Ready, account ID or schema predicate supplies that authority.
use crate::conversation_interval03::live::DeviceInterval03;
use crate::reviewed_intent03::live::execution::{self, HeldReviewed03};
use crate::sealed_dispatch::wire03::{Fetch03, GrantFrame03, ReadyFrame03};
use crate::sealed_payload_election03::live::Error;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;
mod actor;
pub(crate) mod effects;
pub mod http;
mod pending;
mod row;
use row::GrantRow03;
type Result<T> = std::result::Result<T, Error>;
fn sqltime(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| Error::Unsupported)
}

/// Private exact-transaction mode entry. Root/fence/anchor/account locks from
/// the narrow SQL reader are NOT an owner, device or cryptographic proof.
pub(crate) struct Mode03<'held, 'db> {
    tx: &'held Transaction<'db>,
    session: crate::device_socket::DeviceSession,
    site: String,
    instance: String,
    deployment: u64,
    origin: String,
    prior: Option<GrantRow03>,
}
impl<'held, 'db> Mode03<'held, 'db> {
    pub(crate) fn tx(&self) -> &'held Transaction<'db> {
        self.tx
    }
    pub(crate) fn actor(&self) -> DeviceInterval03<'_> {
        DeviceInterval03 {
            session: self.session,
            site: &self.site,
            instance: &self.instance,
            deployment: self.deployment,
            origin: &self.origin,
        }
    }
    async fn lock(
        tx: &'held Transaction<'db>,
        actor: DeviceInterval03<'_>,
        attempt: Uuid,
    ) -> Result<Self> {
        if attempt.is_nil() || actor.session.connection_epoch <= 0 || actor.deployment == 0 {
            return Err(Error::Authentication);
        }
        tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'").await?;
        // Effect readiness includes the full grant and reviewed-v2 validators.
        // Keep that complete current check once, before taking business locks.
        crate::conversation_profile03_effect_storage::require(tx)
            .await
            .map_err(|_| Error::Unavailable)?;
        let rows = tx
            .query(
                "SELECT * FROM public.conversation_profile03_grant_lock($1,$2,$3,$4,$5,$6,$7)",
                &[
                    &actor.session.account_id,
                    &attempt,
                    &actor.session.device_id,
                    &actor.site,
                    &actor.instance,
                    &actor.session.connection_epoch,
                    &sqltime(actor.deployment)?,
                ],
            )
            .await?;
        if rows.len() > 1 {
            return Err(Error::Conflict);
        }
        let prior = rows.first().map(GrantRow03::from_row).transpose()?;
        if let Some(row) = &prior {
            row.actor(actor, attempt)?;
        }
        Ok(Self {
            tx,
            session: actor.session,
            site: actor.site.to_owned(),
            instance: actor.instance.to_owned(),
            deployment: actor.deployment,
            origin: actor.origin.to_owned(),
            prior,
        })
    }
}

fn ready_matches(
    ready: &ReadyFrame03,
    review: &HeldReviewed03<'_, '_>,
    actor: DeviceInterval03<'_>,
) -> Result<()> {
    let r = ready.claims();
    let a = review.selected().authority();
    if r.connection_epoch != actor.session.connection_epoch
        || r.deployment_epoch != sqltime(actor.deployment)?
        || r.binding_generation != sqltime(a.binding_generation)?
        || r.trust_generation != 1
        || r.manifest_version != sqltime(a.manifest_version)?
        || r.line_id != Uuid::from_bytes(a.line_id)
        || r.reader_key_id != a.selected_reader_key_id
        || r.manifest_digest != a.manifest_digest
        || r.root_fingerprint != a.root_fingerprint
        || r.election_digest != a.election_commitment
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Only returned after the real grant transaction commits. A socket write
/// failure keeps this exact one-use fence; this API never creates a retry.
pub(crate) struct CommittedGrant03 {
    frame: GrantFrame03,
}
impl CommittedGrant03 {
    pub(crate) fn frame(&self) -> &GrantFrame03 {
        &self.frame
    }
}
pub(crate) async fn issue_next<C: crate::runtime_db::NativeConnection>(
    client: &mut C,
    socket: crate::device_socket::SocketActor,
    actor: DeviceInterval03<'_>,
    ready: &ReadyFrame03,
) -> Result<Option<CommittedGrant03>> {
    actor::socket_matches(socket, actor)?;
    let attempt = Uuid::new_v4();
    let tx = crate::runtime_db::begin_native(client)
        .await
        .map_err(|_| Error::Unavailable)?;
    let mode = Mode03::lock(&tx, actor, attempt).await?;
    if mode.prior.is_some() {
        return Err(Error::Conflict);
    }
    // A prior unknown/granted liability remains a fence even after its clock
    // deadline. Readiness never erases it or selects a replacement attempt.
    let Some(message) = pending::next(&tx, actor, ready).await? else {
        drop(mode);
        tx.rollback().await?;
        return Ok(None);
    };
    let mut review = execution::lock(&mode, message).await?;
    // The received Ready and the selected current key do not establish which
    // enrolled key actually proved possession during this exact session claim.
    actor::verify_new(socket, actor, &review)?;
    ready_matches(ready, &review, actor)?;
    // Preserve the complete signed/current bound. The pinned SQL mint caps
    // this original grant at thirty seconds from its actual primary mint time.
    let permission = review.deadline().await?;
    review.verify_until(permission).await?;
    let rows = tx
        .query(
            "SELECT * FROM public.conversation_profile03_grant_issue($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            &[
                &actor.session.account_id,
                &message,
                &attempt,
                &actor.session.device_id,
                &actor.site,
                &actor.instance,
                &actor.session.connection_epoch,
                &sqltime(actor.deployment)?,
                &sqltime(permission)?,
            ],
        )
        .await?;
    if rows.len() != 1 {
        return Err(Error::Conflict);
    }
    let row = GrantRow03::from_row(&rows[0])?;
    row.actor(actor, attempt)?;
    let original = actor::RetainedActor03::read(&tx, &row).await?;
    original.matches_socket(socket)?;
    original.matches_selected(&review)?;
    if row.numbers[9] > permission {
        return Err(Error::Expired);
    }
    review.verify_until(row.numbers[9]).await?;
    // SQL minted this original after the pre-issue held clock. Refresh current
    // permission first, then compare against that unchanged mint and expiry.
    row.matches(&review)?;
    actor::verify_new(socket, actor, &review)?;
    original.matches_selected(&review)?;
    ready_matches(ready, &review, actor)?;
    let frame = row.frame()?;
    drop(review);
    drop(mode);
    tx.commit().await?;
    Ok(Some(CommittedGrant03 { frame }))
}

/// Independently configured runtime selection. Instance/account/device/owner
/// still come from the retained ledger plus current records, never the wire.
#[derive(Clone, Copy)]
pub(crate) struct FetchServing03<'a> {
    pub site: &'a str,
    pub deployment: u64,
    pub origin: &'a str,
}
async fn preflight(client: &Client, serving: FetchServing03<'_>, request: &Fetch03) -> Result<()> {
    let claims = request.grant().claims();
    let hint=client.query_opt("SELECT * FROM public.conversation_profile03_grants WHERE account_id=$1 AND attempt_id=$2",&[&claims.account_id,&claims.attempt_id]).await?.ok_or(Error::NotFound)?;
    let hint = GrantRow03::from_row(&hint)?;
    if hint.site != serving.site
        || hint.numbers[3] != serving.deployment
        || hint.frame()?.claims() != claims
    {
        return Err(Error::Authentication);
    }
    let original = actor::RetainedActor03::read(client, &hint).await?;
    let row=client.query_opt("SELECT signing_key_sec1 FROM public.device_keys WHERE account_id=$1 AND device_id=$2 AND revoked_at IS NULL",&[&hint.ids[0],&hint.ids[7]]).await?.ok_or(Error::Authentication)?;
    let point: Vec<u8> = row.try_get(0)?;
    if point.as_slice() != original.point {
        return Err(Error::Authentication);
    }
    request
        .verify(&original.verifying_key()?)
        .map_err(|_| Error::Authentication)?;
    Ok(())
}
pub(crate) async fn fetch<C: crate::runtime_db::NativeConnection>(
    client: &mut C,
    serving: FetchServing03<'_>,
    request: &Fetch03,
) -> Result<serde_json::Value> {
    let claims = request.grant().claims();
    let tx = crate::runtime_db::begin_native(client)
        .await
        .map_err(|_| Error::Unavailable)?;
    tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'").await?;
    crate::conversation_profile03_grant_storage::require(&tx)
        .await
        .map_err(|_| Error::Unavailable)?;
    // This immutable pre-lock lookup is only an actor hint. The narrow locked
    // reader independently derives and compares the actual original context.
    let hint=tx.query_opt("SELECT * FROM public.conversation_profile03_grants WHERE account_id=$1 AND attempt_id=$2", &[&claims.account_id,&claims.attempt_id]).await?.ok_or(Error::NotFound)?;
    let hint = GrantRow03::from_row(&hint)?;
    if hint.site != serving.site
        || hint.numbers[3] != serving.deployment
        || hint.frame()?.claims() != claims
    {
        return Err(Error::Authentication);
    }
    let actor = DeviceInterval03 {
        session: crate::device_socket::DeviceSession {
            account_id: hint.ids[0],
            device_id: hint.ids[7],
            connection_epoch: sqltime(hint.numbers[2])?,
        },
        site: &hint.site,
        instance: &hint.instance,
        deployment: serving.deployment,
        origin: serving.origin,
    };
    let mode = Mode03::lock(&tx, actor, claims.attempt_id).await?;
    let row = mode.prior.as_ref().ok_or(Error::NotFound)?;
    if row.frame()?.claims() != claims {
        return Err(Error::Conflict);
    }
    let original = actor::RetainedActor03::read(&tx, row).await?;
    let mut review = execution::lock(&mode, claims.message_id).await?;
    row.matches(&review)?;
    original.matches_selected(&review)?;
    request
        .verify(&original.verifying_key()?)
        .map_err(|_| Error::Authentication)?;
    // response begins with the same full original-expiry verification, then
    // performs the final current comparison used by both projections.
    let response = review.response(request.grant()).await?;
    original.matches_selected(&review)?;
    // Fetch is data-read-only: no lease/time/attempt/anchor renewal or commit.
    // Read locks remain held through the complete projection's construction.
    drop(review);
    drop(mode);
    tx.rollback().await?;
    Ok(response)
}
