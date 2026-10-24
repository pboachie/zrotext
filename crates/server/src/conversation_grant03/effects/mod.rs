// SPDX-License-Identifier: AGPL-3.0-only
//! Transaction-owning typed effect entry. No candidate escapes before COMMIT.
use super::*;
use crate::conversation_effect03::wire::{Kind03, OrdinaryAdmission03, Request03};
use crate::device_socket::{DeviceSocketState, SocketActor};
use std::sync::atomic::Ordering;

mod clock;
mod closure;
mod history;
mod outcome;
mod status;
mod submit;
use history::Scope03;

/// A consumed request-admission receipt, not a current or effect permission.
/// Only the actual independently committed request-budget path constructs it.
pub(crate) struct Admitted03 {
    scope: Scope03,
    ordinary_admission: OrdinaryAdmission03,
}
async fn ready(tx: &Transaction<'_>) -> Result<()> {
    crate::conversation_profile03_effect_storage::require(tx)
        .await
        .map_err(|_| Error::Unavailable)?;
    tx.batch_execute("SET LOCAL search_path TO pg_catalog; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'").await?;
    if tx
        .query_one("SHOW transaction_isolation", &[])
        .await?
        .try_get::<_, String>(0)?
        != "read committed"
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}

/// This admission transaction commits independently of later invalid proofs,
/// failed current content checks or UNKNOWN writes. No owner Principal is used.
pub(crate) async fn admit<C: crate::runtime_db::NativeConnection>(
    client: &mut C,
    actor: SocketActor,
    state: &DeviceSocketState,
    ordinary_admission: OrdinaryAdmission03,
) -> Result<Admitted03> {
    let scope = Scope03::from_socket(actor, state)?;
    if state.draining.load(Ordering::Acquire) {
        return Err(Error::Authentication);
    }
    let tx = crate::runtime_db::begin_native(client)
        .await
        .map_err(|_| Error::Unavailable)?;
    ready(&tx).await?;
    // This fresh selector is NEVER a business attempt or stored row. The
    // documented absent branch locks the real current actor under the native
    // root/account/anchor order. Absence supplies no original-attempt proof.
    // Reject even an unexpected random collision, rather than consuming it.
    let selector = Uuid::new_v4();
    let rows = tx
        .query(
            "SELECT * FROM public.conversation_profile03_effect_history_lock($1,$2,$3,$4,$5,$6,$7)",
            &[
                &scope.session.account_id,
                &selector,
                &scope.session.device_id,
                &scope.site,
                &scope.instance,
                &scope.session.connection_epoch,
                &scope.deployment,
            ],
        )
        .await?;
    if !rows.is_empty() {
        return Err(Error::Conflict);
    }
    let point=tx.query_one(
        "SELECT signing_key_sec1 FROM public.device_keys WHERE account_id=$1 AND device_id=$2 AND revoked_at IS NULL",
        &[&scope.session.account_id,&scope.session.device_id],
    ).await?.try_get::<_,Vec<u8>>(0)?;
    if !scope.proof.matches_point(&point) {
        return Err(Error::Authentication);
    }
    let allowed = crate::auth::abuse_limits::consume_conversation_effect03(
        &tx,
        &state.auth_hasher,
        &scope.proof,
        ordinary_admission,
    )
    .await?;
    tx.commit().await?;
    if !allowed {
        return Err(Error::Unavailable);
    }
    Ok(Admitted03 {
        scope,
        ordinary_admission,
    })
}

/// New submit uses current content permission. Every other kind uses only the
/// separately authenticated immutable original-device history scope. Neither
/// a legacy RadioEvent nor a received permission JSON object is accepted here.
pub(crate) async fn apply<C: crate::runtime_db::NativeConnection>(
    client: &mut C,
    admitted: Admitted03,
    state: &DeviceSocketState,
    origin: Option<&str>,
    request: Request03,
) -> Result<serde_json::Value> {
    let Admitted03 {
        scope,
        ordinary_admission,
    } = admitted;
    if request.kind().admission() != ordinary_admission {
        return Err(Error::Authentication);
    }
    if request.connection_epoch() != scope.session.connection_epoch
        || state.draining.load(Ordering::Acquire)
    {
        return Err(Error::Authentication);
    }
    let tx = crate::runtime_db::begin_native(client)
        .await
        .map_err(|_| Error::Unavailable)?;
    ready(&tx).await?;
    let is_submit = request.kind() == Kind03::Submit;
    let value = match request {
        Request03::Submit(v) => submit::apply(&tx, &scope, origin, &v).await?,
        Request03::Outcome(v) => outcome::record(&tx, &scope, &v).await?,
        Request03::SubmitStatus(v) => status::submit(&tx, &scope, &v).await?,
        Request03::Challenge(v) => closure::challenge(&tx, &scope, &v).await?,
        Request03::Proof(v) => closure::accept(&tx, &scope, &v).await?,
        Request03::ProofStatus(v) => closure::status(&tx, &scope, &v).await?,
    };
    if state.draining.load(Ordering::Acquire) {
        return Err(Error::Unavailable);
    }
    tx.commit().await?;
    // A local drain during COMMIT withdraws the first response as UNKNOWN;
    // the durable accepted row remains. No subsequent path can emit it again
    // as submit_once, even though this response never reached the device.
    if is_submit && state.draining.load(Ordering::Acquire) {
        return Err(Error::Unavailable);
    }
    Ok(value)
}

/// This distinct entry admits only the closed passive clock request. It never
/// reuses an old status timestamp or broadens a current/content parser.
pub(crate) async fn history_clock<C: crate::runtime_db::NativeConnection>(
    client: &mut C,
    admitted: Admitted03,
    state: &DeviceSocketState,
    request: crate::conversation_effect03::history_clock::Request03,
) -> Result<serde_json::Value> {
    let Admitted03 {
        scope,
        ordinary_admission,
    } = admitted;
    if ordinary_admission != OrdinaryAdmission03::Read {
        return Err(Error::Authentication);
    }
    if request.connection_epoch != scope.session.connection_epoch
        || state.draining.load(Ordering::Acquire)
    {
        return Err(Error::Authentication);
    }
    let tx = crate::runtime_db::begin_native(client)
        .await
        .map_err(|_| Error::Unavailable)?;
    ready(&tx).await?;
    let value = clock::read(&tx, &scope, &request).await?;
    if state.draining.load(Ordering::Acquire) {
        return Err(Error::Unavailable);
    }
    tx.commit().await?;
    Ok(value)
}
