// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant known-correlation receipt persistence. No production issuer/caller.
//! The proposal schema is NOT installed by ordinary migrations. This module
//! cannot create correlations, authorize content, submit, retry or meter SMS.

use super::{ReceiptEffect, Rejection, Request, VerifiedReceipt};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;
use zrotext_domain::MessageState;

pub mod lifecycle;
mod store;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

/// Future account-scoped elected-writer authority. No production issuer,
/// constructor, Default, deserializer, HTTP input or configurable test mode.
/// Site/epoch checks supplement this proof; they do not elect a writer.
///
/// Safe downstream code cannot construct a permit:
/// ```compile_fail
/// use zrotext_server::provider_sms::receipts::ElectedWriterPermit;
/// let _ = ElectedWriterPermit::default();
/// ```
pub struct ElectedWriterPermit {
    account: Uuid,
    site: String,
    epoch: i64,
}
impl ElectedWriterPermit {
    #[cfg(test)]
    pub(crate) fn synthetic(account: Uuid, site: &str, epoch: i64) -> Self {
        Self {
            account,
            site: site.into(),
            epoch,
        }
    }
}

/// Closed diagnostics deliberately contain no provider identities or SQL detail.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("provider receipt proposal unavailable")]
    Unavailable,
    #[error("provider receipt writer authority unavailable")]
    Authority,
    #[error("provider receipt correlation unavailable")]
    Uncorrelated,
    #[error("provider receipt storage inconsistent")]
    Inconsistent,
    #[error("provider receipt version exhausted")]
    VersionExhausted,
    #[error("provider receipt evidence refused: {0:?}")]
    Evidence(Rejection),
    #[error("provider receipt storage unavailable")]
    Database,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Outcome {
    pub effect: ReceiptEffect,
    pub state: MessageState,
    pub delivery_failed: bool,
    pub version: i64,
}

fn route_fingerprint(request: &Request) -> [u8; 32] {
    let route = &request.route;
    let mut hash = Sha256::new();
    hash.update(b"ZT/provider-receipt-route/v1\0telnyx-sms-v2\0");
    for identity in [route.account, route.organization, route.profile] {
        hash.update(identity.as_bytes());
    }
    hash.update(route.revision.to_be_bytes());
    hash.update((route.sender.len() as u64).to_be_bytes());
    hash.update(route.sender.as_bytes());
    hash.finalize().into()
}

async fn authority(tx: &Transaction<'_>, permit: &ElectedWriterPermit) -> Result<(), Error> {
    if permit.account.is_nil() || permit.site.is_empty() || permit.epoch <= 0 {
        return Err(Error::Authority);
    }
    let row = tx
        .query_opt(
            "SELECT p.epoch,s.enabled,s.draining,NOT pg_is_in_recovery() \
        FROM deployment_authority p JOIN sites s ON s.site_id=$1 WHERE p.singleton \
        FOR SHARE OF p,s",
            &[&permit.site],
        )
        .await
        .map_err(|_| Error::Database)?
        .ok_or(Error::Authority)?;
    if row.get::<_, i64>(0) != permit.epoch
        || !row.get::<_, bool>(1)
        || row.get::<_, bool>(2)
        || !row.get::<_, bool>(3)
    {
        return Err(Error::Authority);
    }
    Ok(())
}

async fn lock_account(tx: &Transaction<'_>, account: Uuid) -> Result<(), Error> {
    // Disable closes future admission, not evidence for an irreversible intent.
    // Account deletion and the stronger owner-erasure lock still fence receipts.
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
        &[&account],
    )
    .await
    .map_err(|_| Error::Database)?
    .ok_or(Error::Uncorrelated)?;
    Ok(())
}

/// Apply only independently verified evidence to an already known correlation.
/// A valid receipt, arbitrary Request or provider ID never creates a row.
/// A lost commit reply is unresolved storage outcome: replay the same receipt,
/// never send again. No external call occurs within this transaction.
pub async fn record_known_receipt(
    client: &mut Client,
    permit: &ElectedWriterPermit,
    event: &VerifiedReceipt,
) -> Result<Outcome, Error> {
    if permit.account != event.request.route.account {
        return Err(Error::Authority);
    }
    let tx = client.transaction().await.map_err(|_| Error::Database)?;
    if !lifecycle::installed(&tx).await? {
        return Err(Error::Unavailable);
    }
    authority(&tx, permit).await?;
    lock_account(&tx, permit.account).await?;
    let row = tx
        .query_opt(
            "SELECT attempt_id,state,delivery_failed,event_count,state_version,request_digest \
        FROM provider_receipt_attempts WHERE account_id=$1 AND provider='telnyx_sms_v2' \
        AND route_fingerprint=$2 AND provider_message_id=$3 AND erased_at IS NULL FOR UPDATE",
            &[
                &permit.account,
                &route_fingerprint(&event.request).as_slice(),
                &event.message_id,
            ],
        )
        .await
        .map_err(|_| Error::Database)?
        .ok_or(Error::Uncorrelated)?;
    let (mut attempt, version) = store::rehydrate(&tx, &row, event).await?;
    authority(&tx, permit).await?; // fresh read after all account/attempt waits
    let effect = attempt.receipt(event).map_err(Error::Evidence)?;
    let next_version = if effect == ReceiptEffect::Duplicate {
        version
    } else {
        version.checked_add(1).ok_or(Error::VersionExhausted)?
    };
    if effect == ReceiptEffect::Applied {
        tx.execute("INSERT INTO provider_receipt_events(account_id,attempt_id,event_id,semantic_digest,fact,state_version) \
            VALUES($1,$2,$3,$4,$5,$6)", &[&permit.account,&attempt.attempt_id,&event.event_id,
            &event.identity.as_slice(),&store::fact_name(event.fact),&next_version])
            .await.map_err(|_| Error::Database)?;
        let changed = tx
            .execute(
                "UPDATE provider_receipt_attempts SET state=$3,delivery_failed=$4, \
            event_count=event_count+1,state_version=$5,updated_at=clock_timestamp() \
            WHERE account_id=$1 AND attempt_id=$2 AND state_version=$6 AND erased_at IS NULL",
                &[
                    &permit.account,
                    &attempt.attempt_id,
                    &store::state_name(attempt.state)?,
                    &attempt.delivery_failed,
                    &next_version,
                    &version,
                ],
            )
            .await
            .map_err(|_| Error::Database)?;
        if changed != 1 {
            return Err(Error::Inconsistent);
        }
    }
    let outcome = Outcome {
        effect,
        state: attempt.state,
        delivery_failed: attempt.delivery_failed,
        version: next_version,
    };
    tx.commit().await.map_err(|_| Error::Database)?;
    Ok(outcome)
}

/// Dormant internal erasure. Retains only the account/opaque attempt identity
/// until full account erasure. No production caller or retention worker exists.
pub async fn erase_receipt_attempt(
    client: &mut Client,
    permit: &ElectedWriterPermit,
    attempt: Uuid,
) -> Result<bool, Error> {
    let tx = client.transaction().await.map_err(|_| Error::Database)?;
    if !lifecycle::installed(&tx).await? {
        return Err(Error::Unavailable);
    }
    authority(&tx, permit).await?;
    lock_account(&tx, permit.account).await?;
    let row = tx
        .query_opt(
            "SELECT erased_at IS NOT NULL,state_version FROM provider_receipt_attempts \
        WHERE account_id=$1 AND attempt_id=$2 FOR UPDATE",
            &[&permit.account, &attempt],
        )
        .await
        .map_err(|_| Error::Database)?
        .ok_or(Error::Uncorrelated)?;
    authority(&tx, permit).await?;
    if row.get::<_, bool>(0) {
        return Ok(false);
    }
    // Erasure remains available at the hard version limit. The proposal allows
    // equality only for this irreversible active-to-erased transition at MAX;
    // ordinary evidence must still advance and an erased row cannot update.
    let version = row.get::<_, i64>(1).saturating_add(1);
    tx.execute(
        "DELETE FROM provider_receipt_events WHERE account_id=$1 AND attempt_id=$2",
        &[&permit.account, &attempt],
    )
    .await
    .map_err(|_| Error::Database)?;
    tx.execute("UPDATE provider_receipt_attempts SET erased_at=clock_timestamp(),route_fingerprint=NULL, \
        request_digest=NULL,provider_message_id=NULL,state=NULL,delivery_failed=NULL,event_count=0, \
        accepted_at=NULL,updated_at=NULL,created_epoch=NULL,state_version=$3 \
        WHERE account_id=$1 AND attempt_id=$2", &[&permit.account,&attempt,&version])
        .await.map_err(|_| Error::Database)?;
    tx.commit().await.map_err(|_| Error::Database)?;
    Ok(true)
}
