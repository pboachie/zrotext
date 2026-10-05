// SPDX-License-Identifier: AGPL-3.0-only
use super::{contracts::OpeningKey, model::Receipt};
use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::{ConversationError, activation},
};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

pub(super) const ADMITTED_LIMIT: i64 = 8192;

pub(super) async fn begin(client: &mut Client) -> Result<Transaction<'_>, ConversationError> {
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    if !installed(&tx).await? {
        return Err(ConversationError::Unavailable);
    }
    Ok(tx)
}

/// Optional dormant tables. Partial installation is an error in the caller's
/// transaction; it must never be mistaken for an uninstalled no-op lifecycle.
pub(crate) async fn installed(tx: &Transaction<'_>) -> Result<bool, tokio_postgres::Error> {
    super::schema::installed(tx).await
}

pub(super) fn digest(
    account: Uuid,
    operation: i16,
    request: &impl serde::Serialize,
) -> Result<Vec<u8>, ConversationError> {
    let mut hash = Sha256::new();
    hash.update(b"ZT/opening-request/v1\0");
    hash.update(account.as_bytes());
    hash.update(operation.to_be_bytes());
    hash.update(serde_json::to_vec(request).map_err(|_| ConversationError::Invalid)?);
    Ok(hash.finalize().to_vec())
}

pub(super) async fn replay(
    tx: &Transaction<'_>,
    account: Uuid,
    request: Uuid,
    digest: &[u8],
) -> Result<Option<Receipt>, ConversationError> {
    let Some(row) = tx.query_opt("SELECT redacted,request_digest,result FROM workflow_opening_requests WHERE account_id=$1 AND request_id=$2 FOR SHARE", &[&account,&request]).await? else { return Ok(None); };
    if row.get::<_, bool>(0) {
        return Err(ConversationError::NotFound);
    }
    if row.get::<_, Option<Vec<u8>>>(1).as_deref() != Some(digest) {
        return Err(ConversationError::Conflict);
    }
    let bytes = row
        .get::<_, Option<Vec<u8>>>(2)
        .ok_or(ConversationError::Unavailable)?;
    Ok(Some(
        serde_json::from_slice(&bytes).map_err(|_| ConversationError::Unavailable)?,
    ))
}

pub(super) async fn ordinary_capacity(
    tx: &Transaction<'_>,
    account: Uuid,
) -> Result<(), ConversationError> {
    let count:i64 = tx.query_one("SELECT count(*) FROM workflow_opening_requests WHERE account_id=$1 AND admission_charged", &[&account]).await?.get(0);
    if count >= ADMITTED_LIMIT {
        return Err(ConversationError::Conflict);
    }
    Ok(())
}

pub(super) struct Mutation<'a> {
    pub(super) request: Uuid,
    pub(super) operation: i16,
    pub(super) subject_kind: i16,
    pub(super) subject: Uuid,
    pub(super) digest: &'a [u8],
    pub(super) receipt: &'a Receipt,
    pub(super) charged: bool,
}
pub(super) async fn record(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    mutation: Mutation<'_>,
) -> Result<(), ConversationError> {
    let m = mutation;
    let result = serde_json::to_vec(m.receipt).map_err(|_| ConversationError::Unavailable)?;
    tx.execute("INSERT INTO workflow_opening_requests(account_id,request_id,opening_id,subject_kind,subject_id,operation,request_digest,result,actor_user_id,actor_session_id,committed_ms,admission_charged) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        &[&owner.tenant.account_id(),&m.request,&m.receipt.opening.opening_id,&m.subject_kind,&m.subject,&m.operation,&m.digest,&result,&owner.user_id,&owner.session_id,&activation::now(tx).await?,&m.charged]).await?;
    Ok(())
}

pub(super) async fn counts(
    tx: &Transaction<'_>,
    account: Uuid,
    opening: Uuid,
) -> Result<(i64, i64), ConversationError> {
    let row = tx.query_one("SELECT count(*) FILTER(WHERE phase='pending'),count(*) FILTER(WHERE phase='confirmed') FROM workflow_opening_allocations WHERE account_id=$1 AND opening_id=$2", &[&account,&opening]).await?;
    Ok((row.get(0), row.get(1)))
}

pub(super) async fn status(
    tx: &Transaction<'_>,
    account: Uuid,
    key: OpeningKey,
    phase: String,
) -> Result<Receipt, ConversationError> {
    let (pending, confirmed) = counts(tx, account, key.opening_id).await?;
    Ok(Receipt {
        opening: key,
        offer: None,
        allocation_id: None,
        allocation_version: None,
        phase,
        pending,
        confirmed,
    })
}
