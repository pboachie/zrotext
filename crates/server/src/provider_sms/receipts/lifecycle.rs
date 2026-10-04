// SPDX-License-Identifier: AGPL-3.0-only
use super::Error;
use crate::{
    auth::{self, SessionPrincipal},
    http_owner_conversations::{ConversationError, lock_owner},
};
use serde::Serialize;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

/// Detect absence separately from partial installation; partial schemas fail closed.
pub(crate) async fn installed(tx: &Transaction<'_>) -> Result<bool, Error> {
    let row = tx
        .query_one(
            "SELECT to_regclass('provider_receipt_attempts') IS NOT NULL, \
        to_regclass('provider_receipt_events') IS NOT NULL",
            &[],
        )
        .await
        .map_err(|_| Error::Database)?;
    match (row.get::<_, bool>(0), row.get::<_, bool>(1)) {
        (false, false) => Ok(false),
        (true, true) => Ok(true),
        _ => Err(Error::Unavailable),
    }
}

#[derive(Default, Serialize)]
pub struct Page {
    pub items: Vec<Metadata>,
    pub next_cursor: Option<Uuid>,
}
/// Owner metadata excludes external correlation/event IDs and every digest.
#[derive(Serialize)]
pub struct Metadata {
    attempt_id: Uuid,
    provider: String,
    state: String,
    delivery_failed: bool,
    state_version: i64,
    event_count: i16,
    accepted_at_ms: i64,
    updated_at_ms: i64,
}

pub(crate) async fn export(
    client: &mut Client,
    owner: &SessionPrincipal,
    after: Option<Uuid>,
) -> Result<Page, ConversationError> {
    let tx = client.transaction().await?;
    lock_owner(&tx, owner).await?;
    if !installed(&tx)
        .await
        .map_err(|_| ConversationError::Unavailable)?
    {
        if after.is_some() {
            return Err(ConversationError::NotFound);
        }
        auth::require_current_owner(&tx, owner)
            .await
            .map_err(|_| ConversationError::Forbidden)?;
        tx.commit().await?;
        return Ok(Page::default());
    }
    let account = owner.tenant.account_id();
    if let Some(cursor) = after {
        tx.query_opt(
            "SELECT attempt_id FROM provider_receipt_attempts \
            WHERE account_id=$1 AND attempt_id=$2 AND erased_at IS NULL",
            &[&account, &cursor],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    }
    let rows = tx.query("SELECT attempt_id,provider,state,delivery_failed,state_version,event_count, \
        (extract(epoch FROM accepted_at)*1000)::bigint,(extract(epoch FROM updated_at)*1000)::bigint \
        FROM provider_receipt_attempts WHERE account_id=$1 AND erased_at IS NULL \
        AND ($2::uuid IS NULL OR attempt_id>$2) ORDER BY attempt_id LIMIT 21 FOR SHARE",
        &[&account,&after]).await?;
    let next_cursor = if rows.len() > 20 {
        Some(rows[19].get(0))
    } else {
        None
    };
    let items = rows
        .iter()
        .take(20)
        .map(|row| {
            Ok(Metadata {
                attempt_id: row.try_get(0)?,
                provider: row.try_get(1)?,
                state: row.try_get(2)?,
                delivery_failed: row.try_get(3)?,
                state_version: row.try_get(4)?,
                event_count: row.try_get(5)?,
                accepted_at_ms: row.try_get(6)?,
                updated_at_ms: row.try_get(7)?,
            })
        })
        .collect::<Result<Vec<_>, tokio_postgres::Error>>()?;
    auth::require_current_owner(&tx, owner)
        .await
        .map_err(|_| ConversationError::Forbidden)?;
    tx.commit().await?;
    Ok(Page { items, next_cursor })
}
