// SPDX-License-Identifier: AGPL-3.0-only
use crate::{MessageSnapshot, StoreError, state_from_str};
use tokio_postgres::GenericClient;
use uuid::Uuid;

/// Canonical metadata read usable inside a caller's authority transaction.
/// The caller authenticates the tenant and any narrower device/line scope.
pub async fn message_status<C: GenericClient + Sync>(
    db: &C,
    account_id: Uuid,
    message_id: Uuid,
) -> Result<Option<MessageSnapshot>, StoreError> {
    let row = db
        .query_opt(
            "SELECT device_id,state,state_version,
         (extract(epoch FROM created_at)*1000)::bigint,
         (extract(epoch FROM updated_at)*1000)::bigint
         FROM messages WHERE account_id=$1 AND id=$2",
            &[&account_id, &message_id],
        )
        .await?;
    row.map(|row| {
        Ok(MessageSnapshot {
            account_id,
            message_id,
            device_id: row.get(0),
            state: state_from_str(&row.get::<_, String>(1)).ok_or(StoreError::InvalidTransition)?,
            state_version: row.get(2),
            created_at_ms: row.get(3),
            updated_at_ms: row.get(4),
        })
    })
    .transpose()
}
