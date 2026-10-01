// SPDX-License-Identifier: AGPL-3.0-only
use super::MigrationError;
use tokio_postgres::Client;

pub(super) const PENDING_RECIPIENT_INDEX_MIGRATION: i64 = 62;
pub(super) const PENDING_RECIPIENT_INDEX_FILE: &str = "062_pending_recipient_index.sql";

// cancel_pending_recipient keys on the account and recipient of pending
// sends. The index is built online, before the numbered file records its
// checksummed shape gate. The NOT NULL column of the predicate keeps it
// exclusive to recipient-keyed lookups.
pub(super) const CREATE_PENDING_RECIPIENT_INDEX: &str = "CREATE INDEX CONCURRENTLY messages_pending_recipient \
     ON public.messages (recipient_e164, account_id) \
     WHERE state IN ('queued','claimed') AND recipient_e164 IS NOT NULL";

async fn index_ready(client: &Client, name: &str) -> Result<bool, MigrationError> {
    Ok(client
        .query_one(
            "SELECT to_regclass($1) IS NOT NULL",
            &[&format!("public.{name}")],
        )
        .await?
        .get(0))
}

pub(super) async fn prepare_pending_recipient_index(client: &Client) -> Result<(), MigrationError> {
    if !index_ready(client, "messages_pending_recipient").await? {
        client.batch_execute(CREATE_PENDING_RECIPIENT_INDEX).await?;
    }
    Ok(())
}

pub(super) async fn verify_pending_recipient_index(client: &Client) -> Result<(), MigrationError> {
    let ready: bool = client
        .query_one("SELECT public.pending_recipient_index_ready('public')", &[])
        .await?
        .get(0);
    if !ready {
        return Err(MigrationError::PendingRecipientIndexUnavailable);
    }
    Ok(())
}
