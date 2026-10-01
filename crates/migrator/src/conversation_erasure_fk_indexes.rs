// SPDX-License-Identifier: AGPL-3.0-only
use super::MigrationError;
use tokio_postgres::Client;

pub(super) const CONVERSATION_ERASURE_FK_INDEXES_MIGRATION: i64 = 66;
pub(super) const CONVERSATION_ERASURE_FK_INDEXES_FILE: &str =
    "066_conversation_interval_session_index.sql";

// Owner account erasure deletes the account's sessions; each deleted row
// probes conversation_intervals on exactly the referencing foreign-key
// columns (issue #660). Accounts that own intervals hold line bindings the
// registry forbids deleting, so they can never be erased - the probe matters
// for every erasable account against the cross-tenant table. The index is
// built online, before the numbered file records its checksummed shape gate.
pub(super) const CREATE_CONVERSATION_INTERVAL_SESSION_INDEX: &str = "CREATE INDEX CONCURRENTLY erasure_fk_conversation_interval_session \
     ON public.conversation_intervals (account_id, initiating_session_id)";

async fn index_ready(client: &Client, name: &str) -> Result<bool, MigrationError> {
    Ok(client
        .query_one(
            "SELECT to_regclass($1) IS NOT NULL",
            &[&format!("public.{name}")],
        )
        .await?
        .get(0))
}

pub(super) async fn prepare_conversation_erasure_fk_indexes(
    client: &Client,
) -> Result<(), MigrationError> {
    if !index_ready(client, "erasure_fk_conversation_interval_session").await? {
        client
            .batch_execute(CREATE_CONVERSATION_INTERVAL_SESSION_INDEX)
            .await?;
    }
    Ok(())
}

pub(super) async fn verify_conversation_erasure_fk_indexes(
    client: &Client,
) -> Result<(), MigrationError> {
    let ready: bool = client
        .query_one(
            "SELECT public.conversation_interval_session_index_ready('public')",
            &[],
        )
        .await?
        .get(0);
    if !ready {
        return Err(MigrationError::ConversationErasureFkIndexesUnavailable);
    }
    Ok(())
}
