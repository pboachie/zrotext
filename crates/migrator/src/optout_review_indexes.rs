// SPDX-License-Identifier: AGPL-3.0-only
use super::MigrationError;
use tokio_postgres::Client;

pub(super) const OPTOUT_REVIEW_INDEXES_MIGRATION: i64 = 60;
pub(super) const OPTOUT_REVIEW_INDEXES_FILE: &str = "060_optout_review_indexes.sql";

// The review queue pages by (changed_at, recipient) inside one account; the
// review-event lookups key on the COALESCE expression the cursor and decision
// queries filter on. Both are built online; the redundant duplicate of the
// primary key's columns is dropped online in the same step.
pub(super) const CREATE_REVIEW_QUEUE_INDEX: &str = "CREATE INDEX CONCURRENTLY recipient_suppressions_review_queue \
     ON public.recipient_suppressions (account_id, changed_at DESC, recipient_e164 DESC) \
     WHERE active AND source IN ('sms_review','sms_unsolicited_review')";
pub(super) const CREATE_REVIEW_EVENT_INDEX: &str = "CREATE INDEX CONCURRENTLY recipient_suppressions_review_event \
     ON public.recipient_suppressions (account_id, COALESCE(source_event_id, source_unsolicited_event_id)) \
     WHERE source IN ('sms_review','sms_unsolicited_review')";
pub(super) const DROP_SUPPRESSIONS_ACTIVE_INDEX: &str =
    "DROP INDEX CONCURRENTLY IF EXISTS public.recipient_suppressions_active";

async fn index_ready(client: &Client, name: &str) -> Result<bool, MigrationError> {
    Ok(client
        .query_one(
            "SELECT to_regclass($1) IS NOT NULL",
            &[&format!("public.{name}")],
        )
        .await?
        .get(0))
}

pub(super) async fn prepare_optout_review_indexes(client: &Client) -> Result<(), MigrationError> {
    if !index_ready(client, "recipient_suppressions_review_queue").await? {
        client.batch_execute(CREATE_REVIEW_QUEUE_INDEX).await?;
    }
    if !index_ready(client, "recipient_suppressions_review_event").await? {
        client.batch_execute(CREATE_REVIEW_EVENT_INDEX).await?;
    }
    client.batch_execute(DROP_SUPPRESSIONS_ACTIVE_INDEX).await?;
    Ok(())
}

pub(super) async fn verify_optout_review_indexes(client: &Client) -> Result<(), MigrationError> {
    let ready: bool = client
        .query_one("SELECT public.optout_review_indexes_ready('public')", &[])
        .await?
        .get(0);
    if !ready {
        return Err(MigrationError::OptoutReviewIndexesUnavailable);
    }
    Ok(())
}
