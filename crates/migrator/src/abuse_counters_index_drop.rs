// SPDX-License-Identifier: AGPL-3.0-only
use super::MigrationError;
use tokio_postgres::Client;

pub(super) const ABUSE_COUNTERS_INDEX_DROP_MIGRATION: i64 = 58;
pub(super) const ABUSE_COUNTERS_INDEX_DROP_FILE: &str = "058_drop_abuse_counters_updated_index.sql";

// The updated_at index turned every abuse-budget charge into a non-HOT
// update. Dropping it needs no lock that blocks charges; the numbered file
// then asserts the index is gone before the ledger records it.
pub(super) const DROP_ABUSE_COUNTERS_STALE_INDEX: &str =
    "DROP INDEX CONCURRENTLY IF EXISTS public.auth_abuse_counters_stale";

pub(super) async fn prepare_abuse_counters_index_drop(
    client: &Client,
) -> Result<(), MigrationError> {
    client
        .batch_execute(DROP_ABUSE_COUNTERS_STALE_INDEX)
        .await?;
    Ok(())
}

pub(super) async fn verify_abuse_counters_index_dropped(
    client: &Client,
) -> Result<(), MigrationError> {
    let present: bool = client
        .query_one(
            "SELECT to_regclass('public.auth_abuse_counters_stale') IS NOT NULL",
            &[],
        )
        .await?
        .get(0);
    if present {
        return Err(MigrationError::AbuseCountersStaleIndexPresent);
    }
    Ok(())
}
