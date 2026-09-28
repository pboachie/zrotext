// SPDX-License-Identifier: AGPL-3.0-only
use super::MigrationError;
use tokio_postgres::Client;

pub(super) const RECENT_ATTEMPT_INDEX_MIGRATION: i64 = 50;
pub(super) const RECENT_ATTEMPT_INDEX_FILE: &str = "050_message_attempts_recent_index.sql";
// Leads with the dispatch probe's equality columns, then created_at, so
// "any attempt for this device in the last N seconds" is a bounded range scan
// that never visits the device's older attempt history.
pub(super) const CREATE_RECENT_ATTEMPT_INDEX: &str = "CREATE INDEX CONCURRENTLY message_attempts_device_created \
     ON public.message_attempts (account_id, device_id, created_at)";
pub(super) const DROP_RECENT_ATTEMPT_INDEX: &str =
    "DROP INDEX CONCURRENTLY public.message_attempts_device_created";

// Check the complete index shape before deciding whether an interrupted build
// is ours to remove. A relation with the expected name but a different shape
// belongs to an operator and must never be dropped automatically.
pub(super) const RECENT_ATTEMPT_INDEX_STATUS: &str = r#"
SELECT COALESCE(
    idx.relkind = 'i' AND idx.relpersistence = 'p'
    AND tbl_ns.nspname = 'public' AND tbl.relname = 'message_attempts'
    AND am.amname = 'btree'
    AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
    AND ix.indnkeyatts = 3 AND ix.indnatts = 3
    AND ix.indexprs IS NULL
    AND ix.indkey[0] = (
        SELECT attnum FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'account_id' AND NOT attisdropped
    )
    AND ix.indkey[1] = (
        SELECT attnum FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'device_id' AND NOT attisdropped
    )
    AND ix.indkey[2] = (
        SELECT attnum FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'created_at' AND NOT attisdropped
    )
    AND ix.indoption[0] = 0 AND ix.indoption[1] = 0 AND ix.indoption[2] = 0
    AND ix.indcollation[0] = 0 AND ix.indcollation[1] = 0 AND ix.indcollation[2] = 0
    AND ix.indclass[0] = (
        SELECT opc.oid FROM pg_catalog.pg_opclass opc
        WHERE opc.opcmethod = am.oid
          AND opc.opcintype = 'uuid'::pg_catalog.regtype
          AND opc.opcdefault
    )
    AND ix.indclass[1] = (
        SELECT opc.oid FROM pg_catalog.pg_opclass opc
        WHERE opc.opcmethod = am.oid
          AND opc.opcintype = 'uuid'::pg_catalog.regtype
          AND opc.opcdefault
    )
    AND ix.indclass[2] = (
        SELECT opc.oid FROM pg_catalog.pg_opclass opc
        WHERE opc.opcmethod = am.oid
          AND opc.opcintype = 'timestamp with time zone'::pg_catalog.regtype
          AND opc.opcdefault
    )
    AND ix.indpred IS NULL,
    FALSE
) AS expected_shape,
COALESCE(ix.indisvalid AND ix.indisready AND ix.indislive, FALSE) AS ready
FROM pg_catalog.pg_class idx
JOIN pg_catalog.pg_namespace ns ON ns.oid = idx.relnamespace
LEFT JOIN pg_catalog.pg_index ix ON ix.indexrelid = idx.oid
LEFT JOIN pg_catalog.pg_class tbl ON tbl.oid = ix.indrelid
LEFT JOIN pg_catalog.pg_namespace tbl_ns ON tbl_ns.oid = tbl.relnamespace
LEFT JOIN pg_catalog.pg_am am ON am.oid = idx.relam
WHERE ns.nspname = 'public' AND idx.relname = 'message_attempts_device_created'
"#;

pub(super) async fn recent_attempt_index_status(
    client: &Client,
) -> Result<Option<(bool, bool)>, MigrationError> {
    Ok(client
        .query_opt(RECENT_ATTEMPT_INDEX_STATUS, &[])
        .await?
        .map(|row| (row.get(0), row.get(1))))
}

pub(super) async fn prepare_recent_attempt_index(client: &Client) -> Result<(), MigrationError> {
    match recent_attempt_index_status(client).await? {
        None => {}
        Some((false, _)) => return Err(MigrationError::RecentAttemptIndexConflict),
        Some((true, true)) => return Ok(()),
        Some((true, false)) => {
            // A canceled concurrent build leaves an invalid catalog entry.
            // This is safe to retry only after its exact shape is established.
            let building: bool = client
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_progress_create_index \
                     WHERE index_relid=to_regclass('public.message_attempts_device_created'))",
                    &[],
                )
                .await?
                .get(0);
            if building {
                return Err(MigrationError::RecentAttemptIndexBuildInProgress);
            }
            client.batch_execute(DROP_RECENT_ATTEMPT_INDEX).await?;
        }
    }
    client.batch_execute(CREATE_RECENT_ATTEMPT_INDEX).await?;
    if recent_attempt_index_status(client).await? != Some((true, true)) {
        return Err(MigrationError::RecentAttemptIndexUnavailable);
    }
    Ok(())
}

pub(super) async fn verify_recent_attempt_index(client: &Client) -> Result<(), MigrationError> {
    let ready: bool = client
        .query_one(
            "SELECT public.message_attempts_recent_index_ready('public')",
            &[],
        )
        .await?
        .get(0);
    if !ready {
        return Err(MigrationError::RecentAttemptIndexUnavailable);
    }
    Ok(())
}
