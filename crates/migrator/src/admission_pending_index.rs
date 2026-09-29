// SPDX-License-Identifier: AGPL-3.0-only
use super::MigrationError;
use tokio_postgres::Client;

pub(super) const ADMISSION_PENDING_INDEX_MIGRATION: i64 = 52;
pub(super) const ADMISSION_PENDING_INDEX_FILE: &str = "052_admission_pending_index.sql";
// Leads with the admission count's account equality so the account-locked
// accept transaction reads only the account's pending entries. The predicate
// matches the counted states, so terminal history is never visited.
pub(super) const CREATE_ADMISSION_PENDING_INDEX: &str = "CREATE INDEX CONCURRENTLY messages_admission_pending ON public.messages (account_id, device_id) \
     WHERE state IN ('queued', 'claimed')";
pub(super) const DROP_ADMISSION_PENDING_INDEX: &str =
    "DROP INDEX CONCURRENTLY public.messages_admission_pending";

// Check the complete index shape before deciding whether an interrupted build
// is ours to remove. A relation with the expected name but a different shape
// belongs to an operator and must never be dropped automatically.
pub(super) const ADMISSION_PENDING_INDEX_STATUS: &str = r#"
SELECT COALESCE(
    idx.relkind = 'i' AND idx.relpersistence = 'p'
    AND tbl_ns.nspname = 'public' AND tbl.relname = 'messages'
    AND am.amname = 'btree'
    AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
    AND ix.indnkeyatts = 2 AND ix.indnatts = 2
    AND ix.indexprs IS NULL
    AND ix.indkey[0] = (
        SELECT attnum FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'account_id' AND NOT attisdropped
    )
    AND ix.indkey[1] = (
        SELECT attnum FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'device_id' AND NOT attisdropped
    )
    AND ix.indoption[0] = 0 AND ix.indoption[1] = 0
    AND ix.indcollation[0] = 0 AND ix.indcollation[1] = 0
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
    AND pg_catalog.pg_get_expr(ix.indpred, ix.indrelid) =
        '(state = ANY (ARRAY[''queued''::text, ''claimed''::text]))',
    FALSE
) AS expected_shape,
COALESCE(ix.indisvalid AND ix.indisready AND ix.indislive, FALSE) AS ready
FROM pg_catalog.pg_class idx
JOIN pg_catalog.pg_namespace ns ON ns.oid = idx.relnamespace
LEFT JOIN pg_catalog.pg_index ix ON ix.indexrelid = idx.oid
LEFT JOIN pg_catalog.pg_class tbl ON tbl.oid = ix.indrelid
LEFT JOIN pg_catalog.pg_namespace tbl_ns ON tbl_ns.oid = tbl.relnamespace
LEFT JOIN pg_catalog.pg_am am ON am.oid = idx.relam
WHERE ns.nspname = 'public' AND idx.relname = 'messages_admission_pending'
"#;

pub(super) async fn admission_pending_index_status(
    client: &Client,
) -> Result<Option<(bool, bool)>, MigrationError> {
    Ok(client
        .query_opt(ADMISSION_PENDING_INDEX_STATUS, &[])
        .await?
        .map(|row| (row.get(0), row.get(1))))
}

pub(super) async fn prepare_admission_pending_index(client: &Client) -> Result<(), MigrationError> {
    match admission_pending_index_status(client).await? {
        None => {}
        Some((false, _)) => return Err(MigrationError::AdmissionPendingIndexConflict),
        Some((true, true)) => return Ok(()),
        Some((true, false)) => {
            // A canceled concurrent build leaves an invalid catalog entry.
            // This is safe to retry only after its exact shape is established.
            let building: bool = client
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_progress_create_index \
                     WHERE index_relid=to_regclass('public.messages_admission_pending'))",
                    &[],
                )
                .await?
                .get(0);
            if building {
                return Err(MigrationError::AdmissionPendingIndexBuildInProgress);
            }
            client.batch_execute(DROP_ADMISSION_PENDING_INDEX).await?;
        }
    }
    client.batch_execute(CREATE_ADMISSION_PENDING_INDEX).await?;
    if admission_pending_index_status(client).await? != Some((true, true)) {
        return Err(MigrationError::AdmissionPendingIndexUnavailable);
    }
    Ok(())
}

pub(super) async fn verify_admission_pending_index(client: &Client) -> Result<(), MigrationError> {
    let ready: bool = client
        .query_one(
            "SELECT public.messages_admission_pending_index_ready('public')",
            &[],
        )
        .await?
        .get(0);
    if !ready {
        return Err(MigrationError::AdmissionPendingIndexUnavailable);
    }
    Ok(())
}
