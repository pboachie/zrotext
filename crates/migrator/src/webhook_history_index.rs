// SPDX-License-Identifier: AGPL-3.0-only
use super::MigrationError;
use tokio_postgres::Client;

pub(super) const WEBHOOK_HISTORY_INDEX_MIGRATION: i64 = 57;
pub(super) const WEBHOOK_HISTORY_INDEX_FILE: &str = "057_webhook_history_index.sql";
// Owner webhook history pages backward by (created_at,id) inside one
// endpoint; leading with endpoint_id turns every page into a bounded index
// scan instead of a read-and-sort over the endpoint's retention history.
pub(super) const CREATE_WEBHOOK_HISTORY_INDEX: &str = "CREATE INDEX CONCURRENTLY webhook_deliveries_history \
     ON public.webhook_deliveries (endpoint_id, created_at DESC, id DESC)";
pub(super) const DROP_WEBHOOK_HISTORY_INDEX: &str =
    "DROP INDEX CONCURRENTLY public.webhook_deliveries_history";

// Check the complete index shape before deciding whether an interrupted build
// is ours to remove. A relation with the expected name but a different shape
// belongs to an operator and must never be dropped automatically.
pub(super) const WEBHOOK_HISTORY_INDEX_STATUS: &str = r#"
SELECT COALESCE(
    idx.relkind = 'i' AND idx.relpersistence = 'p'
    AND tbl_ns.nspname = 'public' AND tbl.relname = 'webhook_deliveries'
    AND am.amname = 'btree'
    AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
    AND ix.indnkeyatts = 3 AND ix.indnatts = 3
    AND ix.indexprs IS NULL
    AND ix.indkey[0] = (
        SELECT attnum FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'endpoint_id' AND NOT attisdropped
    )
    AND ix.indkey[1] = (
        SELECT attnum FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'created_at' AND NOT attisdropped
    )
    AND ix.indkey[2] = (
        SELECT attnum FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'id' AND NOT attisdropped
    )
    AND ix.indoption[0] = 0 AND ix.indoption[1] = 3 AND ix.indoption[2] = 3
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
          AND opc.opcintype = 'timestamp with time zone'::pg_catalog.regtype
          AND opc.opcdefault
    )
    AND ix.indclass[2] = (
        SELECT opc.oid FROM pg_catalog.pg_opclass opc
        WHERE opc.opcmethod = am.oid
          AND opc.opcintype = 'uuid'::pg_catalog.regtype
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
WHERE ns.nspname = 'public' AND idx.relname = 'webhook_deliveries_history'
"#;

pub(super) async fn webhook_history_index_status(
    client: &Client,
) -> Result<Option<(bool, bool)>, MigrationError> {
    Ok(client
        .query_opt(WEBHOOK_HISTORY_INDEX_STATUS, &[])
        .await?
        .map(|row| (row.get(0), row.get(1))))
}

pub(super) async fn prepare_webhook_history_index(client: &Client) -> Result<(), MigrationError> {
    match webhook_history_index_status(client).await? {
        None => {}
        Some((false, _)) => return Err(MigrationError::WebhookHistoryIndexConflict),
        Some((true, true)) => return Ok(()),
        Some((true, false)) => {
            // A canceled concurrent build leaves an invalid catalog entry.
            // This is safe to retry only after its exact shape is established.
            let building: bool = client
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_progress_create_index \
                     WHERE index_relid=to_regclass('public.webhook_deliveries_history'))",
                    &[],
                )
                .await?
                .get(0);
            if building {
                return Err(MigrationError::WebhookHistoryIndexBuildInProgress);
            }
            client.batch_execute(DROP_WEBHOOK_HISTORY_INDEX).await?;
        }
    }
    client.batch_execute(CREATE_WEBHOOK_HISTORY_INDEX).await?;
    if webhook_history_index_status(client).await? != Some((true, true)) {
        return Err(MigrationError::WebhookHistoryIndexUnavailable);
    }
    Ok(())
}

pub(super) async fn verify_webhook_history_index(client: &Client) -> Result<(), MigrationError> {
    let ready: bool = client
        .query_one("SELECT public.webhook_history_index_ready('public')", &[])
        .await?
        .get(0);
    if !ready {
        return Err(MigrationError::WebhookHistoryIndexUnavailable);
    }
    Ok(())
}
