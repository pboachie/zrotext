// SPDX-License-Identifier: AGPL-3.0-only
use super::MigrationError;
use tokio_postgres::Client;

pub(super) const RADIO_EVIDENCE_INDEX_MIGRATION: i64 = 40;
pub(super) const RADIO_EVIDENCE_INDEX_FILE: &str = "040_radio_evidence_index.sql";
pub(super) const CREATE_RADIO_EVIDENCE_INDEX: &str = "CREATE INDEX CONCURRENTLY message_events_attempt_evidence ON public.message_events (attempt_id, evidence_code)";
pub(super) const DROP_RADIO_EVIDENCE_INDEX: &str =
    "DROP INDEX CONCURRENTLY public.message_events_attempt_evidence";

// Check the complete index shape before deciding whether an interrupted build
// is ours to remove. A relation with the expected name but a different shape
// belongs to an operator and must never be dropped automatically.
pub(super) const RADIO_EVIDENCE_INDEX_STATUS: &str = r#"
SELECT COALESCE(
    idx.relkind = 'i' AND idx.relpersistence = 'p'
    AND tbl_ns.nspname = 'public' AND tbl.relname = 'message_events'
    AND am.amname = 'btree'
    AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
    AND ix.indnkeyatts = 2 AND ix.indnatts = 2
    AND ix.indexprs IS NULL
    AND ix.indkey[0] = (
        SELECT attnum FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'attempt_id' AND NOT attisdropped
    )
    AND ix.indkey[1] = (
        SELECT attnum FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'evidence_code' AND NOT attisdropped
    )
    AND ix.indoption[0] = 0 AND ix.indoption[1] = 0
    AND ix.indcollation[0] = 0 AND ix.indcollation[1] = (
        SELECT attcollation FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'evidence_code' AND NOT attisdropped
    )
    AND ix.indclass[0] = (
        SELECT opc.oid FROM pg_catalog.pg_opclass opc
        WHERE opc.opcmethod = am.oid
          AND opc.opcintype = 'uuid'::pg_catalog.regtype
          AND opc.opcdefault
    )
    AND ix.indclass[1] = (
        SELECT opc.oid FROM pg_catalog.pg_opclass opc
        WHERE opc.opcmethod = am.oid
          AND opc.opcintype = 'text'::pg_catalog.regtype
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
WHERE ns.nspname = 'public' AND idx.relname = 'message_events_attempt_evidence'
"#;

pub(super) async fn radio_evidence_index_status(
    client: &Client,
) -> Result<Option<(bool, bool)>, MigrationError> {
    Ok(client
        .query_opt(RADIO_EVIDENCE_INDEX_STATUS, &[])
        .await?
        .map(|row| (row.get(0), row.get(1))))
}

pub(super) async fn prepare_radio_evidence_index(client: &Client) -> Result<(), MigrationError> {
    match radio_evidence_index_status(client).await? {
        None => {}
        Some((false, _)) => return Err(MigrationError::RadioEvidenceIndexConflict),
        Some((true, true)) => return Ok(()),
        Some((true, false)) => {
            // A canceled concurrent build leaves an invalid catalog entry.
            // This is safe to retry only after its exact shape is established.
            let building: bool = client
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_progress_create_index \
                     WHERE index_relid=to_regclass('public.message_events_attempt_evidence'))",
                    &[],
                )
                .await?
                .get(0);
            if building {
                return Err(MigrationError::RadioEvidenceIndexBuildInProgress);
            }
            client.batch_execute(DROP_RADIO_EVIDENCE_INDEX).await?;
        }
    }
    client.batch_execute(CREATE_RADIO_EVIDENCE_INDEX).await?;
    if radio_evidence_index_status(client).await? != Some((true, true)) {
        return Err(MigrationError::RadioEvidenceIndexUnavailable);
    }
    Ok(())
}

pub(super) async fn verify_radio_evidence_index(client: &Client) -> Result<(), MigrationError> {
    let ready: bool = client
        .query_one(
            "SELECT public.message_events_radio_evidence_index_ready('public')",
            &[],
        )
        .await?
        .get(0);
    if !ready {
        return Err(MigrationError::RadioEvidenceIndexUnavailable);
    }
    Ok(())
}
