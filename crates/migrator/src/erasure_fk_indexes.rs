// SPDX-License-Identifier: AGPL-3.0-only
use super::MigrationError;
use tokio_postgres::Client;

pub(super) const ERASURE_FK_INDEX_MIGRATION: i64 = 59;
pub(super) const ERASURE_FK_INDEX_FILE: &str = "059_erasure_fk_indexes.sql";

// Owner account erasure deletes every account-keyed row in one transaction,
// and for each deleted row PostgreSQL checks every referencing foreign key.
// These indexes give each check a bounded lookup instead of a scan of the
// referencing table (issue #515). All leading columns are uuid, so every
// collation is 0 and every opclass is the default uuid opclass.
pub(super) const CREATE_WEBHOOK_DELIVERIES_EVENT_INDEX: &str = "CREATE INDEX CONCURRENTLY erasure_fk_webhook_deliveries_event \
     ON public.webhook_deliveries (account_id, event_id)";
pub(super) const DROP_WEBHOOK_DELIVERIES_EVENT_INDEX: &str =
    "DROP INDEX CONCURRENTLY public.erasure_fk_webhook_deliveries_event";
pub(super) const CREATE_SUPPRESSIONS_ATTEMPT_INDEX: &str = "CREATE INDEX CONCURRENTLY erasure_fk_suppressions_attempt \
     ON public.recipient_suppressions (source_attempt_id)";
pub(super) const DROP_SUPPRESSIONS_ATTEMPT_INDEX: &str =
    "DROP INDEX CONCURRENTLY public.erasure_fk_suppressions_attempt";
pub(super) const CREATE_SUPPRESSIONS_EVENT_INDEX: &str = "CREATE INDEX CONCURRENTLY erasure_fk_suppressions_event \
     ON public.recipient_suppressions (account_id, source_event_id)";
pub(super) const DROP_SUPPRESSIONS_EVENT_INDEX: &str =
    "DROP INDEX CONCURRENTLY public.erasure_fk_suppressions_event";
pub(super) const CREATE_HOLDS_RELEASE_EVENT_INDEX: &str = "CREATE INDEX CONCURRENTLY erasure_fk_holds_release_event \
     ON public.owner_recipient_holds (account_id, release_event_id) \
     WHERE release_event_id IS NOT NULL";
pub(super) const DROP_HOLDS_RELEASE_EVENT_INDEX: &str =
    "DROP INDEX CONCURRENTLY public.erasure_fk_holds_release_event";
pub(super) const CREATE_OPT_OUT_AUDIT_RELEASE_EVENT_INDEX: &str = "CREATE INDEX CONCURRENTLY erasure_fk_opt_out_audit_release_event \
     ON public.owner_opt_out_audit (account_id, release_event_id) \
     WHERE release_event_id IS NOT NULL";
pub(super) const DROP_OPT_OUT_AUDIT_RELEASE_EVENT_INDEX: &str =
    "DROP INDEX CONCURRENTLY public.erasure_fk_opt_out_audit_release_event";

// Check the complete index shape before deciding whether an interrupted build
// is ours to remove. A relation with the expected name but a different shape
// belongs to an operator and must never be dropped automatically.
fn index_status_sql(index_name: &str, table: &str, columns: &[&str], predicate: &str) -> String {
    let mut checks = String::new();
    for (position, column) in columns.iter().enumerate() {
        checks.push_str(&format!(
            "    AND ix.indkey[{position}] = (\n\
             \x20       SELECT attnum FROM pg_catalog.pg_attribute\n\
             \x20       WHERE attrelid = tbl.oid AND attname = '{column}' AND NOT attisdropped\n\
             \x20   )\n\
             \x20   AND ix.indoption[{position}] = 0\n\
             \x20   AND ix.indcollation[{position}] = 0\n\
             \x20   AND ix.indclass[{position}] = (\n\
             \x20       SELECT opc.oid FROM pg_catalog.pg_opclass opc\n\
             \x20       WHERE opc.opcmethod = am.oid\n\
             \x20         AND opc.opcintype = 'uuid'::pg_catalog.regtype\n\
             \x20         AND opc.opcdefault\n\
             \x20   )\n"
        ));
    }
    let predicate_check = if predicate.is_empty() {
        "AND ix.indpred IS NULL".to_string()
    } else {
        format!("AND pg_catalog.pg_get_expr(ix.indpred, ix.indrelid) = '{predicate}'")
    };
    format!(
        r#"
SELECT COALESCE(
    idx.relkind = 'i' AND idx.relpersistence = 'p'
    AND tbl_ns.nspname = 'public' AND tbl.relname = '{table}'
    AND am.amname = 'btree'
    AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
    AND ix.indnkeyatts = {count} AND ix.indnatts = {count}
    AND ix.indexprs IS NULL
{checks}    {predicate_check},
    FALSE
) AS expected_shape,
COALESCE(ix.indisvalid AND ix.indisready AND ix.indislive, FALSE) AS ready
FROM pg_catalog.pg_class idx
JOIN pg_catalog.pg_namespace ns ON ns.oid = idx.relnamespace
LEFT JOIN pg_catalog.pg_index ix ON ix.indexrelid = idx.oid
LEFT JOIN pg_catalog.pg_class tbl ON tbl.oid = ix.indrelid
LEFT JOIN pg_catalog.pg_namespace tbl_ns ON tbl_ns.oid = tbl.relnamespace
LEFT JOIN pg_catalog.pg_am am ON am.oid = idx.relam
WHERE ns.nspname = 'public' AND idx.relname = '{index_name}'
"#,
        count = columns.len()
    )
}

struct ErasureFkIndexSpec {
    name: &'static str,
    table: &'static str,
    columns: &'static [&'static str],
    create: &'static str,
    drop: &'static str,
    predicate: &'static str,
}

const ERASURE_FK_INDEXES: [ErasureFkIndexSpec; 5] = [
    ErasureFkIndexSpec {
        name: "erasure_fk_webhook_deliveries_event",
        table: "webhook_deliveries",
        columns: &["account_id", "event_id"],
        create: CREATE_WEBHOOK_DELIVERIES_EVENT_INDEX,
        drop: DROP_WEBHOOK_DELIVERIES_EVENT_INDEX,
        predicate: "",
    },
    ErasureFkIndexSpec {
        name: "erasure_fk_suppressions_attempt",
        table: "recipient_suppressions",
        columns: &["source_attempt_id"],
        create: CREATE_SUPPRESSIONS_ATTEMPT_INDEX,
        drop: DROP_SUPPRESSIONS_ATTEMPT_INDEX,
        predicate: "",
    },
    ErasureFkIndexSpec {
        name: "erasure_fk_suppressions_event",
        table: "recipient_suppressions",
        columns: &["account_id", "source_event_id"],
        create: CREATE_SUPPRESSIONS_EVENT_INDEX,
        drop: DROP_SUPPRESSIONS_EVENT_INDEX,
        predicate: "",
    },
    ErasureFkIndexSpec {
        name: "erasure_fk_holds_release_event",
        table: "owner_recipient_holds",
        columns: &["account_id", "release_event_id"],
        create: CREATE_HOLDS_RELEASE_EVENT_INDEX,
        drop: DROP_HOLDS_RELEASE_EVENT_INDEX,
        predicate: "(release_event_id IS NOT NULL)",
    },
    ErasureFkIndexSpec {
        name: "erasure_fk_opt_out_audit_release_event",
        table: "owner_opt_out_audit",
        columns: &["account_id", "release_event_id"],
        create: CREATE_OPT_OUT_AUDIT_RELEASE_EVENT_INDEX,
        drop: DROP_OPT_OUT_AUDIT_RELEASE_EVENT_INDEX,
        predicate: "(release_event_id IS NOT NULL)",
    },
];

async fn erasure_fk_index_status(
    client: &Client,
    spec: &ErasureFkIndexSpec,
) -> Result<Option<(bool, bool)>, MigrationError> {
    Ok(client
        .query_opt(
            &index_status_sql(spec.name, spec.table, spec.columns, spec.predicate),
            &[],
        )
        .await?
        .map(|row| (row.get(0), row.get(1))))
}

async fn prepare_erasure_fk_index(
    client: &Client,
    spec: &ErasureFkIndexSpec,
) -> Result<(), MigrationError> {
    match erasure_fk_index_status(client, spec).await? {
        None => {}
        Some((false, _)) => return Err(MigrationError::ErasureFkIndexConflict(spec.name)),
        Some((true, true)) => return Ok(()),
        Some((true, false)) => {
            // A canceled concurrent build leaves an invalid catalog entry.
            // This is safe to retry only after its exact shape is established.
            let building: bool = client
                .query_one(
                    &format!(
                        "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_progress_create_index \
                         WHERE index_relid=to_regclass('public.{}'))",
                        spec.name
                    ),
                    &[],
                )
                .await?
                .get(0);
            if building {
                return Err(MigrationError::ErasureFkIndexBuildInProgress(spec.name));
            }
            client.batch_execute(spec.drop).await?;
        }
    }
    client.batch_execute(spec.create).await?;
    if erasure_fk_index_status(client, spec).await? != Some((true, true)) {
        return Err(MigrationError::ErasureFkIndexUnavailable(spec.name));
    }
    Ok(())
}

pub(super) async fn prepare_erasure_fk_indexes(client: &Client) -> Result<(), MigrationError> {
    for spec in &ERASURE_FK_INDEXES {
        prepare_erasure_fk_index(client, spec).await?;
    }
    Ok(())
}

pub(super) async fn verify_erasure_fk_indexes(client: &Client) -> Result<(), MigrationError> {
    let ready: bool = client
        .query_one("SELECT public.erasure_fk_indexes_ready('public')", &[])
        .await?
        .get(0);
    if !ready {
        return Err(MigrationError::ErasureFkIndexUnavailable(
            "erasure foreign-key support indexes",
        ));
    }
    Ok(())
}
