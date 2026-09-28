// SPDX-License-Identifier: AGPL-3.0-only
use super::MigrationError;
use tokio_postgres::Client;

pub(super) const OWNER_QUEUE_INDEX_MIGRATION: i64 = 49;
pub(super) const OWNER_QUEUE_INDEX_FILE: &str = "049_owner_queue_probe_indexes.sql";

// Both indexes lead with device_id so the owner queue probes constrain the
// scan to one device, and their predicates are exactly the probe state sets so
// the planner can drop the state filter on every supported PostgreSQL release.
pub(super) const CREATE_OWNER_PENDING_STATE_INDEX: &str = "CREATE INDEX CONCURRENTLY messages_owner_pending_state \
     ON public.messages (device_id, state, created_at) \
     WHERE state IN ('accepted', 'queued', 'claimed')";
pub(super) const DROP_OWNER_PENDING_STATE_INDEX: &str =
    "DROP INDEX CONCURRENTLY public.messages_owner_pending_state";
pub(super) const CREATE_OWNER_IN_FLIGHT_STATE_INDEX: &str = "CREATE INDEX CONCURRENTLY messages_owner_in_flight_state \
     ON public.messages (device_id, state, created_at) \
     WHERE state IN ('submitting', 'submitted')";
pub(super) const DROP_OWNER_IN_FLIGHT_STATE_INDEX: &str =
    "DROP INDEX CONCURRENTLY public.messages_owner_in_flight_state";

// Check the complete index shape before deciding whether an interrupted build
// is ours to remove. A relation with the expected name but a different shape
// belongs to an operator and must never be dropped automatically.
fn index_status_sql(index_name: &str, predicate: &str) -> String {
    format!(
        r#"
SELECT COALESCE(
    idx.relkind = 'i' AND idx.relpersistence = 'p'
    AND tbl_ns.nspname = 'public' AND tbl.relname = 'messages'
    AND am.amname = 'btree'
    AND NOT ix.indisunique AND NOT ix.indisprimary AND NOT ix.indisexclusion
    AND ix.indnkeyatts = 3 AND ix.indnatts = 3
    AND ix.indexprs IS NULL
    AND ix.indkey[0] = (
        SELECT attnum FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'device_id' AND NOT attisdropped
    )
    AND ix.indkey[1] = (
        SELECT attnum FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'state' AND NOT attisdropped
    )
    AND ix.indkey[2] = (
        SELECT attnum FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'created_at' AND NOT attisdropped
    )
    AND ix.indoption[0] = 0 AND ix.indoption[1] = 0 AND ix.indoption[2] = 0
    AND ix.indcollation[0] = 0
    AND ix.indcollation[1] = (
        SELECT attcollation FROM pg_catalog.pg_attribute
        WHERE attrelid = tbl.oid AND attname = 'state' AND NOT attisdropped
    )
    AND ix.indcollation[2] = 0
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
    AND ix.indclass[2] = (
        SELECT opc.oid FROM pg_catalog.pg_opclass opc
        WHERE opc.opcmethod = am.oid
          AND opc.opcintype = 'timestamp with time zone'::pg_catalog.regtype
          AND opc.opcdefault
    )
    AND pg_catalog.pg_get_expr(ix.indpred, ix.indrelid) = '{predicate}',
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
"#
    )
}

struct OwnerQueueIndexSpec {
    name: &'static str,
    create: &'static str,
    drop: &'static str,
    predicate: &'static str,
}

const OWNER_QUEUE_INDEXES: [OwnerQueueIndexSpec; 2] = [
    OwnerQueueIndexSpec {
        name: "messages_owner_pending_state",
        create: CREATE_OWNER_PENDING_STATE_INDEX,
        drop: DROP_OWNER_PENDING_STATE_INDEX,
        predicate: "(state = ANY (ARRAY[''accepted''::text, ''queued''::text, ''claimed''::text]))",
    },
    OwnerQueueIndexSpec {
        name: "messages_owner_in_flight_state",
        create: CREATE_OWNER_IN_FLIGHT_STATE_INDEX,
        drop: DROP_OWNER_IN_FLIGHT_STATE_INDEX,
        predicate: "(state = ANY (ARRAY[''submitting''::text, ''submitted''::text]))",
    },
];

async fn owner_queue_index_status(
    client: &Client,
    spec: &OwnerQueueIndexSpec,
) -> Result<Option<(bool, bool)>, MigrationError> {
    Ok(client
        .query_opt(&index_status_sql(spec.name, spec.predicate), &[])
        .await?
        .map(|row| (row.get(0), row.get(1))))
}

async fn prepare_owner_queue_index(
    client: &Client,
    spec: &OwnerQueueIndexSpec,
) -> Result<(), MigrationError> {
    match owner_queue_index_status(client, spec).await? {
        None => {}
        Some((false, _)) => return Err(MigrationError::OwnerQueueIndexConflict(spec.name)),
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
                return Err(MigrationError::OwnerQueueIndexBuildInProgress(spec.name));
            }
            client.batch_execute(spec.drop).await?;
        }
    }
    client.batch_execute(spec.create).await?;
    if owner_queue_index_status(client, spec).await? != Some((true, true)) {
        return Err(MigrationError::OwnerQueueIndexUnavailable(spec.name));
    }
    Ok(())
}

pub(super) async fn prepare_owner_queue_indexes(client: &Client) -> Result<(), MigrationError> {
    for spec in &OWNER_QUEUE_INDEXES {
        prepare_owner_queue_index(client, spec).await?;
    }
    Ok(())
}

pub(super) async fn verify_owner_queue_indexes(client: &Client) -> Result<(), MigrationError> {
    let ready: bool = client
        .query_one(
            "SELECT public.owner_queue_probe_indexes_ready('public')",
            &[],
        )
        .await?
        .get(0);
    if !ready {
        return Err(MigrationError::OwnerQueueIndexUnavailable(
            "messages_owner_pending_state/messages_owner_in_flight_state",
        ));
    }
    Ok(())
}
