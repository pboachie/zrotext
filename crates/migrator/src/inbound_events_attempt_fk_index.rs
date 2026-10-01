// SPDX-License-Identifier: AGPL-3.0-only
use super::MigrationError;
use super::erasure_fk_indexes::{ErasureFkIndexSpec, prepare_erasure_fk_index};
use tokio_postgres::Client;

pub(super) const INBOUND_EVENTS_ATTEMPT_FK_INDEX_MIGRATION: i64 = 61;
pub(super) const INBOUND_EVENTS_ATTEMPT_FK_INDEX_FILE: &str =
    "061_inbound_events_attempt_fk_index.sql";

// Owner account erasure deletes message_attempts row by row, and each deleted
// row checks the inbound_events (account_id, device_id, message_id, attempt_id)
// foreign key (issues #515 and #601). Until this migration the check was
// served only by the (account_id, message_id) prefix of inbound_events_timeline,
// and #601 measured it at 7.4 s of an 8.5 s erasure when one message carried
// many attempts. All four columns are uuid, so every collation is 0 and every
// opclass is the default uuid opclass.
pub(super) const CREATE_INBOUND_EVENTS_ATTEMPT_FK_INDEX: &str = "CREATE INDEX CONCURRENTLY erasure_fk_inbound_events_attempt \
     ON public.inbound_events (account_id, device_id, message_id, attempt_id)";
pub(super) const DROP_INBOUND_EVENTS_ATTEMPT_FK_INDEX: &str =
    "DROP INDEX CONCURRENTLY public.erasure_fk_inbound_events_attempt";

const INBOUND_EVENTS_ATTEMPT_FK_INDEX: ErasureFkIndexSpec = ErasureFkIndexSpec {
    name: "erasure_fk_inbound_events_attempt",
    table: "inbound_events",
    columns: &["account_id", "device_id", "message_id", "attempt_id"],
    create: CREATE_INBOUND_EVENTS_ATTEMPT_FK_INDEX,
    drop: DROP_INBOUND_EVENTS_ATTEMPT_FK_INDEX,
    predicate: "",
};

pub(super) async fn prepare_inbound_events_attempt_fk_index(
    client: &Client,
) -> Result<(), MigrationError> {
    prepare_erasure_fk_index(client, &INBOUND_EVENTS_ATTEMPT_FK_INDEX).await
}

pub(super) async fn verify_inbound_events_attempt_fk_index(
    client: &Client,
) -> Result<(), MigrationError> {
    let ready: bool = client
        .query_one(
            "SELECT public.inbound_events_attempt_fk_index_ready('public')",
            &[],
        )
        .await?
        .get(0);
    if !ready {
        return Err(MigrationError::ErasureFkIndexUnavailable(
            "erasure_fk_inbound_events_attempt",
        ));
    }
    Ok(())
}
