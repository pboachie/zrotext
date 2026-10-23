// SPDX-License-Identifier: AGPL-3.0-only
//! Typed immutable evidence; never calls the legacy radio-event writer.
use super::{history::*, *};
use crate::conversation_effect03::wire;

pub(super) async fn record(
    tx: &Transaction<'_>,
    scope: &Scope03,
    request: &wire::Outcome03,
) -> Result<serde_json::Value> {
    let mut held = HeldHistory03::lock(tx, scope, request.attempt_id).await?;
    let submit = wire::Submit03 {
        connection_epoch: request.connection_epoch,
        event_id: request.submit_event_id,
        message_id: request.message_id,
        attempt_id: request.attempt_id,
        fetch_sha256: request.fetch_sha256,
        segment_count: request.segment_count,
        observed_ms: request.submit_observed_ms,
    }
    .candidate_command(
        scope.session.account_id,
        scope.session.device_id,
        &held.original.session,
    )
    .map_err(|_| Error::Unsupported)?;
    held.original.command(&submit)?;
    let command = request
        .candidate_command(
            scope.session.account_id,
            scope.session.device_id,
            &held.original.session,
        )
        .map_err(|_| Error::Unsupported)?;
    let bytes = &command.bytes()[..];
    let [a, b, c, d, e, f] = scope.sql_actor();
    let rows = tx
        .query(
            "SELECT * FROM public.conversation_profile03_effect_outcome($1,$2,$3,$4,$5,$6,$7)",
            &[a, b, c, d, e, f, &bytes],
        )
        .await?;
    if rows.len() != 1 {
        return Err(Error::Conflict);
    }
    let row = &rows[0];
    let inserted: bool = row.try_get("inserted")?;
    let digest = command.digest().map_err(|_| Error::Unsupported)?;
    if row.try_get::<_, Vec<u8>>("command")?.as_slice() != command.bytes()
        || row.try_get::<_, Vec<u8>>("event_sha256")?.as_slice() != digest
        || row.try_get::<_, Uuid>("account_id")? != scope.session.account_id
        || row.try_get::<_, Uuid>("device_id")? != scope.session.device_id
        || row.try_get::<_, Uuid>("message_id")? != request.message_id
        || row.try_get::<_, Uuid>("attempt_id")? != request.attempt_id
        || row.try_get::<_, Uuid>("event_id")? != request.event_id
        || row.try_get::<_, Uuid>("submit_event_id")? != request.submit_event_id
    {
        return Err(Error::Conflict);
    }
    held.revalidate(scope).await?;
    let recorded = positive(row.try_get("recorded_ms")?)?;
    if recorded > held.now_ms() {
        return Err(Error::Expired);
    }
    Ok(serde_json::json!({
        "v":1,"type":"payload_profile_outcome_ack03",
        "connection_epoch":scope.session.connection_epoch,
        "event_id":request.event_id,"message_id":request.message_id,
        "attempt_id":request.attempt_id,"submit_event_id":request.submit_event_id,
        "submit_command_sha256":B.encode(request.submit_sha256),
        "event_sha256":B.encode(digest),"recorded_ms":recorded.to_string(),
        "disposition":if inserted {"recorded"} else {"history_only"},
        "resulting_state":row.try_get::<_,Option<String>>("resulting_state")?
    }))
}
