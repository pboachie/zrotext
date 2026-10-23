// SPDX-License-Identifier: AGPL-3.0-only
//! Correlated original submit receipts after reconnect, Stop or content erasure.
use super::{history::*, *};
use crate::conversation_effect03::{SubmitCommand03, wire};
use tokio_postgres::Row;

pub(super) fn accepted_submit(row: &Row, original: &Original03) -> Result<(SubmitCommand03, u64)> {
    let command = SubmitCommand03::decode(&row.try_get::<_, Vec<u8>>("command")?)
        .map_err(|_| Error::Unsupported)?;
    original.command(&command)?;
    let accepted = positive(row.try_get("accepted_ms")?)?;
    if row.try_get::<_, Vec<u8>>("command_sha256")?.as_slice()
        != command.digest().map_err(|_| Error::Unsupported)?
        || accepted < original.grant.numbers[8]
        || accepted >= original.grant.numbers[9]
    {
        return Err(Error::Conflict);
    }
    Ok((command, accepted))
}

pub(super) async fn submit(
    tx: &Transaction<'_>,
    scope: &Scope03,
    request: &wire::SubmitStatus03,
) -> Result<serde_json::Value> {
    let mut held = HeldHistory03::lock(tx, scope, request.attempt_id).await?;
    if request.message_id != held.original.grant.ids[1] {
        return Err(Error::Conflict);
    }
    let row = tx.query_opt(
        "SELECT * FROM public.conversation_profile03_submits WHERE account_id=$1 AND attempt_id=$2",
        &[&scope.session.account_id,&request.attempt_id],
    ).await?;
    let receipt = if let Some(row) = row {
        let (command, accepted) = accepted_submit(&row, &held.original)?;
        if command.identities()[2] != *request.event_id.as_bytes()
            || command.digest().map_err(|_| Error::Unsupported)? != request.submit_sha256
        {
            return Err(Error::Conflict);
        }
        serde_json::json!({
            "accepted_ms":accepted.to_string(),"state":"submitting",
            "fetch_transcript_sha256":B.encode(command.fetch_digest()),
            "segment_count":command.segment_count(),
            "observed_ms":command.observed_ms().to_string(),
            "original_device_session_digest":B.encode(held.original.session),
            "original_connection_epoch":held.original.grant.numbers[2].to_string(),
            "original_deployment_epoch":held.original.grant.numbers[3].to_string()
        })
    } else {
        serde_json::Value::Null
    };
    held.revalidate(scope).await?;
    Ok(serde_json::json!({
        "v":1,"type":"payload_profile_submit_status03",
        "connection_epoch":scope.session.connection_epoch,"request_id":request.request_id,
        "event_id":request.event_id,"message_id":request.message_id,
        "attempt_id":request.attempt_id,"submit_command_sha256":B.encode(request.submit_sha256),
        "status":if receipt.is_null() {"not_found"} else {"accepted"},"receipt":receipt
    }))
}
