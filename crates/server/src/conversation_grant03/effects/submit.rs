// SPDX-License-Identifier: AGPL-3.0-only
//! Fresh submit needs the whole held current proof; duplicate acceptance is passive.
use super::{history::*, *};
use crate::conversation_effect03::wire;

fn reply(
    scope: &Scope03,
    request: &wire::Submit03,
    command: &crate::conversation_effect03::SubmitCommand03,
    accepted: u64,
    permissions: Option<(serde_json::Value, serde_json::Value)>,
) -> Result<serde_json::Value> {
    let once = permissions.is_some();
    let (current, interval) =
        permissions.unwrap_or((serde_json::Value::Null, serde_json::Value::Null));
    Ok(serde_json::json!({
        "v":1,"type":"payload_profile_submit_ack03","connection_epoch":scope.session.connection_epoch,
        "event_id":request.event_id,"message_id":request.message_id,"attempt_id":request.attempt_id,
        "submit_command_sha256":B.encode(command.digest().map_err(|_| Error::Unsupported)?),
        "fetch_transcript_sha256":B.encode(command.fetch_digest()),"segment_count":command.segment_count(),
        "observed_ms":command.observed_ms().to_string(),"accepted_ms":accepted.to_string(),"state":"submitting",
        "disposition":if once {"submit_once"} else {"history_only"},"current":current,"interval_permission":interval
    }))
}
async fn call(
    tx: &Transaction<'_>,
    scope: &Scope03,
    command: &crate::conversation_effect03::SubmitCommand03,
) -> Result<tokio_postgres::Row> {
    let [a, b, c, d, e, f] = scope.sql_actor();
    let bytes = &command.bytes()[..];
    let mut rows = tx
        .query(
            "SELECT * FROM public.conversation_profile03_effect_submit($1,$2,$3,$4,$5,$6,$7)",
            &[a, b, c, d, e, f, &bytes],
        )
        .await?;
    if rows.len() != 1 {
        return Err(Error::Conflict);
    }
    Ok(rows.remove(0))
}
pub(super) async fn apply(
    tx: &Transaction<'_>,
    scope: &Scope03,
    origin: Option<&str>,
    request: &wire::Submit03,
) -> Result<serde_json::Value> {
    // This is an immutable selector hint, not a lock or accepted fact. The
    // historical path independently takes current original-actor locks; the
    // NEW path instead selects the genuine owner BEFORE line/device readers.
    let exists=tx.query_opt(
        "SELECT 1 FROM public.conversation_profile03_submits WHERE account_id=$1 AND attempt_id=$2",
        &[&scope.session.account_id,&request.attempt_id],
    ).await?.is_some();
    if exists {
        let mut held = HeldHistory03::lock(tx, scope, request.attempt_id).await?;
        let command = request
            .candidate_command(
                scope.session.account_id,
                scope.session.device_id,
                &held.original.session,
            )
            .map_err(|_| Error::Unsupported)?;
        held.original.command(&command)?;
        let row = call(tx, scope, &command).await?;
        if row.try_get::<_, bool>("inserted")? {
            return Err(Error::Conflict);
        }
        let (retained, accepted) = super::status::accepted_submit(&row, &held.original)?;
        if retained.bytes() != command.bytes() {
            return Err(Error::Conflict);
        }
        held.revalidate(scope).await?;
        return reply(scope, request, &command, accepted, None);
    }
    let origin = origin.ok_or(Error::Authentication)?;
    let actor = DeviceInterval03 {
        session: scope.session,
        site: &scope.site,
        instance: &scope.instance,
        deployment: u64::try_from(scope.deployment).map_err(|_| Error::Authentication)?,
        origin,
    };
    let mode = Mode03::lock(tx, actor, request.attempt_id).await?;
    let row = mode.prior.as_ref().ok_or(Error::NotFound)?;
    let original = Original03::read(tx, scope, request.attempt_id).await?;
    if original.grant.frame()?.claims() != row.frame()?.claims() {
        return Err(Error::Conflict);
    }
    let command = request
        .candidate_command(
            scope.session.account_id,
            scope.session.device_id,
            &original.session,
        )
        .map_err(|_| Error::Unsupported)?;
    original.command(&command)?;
    let end = row.numbers[9];
    let mut review = execution::lock(&mode, request.message_id).await?;
    row.matches(&review)?;
    review.verify_until(end).await?;
    if review
        .selected()
        .enrolled_signing_key()?
        .to_sec1_point(false)
        .as_bytes()
        != scope.proof.signing_point()
        || command.segment_count() > review.sms_ceiling()
    {
        return Err(Error::Authentication);
    }
    if command.observed_ms() < row.numbers[8].saturating_sub(2_000).max(1)
        || command.observed_ms()
            > review
                .selected()
                .now_ms()
                .checked_add(2_000)
                .ok_or(Error::Expired)?
    {
        return Err(Error::Expired);
    }
    let accepted = call(tx, scope, &command).await?;
    let inserted: bool = accepted.try_get("inserted")?;
    let (retained, accepted_ms) = super::status::accepted_submit(&accepted, &original)?;
    if retained.bytes() != command.bytes() {
        return Err(Error::Conflict);
    }
    let permissions = if inserted {
        review.verify_until(end).await?;
        row.matches(&review)?;
        if review
            .selected()
            .enrolled_signing_key()?
            .to_sec1_point(false)
            .as_bytes()
            != scope.proof.signing_point()
        {
            return Err(Error::Authentication);
        }
        let permissions = review
            .submit_permission(&row.frame()?, request.event_id)
            .await?;
        // The shared final projection clock must also cover the actual SQL
        // acceptance sample. Refuse a primary regression; never clamp it.
        if review.selected().now_ms() < accepted_ms {
            return Err(Error::Expired);
        }
        Some(permissions)
    } else {
        None
    };
    // This candidate is private to the transaction-owning entry point. An SQL
    // row/inserted flag alone never escapes as an invocation permit. The caller
    // must COMMIT and pass its still-live socket guard before emitting it.
    reply(scope, request, &command, accepted_ms, permissions)
}
