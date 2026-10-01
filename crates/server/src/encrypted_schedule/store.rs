// SPDX-License-Identifier: AGPL-3.0-only
//! Transaction-local scheduling; callers commit only after final authority checks.
use super::{
    permit::{ActionFence, Actor},
    policy::WindowPolicy,
    time::{self, Resolution, ReviewReason, Timing},
};
use crate::http_owner_conversations::{ConversationError, context::decisions::LockedAction};
use sha2::{Digest, Sha256};
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub struct ScheduleRequest {
    pub request_id: Uuid,
    pub series_id: Uuid,
    pub ordinal: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Occurrence {
    pub id: Uuid,
    pub series_id: Uuid,
    pub ordinal: u16,
    pub dispatch_id: Uuid,
    pub phase: String,
    pub opens_at_ms: Option<i64>,
    pub closes_at_ms: Option<i64>,
    pub expires_at_ms: i64,
    pub message_id: Option<Uuid>,
}
impl Occurrence {
    fn row(row: &Row) -> Self {
        Self {
            id: row.get("id"),
            series_id: row.get("series_id"),
            ordinal: row.get::<_, i16>("ordinal") as u16,
            dispatch_id: row.get("dispatch_id"),
            phase: row.get("phase"),
            opens_at_ms: row.get("opens_at_ms"),
            closes_at_ms: row.get("closes_at_ms"),
            expires_at_ms: row.get("expires_at_ms"),
            message_id: row.get("message_id"),
        }
    }
}

fn window_error(error: time::WindowError) -> ConversationError {
    match error {
        time::WindowError::Invalid => ConversationError::Invalid,
        time::WindowError::Database(error) => ConversationError::Database(error),
    }
}
async fn now(tx: &Transaction<'_>) -> Result<i64, ConversationError> {
    Ok(tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0))
}

/// Every occurrence requires its own exact independently approved action.
/// This method never stores ciphertext, renders content, or creates messages.
pub(crate) async fn schedule_core<'connection>(
    permit: &mut impl ActionFence<'connection>,
    request: ScheduleRequest,
    policy: &WindowPolicy,
) -> Result<Occurrence, ConversationError> {
    if request.request_id.is_nil()
        || request.series_id.is_nil()
        || request.ordinal >= policy.max_occurrences
    {
        return Err(ConversationError::Invalid);
    }
    permit.recheck().await?;
    let key = permit.key();
    let policy_id = policy.identity().map_err(window_error)?;
    if permit.descriptor().window_id != policy_id
        || policy.timezone.as_deref().unwrap_or("unknown") != permit.descriptor().timezone
    {
        return Err(ConversationError::Forbidden);
    }
    let content_version = permit.descriptor().content_version;
    let not_before = permit
        .descriptor()
        .not_before
        .checked_mul(1000)
        .ok_or(ConversationError::Invalid)?;
    let expiry = permit.expires_at_ms();
    let context = permit.context_id();
    let routine = permit.routine_id();
    let generation = permit.routine_generation();
    let actor = permit.actor();
    let owner_session = permit.owner_session_id();
    let tx = permit.transaction();
    let resolution = policy
        .resolve_occurrence(tx, request.ordinal)
        .await
        .map_err(window_error)?;
    let canonical = serde_json::to_vec(&(
        request.series_id,
        request.ordinal,
        &policy_id,
        key.account_id,
        key.action_id,
        key.revision,
        key.binding_digest,
    ))
    .map_err(|_| ConversationError::Invalid)?;
    let digest = Sha256::digest(canonical).to_vec();
    if let Some(existing) = tx
        .query_opt(
            "SELECT * FROM workflow_schedule_occurrences WHERE account_id=$1 AND request_id=$2",
            &[&key.account_id, &request.request_id],
        )
        .await?
    {
        if existing.get::<_, Vec<u8>>("request_digest") != digest {
            return Err(ConversationError::Conflict);
        }
        let result = Occurrence::row(&existing);
        permit.recheck().await?;
        return Ok(result);
    }
    if tx.query_one("SELECT EXISTS(SELECT 1 FROM workflow_message_links WHERE account_id=$1 AND action_id=$2 AND revision=$3)", &[&key.account_id,&key.action_id,&key.revision]).await?.get::<_,bool>(0) {
        return Err(ConversationError::Conflict);
    }
    let opens = policy.opens_minute as i16;
    let closes = policy.closes_minute as i16;
    let repeat = policy.repeat_every_days.map(|v| v as i16);
    let count = policy.max_occurrences as i16;
    let pacing = policy.pacing_seconds as i32;
    tx.execute("INSERT INTO workflow_schedule_policies(account_id,id,timezone,first_local_date,opens_minute,closes_minute,repeat_every_days,max_occurrences,pacing_seconds) VALUES($1,$2,$3,$4::text::date,$5,$6,$7,$8,$9) ON CONFLICT(account_id,id) DO NOTHING",
        &[&key.account_id,&policy_id,&policy.timezone,&policy.first_local_date,&opens,&closes,&repeat,&count,&pacing]).await?;
    tx.execute("INSERT INTO workflow_schedule_series(account_id,id,policy_id,context_id,context_revision,routine_id,routine_generation) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(account_id,id) DO NOTHING",
        &[&key.account_id,&request.series_id,&policy_id,&context,&content_version,&routine,&generation]).await?;
    let series = tx
        .query_one(
            "SELECT * FROM workflow_schedule_series WHERE account_id=$1 AND id=$2 FOR UPDATE",
            &[&key.account_id, &request.series_id],
        )
        .await?;
    if series.get::<_, String>("policy_id") != policy_id
        || series.get::<_, Uuid>("context_id") != context
        || series.get::<_, i64>("context_revision") != content_version
        || series.get::<_, Uuid>("routine_id") != routine
        || series.get::<_, i64>("routine_generation") != generation
    {
        return Err(ConversationError::Conflict);
    }
    // Routine permission is already locked by the permit. Pacing spans all
    // series, so choosing another series cannot reset the same routine's delay.
    let pacing_until:i64=tx.query_one("SELECT COALESCE(max(pacing_until_ms),0)::bigint FROM workflow_schedule_series WHERE account_id=$1 AND routine_id=$2",&[&key.account_id,&routine]).await?.get(0);
    let timing = time::timing(now(tx).await?, not_before, expiry, pacing_until, resolution)
        .map_err(window_error)?;
    let (opens_at, closes_at, reason) = match resolution {
        Resolution::Ready {
            opens_at_ms,
            closes_at_ms,
        } => (Some(opens_at_ms), Some(closes_at_ms), None),
        Resolution::OwnerReview(reason) => (
            None,
            None,
            Some(match reason {
                ReviewReason::UnknownTimezone => "unknown_timezone",
                ReviewReason::NonexistentCivilTime => "nonexistent_civil_time",
                ReviewReason::AmbiguousCivilTime => "ambiguous_civil_time",
            }),
        ),
    };
    let phase = match timing {
        Timing::Expired => "expired",
        Timing::MissedWindow => "missed_window",
        Timing::OwnerReview(_) => "owner_review",
        _ => "waiting_window",
    };
    let reason = if phase == "owner_review" {
        reason
    } else {
        None
    };
    let ordinal = request.ordinal as i16;
    let id = Uuid::new_v4();
    let dispatch = Uuid::new_v4();
    let (actor_kind, actor_id) = actor.identity();
    let row=tx.query_one("INSERT INTO workflow_schedule_occurrences(account_id,id,series_id,ordinal,action_id,action_revision,binding_digest,request_id,request_digest,dispatch_id,opens_at_ms,closes_at_ms,not_before_ms,expires_at_ms,phase,review_reason,actor_kind,actor_id,owner_session_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING *",
        &[&key.account_id,&id,&request.series_id,&ordinal,&key.action_id,&key.revision,&&key.binding_digest[..],&request.request_id,&digest,&dispatch,&opens_at,&closes_at,&not_before,&expiry,&phase,&reason,&actor_kind,&actor_id,&owner_session]).await?;
    let result = Occurrence::row(&row);
    audit(
        tx,
        key.account_id,
        result.id,
        Some(actor),
        "schedule",
        &result.phase,
        Some((request.request_id, &digest)),
    )
    .await?;
    permit.recheck().await?;
    Ok(result)
}
#[derive(Clone, Debug)]
pub struct Lease {
    pub occurrence: Occurrence,
    id: Uuid,
    until_ms: i64,
}

/// Claim only the action whose live authority the caller has just locked.
/// Candidate discovery never itself grants work; stale candidates are refused.
pub(crate) async fn claim_core<'connection>(
    permit: &mut impl ActionFence<'connection>,
    occurrence_id: Uuid,
) -> Result<Option<Lease>, ConversationError> {
    permit.recheck().await?;
    let key = permit.key();
    let actor = permit.actor();
    let tx = permit.transaction();
    let series=tx.query_opt("SELECT s.* FROM workflow_schedule_series s JOIN workflow_schedule_occurrences o ON (o.account_id,o.series_id)=(s.account_id,s.id) WHERE o.account_id=$1 AND o.id=$2 FOR UPDATE OF s SKIP LOCKED",&[&key.account_id,&occurrence_id]).await?;
    let Some(series) = series else {
        return Ok(None);
    };
    let Some(row)=tx.query_opt("SELECT * FROM workflow_schedule_occurrences WHERE account_id=$1 AND id=$2 FOR UPDATE SKIP LOCKED",&[&key.account_id,&occurrence_id]).await? else{return Ok(None)};
    if row.get::<_, Uuid>("action_id") != key.action_id
        || row.get::<_, i64>("action_revision") != key.revision
        || row.get::<_, Vec<u8>>("binding_digest") != key.binding_digest
    {
        return Err(ConversationError::Forbidden);
    }
    let phase: String = row.get("phase");
    if !matches!(
        phase.as_str(),
        "waiting_window" | "waiting_renderer" | "waiting_phone" | "claimed"
    ) {
        return Ok(None);
    }
    let instant = now(tx).await?;
    if row.get::<_, i64>("retry_at_ms") > instant
        || row
            .get::<_, Option<i64>>("lease_until_ms")
            .is_some_and(|until| until > instant)
    {
        return Ok(None);
    }
    let earlier:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM workflow_schedule_occurrences WHERE account_id=$1 AND series_id=$2 AND ordinal<$3 AND phase NOT IN ('completed','failed','cancelled','expired','missed_window'))",&[&key.account_id,&row.get::<_,Uuid>("series_id"),&row.get::<_,i16>("ordinal")]).await?.get(0);
    if earlier {
        return Ok(None);
    }
    let routine: Uuid = series.get("routine_id");
    let pacing:i64=tx.query_one("SELECT COALESCE(max(pacing_until_ms),0)::bigint FROM workflow_schedule_series WHERE account_id=$1 AND routine_id=$2",&[&key.account_id,&routine]).await?.get(0);
    let opens: i64 = row.get("opens_at_ms");
    let closes: i64 = row.get("closes_at_ms");
    let expiry: i64 = row.get("expires_at_ms");
    let timing = time::timing(
        instant,
        row.get("not_before_ms"),
        expiry,
        pacing,
        Resolution::Ready {
            opens_at_ms: opens,
            closes_at_ms: closes,
        },
    )
    .map_err(window_error)?;
    match timing {
        Timing::WithinWindow => {}
        Timing::WaitingUntil(_) => return Ok(None),
        Timing::Expired | Timing::MissedWindow => {
            let phase = if timing == Timing::Expired {
                "expired"
            } else {
                "missed_window"
            };
            if timing == Timing::MissedWindow {
                crate::http_owner_conversations::context::decisions::store::cancel_link(tx, key)
                    .await?;
            }
            tx.execute("UPDATE workflow_schedule_occurrences SET phase=$3,lease_id=NULL,lease_until_ms=NULL,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2",&[&key.account_id,&occurrence_id,&phase]).await?;
            audit(
                tx,
                key.account_id,
                occurrence_id,
                Some(actor),
                "expire",
                phase,
                None,
            )
            .await?;
            permit.recheck().await?;
            return Ok(None);
        }
        Timing::OwnerReview(_) => return Err(ConversationError::Conflict),
    }
    let lease_id = Uuid::new_v4();
    let until = instant.saturating_add(30_000).min(expiry).min(closes);
    let row=tx.query_one("UPDATE workflow_schedule_occurrences SET phase='claimed',lease_id=$3,lease_until_ms=$4,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2 RETURNING *",&[&key.account_id,&occurrence_id,&lease_id,&until]).await?;
    audit(
        tx,
        key.account_id,
        occurrence_id,
        Some(actor),
        "claim",
        "claimed",
        None,
    )
    .await?;
    let result = Lease {
        occurrence: Occurrence::row(&row),
        id: lease_id,
        until_ms: until,
    };
    permit.recheck().await?;
    Ok(Some(result))
}

#[derive(Clone, Copy, Debug)]
pub enum Unavailable {
    Renderer,
    Phone,
}

/// Releasing a lease neither authorizes retries nor moves the window/deadline.
pub(crate) async fn defer_core<'connection>(
    permit: &mut impl ActionFence<'connection>,
    lease: &Lease,
    unavailable: Unavailable,
) -> Result<(), ConversationError> {
    permit.recheck().await?;
    let key = permit.key();
    let actor = permit.actor();
    let tx = permit.transaction();
    let instant = now(tx).await?;
    if instant >= lease.until_ms {
        return Err(ConversationError::Conflict);
    }
    let phase = match unavailable {
        Unavailable::Renderer => "waiting_renderer",
        Unavailable::Phone => "waiting_phone",
    };
    if tx.execute("UPDATE workflow_schedule_occurrences SET phase=$7,lease_id=NULL,lease_until_ms=NULL,retry_at_ms=$8,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2 AND action_id=$3 AND action_revision=$4 AND binding_digest=$5 AND phase='claimed' AND lease_id=$6 AND lease_until_ms>floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
        &[&key.account_id,&lease.occurrence.id,&key.action_id,&key.revision,&&key.binding_digest[..],&lease.id,&phase,&instant.saturating_add(5_000)]).await?!=1 {return Err(ConversationError::Conflict);}
    audit(
        tx,
        key.account_id,
        lease.occurrence.id,
        Some(actor),
        "defer",
        phase,
        None,
    )
    .await?;
    permit.recheck().await
}

/// The message must already have the exact explicit owner confirmation in
/// workflow_message_links. Keep this permit and transaction until commit;
/// inserting/linking the existing queue message belongs in that same transaction.
pub(crate) async fn begin_dispatch_core<'connection>(
    permit: &mut impl ActionFence<'connection>,
    lease: &Lease,
    message: Uuid,
) -> Result<Uuid, ConversationError> {
    permit.recheck().await?;
    let key = permit.key();
    let actor = permit.actor();
    let tx = permit.transaction();
    let series=tx.query_one("SELECT s.*,p.pacing_seconds FROM workflow_schedule_series s JOIN workflow_schedule_policies p ON (p.account_id,p.id)=(s.account_id,s.policy_id) WHERE s.account_id=$1 AND s.id=$2 FOR UPDATE OF s",&[&key.account_id,&lease.occurrence.series_id]).await?;
    let row = tx
        .query_one(
            "SELECT * FROM workflow_schedule_occurrences WHERE account_id=$1 AND id=$2 FOR UPDATE",
            &[&key.account_id, &lease.occurrence.id],
        )
        .await?;
    let instant = now(tx).await?;
    if row.get::<_, String>("phase") != "claimed"
        || row.get::<_, Option<Uuid>>("lease_id") != Some(lease.id)
        || row
            .get::<_, Option<i64>>("lease_until_ms")
            .is_none_or(|until| until <= instant)
        || row.get::<_, Uuid>("action_id") != key.action_id
        || row.get::<_, i64>("action_revision") != key.revision
        || row.get::<_, Vec<u8>>("binding_digest") != key.binding_digest
    {
        return Err(ConversationError::Conflict);
    }
    let routine: Uuid = series.get("routine_id");
    let pacing:i64=tx.query_one("SELECT COALESCE(max(pacing_until_ms),0)::bigint FROM workflow_schedule_series WHERE account_id=$1 AND routine_id=$2",&[&key.account_id,&routine]).await?.get(0);
    if time::timing(
        instant,
        row.get("not_before_ms"),
        row.get("expires_at_ms"),
        pacing,
        Resolution::Ready {
            opens_at_ms: row.get("opens_at_ms"),
            closes_at_ms: row.get("closes_at_ms"),
        },
    )
    .map_err(window_error)?
        != Timing::WithinWindow
    {
        return Err(ConversationError::Conflict);
    }
    let dispatch: Uuid = row.get("dispatch_id");
    // The decision transition and schedule update either both commit or both
    // roll back. No caller-supplied dispatch identity can be adopted.
    permit.mark_dispatching(message, dispatch).await?;
    let tx = permit.transaction();
    tx.execute("UPDATE workflow_schedule_occurrences SET phase='dispatching',message_id=$3,lease_id=NULL,lease_until_ms=NULL,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2",&[&key.account_id,&lease.occurrence.id,&message]).await?;
    let pacing_until = instant
        .checked_add(i64::from(series.get::<_, i32>("pacing_seconds")) * 1000)
        .ok_or(ConversationError::Invalid)?;
    tx.execute("UPDATE workflow_schedule_series SET pacing_until_ms=greatest(pacing_until_ms,$3) WHERE account_id=$1 AND id=$2",&[&key.account_id,&lease.occurrence.series_id,&pacing_until]).await?;
    audit(
        tx,
        key.account_id,
        lease.occurrence.id,
        Some(actor),
        "dispatch",
        "dispatching",
        None,
    )
    .await?;
    // Repeat timing after the last potentially blocking write.
    let final_now = now(tx).await?;
    if final_now >= row.get::<_, i64>("closes_at_ms")
        || final_now >= row.get::<_, i64>("expires_at_ms")
    {
        return Err(ConversationError::Conflict);
    }
    permit.recheck().await?;
    Ok(dispatch)
}

/// Cancels only an unsent occurrence. The existing delivery-store helper
/// serializes cancellation against grants and performs a reservation refund once.
pub(crate) async fn cancel_core<'connection>(
    permit: &mut impl ActionFence<'connection>,
    occurrence_id: Uuid,
) -> Result<(), ConversationError> {
    permit.recheck().await?;
    let key = permit.key();
    let actor = permit.actor();
    let tx = permit.transaction();
    let row = tx
        .query_one(
            "SELECT * FROM workflow_schedule_occurrences WHERE account_id=$1 AND id=$2 FOR UPDATE",
            &[&key.account_id, &occurrence_id],
        )
        .await?;
    if row.get::<_, Uuid>("action_id") != key.action_id
        || row.get::<_, i64>("action_revision") != key.revision
        || row.get::<_, Vec<u8>>("binding_digest") != key.binding_digest
    {
        return Err(ConversationError::Forbidden);
    }
    let phase: String = row.get("phase");
    if phase == "cancelled" {
        return permit.recheck().await;
    }
    if matches!(
        phase.as_str(),
        "dispatching" | "unknown" | "completed" | "failed" | "expired" | "missed_window"
    ) {
        return Err(ConversationError::Conflict);
    }
    crate::http_owner_conversations::context::decisions::store::cancel_link(tx, key).await?;
    tx.execute("UPDATE workflow_schedule_occurrences SET phase='cancelled',review_reason=NULL,lease_id=NULL,lease_until_ms=NULL,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2",&[&key.account_id,&occurrence_id]).await?;
    audit(
        tx,
        key.account_id,
        occurrence_id,
        Some(actor),
        "cancel",
        "cancelled",
        None,
    )
    .await?;
    permit.recheck().await
}

/// Clock-driven metadata expiration has no message creation or sending path.
/// Dispatch winners stay uncertain and are reconciled from real delivery state.
pub async fn expire_due(
    tx: &Transaction<'_>,
    account: Uuid,
    limit: u16,
) -> Result<u64, ConversationError> {
    if account.is_nil() || !(1..=100).contains(&limit) {
        return Err(ConversationError::Invalid);
    }
    // Negative projections follow account -> occurrence -> audit/FK locks,
    // avoiding inversion against an approved-action transaction.
    tx.query_opt("SELECT 1 FROM accounts WHERE id=$1 FOR UPDATE", &[&account])
        .await?
        .ok_or(ConversationError::NotFound)?;
    let rows=tx.query("SELECT id FROM workflow_schedule_occurrences WHERE account_id=$1 AND phase IN ('owner_review','waiting_window','waiting_renderer','waiting_phone','claimed') AND expires_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint ORDER BY expires_at_ms,id LIMIT $2 FOR UPDATE SKIP LOCKED",&[&account,&i64::from(limit)]).await?;
    let mut changed = 0;
    for row in rows {
        let id: Uuid = row.get(0);
        audit(tx, account, id, None, "expire", "expired", None).await?;
        changed+=tx.execute("UPDATE workflow_schedule_occurrences SET phase='expired',review_reason=NULL,lease_id=NULL,lease_until_ms=NULL,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2",&[&account,&id]).await?;
    }
    Ok(changed)
}

/// Projects authoritative delivery outcomes, never receipt-based approval.
/// A missing retained message remains unknown; it is never recreated or resent.
pub async fn reconcile(
    tx: &Transaction<'_>,
    account: Uuid,
    limit: u16,
) -> Result<u64, ConversationError> {
    if account.is_nil() || !(1..=100).contains(&limit) {
        return Err(ConversationError::Invalid);
    }
    // Negative projections follow account -> occurrence -> audit/FK locks,
    // avoiding inversion against an approved-action transaction.
    tx.query_opt("SELECT 1 FROM accounts WHERE id=$1 FOR UPDATE", &[&account])
        .await?
        .ok_or(ConversationError::NotFound)?;
    let rows=tx.query("SELECT o.id,o.phase,m.state,o.observed_message_state FROM workflow_schedule_occurrences o LEFT JOIN messages m ON (m.account_id,m.id)=(o.account_id,o.message_id) WHERE o.account_id=$1 AND o.phase IN ('dispatching','unknown') ORDER BY o.updated_at,o.id LIMIT $2 FOR UPDATE OF o SKIP LOCKED",&[&account,&i64::from(limit)]).await?;
    let mut changed = 0;
    for row in rows {
        let id: Uuid = row.get(0);
        let current: String = row.get(1);
        let state: Option<String> = row.get(2);
        let observed: Option<String> = row.get(3);
        let phase = super::state::reconcile_phase(&current, state.as_deref().unwrap_or("missing"))
            .ok_or(ConversationError::Conflict)?;
        if phase == current && observed == state {
            continue;
        }
        audit(tx, account, id, None, "reconcile", phase, None).await?;
        changed+=tx.execute("UPDATE workflow_schedule_occurrences SET phase=$3,observed_message_state=$4,updated_at=clock_timestamp() WHERE account_id=$1 AND id=$2",&[&account,&id,&phase,&state]).await?;
    }
    Ok(changed)
}

pub async fn schedule(
    permit: &mut LockedAction<'_, '_>,
    request: ScheduleRequest,
    policy: &WindowPolicy,
) -> Result<Occurrence, ConversationError> {
    schedule_core(permit, request, policy).await
}
pub async fn claim(
    permit: &mut LockedAction<'_, '_>,
    id: Uuid,
) -> Result<Option<Lease>, ConversationError> {
    claim_core(permit, id).await
}
pub async fn defer(
    permit: &mut LockedAction<'_, '_>,
    lease: &Lease,
    unavailable: Unavailable,
) -> Result<(), ConversationError> {
    defer_core(permit, lease, unavailable).await
}
pub async fn begin_dispatch(
    permit: &mut LockedAction<'_, '_>,
    lease: &Lease,
    message: Uuid,
) -> Result<Uuid, ConversationError> {
    begin_dispatch_core(permit, lease, message).await
}
pub async fn cancel(permit: &mut LockedAction<'_, '_>, id: Uuid) -> Result<(), ConversationError> {
    cancel_core(permit, id).await
}

async fn audit(
    tx: &Transaction<'_>,
    account: Uuid,
    occurrence: Uuid,
    actor: Option<Actor>,
    operation: &str,
    phase: &str,
    request: Option<(Uuid, &[u8])>,
) -> Result<(), ConversationError> {
    let id = Uuid::new_v4();
    let request_id = request.map(|r| r.0).unwrap_or(id);
    let fallback = Sha256::digest(
        [
            b"ZT/schedule-audit/v1\0".as_slice(),
            occurrence.as_bytes(),
            request_id.as_bytes(),
            operation.as_bytes(),
            phase.as_bytes(),
        ]
        .concat(),
    );
    let digest = request.map(|r| r.1).unwrap_or(&fallback);
    let (kind, actor_id) = actor
        .map(|a| {
            let (kind, id) = a.identity();
            (kind, Some(id))
        })
        .unwrap_or(("system", None));
    tx.execute("INSERT INTO workflow_schedule_audit(account_id,id,occurrence_id,request_id,request_digest,actor_kind,actor_id,operation,result) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        &[&account,&id,&occurrence,&request_id,&digest,&kind,&actor_id,&operation,&phase]).await?;
    Ok(())
}
