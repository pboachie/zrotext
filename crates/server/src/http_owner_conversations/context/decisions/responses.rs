// SPDX-License-Identifier: AGPL-3.0-only
use super::super::{
    ConversationError, SessionPrincipal, activation, authorize, load, lock_current, lock_owner,
    wire,
};
use super::{
    ActionKey,
    model::Phase,
    reply::{self, ReplyDisposition},
    store,
};
use serde::{Deserialize, Serialize};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Correlation {
    pub context_id: Uuid,
    pub context_revision: i64,
    pub event_id: Uuid,
    /// Explicit owner-selected exact request, never inferred from the peer.
    pub request_action: Option<ActionKey>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorrelationResult {
    pub event_id: Uuid,
    pub disposition: String,
    pub stopped_routines: i64,
    pub cancelled_messages: i64,
    pub irreversible_messages: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TakeoverResult {
    pub context_id: Uuid,
    pub stopped_routines: i64,
    pub cancelled_messages: i64,
    pub irreversible_messages: i64,
}

async fn replay<T: serde::de::DeserializeOwned>(
    tx: &Transaction<'_>,
    account: Uuid,
    request: Uuid,
    digest: &[u8],
) -> Result<Option<T>, ConversationError> {
    store::replay_bytes(tx, account, request, digest)
        .await?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| ConversationError::Conflict))
        .transpose()
}
async fn record<T: Serialize>(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    scope: (Uuid, Uuid),
    request: Uuid,
    operation: i16,
    digest: &[u8],
    result: &T,
) -> Result<(), ConversationError> {
    let account = owner.tenant.account_id();
    if tx
        .query_one(
            "SELECT count(*) FROM workflow_action_mutations WHERE account_id=$1",
            &[&account],
        )
        .await?
        .get::<_, i64>(0)
        >= 8192
    {
        return Err(ConversationError::Conflict);
    }
    let bytes = serde_json::to_vec(result).map_err(|_| ConversationError::Unavailable)?;
    tx.execute("INSERT INTO workflow_action_mutations(account_id,request_id,context_id,subject_id,operation,request_digest,result,actor_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
        &[&account,&request,&scope.0,&scope.1,&operation,&digest,&bytes,&owner.user_id]).await?;
    Ok(())
}

/// Caller already holds root/account/context, then fences routines/actions before jobs.
async fn stop(
    tx: &Transaction<'_>,
    account: Uuid,
    context: Uuid,
    routine: Option<Uuid>,
) -> Result<(i64, i64, i64), ConversationError> {
    let routines=tx.query("SELECT id FROM workflow_routines WHERE account_id=$1 AND context_id=$2 AND ($3::uuid IS NULL OR id=$3) ORDER BY id FOR UPDATE",&[&account,&context,&routine]).await?;
    if routines.len() > 256 {
        return Err(ConversationError::Conflict);
    }
    let stopped=tx.execute("UPDATE workflow_routines SET stopped_at=clock_timestamp() WHERE account_id=$1 AND context_id=$2 AND ($3::uuid IS NULL OR id=$3) AND stopped_at IS NULL",&[&account,&context,&routine]).await? as i64;
    let actions=tx.query("SELECT a.account_id,a.id,a.revision,a.binding_digest,a.record_version,a.phase,l.message_id FROM workflow_actions a LEFT JOIN workflow_message_links l ON (l.account_id,l.action_id,l.revision)=(a.account_id,a.id,a.revision) WHERE a.account_id=$1 AND a.context_id=$2 AND ($3::uuid IS NULL OR a.routine_id=$3) AND a.phase IN ('proposed','approved','invalidated','dispatching','unknown') ORDER BY a.id FOR UPDATE OF a",&[&account,&context,&routine]).await?;
    if actions.len() > 256 {
        return Err(ConversationError::Conflict);
    }
    let (mut cancelled, mut irreversible) = (0, 0);
    for row in actions {
        let current = store::state(&row)?;
        let message: Option<Uuid> = row.get(6);
        let cancelled_message = if let Some(id) = message {
            let ok = match zrotext_delivery_store::cancel_in_transaction(tx, account, id).await {
                Ok(cancelled) => cancelled,
                Err(zrotext_delivery_store::StoreError::InvalidTransition) => false,
                Err(_) => return Err(ConversationError::Unavailable),
            };
            if ok {
                cancelled += 1
            } else {
                irreversible += 1
            };
            ok
        } else {
            true
        };
        let phase = if cancelled_message && current.phase != Phase::Unknown {
            "cancelled"
        } else {
            "unknown"
        };
        tx.execute("UPDATE workflow_actions SET phase=$3,record_version=record_version+1,approved_by=CASE WHEN $3='cancelled' THEN NULL ELSE approved_by END,approved_at=CASE WHEN $3='cancelled' THEN NULL ELSE approved_at END WHERE account_id=$1 AND id=$2",
            &[&account,&current.key.action_id,&phase]).await?;
    }
    crate::encrypted_schedule::store::cancel_stopped(tx, account, context, routine).await?;
    Ok((stopped, cancelled, irreversible))
}

pub async fn takeover(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: Uuid,
    context: Uuid,
) -> Result<TakeoverResult, ConversationError> {
    let account = owner.tenant.account_id();
    let digest = store::request_digest(6, &context)?;
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, account).await?;
    lock_owner(&tx, owner).await?;
    let bytes = load(&tx, account, context, None).await?;
    let h = wire::parse(&bytes)?;
    authorize(&tx, owner, &mut authority, &h, true).await?;
    if let Some(result) = replay(&tx, account, request, &digest).await? {
        authorize(&tx, owner, &mut authority, &h, true).await?;
        drop(authority);
        tx.commit().await?;
        return Ok(result);
    }
    if tx.execute("INSERT INTO workflow_context_fences(account_id,context_id,stopped_at,actor_user_id) VALUES($1,$2,clock_timestamp(),$3) ON CONFLICT(account_id,context_id) DO UPDATE SET stopped_at=EXCLUDED.stopped_at,actor_user_id=EXCLUDED.actor_user_id WHERE workflow_context_fences.stopped_at IS NULL",&[&account,&context,&owner.user_id]).await?!=1 {return Err(ConversationError::Conflict);}
    let (stopped_routines, cancelled_messages, irreversible_messages) =
        stop(&tx, account, context, None).await?;
    let result = TakeoverResult {
        context_id: context,
        stopped_routines,
        cancelled_messages,
        irreversible_messages,
    };
    let encoded = serde_json::to_vec(&result).map_err(|_| ConversationError::Unavailable)?;
    tx.execute("UPDATE workflow_context_fences SET takeover_request_id=$3,takeover_digest=$4,takeover_result=$5 WHERE account_id=$1 AND context_id=$2",&[&account,&context,&request,&digest,&encoded]).await?;
    authorize(&tx, owner, &mut authority, &h, true).await?;
    drop(authority);
    tx.commit().await?;
    Ok(result)
}

async fn exception(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    h: &wire::Header,
    event: Uuid,
) -> Result<(), ConversationError> {
    let input = super::super::ExceptionInput {
        context_id: h.context,
        context_revision: h.revision,
        source_kind: 1,
        source_id: event,
        reason: 1,
    };
    let id = super::super::exception_id(h.account, input);
    let digest = input.digest(h.account)?;
    if let Some(row) = tx
        .query_opt(
            "SELECT request_digest FROM workflow_exceptions WHERE account_id=$1 AND id=$2",
            &[&h.account, &id],
        )
        .await?
    {
        if row.get::<_, Vec<u8>>(0) != digest {
            return Err(ConversationError::Conflict);
        }
        return Ok(());
    }
    if tx
        .query_one(
            "SELECT count(*) FROM workflow_exceptions WHERE account_id=$1 AND context_id=$2",
            &[&h.account, &h.context],
        )
        .await?
        .get::<_, i64>(0)
        >= 32
    {
        return Err(ConversationError::Conflict);
    }
    tx.execute("INSERT INTO workflow_exceptions(account_id,context_id,id,context_revision,source_kind,source_id,reason,request_digest) VALUES($1,$2,$3,$4,1,$5,1,$6)",&[&h.account,&h.context,&id,&h.revision,&event,&digest]).await?;
    super::super::audit(tx, owner, (h.context, id), 1, id, 2, &digest).await
}

pub async fn correlate_reply(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: Uuid,
    input: Correlation,
) -> Result<CorrelationResult, ConversationError> {
    let account = owner.tenant.account_id();
    let digest = store::request_digest(5, &input)?;
    if input.context_id.is_nil() || input.event_id.is_nil() || input.context_revision < 1 {
        return Err(ConversationError::Invalid);
    }
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, account).await?;
    lock_owner(&tx, owner).await?;
    let bytes = load(&tx, account, input.context_id, Some(input.context_revision)).await?;
    let h = wire::parse(&bytes)?;
    authorize(&tx, owner, &mut authority, &h, true).await?;
    // Historical replay restores metadata only, under current owner/context authority.
    if let Some(result) = replay(&tx, account, request, &digest).await? {
        authorize(&tx, owner, &mut authority, &h, true).await?;
        drop(authority);
        tx.commit().await?;
        return Ok(result);
    }
    let event=tx.query_opt("SELECT p.trust_generation,p.manifest_version,p.manifest_digest,p.verified_manifest,p.accepted_at_ms,e.envelope FROM conversation_inbound_provenance p JOIN sealed_inbound_events e ON (e.account_id,e.id)=(p.account_id,p.event_id) WHERE p.account_id=$1 AND p.event_id=$2 AND p.interval_id=$3 AND e.device_id=$4 AND e.line_id=$5 AND e.binding_generation=$6 FOR SHARE OF p,e",
        &[&account,&input.event_id,&h.interval,&h.device,&h.line,&h.binding_generation]).await?.ok_or(ConversationError::NotFound)?;
    let interval = activation::load(&tx, account, h.interval).await?;
    let source: Vec<u8> = event
        .get::<_, Option<Vec<u8>>>(5)
        .ok_or(ConversationError::NotFound)?;
    let claims =
        crate::sealed_envelope::parse(&source, crate::sealed_envelope::Profile::Draft02Candidate)
            .map_err(|_| ConversationError::Forbidden)?;
    let readers = activation::readers(&interval.statement);
    let wanted = activation::wanted(&interval.statement, input.event_id, &readers);
    let snapshot = crate::sealed_manifest_store::outbound::ManifestSnapshot {
        generation: event.get(0),
        version: event.get(1),
        digest: event
            .get::<_, Vec<u8>>(2)
            .try_into()
            .map_err(|_| ConversationError::Forbidden)?,
        bytes: event.get(3),
        accepted_ms: event.get(4),
    };
    authority
        .verify_history(&wanted, &snapshot, &source)
        .await?;
    if let Some(row)=tx.query_opt("SELECT request_digest,request_id FROM workflow_reply_correlations WHERE account_id=$1 AND event_id=$2",&[&account,&input.event_id]).await? {
        if row.get::<_,Vec<u8>>(0)!=digest{return Err(ConversationError::Conflict);}
        let original:Uuid=row.get(1);let result=replay(&tx,account,original,&digest).await?.ok_or(ConversationError::Unavailable)?;
        authorize(&tx,owner,&mut authority,&h,true).await?;drop(authority);tx.commit().await?;return Ok(result);
    }
    let mut disposition = ReplyDisposition::Ambiguous;
    let mut stop_routine = None;
    if let Some(key) = input.request_action {
        if key.account_id != account {
            return Err(ConversationError::NotFound);
        }
        let d = store::descriptor(&tx, key).await?;
        if d.identities()?.content != h.context {
            return Err(ConversationError::NotFound);
        }
        tx.query_opt("SELECT 1 FROM workflow_context_fences WHERE account_id=$1 AND context_id=$2 FOR UPDATE",&[&account,&h.context]).await?.ok_or(ConversationError::NotFound)?;
        let stopped=tx.query_opt("SELECT stopped_at IS NOT NULL FROM workflow_routines WHERE account_id=$1 AND id=$2 AND context_id=$3 FOR UPDATE",&[&account,&d.identities()?.routine,&h.context]).await?.ok_or(ConversationError::NotFound)?.get::<_,bool>(0);
        let current = store::head(&tx, account, key.action_id).await?;
        if current.key != key {
            return Err(ConversationError::Conflict);
        }
        let issued=tx.query_opt("SELECT floor(extract(epoch FROM j.grant_issued_at)*1000)::bigint FROM workflow_message_links l JOIN dispatch_jobs j ON (j.account_id,j.message_id)=(l.account_id,l.message_id) WHERE l.account_id=$1 AND l.action_id=$2 AND l.revision=$3",&[&account,&key.action_id,&key.revision]).await?.and_then(|r|r.get::<_,Option<i64>>(0));
        disposition = reply::disposition(
            current.phase,
            d.not_before * 1000,
            d.expires_at_ms()?,
            issued,
            claims.observed_ms as i64,
            activation::now(&tx).await?,
        );
        if disposition == ReplyDisposition::Qualifying && stopped {
            disposition = ReplyDisposition::Ambiguous;
        }
        if disposition == ReplyDisposition::Qualifying {
            stop_routine = Some(d.identities()?.routine);
        }
    }
    let counts = if let Some(routine) = stop_routine {
        stop(&tx, account, h.context, Some(routine)).await?
    } else {
        (0, 0, 0)
    };
    let label = match disposition {
        ReplyDisposition::Qualifying => "qualifying",
        ReplyDisposition::Ambiguous => "ambiguous",
        ReplyDisposition::Late => "late",
        ReplyDisposition::Unrelated => "unrelated",
    };
    if matches!(
        disposition,
        ReplyDisposition::Ambiguous | ReplyDisposition::Late
    ) {
        exception(&tx, owner, &h, input.event_id).await?;
    }
    let key = input.request_action;
    let action = key.map(|k| k.action_id);
    let revision = key.map(|k| k.revision);
    let binding = key.map(|k| k.binding_digest.to_vec());
    let result = CorrelationResult {
        event_id: input.event_id,
        disposition: label.into(),
        stopped_routines: counts.0,
        cancelled_messages: counts.1,
        irreversible_messages: counts.2,
    };
    let encoded = serde_json::to_vec(&result).map_err(|_| ConversationError::Unavailable)?;
    tx.execute("INSERT INTO workflow_reply_correlations(account_id,event_id,live_event_id,context_id,action_id,action_revision,binding_digest,disposition,request_digest,request_id,actor_user_id,safety_routine_id,result) VALUES($1,$2,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        &[&account,&input.event_id,&h.context,&action,&revision,&binding,&label,&digest,&request,&owner.user_id,&stop_routine,&encoded]).await?;
    // One safety record per immutable routine cannot consume discretionary capacity.
    if stop_routine.is_none() {
        record(
            &tx,
            owner,
            (h.context, input.event_id),
            request,
            5,
            &digest,
            &result,
        )
        .await?;
    }
    authorize(&tx, owner, &mut authority, &h, true).await?;
    drop(authority);
    tx.commit().await?;
    Ok(result)
}
