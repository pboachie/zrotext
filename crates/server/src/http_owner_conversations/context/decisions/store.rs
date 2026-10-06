// SPDX-License-Identifier: AGPL-3.0-only
use super::super::{ConversationError, SessionPrincipal, activation, wire};
use super::{
    ActionKey, Descriptor,
    fence::{checked_descriptor, live_routine, recheck_descriptor},
    model::{self, Decision, Phase},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Row, Transaction};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionState {
    pub key: ActionKey,
    pub record_version: i64,
    pub phase: Phase,
}
pub(crate) fn state(row: &Row) -> Result<ActionState, ConversationError> {
    Ok(ActionState {
        key: ActionKey {
            account_id: row.get(0),
            action_id: row.get(1),
            revision: row.get(2),
            binding_digest: row
                .get::<_, Vec<u8>>(3)
                .try_into()
                .map_err(|_| ConversationError::Unavailable)?,
        },
        record_version: row.get(4),
        phase: Phase::parse(&row.get::<_, String>(5))?,
    })
}
pub(crate) async fn head(
    tx: &Transaction<'_>,
    account: Uuid,
    action: Uuid,
) -> Result<ActionState, ConversationError> {
    let row=tx.query_opt("SELECT account_id,id,revision,binding_digest,record_version,phase FROM workflow_actions WHERE account_id=$1 AND id=$2 FOR UPDATE",&[&account,&action]).await?.ok_or(ConversationError::NotFound)?;
    state(&row)
}
pub(crate) async fn descriptor(
    tx: &Transaction<'_>,
    key: ActionKey,
) -> Result<Descriptor, ConversationError> {
    profile(tx, key).await?.phone()
}
pub(crate) async fn profile(
    tx: &Transaction<'_>,
    key: ActionKey,
) -> Result<super::action_profile::StoredProfile, ConversationError> {
    key.validate()?;
    let row=tx.query_opt("SELECT descriptor FROM workflow_action_versions WHERE account_id=$1 AND action_id=$2 AND revision=$3 AND binding_digest=$4",
        &[&key.account_id,&key.action_id,&key.revision,&&key.binding_digest[..]]).await?.ok_or(ConversationError::NotFound)?;
    super::action_profile::StoredProfile::parse(&row.get::<_, Vec<u8>>(0), key)
}
pub(crate) fn request_digest<T: Serialize>(
    operation: i16,
    input: &T,
) -> Result<Vec<u8>, ConversationError> {
    let mut hash = Sha256::new();
    hash.update(b"ZT/workflow-mutation/v1\0");
    hash.update(operation.to_be_bytes());
    hash.update(serde_json::to_vec(input).map_err(|_| ConversationError::Invalid)?);
    Ok(hash.finalize().to_vec())
}
pub(crate) async fn replay_bytes(
    tx: &Transaction<'_>,
    account: Uuid,
    request: Uuid,
    digest: &[u8],
) -> Result<Option<Vec<u8>>, ConversationError> {
    if request.is_nil() {
        return Err(ConversationError::Invalid);
    }
    let rows=tx.query("SELECT request_digest,result FROM workflow_action_mutations WHERE account_id=$1 AND request_id=$2 UNION ALL SELECT takeover_digest,takeover_result FROM workflow_context_fences WHERE account_id=$1 AND takeover_request_id=$2 UNION ALL SELECT request_digest,result FROM workflow_reply_correlations WHERE account_id=$1 AND request_id=$2 AND safety_routine_id IS NOT NULL",&[&account,&request]).await?;
    if rows.len() > 1 {
        return Err(ConversationError::Conflict);
    }
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    if row.get::<_, Vec<u8>>(0) != digest {
        return Err(ConversationError::Conflict);
    }
    Ok(Some(row.get(1)))
}
pub(crate) async fn replay(
    tx: &Transaction<'_>,
    account: Uuid,
    request: Uuid,
    digest: &[u8],
) -> Result<Option<ActionState>, ConversationError> {
    replay_bytes(tx, account, request, digest)
        .await?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| ConversationError::Conflict))
        .transpose()
}
pub(crate) async fn record(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    context: Uuid,
    request: Uuid,
    op: i16,
    digest: &[u8],
    result: &ActionState,
) -> Result<(), ConversationError> {
    record_actor(
        tx,
        (
            owner.tenant.account_id(),
            super::proposal::Actor::Owner(owner.user_id),
        ),
        context,
        request,
        op,
        digest,
        result,
    )
    .await
}
async fn record_actor(
    tx: &Transaction<'_>,
    identity: (Uuid, super::proposal::Actor),
    context: Uuid,
    request: Uuid,
    op: i16,
    digest: &[u8],
    result: &ActionState,
) -> Result<(), ConversationError> {
    record_result(
        tx,
        identity,
        context,
        (request, op),
        result.key.action_id,
        digest,
        result,
    )
    .await
}
pub(crate) async fn record_result<T: Serialize>(
    tx: &Transaction<'_>,
    identity: (Uuid, super::proposal::Actor),
    context: Uuid,
    request: (Uuid, i16),
    subject: Uuid,
    digest: &[u8],
    result: &T,
) -> Result<(), ConversationError> {
    let (request, op) = request;
    let (account, actor) = identity;
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM workflow_action_mutations WHERE account_id=$1",
            &[&account],
        )
        .await?
        .get(0);
    if count >= 8192 {
        return Err(ConversationError::Conflict);
    }
    let bytes = serde_json::to_vec(result).map_err(|_| ConversationError::Unavailable)?;
    match actor {
        super::proposal::Actor::Owner(user) => {
            tx.execute("INSERT INTO workflow_action_mutations(account_id,request_id,context_id,subject_id,operation,request_digest,result,actor_user_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", &[&account,&request,&context,&subject,&op,&digest,&bytes,&user]).await?;
        }
        super::proposal::Actor::Integration(grant) => {
            tx.execute("INSERT INTO workflow_action_mutations(account_id,request_id,context_id,subject_id,operation,request_digest,result,actor_kind,actor_grant_id) VALUES($1,$2,$3,$4,$5,$6,$7,'integration',$8)", &[&account,&request,&context,&subject,&op,&digest,&bytes,&grant]).await?;
        }
    }
    Ok(())
}
/// The shared transition consumes an existing owner-confirmed message only.
/// Callers retain their private authority fence before and after this write.
pub(crate) async fn dispatch_transition(
    tx: &Transaction<'_>,
    descriptor: &Descriptor,
    context: Uuid,
    actor: super::proposal::Actor,
    message: Uuid,
    dispatch: Uuid,
) -> Result<(), ConversationError> {
    let key = descriptor.key()?;
    if activation::now(tx).await?
        < descriptor
            .not_before
            .checked_mul(1000)
            .ok_or(ConversationError::Invalid)?
    {
        return Err(ConversationError::Conflict);
    }
    tx.query_opt("SELECT 1 FROM workflow_message_links l JOIN messages m ON (m.account_id,m.id)=(l.account_id,l.live_message_id) WHERE l.account_id=$1 AND l.action_id=$2 AND l.revision=$3 AND l.binding_digest=$4 AND l.message_id=$5 AND l.dispatch_id=$6 AND m.workflow_action_id=$2 AND m.state IN ('queued','claimed') AND m.transport_payload IS NOT NULL AND sha256(m.transport_payload)=l.message_digest AND NOT EXISTS(SELECT 1 FROM message_attempts a WHERE a.account_id=m.account_id AND a.message_id=m.id) FOR UPDATE OF m",
        &[&key.account_id,&key.action_id,&key.revision,&&key.binding_digest[..],&message,&dispatch]).await?.ok_or(ConversationError::Forbidden)?;
    if let super::proposal::Actor::Integration(grant) = actor
        && tx.execute("UPDATE messages SET workflow_executor_grant=$3 WHERE account_id=$1 AND id=$2 AND (workflow_executor_grant IS NULL OR workflow_executor_grant=$3)", &[&key.account_id,&message,&grant]).await? != 1 {
        return Err(ConversationError::Forbidden);
    }
    if tx.execute("UPDATE workflow_actions SET phase='dispatching',record_version=record_version+1 WHERE account_id=$1 AND id=$2 AND revision=$3 AND binding_digest=$4 AND phase='approved'", &[&key.account_id,&key.action_id,&key.revision,&&key.binding_digest[..]]).await? != 1 {
        return Err(ConversationError::Conflict);
    }
    let state = head(tx, key.account_id, key.action_id).await?;
    let digest = match actor {
        super::proposal::Actor::Owner(_) => request_digest(7, &(key, message, dispatch))?,
        super::proposal::Actor::Integration(grant) => {
            request_digest(7, &(grant, key, message, dispatch))?
        }
    };
    record_actor(
        tx,
        (key.account_id, actor),
        context,
        dispatch,
        7,
        &digest,
        &state,
    )
    .await
}
pub(crate) async fn version(
    tx: &Transaction<'_>,
    d: &Descriptor,
    h: &wire::Header,
) -> Result<(), ConversationError> {
    let ids = d.identities()?;
    let key = d.key()?;
    let bytes = d.canonical()?;
    let not_before = d.not_before * 1000;
    let expires = d.expires_at_ms()?;
    let interval = activation::load(tx, h.account, h.interval).await?;
    let readers = activation::readers(&interval.statement);
    let wanted = activation::wanted(&interval.statement, h.context, &readers);
    let mut authority = super::super::lock_current(tx, h.account).await?;
    let deadline = authority
        .admission_deadline(&wanted)
        .await?
        .min(h.expires_ms);
    drop(authority);
    tx.execute("INSERT INTO workflow_action_versions(account_id,action_id,revision,binding_digest,descriptor,context_id,content_version,routine_id,authority_generation,not_before_ms,expires_at_ms,context_trust_generation,context_manifest_version,context_manifest_digest,context_authority_deadline_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        &[&key.account_id,&key.action_id,&key.revision,&&key.binding_digest[..],&bytes,&h.context,&d.content_version,&ids.routine,&d.authority_generation,&not_before,&expires,&h.trust_generation,&h.manifest_version,&&h.manifest_digest[..],&deadline]).await?;
    Ok(())
}
fn cas(current: &ActionState, key: ActionKey, expected: i64) -> Result<(), ConversationError> {
    if current.key != key || current.record_version != expected {
        return Err(ConversationError::Conflict);
    }
    Ok(())
}
pub async fn register(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: Uuid,
    d: Descriptor,
) -> Result<ActionState, ConversationError> {
    let tx = client.transaction().await?;
    let mut permit = super::proposal::OwnerProposal::checked(&tx, owner, d).await?;
    let result = register_core(&mut permit, request).await?;
    drop(permit);
    tx.commit().await?;
    Ok(result)
}
pub(crate) async fn register_core<'connection>(
    permit: &mut impl super::proposal::ProposalFence<'connection>,
    request: Uuid,
) -> Result<ActionState, ConversationError> {
    let d = permit.descriptor().clone();
    let h = permit.header().clone();
    if d.revision != 1 {
        return Err(ConversationError::Invalid);
    }
    let key = d.key()?;
    let ids = d.identities()?;
    let actor = permit.actor();
    let digest = match actor {
        super::proposal::Actor::Owner(_) => request_digest(1, &d)?,
        super::proposal::Actor::Integration(grant) => request_digest(1, &(grant, &d))?,
    };
    permit.recheck().await?;
    let tx = permit.transaction();
    if let Some(result) = replay(tx, key.account_id, request, &digest).await? {
        live_routine(tx, &d, &h).await?;
        permit.recheck().await?;
        return Ok(result);
    }
    if activation::now(tx).await? >= d.expires_at_ms()? {
        return Err(ConversationError::Forbidden);
    }
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM workflow_actions WHERE account_id=$1",
            &[&key.account_id],
        )
        .await?
        .get(0);
    if count >= 1000 {
        return Err(ConversationError::Conflict);
    }
    if tx
        .query_one(
            "SELECT count(*) FROM workflow_actions WHERE account_id=$1 AND context_id=$2",
            &[&key.account_id, &h.context],
        )
        .await?
        .get::<_, i64>(0)
        >= 256
    {
        return Err(ConversationError::Conflict);
    }
    tx.execute("INSERT INTO workflow_context_fences(account_id,context_id) VALUES($1,$2) ON CONFLICT DO NOTHING",&[&key.account_id,&h.context]).await?;
    tx.execute("INSERT INTO workflow_routines(account_id,id,context_id,generation) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",&[&key.account_id,&ids.routine,&h.context,&d.authority_generation]).await?;
    live_routine(tx, &d, &h).await?;
    let result = ActionState {
        key,
        record_version: 1,
        phase: Phase::Proposed,
    };
    match actor {
        super::proposal::Actor::Owner(_) => {
            tx.execute("INSERT INTO workflow_actions(account_id,id,context_id,routine_id,revision,binding_digest,record_version,phase) VALUES($1,$2,$3,$4,1,$5,1,'proposed')", &[&key.account_id,&key.action_id,&h.context,&ids.routine,&&key.binding_digest[..]]).await?;
        }
        super::proposal::Actor::Integration(grant) => {
            tx.execute("INSERT INTO workflow_actions(account_id,id,context_id,routine_id,revision,binding_digest,record_version,phase,integration_origin_grant) VALUES($1,$2,$3,$4,1,$5,1,'proposed',$6)", &[&key.account_id,&key.action_id,&h.context,&ids.routine,&&key.binding_digest[..],&grant]).await?;
        }
    }
    version(tx, &d, &h).await?;
    record_actor(
        tx,
        (key.account_id, actor),
        h.context,
        request,
        1,
        &digest,
        &result,
    )
    .await?;
    permit.recheck().await?;
    Ok(result)
}
pub async fn read(
    client: &mut Client,
    owner: &SessionPrincipal,
    key: ActionKey,
) -> Result<ActionState, ConversationError> {
    if key.account_id != owner.tenant.account_id() {
        return Err(ConversationError::NotFound);
    }
    let tx = client.transaction().await?;
    let d = match profile(&tx, key).await? {
        super::action_profile::StoredProfile::Provider(d) => {
            let mut permit = super::proposal::ProviderProposal::checked(&tx, owner, d).await?;
            let result = head(&tx, key.account_id, key.action_id).await?;
            permit.recheck().await?;
            drop(permit);
            tx.commit().await?;
            return Ok(result);
        }
        super::action_profile::StoredProfile::Phone(d) => d,
    };
    let (mut authority, h) = checked_descriptor(&tx, owner, &d).await?;
    let result = head(&tx, key.account_id, key.action_id).await?;
    recheck_descriptor(&tx, owner, &mut authority, &h, &d).await?;
    drop(authority);
    tx.commit().await?;
    Ok(result)
}
pub async fn decide(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: Uuid,
    expected: i64,
    key: ActionKey,
    decision: Decision,
) -> Result<ActionState, ConversationError> {
    if key.account_id != owner.tenant.account_id() {
        return Err(ConversationError::NotFound);
    }
    let digest = request_digest(2, &(key, expected, decision))?;
    let tx = client.transaction().await?;
    let d = match profile(&tx, key).await? {
        super::action_profile::StoredProfile::Provider(d) => {
            if decision == Decision::Approve {
                let mut permit = super::proposal::ProviderProposal::checked(&tx, owner, d).await?;
                permit.recheck().await?;
                return Err(ConversationError::Unavailable);
            }
            let result = cancel_provider(&tx, owner, request, expected, key, d).await?;
            tx.commit().await?;
            return Ok(result);
        }
        super::action_profile::StoredProfile::Phone(d) => d,
    };
    let (mut authority, h) = checked_descriptor(&tx, owner, &d).await?;
    if let Some(result) = replay(&tx, key.account_id, request, &digest).await? {
        recheck_descriptor(&tx, owner, &mut authority, &h, &d).await?;
        drop(authority);
        tx.commit().await?;
        return Ok(result);
    }
    live_routine(&tx, &d, &h).await?;
    let mut result = head(&tx, key.account_id, key.action_id).await?;
    cas(&result, key, expected)?;
    if activation::now(&tx).await? >= d.expires_at_ms()? {
        return Err(ConversationError::Forbidden);
    }
    result.phase = model::decide(result.phase, decision)?;
    result.record_version += 1;
    if decision == Decision::Cancel {
        cancel_link(&tx, key).await?;
    }
    let approver = (decision == Decision::Approve).then_some(owner.user_id);
    tx.execute("UPDATE workflow_actions SET phase=$3,record_version=$4,approved_by=$5,approved_at=CASE WHEN $5::uuid IS NULL THEN NULL ELSE clock_timestamp() END WHERE account_id=$1 AND id=$2",
        &[&key.account_id,&key.action_id,&result.phase.as_str(),&result.record_version,&approver]).await?;
    record(&tx, owner, h.context, request, 2, &digest, &result).await?;
    recheck_descriptor(&tx, owner, &mut authority, &h, &d).await?;
    drop(authority);
    tx.commit().await?;
    Ok(result)
}
pub(crate) async fn cancel_link(
    tx: &Transaction<'_>,
    key: ActionKey,
) -> Result<(), ConversationError> {
    if let Some(row)=tx.query_opt("SELECT message_id FROM workflow_message_links WHERE account_id=$1 AND action_id=$2 AND revision=$3",&[&key.account_id,&key.action_id,&key.revision]).await? {
        let message:Uuid=row.get(0);
        if !zrotext_delivery_store::cancel_in_transaction(tx,key.account_id,message).await.map_err(|_|ConversationError::Unavailable)? {
            return Err(ConversationError::Conflict);
        }
    }
    Ok(())
}
pub async fn edit(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: Uuid,
    expected: i64,
    previous: ActionKey,
    next: Descriptor,
) -> Result<ActionState, ConversationError> {
    if previous.account_id != owner.tenant.account_id() {
        return Err(ConversationError::NotFound);
    }
    let digest = request_digest(3, &(previous, expected, &next))?;
    let tx = client.transaction().await?;
    let old = descriptor(&tx, previous).await?;
    let (mut authority, h) = checked_descriptor(&tx, owner, &next).await?;
    if let Some(result) = replay(&tx, previous.account_id, request, &digest).await? {
        recheck_descriptor(&tx, owner, &mut authority, &h, &next).await?;
        drop(authority);
        tx.commit().await?;
        return Ok(result);
    }
    live_routine(&tx, &next, &h).await?;
    let current = head(&tx, previous.account_id, previous.action_id).await?;
    cas(&current, previous, expected)?;
    model::edit(&old, &next, current.phase)?;
    cancel_link(&tx, previous).await?;
    let ids = next.identities()?;
    let result = ActionState {
        key: next.key()?,
        record_version: current.record_version + 1,
        phase: Phase::Invalidated,
    };
    tx.execute("UPDATE workflow_actions SET context_id=$3,routine_id=$4,revision=$5,binding_digest=$6,record_version=$7,phase='invalidated',approved_by=NULL,approved_at=NULL WHERE account_id=$1 AND id=$2",
        &[&result.key.account_id,&result.key.action_id,&h.context,&ids.routine,&result.key.revision,&&result.key.binding_digest[..],&result.record_version]).await?;
    version(&tx, &next, &h).await?;
    record(&tx, owner, h.context, request, 3, &digest, &result).await?;
    recheck_descriptor(&tx, owner, &mut authority, &h, &next).await?;
    drop(authority);
    tx.commit().await?;
    Ok(result)
}

/// This separate live-owner confirmation binds the exact rendered ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderedBinding {
    pub message_id: Uuid,
    pub dispatch_id: Uuid,
    pub message_digest: String,
}
pub async fn bind_message(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: Uuid,
    expected: i64,
    key: ActionKey,
    binding: RenderedBinding,
) -> Result<ActionState, ConversationError> {
    if key.account_id != owner.tenant.account_id() {
        return Err(ConversationError::NotFound);
    }
    let message_digest = super::descriptor::decode_digest(&binding.message_digest)?;
    let digest = request_digest(4, &(key, expected, &binding))?;
    let tx = client.transaction().await?;
    let d = descriptor(&tx, key).await?;
    let (mut authority, h) = checked_descriptor(&tx, owner, &d).await?;
    if let Some(result) = replay(&tx, key.account_id, request, &digest).await? {
        recheck_descriptor(&tx, owner, &mut authority, &h, &d).await?;
        drop(authority);
        tx.commit().await?;
        return Ok(result);
    }
    drop(authority);
    let mut permit = super::lock_approved(&tx, owner, key).await?;
    let mut result = head(permit.transaction(), key.account_id, key.action_id).await?;
    cas(&result, key, expected)?;
    permit
        .bind_message(binding.message_id, binding.dispatch_id, message_digest)
        .await?;
    result.record_version += 1;
    tx.execute(
        "UPDATE workflow_actions SET record_version=$3 WHERE account_id=$1 AND id=$2",
        &[&key.account_id, &key.action_id, &result.record_version],
    )
    .await?;
    record(&tx, owner, h.context, request, 4, &digest, &result).await?;
    permit.recheck().await?;
    drop(permit);
    tx.commit().await?;
    Ok(result)
}

/// Separate owner-specific replay namespace; never changes legacy request bytes.
pub(crate) fn provider_request_digest<T: Serialize>(
    operation: i16,
    owner: Uuid,
    request: Uuid,
    input: &T,
) -> Result<Vec<u8>, ConversationError> {
    if owner.is_nil() || request.is_nil() {
        return Err(ConversationError::Invalid);
    }
    let mut hash = Sha256::new();
    hash.update(b"ZT/provider-proposal-history/v1\0");
    hash.update(operation.to_be_bytes());
    hash.update(
        serde_json::to_vec(&(owner, request, input)).map_err(|_| ConversationError::Invalid)?,
    );
    Ok(hash.finalize().to_vec())
}
async fn provider_version(
    tx: &Transaction<'_>,
    d: &super::action_profile::ProviderAction,
    h: &wire::Header,
) -> Result<(), ConversationError> {
    let key = d.key()?;
    let c = d.common();
    let routine = super::descriptor::identifier(&c.routine_id)?;
    let bytes = d.canonical();
    let not_before = c
        .not_before
        .checked_mul(1000)
        .ok_or(ConversationError::Invalid)?;
    let expires = d.expires_ms()?;
    let interval = activation::load(tx, h.account, h.interval).await?;
    let readers = activation::readers(&interval.statement);
    let wanted = activation::wanted(&interval.statement, h.context, &readers);
    let mut authority = super::super::lock_current(tx, h.account).await?;
    let deadline = authority
        .admission_deadline(&wanted)
        .await?
        .min(h.expires_ms);
    drop(authority);
    tx.execute("INSERT INTO workflow_action_versions(account_id,action_id,revision,binding_digest,descriptor,context_id,content_version,routine_id,authority_generation,not_before_ms,expires_at_ms,context_trust_generation,context_manifest_version,context_manifest_digest,context_authority_deadline_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
        &[&key.account_id,&key.action_id,&key.revision,&&key.binding_digest[..],&bytes,&h.context,&c.content_version,&routine,&c.authority_generation,&not_before,&expires,&h.trust_generation,&h.manifest_version,&&h.manifest_digest[..],&deadline]).await?;
    Ok(())
}
pub(crate) async fn register_provider(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: Uuid,
    d: super::action_profile::ProviderAction,
) -> Result<ActionState, ConversationError> {
    if d.common().revision != 1 {
        return Err(ConversationError::Invalid);
    }
    let key = d.key()?;
    let routine = super::descriptor::identifier(&d.common().routine_id)?;
    let digest = provider_request_digest(1, owner.user_id, request, &d.canonical())?;
    let tx = client.transaction().await?;
    let mut permit = super::proposal::ProviderProposal::checked(&tx, owner, d).await?;
    permit.recheck().await?;
    if let Some(result) = replay(&tx, key.account_id, request, &digest).await? {
        super::fence::live_provider_routine(&tx, &permit.descriptor, &permit.header).await?;
        permit.recheck().await?;
        drop(permit);
        tx.commit().await?;
        return Ok(result);
    }
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM workflow_actions WHERE account_id=$1",
            &[&key.account_id],
        )
        .await?
        .get(0);
    let scoped: i64 = tx
        .query_one(
            "SELECT count(*) FROM workflow_actions WHERE account_id=$1 AND context_id=$2",
            &[&key.account_id, &permit.header.context],
        )
        .await?
        .get(0);
    if count >= 1000 || scoped >= 256 {
        return Err(ConversationError::Conflict);
    }
    tx.execute("INSERT INTO workflow_context_fences(account_id,context_id) VALUES($1,$2) ON CONFLICT DO NOTHING", &[&key.account_id,&permit.header.context]).await?;
    tx.execute("INSERT INTO workflow_routines(account_id,id,context_id,generation) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING", &[&key.account_id,&routine,&permit.header.context,&permit.descriptor.common().authority_generation]).await?;
    super::fence::live_provider_routine(&tx, &permit.descriptor, &permit.header).await?;
    tx.execute("INSERT INTO workflow_actions(account_id,id,context_id,routine_id,revision,binding_digest,record_version,phase) VALUES($1,$2,$3,$4,1,$5,1,'proposed')", &[&key.account_id,&key.action_id,&permit.header.context,&routine,&&key.binding_digest[..]]).await?;
    provider_version(&tx, &permit.descriptor, &permit.header).await?;
    let result = ActionState {
        key,
        record_version: 1,
        phase: Phase::Proposed,
    };
    record(
        &tx,
        owner,
        permit.header.context,
        request,
        1,
        &digest,
        &result,
    )
    .await?;
    permit.recheck().await?;
    drop(permit);
    tx.commit().await?;
    Ok(result)
}
async fn cancel_provider(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    request: Uuid,
    expected: i64,
    key: ActionKey,
    d: super::action_profile::ProviderAction,
) -> Result<ActionState, ConversationError> {
    let digest = provider_request_digest(
        2,
        owner.user_id,
        request,
        &(key, expected, Decision::Cancel),
    )?;
    let mut permit = super::proposal::ProviderProposal::checked(tx, owner, d).await?;
    if let Some(result) = replay(tx, key.account_id, request, &digest).await? {
        permit.recheck().await?;
        return Ok(result);
    }
    super::fence::live_provider_routine(tx, &permit.descriptor, &permit.header).await?;
    let mut result = head(tx, key.account_id, key.action_id).await?;
    cas(&result, key, expected)?;
    result.phase = model::decide(result.phase, Decision::Cancel)?;
    result.record_version = result
        .record_version
        .checked_add(1)
        .ok_or(ConversationError::Conflict)?;
    no_provider_link(tx, key).await?;
    tx.execute("UPDATE workflow_actions SET phase='cancelled',record_version=$3,approved_by=NULL,approved_at=NULL WHERE account_id=$1 AND id=$2", &[&key.account_id,&key.action_id,&result.record_version]).await?;
    record(
        tx,
        owner,
        permit.header.context,
        request,
        2,
        &digest,
        &result,
    )
    .await?;
    permit.recheck().await?;
    Ok(result)
}
async fn no_provider_link(tx: &Transaction<'_>, key: ActionKey) -> Result<(), ConversationError> {
    if tx.query_one("SELECT EXISTS(SELECT 1 FROM workflow_message_links WHERE account_id=$1 AND action_id=$2)", &[&key.account_id,&key.action_id]).await?.get::<_,bool>(0) { return Err(ConversationError::Unavailable); }
    Ok(())
}
/// Rust service only: there is no HTTP02 edit request or route. The caller
/// supplies the complete next canonical descriptor, never projected fields.
pub async fn edit_provider(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: Uuid,
    expected: i64,
    previous: ActionKey,
    next: &[u8],
) -> Result<ActionState, ConversationError> {
    if previous.account_id != owner.tenant.account_id() {
        return Err(ConversationError::NotFound);
    }
    let next = super::action_profile::ProviderAction::parse(next)?;
    let digest = provider_request_digest(
        3,
        owner.user_id,
        request,
        &(previous, expected, next.canonical()),
    )?;
    let tx = client.transaction().await?;
    let old = match profile(&tx, previous).await? {
        super::action_profile::StoredProfile::Provider(d) => d,
        _ => return Err(ConversationError::Conflict),
    };
    let mut permit = super::proposal::ProviderProposal::checked(&tx, owner, next).await?;
    if let Some(result) = replay(&tx, previous.account_id, request, &digest).await? {
        permit.recheck().await?;
        drop(permit);
        tx.commit().await?;
        return Ok(result);
    }
    super::fence::live_provider_routine(&tx, &permit.descriptor, &permit.header).await?;
    let current = head(&tx, previous.account_id, previous.action_id).await?;
    cas(&current, previous, expected)?;
    model::edit_provider(&old, &permit.descriptor, current.phase)?;
    no_provider_link(&tx, previous).await?;
    let result = ActionState {
        key: permit.descriptor.key()?,
        record_version: current
            .record_version
            .checked_add(1)
            .ok_or(ConversationError::Conflict)?,
        phase: Phase::Invalidated,
    };
    tx.execute("UPDATE workflow_actions SET revision=$3,binding_digest=$4,record_version=$5,phase='invalidated',approved_by=NULL,approved_at=NULL WHERE account_id=$1 AND id=$2", &[&previous.account_id,&previous.action_id,&result.key.revision,&&result.key.binding_digest[..],&result.record_version]).await?;
    provider_version(&tx, &permit.descriptor, &permit.header).await?;
    record(
        &tx,
        owner,
        permit.header.context,
        request,
        3,
        &digest,
        &result,
    )
    .await?;
    permit.recheck().await?;
    drop(permit);
    tx.commit().await?;
    Ok(result)
}
