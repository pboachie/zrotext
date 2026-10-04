// SPDX-License-Identifier: AGPL-3.0-only
//! Separately owner-granted customer-local routine admission. Startup mounts
//! these authenticated routes only under the default-off customer routine gate.
pub mod contracts;
pub mod http;
pub(crate) mod lifecycle;
mod original;
mod output;
mod store;
use super::{
    IntegrationPrincipal, Operation,
    scope::{self, CheckedScope},
};
use crate::{
    auth::{AuthError, SessionPrincipal},
    encrypted_schedule::time::Resolution,
    http_owner_conversations::{
        self as owner, activation,
        context::decisions::{self, Descriptor},
    },
};
use contracts::*;
pub(crate) use original::{admit as admit_original, current as current_original};
pub use output::{bind_output, resume};
#[cfg(test)]
pub(crate) use output::{bind_with_original, resume_with_original};
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

fn error(e: owner::ConversationError) -> AuthError {
    match e {
        owner::ConversationError::Database(e) => AuthError::Database(e),
        owner::ConversationError::Invalid => AuthError::InvalidInput,
        owner::ConversationError::Conflict => AuthError::Conflict,
        _ => AuthError::Forbidden,
    }
}
fn digest(value: &impl serde::Serialize) -> Result<Vec<u8>, AuthError> {
    Ok(Sha256::digest(serde_json::to_vec(value).map_err(|_| AuthError::InvalidInput)?).to_vec())
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode(value: &str) -> Result<Vec<u8>, AuthError> {
    decisions::descriptor::decode_digest(value)
        .map(|v| v.to_vec())
        .map_err(error)
}
async fn begin(client: &mut Client) -> Result<Transaction<'_>, AuthError> {
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    Ok(tx)
}

async fn descriptor(
    tx: &Transaction<'_>,
    checked: &CheckedScope<'_, '_>,
    policy: &Policy,
    action: Uuid,
    routine: Uuid,
) -> Result<Descriptor, AuthError> {
    let Resolution::Ready {
        opens_at_ms,
        closes_at_ms,
    } = policy
        .window
        .resolve_occurrence(tx, 0)
        .await
        .map_err(|_| AuthError::Forbidden)?
    else {
        return Err(AuthError::Forbidden);
    };
    let now = activation::now(tx).await.map_err(error)?;
    let expiry = closes_at_ms
        .min(policy.expires_ms)
        .min(checked.header.expires_ms);
    if now < opens_at_ms || now >= expiry {
        return Err(AuthError::Forbidden);
    }
    let purpose = match checked.purpose().as_str() {
        "transactional" => 1,
        "operational" => 2,
        "marketing" => 3,
        _ => return Err(AuthError::Forbidden),
    };
    Ok(Descriptor {
        account_id: checked.header.account.to_string(),
        action_id: action.to_string(),
        revision: 1,
        line_id: checked.header.line.to_string(),
        recipient_id: checked.contact().to_string(),
        purpose_id: Uuid::from_u128(purpose).to_string(),
        content_ref: checked.header.context.to_string(),
        content_digest: hex(&checked.source_digest()),
        content_version: checked.header.revision,
        not_before: opens_at_ms / 1000,
        expires_at: expiry / 1000,
        timezone: policy.window.timezone.clone().ok_or(AuthError::Forbidden)?,
        window_id: policy.window.identity().map_err(|_| AuthError::Forbidden)?,
        routine_id: routine.to_string(),
        authority_generation: policy.generation,
        commitment: "sensitive".into(),
    })
}
async fn live(
    tx: &Transaction<'_>,
    checked: &mut CheckedScope<'_, '_>,
    policy: &Policy,
) -> Result<(), AuthError> {
    let d = descriptor(tx, checked, policy, policy.request_id, policy.routine_id).await?;
    decisions::fence::contact(tx, &d, &checked.header)
        .await
        .map_err(error)?;
    decisions::fence::live_routine(tx, &d, &checked.header)
        .await
        .map_err(error)?;
    checked.recheck().await
}

/// A read credential alone never grants execution. A current owner explicitly
/// grants this exact deterministic kind/window and bounded call/turn operation.
pub async fn configure(
    client: &mut Client,
    owner: &SessionPrincipal,
    input: &IntegrationPrincipal,
    p: Policy,
) -> Result<(), AuthError> {
    configure_with_original(client, owner, input, None, p).await
}

pub(crate) async fn configure_with_original(
    client: &mut Client,
    owner: &SessionPrincipal,
    input: &IntegrationPrincipal,
    original: Option<&crate::original_reply::Principal>,
    p: Policy,
) -> Result<(), AuthError> {
    if !p.validate() || owner.tenant.account_id() != input.account_id() {
        return Err(AuthError::InvalidInput);
    }
    let tx = begin(client).await?;
    let mut checked =
        scope::lock_scope(&tx, input, p.context_id, Operation::ContextContent).await?;
    owner::lock_owner(&tx, owner).await.map_err(error)?;
    original::configure_check(&tx, input, original, &checked, &p).await?;
    let now = activation::now(&tx).await.map_err(error)?;
    if p.expires_ms <= now
        || p.expires_ms - now > 86_400_000
        || p.expires_ms > checked.header.expires_ms
    {
        return Err(AuthError::Forbidden);
    }
    tx.execute("INSERT INTO workflow_context_fences(account_id,context_id) VALUES($1,$2) ON CONFLICT DO NOTHING",&[&input.account_id(),&p.context_id]).await?;
    tx.execute("INSERT INTO workflow_routines(account_id,id,context_id,generation) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",&[&input.account_id(),&p.routine_id,&p.context_id,&p.generation]).await?;
    live(&tx, &mut checked, &p).await?;
    store::configure(
        &tx,
        owner,
        input,
        &p,
        checked.header.revision,
        &checked.source_digest(),
        &digest(&p)?,
    )
    .await?;
    live(&tx, &mut checked, &p).await?;
    owner::fresh_owner(&tx, owner).await.map_err(error)?;
    original::configure_check(&tx, input, original, &checked, &p).await?;
    drop(checked);
    tx.commit().await?;
    Ok(())
}

/// Commits the irreversible unknown checkpoint before customer-local execution.
/// Even restart, response loss or timeout cannot grant a second provider call.
pub async fn admit(
    client: &mut Client,
    input: &IntegrationPrincipal,
    v: Invocation,
) -> Result<Call, AuthError> {
    if v.direction != Direction::OwnerDeclared || v.request_id.is_nil() || v.input_revision < 1 {
        return Err(AuthError::Forbidden);
    }
    let tx = begin(client).await?;
    let mut checked =
        scope::lock_scope(&tx, input, v.context_id, Operation::ContextContent).await?;
    let policy = store::policy(&tx, input, v.policy_id).await?;
    if policy.original_input.is_some()
        || policy.context_id != v.context_id
        || checked.header.revision != v.input_revision
        || decode(&v.input_source_digest)?.as_slice() != checked.source_digest()
    {
        return Err(AuthError::Forbidden);
    }
    live(&tx, &mut checked, &policy).await?;
    let result = store::admit(&tx, input, &policy, v.request_id, &digest(&v)?).await?;
    live(&tx, &mut checked, &policy).await?;
    store::policy(&tx, input, v.policy_id).await?;
    drop(checked);
    tx.commit().await?;
    Ok(result)
}

/// Reports only the digest of an already encrypted customer-local archive
/// artifact. No plaintext commitment, provider settlement or approval is stored.
/// Owner comparison and a separately authorized output publication are required.
pub async fn produced(
    client: &mut Client,
    input: &IntegrationPrincipal,
    context: Uuid,
    call: Uuid,
    result_digest: String,
) -> Result<Call, AuthError> {
    produced_with_original(client, input, None, context, call, result_digest).await
}
pub(crate) async fn produced_with_original(
    client: &mut Client,
    input: &IntegrationPrincipal,
    original: Option<&crate::original_reply::Principal>,
    context: Uuid,
    call: Uuid,
    result_digest: String,
) -> Result<Call, AuthError> {
    let hash = decode(&result_digest)?;
    let tx = begin(client).await?;
    let mut checked = scope::lock_scope(&tx, input, context, Operation::ContextContent).await?;
    let p = store::call_policy(&tx, input, call).await?;
    if p.context_id != context {
        return Err(AuthError::Forbidden);
    }
    live(&tx, &mut checked, &p).await?;
    original::recheck(&tx, input, original, call, &p, &checked).await?;
    let result = store::produced(&tx, input, call, &hash).await?;
    live(&tx, &mut checked, &p).await?;
    store::policy(&tx, input, p.policy_id).await?;
    original::recheck(&tx, input, original, call, &p, &checked).await?;
    drop(checked);
    tx.commit().await?;
    Ok(result)
}

/// Current read includes separate live routine admission authority, not hints.
pub async fn current(
    client: &mut Client,
    input: &IntegrationPrincipal,
    context: Uuid,
    policy: Uuid,
) -> Result<Policy, AuthError> {
    current_with_original(client, input, None, context, policy).await
}
pub(crate) async fn current_with_original(
    client: &mut Client,
    input: &IntegrationPrincipal,
    original: Option<&crate::original_reply::Principal>,
    context: Uuid,
    policy: Uuid,
) -> Result<Policy, AuthError> {
    let tx = begin(client).await?;
    let mut checked = scope::lock_scope(&tx, input, context, Operation::ContextContent).await?;
    let p = store::policy(&tx, input, policy).await?;
    if p.context_id != context {
        return Err(AuthError::Forbidden);
    }
    live(&tx, &mut checked, &p).await?;
    original::configure_check(&tx, input, original, &checked, &p).await?;
    drop(checked);
    tx.commit().await?;
    Ok(p)
}

/// Owner revocation remains available after reader/context expiry.
pub async fn withdraw(
    client: &mut Client,
    owner: &SessionPrincipal,
    policy: Uuid,
) -> Result<(), AuthError> {
    let tx = begin(client).await?;
    owner::lock_owner(&tx, owner).await.map_err(error)?;
    tx.execute("UPDATE workflow_routine_policies SET withdrawn_ms=COALESCE(withdrawn_ms,floor(extract(epoch FROM clock_timestamp())*1000)::bigint) WHERE account_id=$1 AND id=$2",&[&owner.tenant.account_id(),&policy]).await?;
    // Account serialization excludes admission/resume while the policy and its
    // already-created output routines are irreversibly stopped. Do not stop
    // the shared input routine: another explicitly granted policy may use it.
    lifecycle::stop_outputs(&tx, owner.tenant.account_id(), policy).await?;
    owner::fresh_owner(&tx, owner).await.map_err(error)?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;

/// Optional-schema compatibility applies only to installations without this
/// candidate ledger. Once a source marker exists it cannot be erased separately
/// or reclassified as an ordinary action, including later action revisions.
pub(crate) async fn original_action_current(
    tx: &Transaction<'_>,
    descriptor: &Descriptor,
) -> Result<(), owner::ConversationError> {
    if !tx
        .query_one(
            "SELECT to_regclass('workflow_routine_original_sources') IS NOT NULL",
            &[],
        )
        .await?
        .get::<_, bool>(0)
    {
        return Ok(());
    }
    let key = descriptor.key()?;
    if let Some(row)=tx.query_opt("SELECT contact_id,purpose,line_id,expires_ms FROM workflow_routine_original_sources WHERE account_id=$1 AND call_id=$2 FOR SHARE",&[&key.account_id,&key.action_id]).await? {
        let ids=descriptor.identities()?;
        if ids.content!=key.action_id || ids.routine!=key.action_id || ids.recipient!=row.get::<_,Uuid>(0)
            || descriptor.purpose()?!=row.get::<_,String>(1) || ids.line!=row.get::<_,Uuid>(2)
            || descriptor.expires_at_ms()?>row.get::<_,i64>(3) {return Err(owner::ConversationError::Forbidden);}
    }
    if !tx
        .query_one(
            "SELECT workflow_routine_original_action_current($1,$2)",
            &[&key.account_id, &key.action_id],
        )
        .await?
        .get::<_, bool>(0)
    {
        return Err(owner::ConversationError::Forbidden);
    }
    Ok(())
}
