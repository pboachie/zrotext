// SPDX-License-Identifier: AGPL-3.0-only
//! Owner-confirmed opening allocation foundation. No route is mounted and no
//! integration permission, message receipt or model result grants allocation.
mod admit;
mod contact;
pub mod contracts;
pub(crate) mod lifecycle;
pub mod model;
mod reduce;
pub use admit::{confirm, offer, reserve};
pub mod export;
mod schema;
mod source;
mod store;
use crate::{
    auth::SessionPrincipal,
    http_owner_conversations::{self as owner_context, ConversationError, activation},
    sealed_manifest_store::outbound::lock_current,
};
use contracts::{Create, OpeningKey};
use model::Outcome;
pub use reduce::{cancel, close, release};
use tokio_postgres::Client;
use uuid::Uuid;

/// Owner declaration of bounded capacity; no booking or SEND is implied.
pub async fn create(
    client: &mut Client,
    owner: &SessionPrincipal,
    request: Create,
) -> Result<Outcome, ConversationError> {
    if !request.validate() {
        return Err(ConversationError::Invalid);
    }
    let account = owner.tenant.account_id();
    let digest = store::digest(account, 1, &request)?;
    let tx = store::begin(client).await?;
    let mut authority = lock_current(&tx, account).await?;
    owner_context::lock_owner(&tx, owner).await?;
    if let Some(receipt) = store::replay(&tx, account, request.request_id, &digest).await? {
        owner_context::fresh_owner(&tx, owner).await?;
        drop(authority);
        tx.commit().await?;
        return Ok(Outcome {
            receipt,
            applied: false,
            recorded: true,
        });
    }
    store::ordinary_capacity(&tx, account).await?;
    let source = source::check(&tx, owner, &mut authority, &request.description).await?;
    let now = activation::now(&tx).await?;
    if now >= request.decision_deadline_ms || request.decision_deadline_ms > source.deadline_ms() {
        return Err(ConversationError::Forbidden);
    }
    let count: i64 = tx
        .query_one(
            "SELECT count(*) FROM workflow_openings WHERE account_id=$1",
            &[&account],
        )
        .await?
        .get(0);
    if count >= 256 {
        return Err(ConversationError::Conflict);
    }
    let inserted = tx.execute("INSERT INTO workflow_openings(account_id,id,definition_version,state_version,capacity,phase,description_context_id,description_revision,description_digest,decision_deadline_ms,created_by_user,created_session,created_ms) VALUES($1,$2,1,1,$3,'open',$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(account_id,id) DO NOTHING",
        &[&account,&request.opening_id,&request.capacity,&request.description.context_id,&request.description.revision,&decode(&request.description.digest)?,&request.decision_deadline_ms,&owner.user_id,&owner.session_id,&now]).await?;
    if inserted != 1 {
        return Err(ConversationError::Conflict);
    }
    let receipt = store::status(
        &tx,
        account,
        OpeningKey {
            opening_id: request.opening_id,
            definition_version: 1,
            state_version: 1,
        },
        "open".into(),
    )
    .await?;
    store::record(
        &tx,
        owner,
        store::Mutation {
            request: request.request_id,
            operation: 1,
            subject_kind: 1,
            subject: request.opening_id,
            digest: &digest,
            receipt: &receipt,
            charged: true,
        },
    )
    .await?;
    source.recheck(&mut authority).await?;
    if activation::now(&tx).await? >= request.decision_deadline_ms {
        return Err(ConversationError::Forbidden);
    }
    owner_context::fresh_owner(&tx, owner).await?;
    drop(authority);
    tx.commit().await?;
    Ok(Outcome {
        receipt,
        applied: true,
        recorded: true,
    })
}

/// Account-owner metadata remains available when a source or reader is lost.
/// This operation does not reopen authority or decrypt retained content.
pub async fn status(
    client: &mut Client,
    owner: &SessionPrincipal,
    opening: Uuid,
) -> Result<model::Receipt, ConversationError> {
    if opening.is_nil() {
        return Err(ConversationError::Invalid);
    }
    let tx = store::begin(client).await?;
    owner_context::lock_owner(&tx, owner).await?;
    let account = owner.tenant.account_id();
    let row=tx.query_opt("SELECT definition_version,state_version,phase FROM workflow_openings WHERE account_id=$1 AND id=$2 FOR UPDATE", &[&account,&opening]).await?.ok_or(ConversationError::NotFound)?;
    admit::expire_pending(&tx, account, opening).await?;
    let receipt = store::status(
        &tx,
        account,
        OpeningKey {
            opening_id: opening,
            definition_version: row.get(0),
            state_version: row.get(1),
        },
        row.get(2),
    )
    .await?;
    owner_context::fresh_owner(&tx, owner).await?;
    tx.commit().await?;
    Ok(receipt)
}

fn decode(value: &str) -> Result<Vec<u8>, ConversationError> {
    crate::http_owner_conversations::context::decisions::descriptor::decode_digest(value)
        .map(|v| v.to_vec())
}

#[cfg(test)]
mod tests;
