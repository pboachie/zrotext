// SPDX-License-Identifier: AGPL-3.0-only
//! Cancellation of this integration's exact prepared message before its grant.
use super::{
    IntegrationPrincipal, Operation,
    action::{IntegrationAction, error},
};
use crate::{
    auth::AuthError,
    encrypted_schedule::permit::ActionFence,
    http_owner_conversations::context::decisions::{ActionKey, store},
};
use serde::{Deserialize, Serialize};
use tokio_postgres::Client;
use uuid::Uuid;

const EXACT_BINDING: &str = "SELECT m.id FROM workflow_message_links l JOIN messages m ON (m.account_id,m.id)=(l.account_id,l.live_message_id) WHERE l.account_id=$1 AND l.action_id=$2 AND l.revision=$3 AND l.binding_digest=$4 AND l.live_message_id=l.message_id AND m.workflow_action_id=$2 AND m.workflow_executor_grant=$5 AND m.transport_mode='sealed_candidate02' AND m.transport_payload IS NOT NULL AND sha256(m.transport_payload)=l.message_digest";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelState {
    Cancelled,
}

/// Message state only. Cancellation cannot revoke or manufacture an owner decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelOutcome {
    pub key: ActionKey,
    pub message_id: Uuid,
    pub state: CancelState,
}

pub async fn cancel_action(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    request: Uuid,
    key: ActionKey,
) -> Result<CancelOutcome, AuthError> {
    if request.is_nil() {
        return Err(AuthError::InvalidInput);
    }
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    let mut permit = IntegrationAction::lock(&tx, principal, key, Operation::Send).await?;
    // Exact immutable owner binding and the real integration dispatch marker:
    // knowing an action, message or account identifier never grants cancellation.
    let row = tx
        .query_opt(
            EXACT_BINDING,
            &[
                &key.account_id,
                &key.action_id,
                &key.revision,
                &&key.binding_digest[..],
                &principal.grant_id(),
            ],
        )
        .await?
        .ok_or(AuthError::Forbidden)?;
    let message: Uuid = row.get(0);
    let digest = store::request_digest(8, &("cancel-prepared-v1", principal.grant_id(), key))
        .map_err(error)?;
    // The shared bounded access ledger refuses cross-method/request reuse. Its
    // write and the existing cancellation/refund commit or roll back together.
    permit
        .scope
        .record_access(request, key.action_id, &digest)
        .await?;
    let cancelled = zrotext_delivery_store::cancel_in_transaction(&tx, key.account_id, message)
        .await
        .map_err(|e| match e {
            zrotext_delivery_store::StoreError::InvalidTransition => AuthError::Conflict,
            zrotext_delivery_store::StoreError::Database(e) => AuthError::Database(e),
            _ => AuthError::Conflict,
        })?;
    if !cancelled {
        return Err(AuthError::Conflict);
    }
    // Job/message locks serialized the irreversible grant race; now repeat the
    // real current-authority and clock checks after every possible lock wait.
    let current = tx
        .query_opt(
            EXACT_BINDING,
            &[
                &key.account_id,
                &key.action_id,
                &key.revision,
                &&key.binding_digest[..],
                &principal.grant_id(),
            ],
        )
        .await?
        .ok_or(AuthError::Forbidden)?;
    if current.get::<_, Uuid>(0) != message {
        return Err(AuthError::Forbidden);
    }
    permit.recheck().await.map_err(error)?;
    drop(permit);
    tx.commit().await?;
    Ok(CancelOutcome {
        key,
        message_id: message,
        state: CancelState::Cancelled,
    })
}
