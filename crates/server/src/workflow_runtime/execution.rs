// SPDX-License-Identifier: AGPL-3.0-only
use super::{
    IntegrationPrincipal, Operation,
    action::{IntegrationAction, error},
};
use crate::{
    auth::AuthError,
    encrypted_schedule::{permit::ActionFence, store as schedule},
    http_owner_conversations::context::decisions::{
        ActionKey, model::Phase, proposal::Actor, store,
    },
};
use serde::{Deserialize, Serialize};
use tokio_postgres::Client;
use uuid::Uuid;

/// Explicit independently owner-approved immediate timing. A scheduled policy
/// cannot acquire this timing merely by omitting its occurrence identifier.
pub const IMMEDIATE_WINDOW_ID: &str = "immediate-v1";

/// Durable service outcomes. Prepared records dispatch authority, never carrier delivery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum SendOutcome {
    WaitingOwnerBinding,
    WaitingWindow,
    Prepared { message_id: Uuid, dispatch_id: Uuid },
}

/// Executes only an independently owner-confirmed ciphertext binding. The caller
/// cannot nominate queue messages, actors, approvals, dispatch ids or budgets.
/// Exact retries retain the first outcome; a waiting outcome needs a new request
/// identity after its prerequisite changes.
pub async fn send_action(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    request: Uuid,
    key: ActionKey,
    occurrence: Option<Uuid>,
) -> Result<SendOutcome, AuthError> {
    if request.is_nil() || occurrence.is_some_and(|id| id.is_nil()) {
        return Err(AuthError::InvalidInput);
    }
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    let mut permit = IntegrationAction::lock(&tx, principal, key, Operation::Send).await?;
    let existing = tx.query_opt("SELECT id,actor_kind,actor_id FROM workflow_schedule_occurrences WHERE account_id=$1 AND action_id=$2 AND action_revision=$3", &[&key.account_id,&key.action_id,&key.revision]).await?;
    match (occurrence, existing) {
        (Some(id), Some(row))
            if row.get::<_, Uuid>(0) == id
                && row.get::<_, String>(1) == "integration"
                && row.get::<_, Uuid>(2) == principal.grant_id() =>
        {
            principal.require(Operation::Schedule)?;
        }
        (None, None) if permit.descriptor().window_id == IMMEDIATE_WINDOW_ID => {}
        _ => return Err(AuthError::Forbidden),
    }
    let digest =
        store::request_digest(8, &(principal.grant_id(), key, occurrence)).map_err(error)?;
    if let Some(bytes) = store::replay_bytes(&tx, key.account_id, request, &digest)
        .await
        .map_err(error)?
    {
        let result = serde_json::from_slice(&bytes).map_err(|_| AuthError::Conflict)?;
        permit.recheck().await.map_err(error)?;
        drop(permit);
        tx.commit().await?;
        return Ok(result);
    }
    if store::head(&tx, key.account_id, key.action_id)
        .await
        .map_err(error)?
        .phase
        != Phase::Approved
    {
        return Err(AuthError::Conflict);
    }
    let binding = tx.query_opt("SELECT message_id,dispatch_id FROM workflow_message_links WHERE account_id=$1 AND action_id=$2 AND revision=$3 AND binding_digest=$4 AND live_message_id=message_id", &[&key.account_id,&key.action_id,&key.revision,&&key.binding_digest[..]]).await?;
    let result = if let Some(row) = binding {
        let message: Uuid = row.get(0);
        let dispatch: Uuid = row.get(1);
        if let Some(occurrence) = occurrence {
            if let Some(lease) = schedule::claim_core(&mut permit, occurrence)
                .await
                .map_err(error)?
            {
                let actual = schedule::begin_dispatch_core(&mut permit, &lease, message)
                    .await
                    .map_err(error)?;
                if actual != dispatch {
                    return Err(AuthError::Forbidden);
                }
                SendOutcome::Prepared {
                    message_id: message,
                    dispatch_id: dispatch,
                }
            } else {
                SendOutcome::WaitingWindow
            }
        } else {
            permit
                .mark_dispatching(message, dispatch)
                .await
                .map_err(error)?;
            SendOutcome::Prepared {
                message_id: message,
                dispatch_id: dispatch,
            }
        }
    } else {
        SendOutcome::WaitingOwnerBinding
    };
    store::record_result(
        &tx,
        (key.account_id, Actor::Integration(principal.grant_id())),
        permit.context_id(),
        (request, 8),
        key.action_id,
        &digest,
        &result,
    )
    .await
    .map_err(error)?;
    permit
        .scope
        .record_access(request, key.action_id, &digest)
        .await?;
    permit.recheck().await.map_err(error)?;
    drop(permit);
    tx.commit().await?;
    Ok(result)
}
