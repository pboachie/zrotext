// SPDX-License-Identifier: AGPL-3.0-only
use super::{IntegrationPrincipal, Operation, scope};
use crate::{
    auth::AuthError,
    http_owner_conversations::{
        ConversationError,
        context::decisions::{ActionState, store},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_postgres::Client;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionStatus {
    #[serde(flatten)]
    pub action: ActionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery: Option<DeliveryStatus>,
}
impl From<ActionState> for ActionStatus {
    fn from(action: ActionState) -> Self {
        Self {
            action,
            delivery: None,
        }
    }
}
impl std::ops::Deref for ActionStatus {
    type Target = ActionState;
    fn deref(&self) -> &ActionState {
        &self.action
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "availability", rename_all = "snake_case")]
pub enum DeliveryStatus {
    NotBound,
    Unavailable,
    Available {
        message_id: Uuid,
        dispatch_id: Uuid,
        state: zrotext_domain::MessageState,
        state_version: i64,
        accepted_at_ms: i64,
        updated_at_ms: i64,
    },
}
fn error(error: ConversationError) -> AuthError {
    match error {
        ConversationError::Database(error) => AuthError::Database(error),
        ConversationError::Invalid => AuthError::InvalidInput,
        ConversationError::Conflict => AuthError::Conflict,
        _ => AuthError::Forbidden,
    }
}
/// Status grants reveal only the bound action's durable state, never approval
/// authority, a rendered message, a queue operation, or context ciphertext.
pub async fn read_action_status(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    request: Uuid,
    context: Uuid,
    action: Uuid,
) -> Result<ActionState, AuthError> {
    Ok(
        read_action_delivery_status(client, principal, request, context, action)
            .await?
            .action,
    )
}

pub async fn read_action_delivery_status(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    request: Uuid,
    context: Uuid,
    action: Uuid,
) -> Result<ActionStatus, AuthError> {
    if request.is_nil() || action.is_nil() {
        return Err(AuthError::InvalidInput);
    }
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    let mut checked = scope::lock_scope(&tx, principal, context, Operation::Status).await?;
    let state = store::head(&tx, principal.account_id(), action)
        .await
        .map_err(error)?;
    let descriptor = store::descriptor(&tx, state.key).await.map_err(error)?;
    checked.check_descriptor(&descriptor)?;
    let link = tx.query_opt("SELECT message_id,dispatch_id,live_message_id FROM workflow_message_links WHERE account_id=$1 AND action_id=$2 AND revision=$3 AND binding_digest=$4 FOR SHARE",
        &[&state.key.account_id,&state.key.action_id,&state.key.revision,&&state.key.binding_digest[..]]).await?;
    let delivery = if let Some(link) = link {
        let message: Uuid = link.get(0);
        let live: Option<Uuid> = link.get(2);
        if live != Some(message) || tx.query_opt("SELECT 1 FROM messages WHERE account_id=$1 AND id=$2 AND device_id=$3 AND workflow_action_id=$4 FOR SHARE",
            &[&state.key.account_id,&message,&checked.header.device,&state.key.action_id]).await?.is_none() {
            DeliveryStatus::Unavailable
        } else {
            let snapshot = zrotext_delivery_store::message_status(&tx, state.key.account_id, message).await
                .map_err(|error| match error {
                    zrotext_delivery_store::StoreError::Database(error) => AuthError::Database(error),
                    _ => AuthError::Conflict,
                })?;
            match snapshot {
                Some(snapshot) => DeliveryStatus::Available {
                    message_id: message, dispatch_id: link.get(1), state: snapshot.state,
                    state_version: snapshot.state_version, accepted_at_ms: snapshot.created_at_ms,
                    updated_at_ms: snapshot.updated_at_ms,
                },
                None => DeliveryStatus::Unavailable,
            }
        }
    } else {
        DeliveryStatus::NotBound
    };
    let digest = Sha256::digest(
        [
            b"ZT/workflow/status/v1\0".as_slice(),
            context.as_bytes(),
            action.as_bytes(),
        ]
        .concat(),
    );
    checked
        .record_access(request, action, digest.as_slice())
        .await?;
    checked.recheck().await?;
    drop(checked);
    tx.commit().await?;
    Ok(ActionStatus {
        action: state,
        delivery: Some(delivery),
    })
}
