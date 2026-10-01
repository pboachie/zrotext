// SPDX-License-Identifier: AGPL-3.0-only
use super::{IntegrationPrincipal, Operation, scope};
use crate::{
    auth::AuthError,
    http_owner_conversations::{
        ConversationError,
        context::decisions::{ActionState, store},
    },
};
use sha2::{Digest, Sha256};
use tokio_postgres::Client;
use uuid::Uuid;
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
    Ok(state)
}
