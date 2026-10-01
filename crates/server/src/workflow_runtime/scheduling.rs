// SPDX-License-Identifier: AGPL-3.0-only
use super::{
    IntegrationPrincipal, Operation,
    action::{IntegrationAction, error},
};
use crate::{
    auth::AuthError,
    encrypted_schedule::{
        permit::ActionFence,
        policy::WindowPolicy,
        store::{self, Occurrence, ScheduleRequest},
    },
    http_owner_conversations::context::decisions::ActionKey,
};
use tokio_postgres::Client;

/// Adds an occurrence to the shared scheduler after independent Schedule checks.
/// It neither approves the action nor creates a queue message.
pub async fn schedule_action(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    key: ActionKey,
    request: ScheduleRequest,
    policy: &WindowPolicy,
) -> Result<Occurrence, AuthError> {
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    let mut permit = IntegrationAction::lock(&tx, principal, key, Operation::Schedule).await?;
    if let Some(row) = tx.query_opt("SELECT actor_kind,actor_id FROM workflow_schedule_occurrences WHERE account_id=$1 AND request_id=$2", &[&key.account_id,&request.request_id]).await?
        && (row.get::<_,String>(0) != "integration" || row.get::<_,uuid::Uuid>(1) != principal.grant_id()) {
        return Err(AuthError::Conflict);
    }
    let result = store::schedule_core(&mut permit, request, policy)
        .await
        .map_err(error)?;
    let digest = crate::http_owner_conversations::context::decisions::store::request_digest(
        6,
        &(
            principal.grant_id(),
            key,
            request.series_id,
            request.ordinal,
            policy.identity().map_err(|_| AuthError::InvalidInput)?,
        ),
    )
    .map_err(error)?;
    permit
        .scope
        .record_access(request.request_id, key.action_id, &digest)
        .await?;
    permit.recheck().await.map_err(error)?;
    drop(permit);
    tx.commit().await?;
    Ok(result)
}
