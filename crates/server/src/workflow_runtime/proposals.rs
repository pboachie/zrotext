// SPDX-License-Identifier: AGPL-3.0-only
use super::{
    IntegrationPrincipal, Operation,
    scope::{self, CheckedScope},
};
use crate::{
    auth::AuthError,
    http_owner_conversations::{
        ConversationError, activation,
        context::{
            decisions::{
                self, ActionState, Descriptor,
                proposal::{Actor, ProposalFence},
            },
            wire,
        },
    },
};
use tokio_postgres::{Client, Transaction};
fn error(error: ConversationError) -> AuthError {
    match error {
        ConversationError::Database(error) => AuthError::Database(error),
        ConversationError::Invalid => AuthError::InvalidInput,
        ConversationError::Conflict => AuthError::Conflict,
        _ => AuthError::Forbidden,
    }
}
fn authorization(error: AuthError) -> ConversationError {
    match error {
        AuthError::Database(error) => ConversationError::Database(error),
        AuthError::InvalidInput => ConversationError::Invalid,
        _ => ConversationError::Forbidden,
    }
}
pub(crate) struct IntegrationProposal<'tx, 'connection> {
    tx: &'tx Transaction<'connection>,
    scope: CheckedScope<'tx, 'connection>,
    descriptor: Descriptor,
    actor: Actor,
}
impl IntegrationProposal<'_, '_> {
    pub(crate) async fn recheck_current(&mut self) -> Result<(), AuthError> {
        self.recheck().await.map_err(error)
    }
}
impl<'connection> ProposalFence<'connection> for IntegrationProposal<'_, 'connection> {
    fn transaction(&self) -> &Transaction<'connection> {
        self.tx
    }
    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    fn header(&self) -> &wire::Header {
        &self.scope.header
    }
    fn actor(&self) -> Actor {
        self.actor
    }
    fn recheck(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), ConversationError>> + Send + '_>,
    > {
        Box::pin(async move {
            self.scope
                .check_descriptor(&self.descriptor)
                .map_err(authorization)?;
            decisions::fence::contact(self.tx, &self.descriptor, &self.scope.header).await?;
            if activation::now(self.tx).await? >= self.descriptor.expires_at_ms()? {
                return Err(ConversationError::Forbidden);
            }
            self.scope.recheck().await.map_err(authorization)
        })
    }
}
/// Persists a proposal in the existing action ledger. This creates neither an
/// approval nor a message; its immutable actor is the exact integration grant.
pub async fn propose_action(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    request: uuid::Uuid,
    descriptor: Descriptor,
) -> Result<ActionState, AuthError> {
    principal.require(Operation::Propose)?;
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    let result = propose_in_transaction(&tx, principal, request, descriptor).await?;
    tx.commit().await?;
    Ok(result)
}

/// Crate-private composition only; the same current Propose scope is held through
/// the caller's original-event consumption transaction. No read grant is upgraded.
pub(crate) async fn propose_in_transaction(
    tx: &Transaction<'_>,
    principal: &IntegrationPrincipal,
    request: uuid::Uuid,
    descriptor: Descriptor,
) -> Result<ActionState, AuthError> {
    let (result, permit) = propose_held_in_transaction(tx, principal, request, descriptor).await?;
    drop(permit);
    Ok(result)
}
/// Keeps the actual output Propose authority borrowed until composed writes
/// finish; callers must recheck and drop it immediately before committing.
pub(crate) async fn propose_held_in_transaction<'tx, 'connection>(
    tx: &'tx Transaction<'connection>,
    principal: &IntegrationPrincipal,
    request: uuid::Uuid,
    descriptor: Descriptor,
) -> Result<(ActionState, IntegrationProposal<'tx, 'connection>), AuthError> {
    principal.require(Operation::Propose)?;
    let context = descriptor.identities().map_err(error)?.content;
    let scope = scope::lock_scope(tx, principal, context, Operation::Propose).await?;
    let mut permit = IntegrationProposal {
        tx,
        scope,
        descriptor,
        actor: Actor::Integration(principal.grant_id()),
    };
    let result = decisions::store::register_core(&mut permit, request)
        .await
        .map_err(error)?;
    let digest = decisions::store::request_digest(1, &(principal.grant_id(), &permit.descriptor))
        .map_err(error)?;
    permit
        .scope
        .record_access(request, result.key.action_id, &digest)
        .await?;
    permit.recheck().await.map_err(error)?;
    Ok((result, permit))
}
