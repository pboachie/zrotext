// SPDX-License-Identifier: AGPL-3.0-only
//! Private integration permit for the existing decision and scheduling services.
use super::{
    IntegrationPrincipal, Operation,
    scope::{self, CheckedScope},
};
use crate::{
    auth::AuthError,
    encrypted_schedule::permit::{ActionFence, Actor},
    http_owner_conversations::{
        ConversationError,
        context::decisions::{self, ActionKey, Descriptor, model::Phase},
    },
    sealed_envelope::{self, Profile},
};
use tokio_postgres::Transaction;
use uuid::Uuid;

pub(super) fn error(error: ConversationError) -> AuthError {
    match error {
        ConversationError::Database(e) => AuthError::Database(e),
        ConversationError::Invalid => AuthError::InvalidInput,
        ConversationError::Conflict => AuthError::Conflict,
        _ => AuthError::Forbidden,
    }
}
fn authorization(error: AuthError) -> ConversationError {
    match error {
        AuthError::Database(e) => ConversationError::Database(e),
        AuthError::InvalidInput => ConversationError::Invalid,
        AuthError::Conflict => ConversationError::Conflict,
        _ => ConversationError::Forbidden,
    }
}
pub(super) struct IntegrationAction<'tx, 'connection> {
    tx: &'tx Transaction<'connection>,
    pub(super) scope: CheckedScope<'tx, 'connection>,
    descriptor: Descriptor,
    key: ActionKey,
    grant: Uuid,
    operation: Operation,
}
impl<'tx, 'connection> IntegrationAction<'tx, 'connection> {
    pub(super) async fn lock(
        tx: &'tx Transaction<'connection>,
        principal: &IntegrationPrincipal,
        key: ActionKey,
        operation: Operation,
    ) -> Result<Self, AuthError> {
        if !matches!(operation, Operation::Schedule | Operation::Send) {
            return Err(AuthError::Forbidden);
        }
        principal.require(operation)?;
        if key.account_id != principal.account_id() {
            return Err(AuthError::Forbidden);
        }
        let descriptor = decisions::store::descriptor(tx, key).await.map_err(error)?;
        let context = descriptor.identities().map_err(error)?.content;
        let scope = scope::lock_scope(tx, principal, context, operation).await?;
        let mut result = Self {
            tx,
            scope,
            descriptor,
            key,
            grant: principal.grant_id(),
            operation,
        };
        result.recheck().await.map_err(error)?;
        Ok(result)
    }
}
impl<'tx, 'connection> ActionFence<'connection> for IntegrationAction<'tx, 'connection> {
    fn transaction(&self) -> &Transaction<'connection> {
        self.tx
    }
    fn key(&self) -> ActionKey {
        self.key
    }
    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    fn context_id(&self) -> Uuid {
        self.scope.header.context
    }
    fn routine_id(&self) -> Uuid {
        self.descriptor
            .identities()
            .expect("checked identities")
            .routine
    }
    fn routine_generation(&self) -> i64 {
        self.descriptor.authority_generation
    }
    fn expires_at_ms(&self) -> i64 {
        self.descriptor.expires_at_ms().expect("checked timestamp")
    }
    fn actor(&self) -> Actor {
        Actor::Integration(self.grant)
    }
    fn owner_session_id(&self) -> Option<Uuid> {
        None
    }
    async fn recheck(&mut self) -> Result<(), ConversationError> {
        self.scope
            .check_descriptor(&self.descriptor)
            .map_err(authorization)?;
        decisions::fence::contact(self.tx, &self.descriptor, &self.scope.header).await?;
        decisions::fence::live_routine(self.tx, &self.descriptor, &self.scope.header).await?;
        let state =
            decisions::store::head(self.tx, self.key.account_id, self.key.action_id).await?;
        if state.key != self.key || !matches!(state.phase, Phase::Approved | Phase::Dispatching) {
            return Err(ConversationError::Conflict);
        }
        if !self.tx.query_one("SELECT EXISTS(SELECT 1 FROM workflow_actions a JOIN memberships m ON (m.account_id,m.user_id)=(a.account_id,a.approved_by) JOIN users u ON u.id=m.user_id WHERE a.account_id=$1 AND a.id=$2 AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL) AND workflow_action_origin_current($1,$2)", &[&self.key.account_id,&self.key.action_id]).await?.get::<_,bool>(0) {
            return Err(ConversationError::Forbidden);
        }
        self.tx.query_opt("SELECT 1 FROM workflow_actions a JOIN memberships m ON (m.account_id,m.user_id)=(a.account_id,a.approved_by) JOIN users u ON u.id=m.user_id WHERE a.account_id=$1 AND a.id=$2 AND m.role='owner' AND m.revoked_at IS NULL AND u.email_verified_at IS NOT NULL FOR SHARE OF m,u", &[&self.key.account_id,&self.key.action_id]).await?.ok_or(ConversationError::Forbidden)?;
        self.scope.recheck().await.map_err(authorization)?;
        if crate::http_owner_conversations::activation::now(self.tx).await? >= self.expires_at_ms()
        {
            return Err(ConversationError::Forbidden);
        }
        Ok(())
    }
    async fn mark_dispatching(
        &mut self,
        message: Uuid,
        dispatch: Uuid,
    ) -> Result<(), ConversationError> {
        if self.operation != Operation::Send {
            return Err(ConversationError::Forbidden);
        }
        self.recheck().await?;
        let row = self
            .tx
            .query_opt(
                "SELECT transport_payload FROM messages WHERE account_id=$1 AND id=$2 FOR UPDATE",
                &[&self.key.account_id, &message],
            )
            .await?
            .ok_or(ConversationError::NotFound)?;
        let bytes = row
            .get::<_, Option<Vec<u8>>>(0)
            .ok_or(ConversationError::Forbidden)?;
        let envelope = sealed_envelope::parse(&bytes, Profile::Draft02Candidate)
            .map_err(|_| ConversationError::Forbidden)?;
        if envelope.signer_key_id != self.scope.signer().map_err(authorization)? {
            return Err(ConversationError::Forbidden);
        }
        decisions::store::dispatch_transition(
            self.tx,
            &self.descriptor,
            self.scope.header.context,
            decisions::proposal::Actor::Integration(self.grant),
            message,
            dispatch,
        )
        .await?;
        self.recheck().await
    }
}
