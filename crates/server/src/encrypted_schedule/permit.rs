// SPDX-License-Identifier: AGPL-3.0-only
//! Only checked service permits implement this crate-private fence.
use crate::http_owner_conversations::{
    ConversationError,
    context::decisions::{ActionKey, Descriptor, LockedAction},
};
use std::future::Future;
use tokio_postgres::Transaction;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub enum Actor {
    Owner(Uuid),
    Integration(Uuid),
}
impl Actor {
    pub(crate) fn identity(self) -> (&'static str, Uuid) {
        match self {
            Self::Owner(id) => ("owner", id),
            Self::Integration(id) => ("integration", id),
        }
    }
}

/// This trait is inaccessible to HTTP/library callers. Implementations must
/// hold the real current authority, exact approved action and transaction.
/// A future integration adapter checks its independent grants and cannot
/// manufacture a SessionPrincipal or adopt a caller-supplied queue marker.
pub(crate) trait ActionFence<'connection>: Send {
    fn transaction(&self) -> &Transaction<'connection>;
    fn key(&self) -> ActionKey;
    fn descriptor(&self) -> &Descriptor;
    fn context_id(&self) -> Uuid;
    fn routine_id(&self) -> Uuid;
    fn routine_generation(&self) -> i64;
    fn expires_at_ms(&self) -> i64;
    fn actor(&self) -> Actor;
    fn owner_session_id(&self) -> Option<Uuid>;
    fn recheck(&mut self) -> impl Future<Output = Result<(), ConversationError>> + Send;
    fn mark_dispatching(
        &mut self,
        message: Uuid,
        dispatch: Uuid,
    ) -> impl Future<Output = Result<(), ConversationError>> + Send;
}
impl<'tx, 'connection> ActionFence<'connection> for LockedAction<'tx, 'connection> {
    fn transaction(&self) -> &Transaction<'connection> {
        self.transaction()
    }
    fn key(&self) -> ActionKey {
        self.key()
    }
    fn descriptor(&self) -> &Descriptor {
        self.descriptor()
    }
    fn context_id(&self) -> Uuid {
        self.context_id()
    }
    fn routine_id(&self) -> Uuid {
        self.routine_id()
    }
    fn routine_generation(&self) -> i64 {
        self.routine_generation()
    }
    fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms()
    }
    fn actor(&self) -> Actor {
        Actor::Owner(self.actor_user_id())
    }
    fn owner_session_id(&self) -> Option<Uuid> {
        Some(self.actor_session_id())
    }
    async fn recheck(&mut self) -> Result<(), ConversationError> {
        self.recheck().await
    }
    async fn mark_dispatching(
        &mut self,
        message: Uuid,
        dispatch: Uuid,
    ) -> Result<(), ConversationError> {
        self.mark_dispatching(message, dispatch).await
    }
}
