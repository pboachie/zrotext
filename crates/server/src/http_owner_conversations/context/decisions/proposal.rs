// SPDX-License-Identifier: AGPL-3.0-only
//! Internal proof interface; public callers cannot supply an actor or authorization flag.
use super::super::{ConversationError, SessionPrincipal, wire};
use super::{
    Descriptor,
    fence::{checked_descriptor, recheck_descriptor},
};
use crate::sealed_manifest_store::outbound::CurrentAuthority;
use std::future::Future;
use tokio_postgres::Transaction;
use uuid::Uuid;
#[derive(Clone, Copy)]
pub(crate) enum Actor {
    Owner(Uuid),
    Integration(Uuid),
}
pub(crate) trait ProposalFence<'connection>: Send + Sync {
    fn transaction(&self) -> &Transaction<'connection>;
    fn descriptor(&self) -> &Descriptor;
    fn header(&self) -> &wire::Header;
    fn actor(&self) -> Actor;
    fn recheck(
        &mut self,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), ConversationError>> + Send + '_>>;
}
pub(crate) struct OwnerProposal<'tx, 'connection> {
    tx: &'tx Transaction<'connection>,
    owner: &'tx SessionPrincipal,
    authority: CurrentAuthority<'tx, 'connection>,
    header: wire::Header,
    descriptor: Descriptor,
}
impl<'tx, 'connection> OwnerProposal<'tx, 'connection> {
    pub(crate) async fn checked(
        tx: &'tx Transaction<'connection>,
        owner: &'tx SessionPrincipal,
        descriptor: Descriptor,
    ) -> Result<Self, ConversationError> {
        let (authority, header) = checked_descriptor(tx, owner, &descriptor).await?;
        Ok(Self {
            tx,
            owner,
            authority,
            header,
            descriptor,
        })
    }
}
impl<'connection> ProposalFence<'connection> for OwnerProposal<'_, 'connection> {
    fn transaction(&self) -> &Transaction<'connection> {
        self.tx
    }
    fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    fn header(&self) -> &wire::Header {
        &self.header
    }
    fn actor(&self) -> Actor {
        Actor::Owner(self.owner.user_id)
    }
    fn recheck(
        &mut self,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), ConversationError>> + Send + '_>> {
        Box::pin(async move {
            recheck_descriptor(
                self.tx,
                self.owner,
                &mut self.authority,
                &self.header,
                &self.descriptor,
            )
            .await
        })
    }
}

/// Current Owner/context proof for proposal-only metadata. This is deliberately
/// separate from ProposalFence/ActionFence and cannot make a phone effect permit.
pub(crate) struct ProviderProposal<'tx, 'connection> {
    tx: &'tx Transaction<'connection>,
    owner: &'tx SessionPrincipal,
    authority: CurrentAuthority<'tx, 'connection>,
    pub(crate) header: wire::Header,
    pub(crate) descriptor: super::action_profile::ProviderAction,
}
impl<'tx, 'connection> ProviderProposal<'tx, 'connection> {
    pub(crate) async fn checked(
        tx: &'tx Transaction<'connection>,
        owner: &'tx SessionPrincipal,
        descriptor: super::action_profile::ProviderAction,
    ) -> Result<Self, ConversationError> {
        let (authority, header) = super::fence::checked_provider(tx, owner, &descriptor).await?;
        Ok(Self {
            tx,
            owner,
            authority,
            header,
            descriptor,
        })
    }
    pub(crate) async fn recheck(&mut self) -> Result<(), ConversationError> {
        super::fence::recheck_provider(
            self.tx,
            self.owner,
            &mut self.authority,
            &self.header,
            &self.descriptor,
        )
        .await
    }
}
