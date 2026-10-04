// SPDX-License-Identifier: AGPL-3.0-only
use super::super::{
    ConversationError, SessionPrincipal, activation, authorize, fresh_owner, load, lock_current,
    lock_owner, wire,
};
use super::{ActionKey, Descriptor, descriptor::decode_digest};
use crate::sealed_manifest_store::outbound::CurrentAuthority;
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;
use uuid::Uuid;
mod binding;

pub(crate) async fn recheck_descriptor(
    tx: &Transaction<'_>,
    owner: &SessionPrincipal,
    authority: &mut CurrentAuthority<'_, '_>,
    header: &wire::Header,
    d: &Descriptor,
) -> Result<(), ConversationError> {
    authorize(tx, owner, authority, header, true).await?;
    contact(tx, d, header).await?;
    if activation::now(tx).await? >= d.expires_at_ms()? {
        return Err(ConversationError::Forbidden);
    }
    fresh_owner(tx, owner).await
}

pub(crate) async fn checked_descriptor<'tx, 'connection>(
    tx: &'tx Transaction<'connection>,
    owner: &SessionPrincipal,
    descriptor: &Descriptor,
) -> Result<(CurrentAuthority<'tx, 'connection>, wire::Header), ConversationError> {
    let ids = descriptor.identities()?;
    if descriptor.key()?.account_id != owner.tenant.account_id() {
        return Err(ConversationError::NotFound);
    }
    let mut authority = lock_current(tx, owner.tenant.account_id()).await?;
    lock_owner(tx, owner).await?;
    let bytes = load(
        tx,
        owner.tenant.account_id(),
        ids.content,
        Some(descriptor.content_version),
    )
    .await?;
    let header = wire::parse(&bytes)?;
    if header.line != ids.line
        || Sha256::digest(&bytes).as_slice() != decode_digest(&descriptor.content_digest)?
        || descriptor.expires_at_ms()? > header.expires_ms
    {
        return Err(ConversationError::Forbidden);
    }
    authorize(tx, owner, &mut authority, &header, true).await?;
    contact(tx, descriptor, &header).await?;
    Ok((authority, header))
}

pub(crate) async fn contact(
    tx: &Transaction<'_>,
    descriptor: &Descriptor,
    header: &wire::Header,
) -> Result<(), ConversationError> {
    crate::original_reply::source::recheck(tx, descriptor).await?;
    let ids = descriptor.identities()?;
    contact_scope(tx, ids.recipient, descriptor.purpose()?, header)
        .await
        .map(|_| ())
}

/// A contact-purpose fence without manufacturing an action or SEND authority.
pub(crate) async fn contact_scope(
    tx: &Transaction<'_>,
    contact: Uuid,
    purpose: &str,
    header: &wire::Header,
) -> Result<i64, ConversationError> {
    let row = tx
        .query_opt(
            "SELECT recipient_e164 FROM contacts WHERE account_id=$1 AND id=$2 FOR SHARE",
            &[&header.account, &contact],
        )
        .await?
        .ok_or(ConversationError::NotFound)?;
    let peer: String = row.get(0);
    if Sha256::digest(peer.as_bytes()).as_slice() != header.peer_digest {
        return Err(ConversationError::Forbidden);
    }
    let consent=tx.query_opt("SELECT action,effective_at<=clock_timestamp(),expires_at IS NULL OR expires_at>clock_timestamp(),COALESCE(floor(extract(epoch FROM expires_at)*1000)::bigint,9223372036854775807::bigint) FROM contact_consent_records WHERE account_id=$1 AND contact_id=$2 AND purpose=$3 ORDER BY effective_at DESC,recorded_at DESC,id DESC LIMIT 1 FOR SHARE",
        &[&header.account,&contact,&purpose]).await?.ok_or(ConversationError::Forbidden)?;
    if consent.get::<_, String>(0) != "grant"
        || !consent.get::<_, bool>(1)
        || !consent.get::<_, bool>(2)
    {
        return Err(ConversationError::Forbidden);
    }
    if tx.query_one("SELECT EXISTS(SELECT 1 FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164=$2 AND active) OR EXISTS(SELECT 1 FROM owner_recipient_holds WHERE account_id=$1 AND recipient_e164=$2 AND released_at IS NULL)",
        &[&header.account,&peer]).await?.get::<_,bool>(0){return Err(ConversationError::Forbidden);}
    Ok(consent.get(3))
}

pub(crate) async fn live_routine(
    tx: &Transaction<'_>,
    descriptor: &Descriptor,
    header: &wire::Header,
) -> Result<(), ConversationError> {
    let ids = descriptor.identities()?;
    tx.query_opt("SELECT 1 FROM workflow_context_fences WHERE account_id=$1 AND context_id=$2 AND stopped_at IS NULL FOR UPDATE",
        &[&header.account,&header.context]).await?.ok_or(ConversationError::Forbidden)?;
    tx.query_opt("SELECT 1 FROM workflow_routines WHERE account_id=$1 AND id=$2 AND context_id=$3 AND generation=$4 AND stopped_at IS NULL FOR UPDATE",
        &[&header.account,&ids.routine,&header.context,&descriptor.authority_generation]).await?.ok_or(ConversationError::Forbidden)?;
    Ok(())
}

/// Unforgeable transaction-borrowed owner permit. Historical actor IDs cannot create it.
pub struct LockedAction<'tx, 'connection> {
    tx: &'tx Transaction<'connection>,
    owner: &'tx SessionPrincipal,
    authority: CurrentAuthority<'tx, 'connection>,
    header: wire::Header,
    descriptor: Descriptor,
    key: ActionKey,
}
pub async fn lock_approved<'tx, 'connection>(
    tx: &'tx Transaction<'connection>,
    owner: &'tx SessionPrincipal,
    key: ActionKey,
) -> Result<LockedAction<'tx, 'connection>, ConversationError> {
    key.validate()?;
    if key.account_id != owner.tenant.account_id() {
        return Err(ConversationError::NotFound);
    }
    let row=tx.query_opt("SELECT descriptor FROM workflow_action_versions WHERE account_id=$1 AND action_id=$2 AND revision=$3 AND binding_digest=$4",
        &[&key.account_id,&key.action_id,&key.revision,&&key.binding_digest[..]]).await?.ok_or(ConversationError::NotFound)?;
    let descriptor: Descriptor = serde_json::from_slice(&row.get::<_, Vec<u8>>(0))
        .map_err(|_| ConversationError::Unavailable)?;
    if descriptor.key()? != key {
        return Err(ConversationError::Unavailable);
    }
    let (authority, header) = checked_descriptor(tx, owner, &descriptor).await?;
    live_routine(tx, &descriptor, &header).await?;
    tx.query_opt("SELECT 1 FROM workflow_actions WHERE account_id=$1 AND id=$2 AND revision=$3 AND binding_digest=$4 AND phase='approved' FOR UPDATE",
        &[&key.account_id,&key.action_id,&key.revision,&&key.binding_digest[..]]).await?.ok_or(ConversationError::Conflict)?;
    let mut permit = LockedAction {
        tx,
        owner,
        authority,
        header,
        descriptor,
        key,
    };
    permit.recheck().await?;
    Ok(permit)
}
impl<'tx, 'connection> LockedAction<'tx, 'connection> {
    pub(crate) fn transaction(&self) -> &'tx Transaction<'connection> {
        self.tx
    }
    pub(crate) fn owner_actor(&self) -> Uuid {
        self.owner.user_id
    }
    pub(crate) fn actor_user_id(&self) -> Uuid {
        self.owner_actor()
    }
    pub fn actor_session_id(&self) -> Uuid {
        self.owner.session_id
    }
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }
    pub fn key(&self) -> ActionKey {
        self.key
    }
    pub fn context_id(&self) -> Uuid {
        self.header.context
    }
    pub fn routine_id(&self) -> Uuid {
        self.descriptor
            .identities()
            .expect("checked identity")
            .routine
    }
    pub fn routine_generation(&self) -> i64 {
        self.descriptor.authority_generation
    }
    pub fn expires_at_ms(&self) -> i64 {
        self.descriptor.expires_at_ms().expect("checked timestamp")
    }
    pub async fn recheck(&mut self) -> Result<(), ConversationError> {
        recheck_descriptor(
            self.tx,
            self.owner,
            &mut self.authority,
            &self.header,
            &self.descriptor,
        )
        .await?;
        live_routine(self.tx, &self.descriptor, &self.header).await?;
        let now = activation::now(self.tx).await?;
        if now >= self.expires_at_ms() {
            return Err(ConversationError::Forbidden);
        }
        fresh_owner(self.tx, self.owner).await
    }
    pub async fn mark_dispatching(
        &mut self,
        message: Uuid,
        dispatch: Uuid,
    ) -> Result<(), ConversationError> {
        self.recheck().await?;
        super::store::dispatch_transition(
            self.tx,
            &self.descriptor,
            self.header.context,
            super::proposal::Actor::Owner(self.owner.user_id),
            message,
            dispatch,
        )
        .await?;
        self.recheck().await
    }
}
