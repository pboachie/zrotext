// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant atomic existing-root browser signer installation. No root generation or route.
use super::{ConversationError, SessionPrincipal, fresh_owner, lock_line, lock_owner};
use crate::sealed_manifest_store::outbound::lock_current;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

pub struct Enrollment {
    pub device: Uuid,
    pub line: Uuid,
    pub generation: i64,
    pub originating_session: Uuid,
    pub peer: String,
    pub phone_reader: [u8; 32],
    pub archive_reader: [u8; 32],
    pub signer: [u8; 32],
    pub public_point: [u8; 65],
    pub predecessor: [u8; 32],
}
impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Enrollment(redacted)")
    }
}
async fn consent(
    tx: &Transaction<'_>,
    account: Uuid,
    r: &Enrollment,
) -> Result<(), ConversationError> {
    tx.query_opt("SELECT 1 FROM owner_conversation_consents WHERE account_id=$1 AND device_id=$2 AND line_id=$3 AND binding_generation=$4 AND peer=$5 AND disclosure_version='conversation-content-v1' AND revoked_at IS NULL FOR SHARE",
        &[&account,&r.device,&r.line,&r.generation,&r.peer]).await?.ok_or(ConversationError::Forbidden)?;
    Ok(())
}
/// Root-signed successor is independently verified under manifest-before-account locks.
/// CAS, owner/session, selected consent, line and reader authority all share this transaction.
/// Installing a role-5 key never activates capture or authorizes sending.
pub async fn install(
    client: &mut Client,
    owner: &SessionPrincipal,
    r: &Enrollment,
    signed_successor: &[u8],
) -> Result<(), ConversationError> {
    if r.originating_session != owner.session_id
        || r.device.is_nil()
        || r.line.is_nil()
        || r.generation <= 0
    {
        return Err(ConversationError::Forbidden);
    }
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, owner.tenant.account_id()).await?;
    lock_owner(&tx, owner).await?;
    lock_line(
        &tx,
        owner.tenant.account_id(),
        r.device,
        r.line,
        r.generation,
    )
    .await?;
    consent(&tx, owner.tenant.account_id(), r).await?;
    authority
        .install_browser_successor(signed_successor, r)
        .await?;
    fresh_owner(&tx, owner).await?;
    lock_line(
        &tx,
        owner.tenant.account_id(),
        r.device,
        r.line,
        r.generation,
    )
    .await?;
    consent(&tx, owner.tenant.account_id(), r).await?;
    authority
        .recheck_installed_successor(signed_successor, r)
        .await?;
    drop(authority);
    commit_verified(tx, owner).await?;
    Ok(())
}
async fn commit_verified(
    tx: Transaction<'_>,
    owner: &SessionPrincipal,
) -> Result<(), ConversationError> {
    fresh_owner(&tx, owner).await?; // Locks do not freeze expiry during successor verification.
    tx.commit().await?;
    Ok(())
}
#[cfg(test)]
mod tests;
