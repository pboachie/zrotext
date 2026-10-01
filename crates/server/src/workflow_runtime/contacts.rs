// SPDX-License-Identifier: AGPL-3.0-only
use super::{IntegrationPrincipal, Operation, scope};
use crate::auth::AuthError;
use serde::Serialize;
use tokio_postgres::Client;
use uuid::Uuid;

/// Permitted routing metadata only; no numbers, notes or content are decrypted.
#[derive(Serialize)]
pub struct ContactScope {
    pub contact_id: Uuid,
    pub purpose: String,
    pub peer_digest: [u8; 32],
}
pub async fn read_contact(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    request: Uuid,
    context: Uuid,
) -> Result<ContactScope, AuthError> {
    if request.is_nil() {
        return Err(AuthError::InvalidInput);
    }
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    let mut checked = scope::lock_scope(&tx, principal, context, Operation::ContactRead).await?;
    let contact = checked.contact();
    let row = tx
        .query_opt(
            "SELECT recipient_e164 FROM contacts WHERE account_id=$1 AND id=$2 FOR SHARE",
            &[&principal.account_id(), &contact],
        )
        .await?
        .ok_or(AuthError::Forbidden)?;
    use sha2::{Digest, Sha256};
    let peer: String = row.get(0);
    if Sha256::digest(peer.as_bytes()).as_slice() != checked.header.peer_digest {
        return Err(AuthError::Forbidden);
    }
    let result = ContactScope {
        contact_id: contact,
        purpose: checked.purpose(),
        peer_digest: checked.header.peer_digest,
    };
    let digest = Sha256::digest(
        [
            b"ZT/workflow/contact-read/v1\0".as_slice(),
            context.as_bytes(),
            contact.as_bytes(),
        ]
        .concat(),
    );
    checked
        .record_access(request, contact, digest.as_slice())
        .await?;
    checked.recheck().await?;
    drop(checked);
    tx.commit().await?;
    Ok(result)
}
