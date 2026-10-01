// SPDX-License-Identifier: AGPL-3.0-only
use super::{IntegrationPrincipal, Operation};
use crate::{auth::AuthError, http_owner_conversations::context::wire};
use sha2::{Digest, Sha256};
use tokio_postgres::Client;
use uuid::Uuid;

/// Return authenticated public context metadata only. Context ciphertext,
/// contact notes and credentials are never placed in access records.
pub async fn read_context_metadata(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    request: Uuid,
    context: Uuid,
) -> Result<wire::Header, AuthError> {
    Ok(read_context(
        client,
        principal,
        request,
        context,
        Operation::ContextMetadata,
    )
    .await?
    .0)
}

/// The only content returned is the separately owner-declared role-3 envelope.
/// The archive-reader representation never serves as a fallback.
pub async fn read_context_content(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    request: Uuid,
    context: Uuid,
) -> Result<Vec<u8>, AuthError> {
    read_context(
        client,
        principal,
        request,
        context,
        Operation::ContextContent,
    )
    .await?
    .1
    .ok_or(AuthError::Forbidden)
}

async fn read_context(
    client: &mut Client,
    principal: &IntegrationPrincipal,
    request: Uuid,
    context: Uuid,
    operation: Operation,
) -> Result<(wire::Header, Option<Vec<u8>>), AuthError> {
    principal.require(operation)?;
    let operation_bit = operation.bit();
    if request.is_nil() || context.is_nil() {
        return Err(AuthError::InvalidInput);
    }
    let account = principal.account_id();
    let tx = client.transaction().await?;
    tx.batch_execute("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
        .await?;
    let mut checked = super::scope::lock_scope(&tx, principal, context, operation).await?;
    let header = checked.header.clone();
    let reader = checked.reader;
    let projection = if operation == Operation::ContextContent {
        let stored=tx.query_opt("SELECT envelope,envelope_digest FROM workflow_connector_context_envelopes WHERE account_id=$1 AND grant_id=$2 AND context_id=$3 AND context_revision=$4 AND envelope IS NOT NULL FOR SHARE",
            &[&account,&principal.grant_id(),&context,&header.revision]).await?.ok_or(AuthError::Forbidden)?;
        let projection = stored.get::<_, Vec<u8>>(0);
        if Sha256::digest(&projection).as_slice() != stored.get::<_, Vec<u8>>(1) {
            return Err(AuthError::Forbidden);
        }
        let mut expected = header.clone();
        expected.reader = reader;
        if wire::parse(&projection).map_err(|_| AuthError::Forbidden)? != expected {
            return Err(AuthError::Forbidden);
        }
        Some(projection)
    } else {
        None
    };
    let digest = Sha256::digest(
        [
            b"ZT/workflow/context-read/v1\0".as_slice(),
            &operation_bit.to_be_bytes(),
            context.as_bytes(),
        ]
        .concat(),
    );
    checked
        .record_access(request, context, digest.as_slice())
        .await?;
    checked.recheck().await?;
    drop(checked);
    tx.commit().await?;
    Ok((header, projection))
}
