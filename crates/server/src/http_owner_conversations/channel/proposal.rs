// SPDX-License-Identifier: AGPL-3.0-only
//! Exact original proposal and signed successor retrieval, never capture admission.
use super::*;
use crate::sealed_manifest_store::outbound::lock_current;

pub(super) async fn handle(
    client: &mut Client,
    authenticated: &AuthenticatedChannelSession<'_>,
    challenge: Uuid,
    bytes: &[u8],
) -> Result<Vec<u8>, ConversationError> {
    let interval = Uuid::from_slice(&bytes[118..134]).map_err(|_| ConversationError::Invalid)?;
    if interval.is_nil() {
        return Err(ConversationError::Invalid);
    }
    let tx = client.transaction().await?;
    let mut authority = lock_current(&tx, authenticated.device.account_id).await?;
    live(&tx, authenticated.device).await?;
    let row = activation::load(&tx, authenticated.device.account_id, interval)
        .await
        .map_err(|error| match error {
            ConversationError::Database(_) => error,
            _ => ConversationError::Forbidden,
        })?;
    let statement = &row.statement;
    if !matches!(row.phase.as_str(), "pending" | "install_pending")
        || authenticated.device.device_id != statement.device
        || authenticated.device.site_id != statement.site
        || authenticated.device.instance_id != statement.instance
        || authenticated.device.connection_epoch != statement.connection_epoch
        || authenticated.device.deployment_epoch != statement.deployment_epoch
        || authority.generation() != statement.trust_generation
    {
        return Err(ConversationError::Forbidden);
    }
    activation::origin(&tx, statement).await?;
    activation::device_live(&tx, authenticated.device, statement).await?;
    let readers = activation::readers(statement);
    let wanted = activation::wanted(statement, interval, &readers);
    let position = authority.snapshot(&wanted).await?;
    if row.phase == "pending" {
        if position.version != statement.predecessor_version
            || position.digest != statement.predecessor_digest
        {
            return Err(ConversationError::Forbidden);
        }
        let successor = authority
            .next_inbound_snapshot(&row.manifest, &wanted)
            .await?;
        if successor.version != statement.activation_version
            || successor.digest != statement.activation_digest
        {
            return Err(ConversationError::Forbidden);
        }
    } else if position.version != statement.activation_version
        || position.digest != statement.activation_digest
        || position.bytes != row.manifest
    {
        return Err(ConversationError::Forbidden);
    }
    if authority
        .conversation_keys(statement.device, statement.line)
        .await?
        != (statement.reader, statement.signer)
    {
        return Err(ConversationError::Forbidden);
    }
    let original: Vec<u8> = tx
        .query_one(
            "SELECT statement FROM conversation_intervals WHERE account_id=$1 AND id=$2",
            &[&statement.account, &interval],
        )
        .await?
        .get(0);
    if !(380..=1024).contains(&original.len())
        || !(364..=9751).contains(&row.manifest.len())
        || activation::Statement::decode(&original)? != *statement
    {
        return Err(ConversationError::Forbidden);
    }
    // Every blocking lookup precedes the final expiry sample. Return stored bytes unchanged.
    live(&tx, authenticated.device).await?;
    activation::origin(&tx, statement).await?;
    activation::device_live(&tx, authenticated.device, statement).await?;
    authority.inbound_context(&wanted).await?;
    if row.phase == "pending" {
        authority
            .next_inbound_snapshot(&row.manifest, &wanted)
            .await?;
    }
    if activation::now(&tx).await? >= statement.expires_ms {
        return Err(ConversationError::Forbidden);
    }
    drop(authority);
    tx.commit().await?;
    let mut reply = header(authenticated, 17, challenge)?;
    reply.extend_from_slice(&(original.len() as u16).to_be_bytes());
    reply.extend_from_slice(&original);
    reply.extend_from_slice(&(row.manifest.len() as u16).to_be_bytes());
    reply.extend_from_slice(&row.manifest);
    Ok(reply)
}

#[cfg(test)]
mod tests;
