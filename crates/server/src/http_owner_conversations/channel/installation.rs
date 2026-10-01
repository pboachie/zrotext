// SPDX-License-Identifier: AGPL-3.0-only
//! Approval/install transport over the independently authenticated device connection.
use super::*;
pub(super) async fn handle(
    client: &mut Client,
    authenticated: &AuthenticatedChannelSession<'_>,
    kind: u8,
    challenge: Uuid,
    bytes: &[u8],
) -> Result<Vec<u8>, ConversationError> {
    let statement = if kind == 10 {
        let interval =
            Uuid::from_slice(&bytes[166..182]).map_err(|_| ConversationError::Invalid)?;
        let tx = client.transaction().await?;
        live(&tx, authenticated.device).await?;
        let row = activation::load(&tx, authenticated.device.account_id, interval).await?;
        if row.statement.device != authenticated.device.device_id
            || scope(&row.statement)? != bytes[118..]
        {
            return Err(ConversationError::Forbidden);
        }
        tx.commit().await?;
        row.statement
    } else {
        let length = usize::from(u16::from_be_bytes([bytes[118], bytes[119]]));
        let original = &bytes[120..120 + length];
        let signature = &bytes[120 + length..];
        let statement = activation::Statement::decode(original)?;
        if kind == 6 {
            activation::approve(client, authenticated.device, original, signature).await?;
        } else {
            activation::installed(client, authenticated.device, original, signature).await?;
        }
        statement
    };
    let mut reply = header(authenticated, if kind == 6 { 7 } else { 9 }, challenge)?;
    reply.extend_from_slice(&scope(&statement)?);
    if kind == 6 {
        // An approval ACK is not installed/active. Both server installation and
        // durable phone installation must finish before any receipt is eligible.
        let tx = client.transaction().await?;
        live(&tx, authenticated.device).await?;
        let row =
            activation::load(&tx, authenticated.device.account_id, statement.interval).await?;
        if row.statement != statement || !matches!(row.phase.as_str(), "install_pending" | "active")
        {
            return Err(ConversationError::Forbidden);
        }
        live(&tx, authenticated.device).await?;
        tx.commit().await?;
    } else {
        let lease =
            activation::active_lease(client, authenticated.device, statement.interval, challenge)
                .await?;
        if lease.statement_digest != statement.digest()?.to_vec()
            || lease.challenge != challenge
            || !(1..=60000).contains(&lease.valid_for_ms)
        {
            return Err(ConversationError::Forbidden);
        }
        reply.extend_from_slice(&lease.valid_for_ms.to_be_bytes());
    }
    Ok(reply)
}
#[cfg(test)]
mod tests;
