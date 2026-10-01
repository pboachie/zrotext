// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated delivery of an already user-confirmed packet. Never claims or executes a job.
use super::*;
use crate::http_owner_conversations::send::{self, Confirmation};
use crate::sealed_manifest_store::outbound::lock_current;

pub(super) async fn handle(
    client: &mut Client,
    authenticated: &AuthenticatedChannelSession<'_>,
    challenge: Uuid,
    bytes: &[u8],
) -> Result<Vec<u8>, ConversationError> {
    let interval = Uuid::from_slice(bytes.get(166..182).ok_or(ConversationError::Invalid)?)
        .map_err(|_| ConversationError::Invalid)?;
    let tx = client.transaction().await?;
    // Maintain the common manifest -> account -> interval -> proof/message lock order.
    let authority = lock_current(&tx, authenticated.device.account_id).await?;
    live(&tx, authenticated.device).await?;
    let row = activation::load(&tx, authenticated.device.account_id, interval).await?;
    let expected = scope(&row.statement)?;
    let start = 118 + expected.len();
    if row.phase != "active"
        || row.statement.device != authenticated.device.device_id
        || bytes.get(118..start) != Some(expected.as_slice())
        || bytes.len() != start + 16
    {
        return Err(ConversationError::Forbidden);
    }
    let message = Uuid::from_slice(&bytes[start..]).map_err(|_| ConversationError::Invalid)?;
    if message.is_nil() {
        return Err(ConversationError::Invalid);
    }
    let stored = tx.query_opt(
        "SELECT p.confirmation,p.signature,m.transport_payload,p.initiating_session_id \
         FROM conversation_confirmation_records p JOIN messages m ON (m.account_id,m.id)=(p.account_id,p.message_id) \
         WHERE p.account_id=$1 AND p.message_id=$2 AND p.device_id=$3 AND p.interval_id=$4 \
         AND m.device_id=$3 AND m.transport_mode='sealed_candidate02' AND m.state='queued' FOR SHARE OF p,m",
        &[&authenticated.device.account_id,&message,&authenticated.device.device_id,&interval],
    ).await?.ok_or(ConversationError::Forbidden)?;
    let confirmation: Option<Vec<u8>> = stored.get(0);
    let signature: Option<Vec<u8>> = stored.get(1);
    let envelope: Option<Vec<u8>> = stored.get(2);
    let confirmation = confirmation.ok_or(ConversationError::Forbidden)?;
    let signature = signature.ok_or(ConversationError::Forbidden)?;
    let envelope = envelope.ok_or(ConversationError::Forbidden)?;
    let origin: Uuid = stored.get(3);
    drop(authority);
    let verified = send::authorize_delivery(
        &tx,
        authenticated.device,
        origin,
        &envelope,
        &confirmation,
        &signature,
    )
    .await?;
    if verified.message != message || verified.interval != interval {
        return Err(ConversationError::Forbidden);
    }
    let container = pack(&envelope, &confirmation, &signature)?;
    // Recheck after proof/message locks and cryptographic work, before committing the read grant.
    live(&tx, authenticated.device).await?;
    activation::origin(&tx, &row.statement).await?;
    if activation::now(&tx).await? >= verified.expires_ms {
        return Err(ConversationError::Forbidden);
    }
    tx.commit().await?;
    let mut reply = header(authenticated, 15, challenge)?;
    reply.extend_from_slice(&(container.len() as u32).to_be_bytes());
    reply.extend_from_slice(&container);
    Ok(reply)
}

fn pack(
    envelope: &[u8],
    confirmation: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, ConversationError> {
    Confirmation::decode(confirmation)?;
    if envelope.is_empty() || envelope.len() > 39_000 || signature.len() != 64 {
        return Err(ConversationError::Invalid);
    }
    let mut out = b"ZTCR\x01".to_vec();
    out.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    out.extend_from_slice(envelope);
    out.extend_from_slice(&(confirmation.len() as u16).to_be_bytes());
    out.extend_from_slice(confirmation);
    out.extend_from_slice(signature);
    if out.len() > 40_000 {
        return Err(ConversationError::Invalid);
    }
    Ok(out)
}
