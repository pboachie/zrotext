// SPDX-License-Identifier: AGPL-3.0-only
//! Authenticated channel handlers; registration requires the explicit dormant socket router.
use super::{ConversationError, activation};
use crate::inbound::InboundSession;
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

/// Values supplied by the authenticated socket owner, never decoded from a request.
/// Phone-session UUID/origin must be established by the future negotiated connection adapter.
pub struct AuthenticatedChannelSession<'a> {
    pub device: InboundSession<'a>,
    pub phone_session: Uuid,
    pub origin_hash: [u8; 32],
}
fn header(
    s: &AuthenticatedChannelSession<'_>,
    kind: u8,
    challenge: Uuid,
) -> Result<Vec<u8>, ConversationError> {
    if s.phone_session.is_nil()
        || challenge.is_nil()
        || s.device.account_id.is_nil()
        || s.device.device_id.is_nil()
        || s.device.connection_epoch <= 0
        || s.device.deployment_epoch <= 0
    {
        return Err(ConversationError::Invalid);
    }
    let mut out = b"ZTCW\x01".to_vec();
    out.push(kind);
    for id in [s.device.account_id, s.device.device_id, s.phone_session] {
        out.extend_from_slice(id.as_bytes());
    }
    out.extend_from_slice(&s.device.connection_epoch.to_be_bytes());
    out.extend_from_slice(&s.device.deployment_epoch.to_be_bytes());
    out.extend_from_slice(&s.origin_hash);
    out.extend_from_slice(challenge.as_bytes());
    Ok(out)
}
fn request(
    s: &AuthenticatedChannelSession<'_>,
    bytes: &[u8],
) -> Result<(u8, Uuid), ConversationError> {
    if !(118..=48_000).contains(&bytes.len())
        || !matches!(bytes[5], 1 | 3 | 5 | 6 | 8 | 10 | 12 | 14 | 16 | 18)
    {
        return Err(ConversationError::Invalid);
    }
    let kind = bytes[5];
    let nonce = Uuid::from_slice(&bytes[102..118]).map_err(|_| ConversationError::Invalid)?;
    if header(s, kind, nonce)? != bytes[..118] {
        return Err(ConversationError::Forbidden);
    }
    if kind != 12 && bytes.len() > 1208
        || kind == 12 && bytes.len() < 375
        || kind == 14 && !(386..=399).contains(&bytes.len())
        || kind == 16 && bytes.len() != 134
        || kind == 18 && !(434..=447).contains(&bytes.len())
        || kind == 1 && bytes.len() != 118
        || kind == 3 && !(370..=383).contains(&bytes.len())
        || kind == 5
            && (bytes.len() < 500
                || usize::from(u16::from_be_bytes([bytes[118], bytes[119]])) != bytes.len() - 120)
        || matches!(kind, 6 | 8)
            && (bytes.len() < 564
                || usize::from(u16::from_be_bytes([bytes[118], bytes[119]])) + 184 != bytes.len())
        || kind == 10 && !(370..=383).contains(&bytes.len())
    {
        return Err(ConversationError::Invalid);
    }
    Ok((kind, nonce))
}
pub(super) fn scope(statement: &activation::Statement) -> Result<Vec<u8>, ConversationError> {
    statement.encode()?;
    let mut out = Vec::new();
    for id in [
        statement.account,
        statement.device,
        statement.line,
        statement.interval,
        statement.receipt,
        statement.originating_session,
    ] {
        out.extend_from_slice(id.as_bytes());
    }
    for n in [
        statement.generation,
        statement.trust_generation,
        statement.activation_version,
    ] {
        out.extend_from_slice(&n.to_be_bytes());
    }
    out.extend_from_slice(&Sha256::digest(
        activation::statement::DISCLOSURE_TEXT.as_bytes(),
    ));
    out.extend_from_slice(&statement.reader);
    out.extend_from_slice(&statement.activation_digest);
    out.extend_from_slice(&statement.digest()?);
    out.push(statement.peer.len() as u8);
    out.extend_from_slice(statement.peer.as_bytes());
    Ok(out)
}
async fn live(tx: &Transaction<'_>, s: InboundSession<'_>) -> Result<(), ConversationError> {
    tx.query_opt(
        "SELECT 1 FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR UPDATE",
        &[&s.account_id],
    )
    .await?
    .ok_or(ConversationError::Forbidden)?;
    tx.query_opt("SELECT 1 FROM device_sessions s JOIN devices d ON (d.account_id,d.id)=(s.account_id,s.device_id) \
        JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN sites t ON t.site_id=s.site_id \
        JOIN deployment_authority p ON p.singleton=TRUE WHERE s.account_id=$1 AND s.device_id=$2 \
        AND s.site_id=$3 AND s.instance_id=$4 AND s.connection_epoch=$5 AND s.deployment_epoch=$6 \
        AND s.lease_until>clock_timestamp() AND d.revoked_at IS NULL AND k.revoked_at IS NULL \
        AND t.enabled=TRUE AND t.draining=FALSE AND p.epoch=$6 AND NOT pg_is_in_recovery() FOR SHARE OF s,d,k,t,p",
        &[&s.account_id,&s.device_id,&s.site_id,&s.instance_id,&s.connection_epoch,&s.deployment_epoch]).await?.ok_or(ConversationError::Forbidden)?;
    Ok(())
}
/// Recover only the acknowledgement of an already durable closure. Cleared
/// statements are reconstructed from the phone's canonical original, bound to
/// the immutable approval digest and independently checked retained scope.
async fn closed_scope(
    tx: &Transaction<'_>,
    s: InboundSession<'_>,
    original: &[u8],
) -> Result<Vec<u8>, ConversationError> {
    let statement = activation::Statement::decode(original)?;
    if statement.account != s.account_id || statement.device != s.device_id {
        return Err(ConversationError::Forbidden);
    }
    let row = tx.query_opt(
        "SELECT statement_digest,device_id,line_id,binding_generation,receipt_id,initiating_session_id, \
         trust_generation,activation_version,activation_digest,expires_at_ms,phase,closed_at IS NOT NULL,statement \
         FROM conversation_intervals WHERE account_id=$1 AND id=$2 FOR UPDATE",
        &[&s.account_id, &statement.interval],
    ).await?.ok_or(ConversationError::Forbidden)?;
    if row.get::<_, Vec<u8>>(0) != statement.digest()?
        || row.get::<_, Uuid>(1) != statement.device
        || row.get::<_, Uuid>(2) != statement.line
        || row.get::<_, i64>(3) != statement.generation
        || row.get::<_, Uuid>(4) != statement.receipt
        || row.get::<_, Uuid>(5) != statement.originating_session
        || row.get::<_, i64>(6) != statement.trust_generation
        || row.get::<_, i64>(7) != statement.activation_version
        || row.get::<_, Vec<u8>>(8) != statement.activation_digest
        || row.get::<_, i64>(9) != statement.expires_ms
        || !matches!(
            row.get::<_, String>(10).as_str(),
            "history" | "expired" | "withdrawn"
        )
        || !row.get::<_, bool>(11)
        || row
            .get::<_, Option<Vec<u8>>>(12)
            .is_some_and(|saved| saved != original)
    {
        return Err(ConversationError::Forbidden);
    }
    scope(&statement)
}
/// Returns bytes only AFTER durable commit. Socket write alone never means interval closure.
/// Stop preserves retained history; it is not withdrawal/deletion, nor owner read authority.
pub async fn handle(
    client: &mut Client,
    authenticated: &AuthenticatedChannelSession<'_>,
    bytes: &[u8],
) -> Result<Vec<u8>, ConversationError> {
    let (kind, challenge) = request(authenticated, bytes)?;
    if kind == 16 {
        return proposal::handle(client, authenticated, challenge, bytes).await;
    }
    if kind == 12 {
        return capture::handle(client, authenticated, challenge, bytes).await;
    }
    if kind == 14 {
        return delivery::handle(client, authenticated, challenge, bytes).await;
    }
    if kind == 18 {
        return execution::handle(client, authenticated, challenge, bytes).await;
    }
    if matches!(kind, 6 | 8 | 10) {
        return installation::handle(client, authenticated, kind, challenge, bytes).await;
    }
    let tx = client.transaction().await?;
    if kind == 3 {
        // Same manifest-before-account lock order as capture; revocation does not prevent a stop.
        tx.query_opt(
            "SELECT 1 FROM sealed_manifest_authorities WHERE account_id=$1 FOR UPDATE",
            &[&authenticated.device.account_id],
        )
        .await?;
    }
    live(&tx, authenticated.device).await?;
    let mut reply = header(authenticated, if kind == 1 { 2 } else { 4 }, challenge)?;
    if kind == 1 {
        reply.extend_from_slice(&activation::now(&tx).await?.to_be_bytes());
    } else if kind == 5 {
        // A fresh authenticated request may recover a lost ACK after pending
        // closure cleared the statement. It never transitions any interval.
        reply.extend_from_slice(&closed_scope(&tx, authenticated.device, &bytes[120..]).await?);
        reply.push(1);
    } else {
        let interval =
            Uuid::from_slice(&bytes[166..182]).map_err(|_| ConversationError::Invalid)?;
        let row = activation::load(&tx, authenticated.device.account_id, interval).await?;
        let expected = scope(&row.statement)?;
        if bytes[118..] != expected || row.statement.device != authenticated.device.device_id {
            return Err(ConversationError::Forbidden);
        }
        let next = match row.phase.as_str() {
            "active" => "history",
            "pending" | "install_pending" => "expired",
            "history" => "history",
            _ => return Err(ConversationError::Forbidden),
        };
        tx.execute("UPDATE conversation_intervals SET phase=$3,statement=CASE WHEN $3='expired' THEN NULL ELSE statement END,closed_at=COALESCE(closed_at,clock_timestamp()) WHERE account_id=$1 AND id=$2",
            &[&authenticated.device.account_id,&interval,&next]).await?;
        reply.extend_from_slice(&expected);
        reply.push(1);
    }
    live(&tx, authenticated.device).await?;
    tx.commit().await?;
    Ok(reply)
}

mod capture;
mod delivery;
pub(crate) mod execution;
mod installation;
mod proposal;
#[cfg(test)]
mod tests;
