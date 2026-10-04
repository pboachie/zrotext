// SPDX-License-Identifier: AGPL-3.0-only
use super::{ConversationError, Statement, load, origin};
use crate::{
    inbound::InboundSession, sealed_envelope::Envelope,
    sealed_manifest_store::outbound::ManifestSnapshot,
};
use tokio_postgres::Transaction;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct CaptureInterval {
    pub interval: Uuid,
    pub activation_digest: [u8; 32],
}

pub(crate) async fn check_capture(
    tx: &Transaction<'_>,
    session: InboundSession<'_>,
    selector: CaptureInterval,
    claims: &Envelope<'_>,
    generation: i64,
) -> Result<Statement, ConversationError> {
    let raw:Vec<u8>=tx.query_opt("SELECT statement FROM conversation_intervals WHERE account_id=$1 AND id=$2 AND phase='active'", &[&session.account_id,&selector.interval]).await?.ok_or(ConversationError::Forbidden)?.get(0);
    let s = Statement::decode(&raw)?;
    origin(tx, &s).await?;
    let interval = load(tx, session.account_id, selector.interval).await?;
    if interval.phase != "active"
        || interval.accepted_ms.is_none()
        || s.device != session.device_id
        || s.generation != generation
        || claims.account_id != s.account.as_bytes()
        || claims.device_id != s.device.as_bytes()
        || claims.line_id != s.line.as_bytes()
        || selector.activation_digest != s.activation_digest
        || claims.peer != s.peer.as_bytes()
        || claims.signer_key_id != s.signer
        || claims.keyset_version < s.activation_version as u64
        || claims.wraps.len() != super::readers(&s).len()
        || claims
            .wraps
            .iter()
            .zip(super::readers(&s))
            .any(|(wrap, reader)| wrap.role != reader.role || wrap.key_id != reader.key_id)
    {
        return Err(ConversationError::Forbidden);
    }
    super::selected::check_grants(tx, &s).await?;
    Ok(s)
}

pub(crate) async fn save_provenance(
    tx: &Transaction<'_>,
    s: &Statement,
    event: Uuid,
    snapshot: &ManifestSnapshot,
    created: bool,
) -> Result<(), ConversationError> {
    if snapshot.generation != s.trust_generation || snapshot.version < s.activation_version {
        return Err(ConversationError::Forbidden);
    }
    if created {
        tx.execute("INSERT INTO conversation_inbound_provenance(account_id,event_id,interval_id,trust_generation,manifest_version,manifest_digest,verified_manifest,accepted_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
            &[&s.account,&event,&s.interval,&snapshot.generation,&snapshot.version,&snapshot.digest.as_slice(),&snapshot.bytes,&snapshot.accepted_ms]).await?;
    } else {
        // Replay never creates missing provenance (including after ciphertext purge).
        let row=tx.query_opt("SELECT p.interval_id,p.trust_generation,p.manifest_version,p.manifest_digest FROM conversation_inbound_provenance p \
            JOIN sealed_inbound_events e ON (e.account_id,e.id)=(p.account_id,p.event_id) WHERE p.account_id=$1 AND p.event_id=$2 AND e.envelope IS NOT NULL FOR SHARE OF p", &[&s.account,&event]).await?;
        if let Some(row) = row
            && row.get::<_, Uuid>(0) == s.interval
            && row.get::<_, i64>(1) == snapshot.generation
            && row.get::<_, i64>(2) == snapshot.version
            && row.get::<_, Vec<u8>>(3) == snapshot.digest
        {
            return Ok(());
        }
        return Err(ConversationError::Forbidden);
    }
    Ok(())
}
