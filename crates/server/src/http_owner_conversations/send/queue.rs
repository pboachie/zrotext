// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant atomic queue admission. Requires the separately allocated confirmation
//! record schema; it fails closed without it. No route or dispatcher calls this.
use super::{ConversationError, SessionPrincipal, authorize_in_transaction};
use crate::{
    inbound::InboundSession,
    sealed_envelope::{self, Profile},
    sealed_manifest_store::outbound::lock_current,
};
use sha2::{Digest, Sha256};
use tokio_postgres::Client;
use uuid::Uuid;
use zrotext_delivery_store::{
    AcceptOutcome, StoreError,
    sealed::{self, CandidateQueueInput},
};

pub struct ConfirmedPacket<'a> {
    pub envelope: &'a [u8],
    pub confirmation: &'a [u8],
    pub signature: &'a [u8],
}

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("confirmed conversation authority rejected")]
    Authorization(#[from] ConversationError),
    #[error("confirmed conversation queue rejected")]
    Store(#[from] StoreError),
    #[error("confirmed conversation storage unavailable")]
    Database(#[from] tokio_postgres::Error),
}

/// A queue commit is not phone execution or carrier evidence. Billing policy is
/// supplied by the trusted adapter, never by confirmation/request claims.
pub async fn enqueue_confirmed_send(
    client: &mut Client,
    owner: &SessionPrincipal,
    phone: InboundSession<'_>,
    billing_enabled: bool,
    packet: ConfirmedPacket<'_>,
) -> Result<AcceptOutcome, QueueError> {
    let tx = client.transaction().await?;
    if !lifecycle::validate(&tx).await? {
        return Err(ConversationError::Conflict.into());
    }
    // Follow established manifest -> billing customer -> account ordering before
    // the verifier acquires account/session/interval/line locks. No account ->
    // billing inversion is introduced against billing ingress or alpha admission.
    let authority = lock_current(&tx, owner.tenant.account_id())
        .await
        .map_err(ConversationError::from)?;
    let account = sealed::lock_account(&tx, owner.tenant.account_id(), billing_enabled).await?;
    drop(authority);
    let c = authorize_in_transaction(
        &tx,
        owner,
        phone,
        packet.envelope,
        packet.confirmation,
        packet.signature,
    )
    .await?;
    let confirmation_digest: [u8; 32] = Sha256::digest(c.transcript()?).into();
    let signature_digest: [u8; 32] = Sha256::digest(packet.signature).into();
    let old = tx.query_opt(
        "SELECT confirmation_digest,signature_digest,envelope_digest,interval_id,initiating_session_id, \
         device_id,line_id,binding_generation,trust_generation,manifest_version,manifest_digest,signer_key_id, \
         reader_key_id,body_digest,expires_at_ms,confirmation,signature FROM conversation_confirmation_records \
         WHERE account_id=$1 AND message_id=$2 FOR UPDATE", &[&c.account,&c.message],
    ).await?;
    if let Some(row) = &old {
        if row.get::<_, Vec<u8>>(0) != confirmation_digest
            || row.get::<_, Vec<u8>>(1) != signature_digest
            || row.get::<_, Vec<u8>>(2) != c.envelope_digest
            || row.get::<_, Uuid>(3) != c.interval
            || row.get::<_, Uuid>(4) != c.session
            || row.get::<_, Uuid>(5) != c.device
            || row.get::<_, Uuid>(6) != c.line
            || row.get::<_, i64>(7) != c.generation
            || row.get::<_, i64>(8) != c.trust_generation
            || row.get::<_, i64>(9) != c.version
            || row.get::<_, Vec<u8>>(10) != c.manifest
            || row.get::<_, Vec<u8>>(11) != c.signer
            || row.get::<_, Vec<u8>>(12) != c.reader
            || row.get::<_, Vec<u8>>(13) != c.body_digest
            || row.get::<_, i64>(14) != c.expires_ms
            || row
                .get::<_, Option<Vec<u8>>>(15)
                .is_some_and(|bytes| bytes != packet.confirmation)
            || row
                .get::<_, Option<Vec<u8>>>(16)
                .is_some_and(|bytes| bytes != packet.signature)
        {
            return Err(ConversationError::Conflict.into());
        }
    } else if tx
        .query_opt(
            "SELECT 1 FROM messages WHERE account_id=$1 AND id=$2",
            &[&c.account, &c.message],
        )
        .await?
        .is_some()
    {
        // A generic sealed message cannot acquire conversation authority later.
        return Err(ConversationError::Conflict.into());
    }
    let e = sealed_envelope::parse(packet.envelope, Profile::Draft02Candidate)
        .map_err(|_| ConversationError::Invalid)?;
    let unsigned_digest: [u8; 32] = Sha256::digest(e.unsigned).into();
    let outcome = account
        .enqueue(&CandidateQueueInput {
            message_id: c.message,
            device_id: c.device,
            line_id: c.line,
            binding_generation: c.generation,
            manifest_generation: c.trust_generation,
            manifest_version: c.version,
            manifest_digest: &c.manifest,
            signer_key_id: &c.signer,
            unsigned_digest: &unsigned_digest,
            recipient: &c.peer,
            envelope: packet.envelope,
            expires_at_ms: c.expires_ms,
        })
        .await?;
    if old.is_none() {
        if !outcome.created {
            return Err(ConversationError::Conflict.into());
        }
        tx.execute("INSERT INTO conversation_confirmation_records(account_id,message_id,interval_id,initiating_session_id,device_id,line_id, \
            binding_generation,trust_generation,manifest_version,manifest_digest,signer_key_id,reader_key_id,body_digest, \
            expires_at_ms,envelope_digest,confirmation_digest,signature_digest,confirmation,signature) \
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
            &[&c.account,&c.message,&c.interval,&c.session,&c.device,&c.line,&c.generation,&c.trust_generation,&c.version,
              &c.manifest.as_slice(),&c.signer.as_slice(),&c.reader.as_slice(),&c.body_digest.as_slice(),&c.expires_ms,
              &c.envelope_digest.as_slice(),&confirmation_digest.as_slice(),&signature_digest.as_slice(),&packet.confirmation,&packet.signature]).await?;
    } else if outcome.created {
        return Err(ConversationError::Conflict.into());
    }
    // Repeat complete current authorization after queue/quota/proof insert waits.
    // Any expired session, phone lease, manifest or intent rolls all writes back.
    let checked = authorize_in_transaction(
        &tx,
        owner,
        phone,
        packet.envelope,
        packet.confirmation,
        packet.signature,
    )
    .await?;
    if checked != c {
        return Err(ConversationError::Forbidden.into());
    }
    tx.commit().await?;
    Ok(outcome)
}

pub(crate) mod lifecycle;
#[cfg(test)]
mod tests;
