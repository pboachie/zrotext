// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant candidate-02 ingest transaction; no transport calls this module.
//! Independently provisioned owner trust and an active sealed line are required.
//! This stores opaque bytes only: no plaintext, webhook, grant or radio effect.

use crate::{
    inbound::{InboundSession, consume_storage_budget},
    sealed_envelope::{self, ExpectedRecipient, Kind, Profile, VerifyError},
    sealed_manifest::EnvelopeAuthority,
    sealed_manifest_store::{self, AdmissionError},
};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

const MAX_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const MAX_FUTURE_MS: i64 = 5 * 60 * 1000;

#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("invalid sealed inbound claims")]
    InvalidClaims,
    #[error("sealed authority rejected")]
    Authority(#[from] AdmissionError),
    #[error("sealed envelope verification failed")]
    Verification(#[from] VerifyError),
    #[error("sealed observed time outside acceptance window")]
    StaleEvent,
    #[error("sealed event identity conflict")]
    EventConflict,
    #[error("sealed device sequence conflict")]
    SequenceConflict,
    #[error("inbound storage budget exhausted")]
    BudgetExhausted,
    #[error("sealed ingest database operation failed")]
    Database(#[from] tokio_postgres::Error),
}

#[derive(Debug, PartialEq, Eq)]
pub struct IngestOutcome {
    pub event_id: Uuid,
    pub created: bool,
}

async fn check_age(tx: &Transaction<'_>, observed_ms: i64) -> Result<i64, IngestError> {
    let now: i64 = tx
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await?
        .get(0);
    if observed_ms <= 0
        || observed_ms < now.saturating_sub(MAX_AGE_MS)
        || observed_ms > now.saturating_add(MAX_FUTURE_MS)
    {
        return Err(IngestError::StaleEvent);
    }
    Ok(now)
}

/// Own admission, verification, durable replay fences and commit as one unit.
/// All errors roll back, including an authority advance staged before a rejected
/// envelope. A replay still requires current authority/session and valid event
/// age; it never replaces saved bytes or rehydrates purged ciphertext.
pub async fn ingest_candidate02(
    client: &mut Client,
    session: InboundSession<'_>,
    line: Uuid,
    binding_generation: i64,
    manifest_bytes: &[u8],
    envelope_bytes: &[u8],
) -> Result<IngestOutcome, IngestError> {
    // Parse before obtaining database locks. These are untrusted selectors until
    // manifest authorization and exact signature verification both pass below.
    let claims = sealed_envelope::parse(envelope_bytes, Profile::Draft02Candidate)
        .map_err(|_| IngestError::InvalidClaims)?;
    if claims.kind != Kind::Inbound {
        return Err(IngestError::InvalidClaims);
    }
    let event_id = Uuid::from_slice(claims.event_id.ok_or(IngestError::InvalidClaims)?)
        .map_err(|_| IngestError::InvalidClaims)?;
    if event_id.is_nil() {
        return Err(IngestError::InvalidClaims);
    }
    let sequence = claims.local_sequence.ok_or(IngestError::InvalidClaims)? as i64;
    let observed_ms = claims.observed_ms as i64;
    let recipients: Vec<ExpectedRecipient> = claims
        .wraps
        .iter()
        .map(|wrap| {
            Ok(ExpectedRecipient {
                role: wrap.role,
                key_id: wrap
                    .key_id
                    .try_into()
                    .map_err(|_| IngestError::InvalidClaims)?,
            })
        })
        .collect::<Result<_, IngestError>>()?;
    let wanted = EnvelopeAuthority {
        kind: Kind::Inbound,
        account_id: *session.account_id.as_bytes(),
        device_id: *session.device_id.as_bytes(),
        line_id: *line.as_bytes(),
        message_id: *event_id.as_bytes(),
        signer_key_id: claims
            .signer_key_id
            .try_into()
            .map_err(|_| IngestError::InvalidClaims)?,
        peer: claims.peer,
        recipients: &recipients,
    };
    let tx = client.transaction().await?;
    let mut admission =
        sealed_manifest_store::admit(&tx, session, line, binding_generation, manifest_bytes)
            .await?;
    let context = admission.context(&wanted).await?;
    let verified = sealed_envelope::verify(envelope_bytes, &context)?;
    let received_ms = check_age(&tx, observed_ms).await?;
    // Charge the shared account/device storage budget before the INSERT, in
    // this transaction, so a saturated budget never writes envelope bytes. An
    // already stored event is a free replay. The savepoint returns the charge
    // if a concurrent writer stores the same event first.
    let stored = tx
        .query_opt(
            "SELECT 1 FROM sealed_inbound_events WHERE account_id=$1 AND id=$2",
            &[&session.account_id, &event_id],
        )
        .await?
        .is_some();
    if !stored {
        tx.batch_execute("SAVEPOINT sealed_inbound_budget").await?;
        if !consume_storage_budget(&tx, session.account_id, session.device_id).await? {
            return Err(IngestError::BudgetExhausted);
        }
    }
    // All unique constraints remain race authorities, including a collision with
    // a different tenant's globally allocated event UUID. Never read its content.
    let inserted = tx.query_opt(
        "INSERT INTO sealed_inbound_events(id,account_id,device_id,line_id,binding_generation, \
         device_sequence,observed_at,received_at,part_count,envelope,unsigned_digest,envelope_profile) \
         VALUES($1,$2,$3,$4,$5,$6,to_timestamp($7::bigint::double precision/1000), \
         to_timestamp($8::bigint::double precision/1000),NULL,$9,$10,2) \
         ON CONFLICT DO NOTHING RETURNING id",
        &[&event_id,&session.account_id,&session.device_id,&line,&binding_generation,&sequence,
          &observed_ms,&received_ms,&envelope_bytes,&verified.unsigned_digest().as_slice()],
    ).await?;
    if inserted.is_none() {
        if !stored {
            tx.batch_execute("ROLLBACK TO SAVEPOINT sealed_inbound_budget")
                .await?;
        }
        let same_event = tx
            .query_opt(
                "SELECT device_id,line_id,device_sequence,unsigned_digest,envelope_profile \
             FROM sealed_inbound_events WHERE account_id=$1 AND id=$2 FOR SHARE",
                &[&session.account_id, &event_id],
            )
            .await?;
        if let Some(row) = same_event {
            if row.get::<_,Uuid>(0) != session.device_id || row.get::<_,Uuid>(1) != line
                || row.get::<_,i64>(2) != sequence || row.get::<_,Vec<u8>>(3).as_slice() != verified.unsigned_digest().as_slice()
                || row.get::<_,i16>(4) != 2
            {
                return Err(IngestError::EventConflict);
            }
        } else if tx.query_opt(
            "SELECT 1 FROM sealed_inbound_events WHERE account_id=$1 AND device_id=$2 AND device_sequence=$3",
            &[&session.account_id,&session.device_id,&sequence],
        ).await?.is_some() {
            return Err(IngestError::SequenceConflict);
        } else {
            return Err(IngestError::EventConflict);
        }
    }
    // INSERT/uniqueness checks and replay-row locks can wait after earlier time
    // checks. Recheck all temporal authority immediately before committing either
    // outcome. Held row locks serialize revocation/rebinding/session replacement.
    check_age(&tx, observed_ms).await?;
    admission.context(&wanted).await?;
    drop(admission);
    tx.commit().await?;
    Ok(IngestOutcome {
        event_id,
        created: inserted.is_some(),
    })
}

#[cfg(test)]
mod tests;
