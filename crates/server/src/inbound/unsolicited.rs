// SPDX-License-Identifier: AGPL-3.0-only
//! Internal attempt-free, line-bound STOP/review transaction. No transport
//! invokes this yet. The sender is a signed device declaration, not an
//! independently verified carrier identity; no SMS body is stored.

use super::{InboundSession, consume_storage_budget};
use crate::sealed_inbound::line_binding_ready;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio_postgres::{Client, error::SqlState};
use uuid::Uuid;

const DOMAIN: &[u8] = b"zrotext-line-opt-out-v1\0";
const MAX_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const MAX_FUTURE_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Stop,
    Review,
}

impl Action {
    fn code(self) -> u8 {
        match self {
            Self::Stop => 1,
            Self::Review => 2,
        }
    }

    fn source(self) -> &'static str {
        match self {
            Self::Stop => "sms_unsolicited_keyword",
            Self::Review => "sms_unsolicited_review",
        }
    }

    fn classification(self) -> &'static str {
        match self {
            Self::Stop => "opt_out",
            Self::Review => "opt_out_review",
        }
    }
}

#[derive(Clone, Copy)]
pub struct LineOptOut<'a> {
    pub id: Uuid,
    pub line_id: Uuid,
    pub binding_generation: i64,
    /// Sequence is independent from the attempt-bound inbound stream.
    pub sequence: i64,
    pub recipient_e164: &'a str,
    pub action: Action,
    pub observed_at_ms: i64,
    pub signature_der: &'a [u8],
}

#[derive(Debug, Error)]
pub enum LineOptOutError {
    #[error("invalid line opt-out input")]
    InvalidInput,
    #[error("line or writer session unavailable")]
    Unauthorized,
    #[error("invalid device signature")]
    InvalidSignature,
    #[error("event ID was reused with different content")]
    EventConflict,
    #[error("device sequence was reused")]
    SequenceConflict,
    #[error("inbound storage budget exhausted")]
    BudgetExhausted,
    #[error("line opt-out storage failed")]
    Database(#[from] tokio_postgres::Error),
}

fn valid_e164(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=16).contains(&bytes.len())
        && bytes[0] == b'+'
        && (b'1'..=b'9').contains(&bytes[1])
        && bytes[2..].iter().all(u8::is_ascii_digit)
}

fn validate(event: &LineOptOut<'_>) -> Result<(), LineOptOutError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| LineOptOutError::InvalidInput)?
        .as_millis() as i64;
    if event.id.is_nil()
        || event.line_id.is_nil()
        || event.binding_generation <= 0
        || event.sequence <= 0
        || !valid_e164(event.recipient_e164)
        || event.observed_at_ms < now - MAX_AGE_MS
        || event.observed_at_ms > now + MAX_FUTURE_MS
        || !(8..=80).contains(&event.signature_der.len())
    {
        return Err(LineOptOutError::InvalidInput);
    }
    Ok(())
}

/// Exact signed bytes: domain, account/device/line/event UUIDs, line
/// generation and independent sequence as big-endian i64, observed time as
/// big-endian i64, one action byte, then u8 byte length and ASCII E.164.
/// Neither the SMS body nor an outbound message/attempt ID appears here.
pub fn signed_line_opt_out_bytes(
    session: InboundSession<'_>,
    event: &LineOptOut<'_>,
) -> Result<Vec<u8>, LineOptOutError> {
    if session.account_id.is_nil()
        || session.device_id.is_nil()
        || !valid_e164(event.recipient_e164)
        || event.id.is_nil()
        || event.line_id.is_nil()
        || event.binding_generation <= 0
        || event.sequence <= 0
    {
        return Err(LineOptOutError::InvalidInput);
    }
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 16 * 4 + 8 * 3 + 2 + 16);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(session.account_id.as_bytes());
    bytes.extend_from_slice(session.device_id.as_bytes());
    bytes.extend_from_slice(event.line_id.as_bytes());
    bytes.extend_from_slice(&event.binding_generation.to_be_bytes());
    bytes.extend_from_slice(event.id.as_bytes());
    bytes.extend_from_slice(&event.sequence.to_be_bytes());
    bytes.extend_from_slice(&event.observed_at_ms.to_be_bytes());
    bytes.push(event.action.code());
    bytes.push(event.recipient_e164.len() as u8);
    bytes.extend_from_slice(event.recipient_e164.as_bytes());
    Ok(bytes)
}

/// Records an opt-out without an outbound attempt. The account row is locked
/// before checking line identity, just as acceptance locks it before checking
/// suppression. An exact replay leaves the existing suppression untouched.
/// There is deliberately no START counterpart: clearing an unsolicited STOP
/// needs a separately reviewed owner/line-bound consent flow.
pub async fn ingest_line_opt_out(
    client: &mut Client,
    session: InboundSession<'_>,
    event: &LineOptOut<'_>,
) -> Result<bool, LineOptOutError> {
    validate(event)?;
    let statement = signed_line_opt_out_bytes(session, event)?;
    let signature =
        Signature::from_der(event.signature_der).map_err(|_| LineOptOutError::InvalidSignature)?;
    if signature.to_der().as_bytes() != event.signature_der {
        return Err(LineOptOutError::InvalidSignature);
    }
    let mut hash = Sha256::new();
    hash.update(&statement);
    hash.update(event.signature_der);
    let proof_digest = hash.finalize().to_vec();
    let tx = client.transaction().await?;
    if tx
        .query_opt(
            "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR NO KEY UPDATE",
            &[&session.account_id],
        )
        .await?
        .is_none()
        || !line_binding_ready(&tx, session, event.line_id, event.binding_generation).await?
    {
        return Err(LineOptOutError::Unauthorized);
    }
    let key_row = tx
        .query_opt(
            "SELECT signing_key_sec1 FROM device_keys WHERE account_id=$1 AND device_id=$2 \
             AND revoked_at IS NULL FOR SHARE",
            &[&session.account_id, &session.device_id],
        )
        .await?
        .ok_or(LineOptOutError::Unauthorized)?;
    let sec1: Vec<u8> = key_row.get(0);
    let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| LineOptOutError::Unauthorized)?;
    key.verify(&statement, &signature)
        .map_err(|_| LineOptOutError::InvalidSignature)?;
    let observed_seconds = event.observed_at_ms as f64 / 1000.0;
    if tx
        .query_opt(
            "SELECT 1 FROM device_line_bindings WHERE account_id=$1 AND line_id=$2 \
             AND device_id=$3 AND generation=$4 AND state='active' \
             AND activated_at<=to_timestamp($5) FOR SHARE",
            &[
                &session.account_id,
                &event.line_id,
                &session.device_id,
                &event.binding_generation,
                &observed_seconds,
            ],
        )
        .await?
        .is_none()
    {
        return Err(LineOptOutError::Unauthorized);
    }
    if let Some(row) = tx
        .query_opt(
            "SELECT account_id,device_id,event_digest FROM line_opt_out_events WHERE id=$1 FOR SHARE",
            &[&event.id],
        )
        .await?
    {
        let account: Uuid = row.get(0);
        let device: Uuid = row.get(1);
        let saved: Vec<u8> = row.get(2);
        if account != session.account_id || device != session.device_id || saved != proof_digest {
            return Err(LineOptOutError::EventConflict);
        }
        if !line_binding_ready(&tx, session, event.line_id, event.binding_generation).await? {
            return Err(LineOptOutError::Unauthorized);
        }
        tx.commit().await?;
        return Ok(false);
    }
    if tx
        .query_opt(
            "SELECT 1 FROM line_opt_out_events WHERE device_id=$1 AND device_sequence=$2",
            &[&session.device_id, &event.sequence],
        )
        .await?
        .is_some()
    {
        return Err(LineOptOutError::SequenceConflict);
    }
    if !consume_storage_budget(&tx, session.account_id, session.device_id).await? {
        return Err(LineOptOutError::BudgetExhausted);
    }
    let result = tx
        .execute(
            "INSERT INTO line_opt_out_events \
             (id,account_id,device_id,line_id,binding_generation,device_sequence,recipient_e164, \
              classification,observed_at,event_digest,signature_der) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,to_timestamp($9),$10,$11)",
            &[
                &event.id,
                &session.account_id,
                &session.device_id,
                &event.line_id,
                &event.binding_generation,
                &event.sequence,
                &event.recipient_e164,
                &event.action.classification(),
                &observed_seconds,
                &proof_digest,
                &event.signature_der,
            ],
        )
        .await;
    match result {
        Err(error)
            if error.as_db_error().is_some_and(|e| {
                e.code() == &SqlState::UNIQUE_VIOLATION
                    && e.constraint() == Some("line_opt_out_events_device_id_device_sequence_key")
            }) =>
        {
            return Err(LineOptOutError::SequenceConflict);
        }
        Err(error)
            if error.as_db_error().is_some_and(|e| {
                e.code() == &SqlState::UNIQUE_VIOLATION
                    && e.constraint() == Some("line_opt_out_events_pkey")
            }) =>
        {
            return Err(LineOptOutError::EventConflict);
        }
        Err(error) => return Err(LineOptOutError::Database(error)),
        Ok(_) => {}
    }
    tx.execute(
        "INSERT INTO recipient_suppressions \
         (account_id,recipient_e164,active,source_unsolicited_event_id,source_observed_at,source) \
         VALUES($1,$2,TRUE,$3,to_timestamp($4),$5) \
         ON CONFLICT(account_id,recipient_e164) DO UPDATE SET \
         active=TRUE,source_event_id=NULL,source_attempt_id=NULL, \
         source_unsolicited_event_id=EXCLUDED.source_unsolicited_event_id, \
         source_observed_at=EXCLUDED.source_observed_at, \
         source=EXCLUDED.source,changed_at=clock_timestamp()",
        &[
            &session.account_id,
            &event.recipient_e164,
            &event.id,
            &observed_seconds,
            &event.action.source(),
        ],
    )
    .await?;
    if !line_binding_ready(&tx, session, event.line_id, event.binding_generation).await? {
        return Err(LineOptOutError::Unauthorized);
    }
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests;
