// SPDX-License-Identifier: AGPL-3.0-only
//! Device-signed inbound storage foundation. No route calls this module yet.
//! Android's current inbound pilot is local-only; a sealed-content protocol,
//! endpoint management and egress-safe webhook worker are separate gates.

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio_postgres::{Client, error::SqlState};
use uuid::Uuid;

const MAX_AGE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const MAX_FUTURE_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboundSession<'a> {
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub site_id: &'a str,
    pub instance_id: &'a str,
    pub connection_epoch: i64,
    pub deployment_epoch: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Classification {
    CapturedLocal,
    SimUnverified,
    SendUnverified,
    EncryptionUnverified,
}

impl Classification {
    fn code(self) -> u8 {
        match self {
            Self::CapturedLocal => 1,
            Self::SimUnverified => 2,
            Self::SendUnverified => 3,
            Self::EncryptionUnverified => 4,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::CapturedLocal => "captured_local",
            Self::SimUnverified => "sim_unverified",
            Self::SendUnverified => "send_unverified",
            Self::EncryptionUnverified => "encryption_unverified",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Content<'a> {
    MetadataOnly,
    /// Opaque bytes only. This is not a reviewed sealed-envelope protocol.
    OpaquePilot(&'a [u8]),
}

impl Content<'_> {
    fn code(self) -> u8 {
        match self {
            Self::MetadataOnly => 0,
            Self::OpaquePilot(_) => 1,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::MetadataOnly => "metadata_only",
            Self::OpaquePilot(_) => "opaque_pilot",
        }
    }
}

#[derive(Clone, Copy)]
pub struct InboundEvent<'a> {
    pub event_id: Uuid,
    pub sequence: i64,
    pub message_id: Uuid,
    pub attempt_id: Uuid,
    pub classification: Classification,
    pub observed_at_ms: i64,
    pub part_count: i16,
    pub content: Content<'a>,
    pub signature_der: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngestOutcome {
    pub created: bool,
    pub queued_deliveries: u64,
}

#[derive(Debug, Error)]
pub enum InboundError {
    #[error("invalid inbound event")]
    InvalidInput,
    #[error("device session is no longer authorized")]
    Unauthorized,
    #[error("inbound event signature is invalid")]
    InvalidSignature,
    #[error("outbound attempt is unavailable to this device")]
    UnknownSource,
    #[error("event ID was reused with different content")]
    EventConflict,
    #[error("device sequence was reused by another event")]
    SequenceConflict,
    #[error("webhook delivery lease is stale")]
    StaleLease,
    #[error("inbound storage failed")]
    Database(#[from] tokio_postgres::Error),
}

/// Stable signed bytes. Integers use network byte order; UUIDs are 16 raw
/// bytes; the content hash is SHA-256 of ciphertext, or of empty bytes for
/// metadata only. No phone number, SMS body or server-readable secret appears.
pub fn signed_event_bytes(session: InboundSession<'_>, event: &InboundEvent<'_>) -> Vec<u8> {
    let mut bytes = b"zrotext-inbound-v1\0".to_vec();
    bytes.extend_from_slice(session.account_id.as_bytes());
    bytes.extend_from_slice(session.device_id.as_bytes());
    bytes.extend_from_slice(event.event_id.as_bytes());
    bytes.extend_from_slice(&event.sequence.to_be_bytes());
    bytes.extend_from_slice(event.message_id.as_bytes());
    bytes.extend_from_slice(event.attempt_id.as_bytes());
    bytes.push(event.classification.code());
    bytes.extend_from_slice(&event.observed_at_ms.to_be_bytes());
    bytes.extend_from_slice(&event.part_count.to_be_bytes());
    bytes.push(event.content.code());
    let ciphertext = match event.content {
        Content::MetadataOnly => &[][..],
        Content::OpaquePilot(bytes) => bytes,
    };
    bytes.extend_from_slice(&Sha256::digest(ciphertext));
    bytes
}

fn validate(event: &InboundEvent<'_>) -> Result<(), InboundError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| InboundError::InvalidInput)?
        .as_millis() as i64;
    if event.sequence <= 0
        || !(1..=6).contains(&event.part_count)
        || event.observed_at_ms < now - MAX_AGE_MS
        || event.observed_at_ms > now + MAX_FUTURE_MS
        || !(8..=80).contains(&event.signature_der.len())
    {
        return Err(InboundError::InvalidInput);
    }
    if let Content::OpaquePilot(bytes) = event.content
        && (!(32..=8192).contains(&bytes.len())
            || event.classification != Classification::CapturedLocal)
    {
        return Err(InboundError::InvalidInput);
    }
    Ok(())
}

/// Must be invoked only after native WSS challenge authentication. The writer
/// transaction rechecks current session/authority, account, device key and
/// a positive sent attempt before recording an event. A replay does not queue
/// another webhook delivery; a changed payload or sequence is rejected.
pub async fn ingest(
    client: &mut Client,
    session: InboundSession<'_>,
    event: &InboundEvent<'_>,
) -> Result<IngestOutcome, InboundError> {
    validate(event)?;
    let tx = client.transaction().await?;
    let key = tx
        .query_opt(
            "SELECT k.signing_key_sec1 FROM device_sessions s \
         JOIN devices d ON (d.account_id,d.id)=(s.account_id,s.device_id) \
         JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
         JOIN accounts a ON a.id=d.account_id \
         JOIN sites t ON t.site_id=s.site_id \
         JOIN deployment_authority p ON p.singleton=TRUE \
         WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 \
         AND s.instance_id=$4 AND s.connection_epoch=$5 AND s.deployment_epoch=$6 \
         AND s.lease_until>clock_timestamp() AND d.revoked_at IS NULL AND k.revoked_at IS NULL \
         AND a.disabled_at IS NULL AND t.enabled=TRUE AND t.draining=FALSE \
         AND p.epoch=$6 AND NOT pg_is_in_recovery() \
         FOR SHARE OF s,d,k,a,t,p",
            &[
                &session.account_id,
                &session.device_id,
                &session.site_id,
                &session.instance_id,
                &session.connection_epoch,
                &session.deployment_epoch,
            ],
        )
        .await?
        .ok_or(InboundError::Unauthorized)?;
    let sec1: Vec<u8> = key.get(0);
    let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| InboundError::Unauthorized)?;
    let signature =
        Signature::from_der(event.signature_der).map_err(|_| InboundError::InvalidSignature)?;
    let signed = signed_event_bytes(session, event);
    key.verify(&signed, &signature)
        .map_err(|_| InboundError::InvalidSignature)?;

    // A reply can be associated only with a message attempt from this tenant
    // and device that already has positive sent-callback evidence.
    let source = tx
        .query_opt(
            "SELECT 1 FROM message_attempts ma \
         JOIN messages m ON (m.account_id,m.id)=(ma.account_id,ma.message_id) \
         WHERE ma.id=$1 AND ma.account_id=$2 AND ma.device_id=$3 \
         AND ma.message_id=$4 AND ma.status='submitted' \
         AND EXISTS (SELECT 1 FROM message_events me \
             WHERE me.attempt_id=ma.id AND me.evidence_code='sent_callback_ok') \
         FOR SHARE OF ma,m",
            &[
                &event.attempt_id,
                &session.account_id,
                &session.device_id,
                &event.message_id,
            ],
        )
        .await?;
    if source.is_none() {
        return Err(InboundError::UnknownSource);
    }

    let digest = Sha256::digest(&signed).to_vec();
    let observed_seconds = event.observed_at_ms as f64 / 1000.0;
    let ciphertext: Option<&[u8]> = match event.content {
        Content::MetadataOnly => None,
        Content::OpaquePilot(bytes) => Some(bytes),
    };
    let inserted = tx
        .query_opt(
            "INSERT INTO inbound_events \
         (id,account_id,device_id,message_id,attempt_id,device_sequence,classification, \
          observed_at,part_count,content_kind,content_ciphertext,event_digest,signature_der) \
         VALUES($1,$2,$3,$4,$5,$6,$7,to_timestamp($8),$9,$10,$11,$12,$13) \
         ON CONFLICT(id) DO NOTHING RETURNING id",
            &[
                &event.event_id,
                &session.account_id,
                &session.device_id,
                &event.message_id,
                &event.attempt_id,
                &event.sequence,
                &event.classification.as_str(),
                &observed_seconds,
                &event.part_count,
                &event.content.as_str(),
                &ciphertext,
                &digest,
                &event.signature_der,
            ],
        )
        .await;
    let inserted = match inserted {
        Ok(value) => value,
        Err(error)
            if error.as_db_error().is_some_and(|e| {
                e.code() == &SqlState::UNIQUE_VIOLATION
                    && e.constraint() == Some("inbound_events_device_id_device_sequence_key")
            }) =>
        {
            return Err(InboundError::SequenceConflict);
        }
        Err(error) => return Err(InboundError::Database(error)),
    };
    if inserted.is_none() {
        let row = tx
            .query_one(
                "SELECT account_id,device_id,event_digest FROM inbound_events WHERE id=$1",
                &[&event.event_id],
            )
            .await?;
        let account: Uuid = row.get(0);
        let device: Uuid = row.get(1);
        let saved_digest: Vec<u8> = row.get(2);
        if account != session.account_id || device != session.device_id || saved_digest != digest {
            return Err(InboundError::EventConflict);
        }
        // Transaction-start now() cannot fence a lease after a row-lock wait.
        // Session/authority rows stay locked; recheck wall time before commit.
        if tx.query_opt(
            "SELECT 1 FROM device_sessions WHERE account_id=$1 AND device_id=$2 AND lease_until>clock_timestamp()",
            &[&session.account_id, &session.device_id],
        ).await?.is_none() {
            return Err(InboundError::Unauthorized);
        }
        tx.commit().await?;
        return Ok(IngestOutcome {
            created: false,
            queued_deliveries: 0,
        });
    }
    let queued = tx
        .execute(
            "INSERT INTO webhook_deliveries (id,account_id,endpoint_id,event_id) \
         SELECT gen_random_uuid(),account_id,id,$1 FROM webhook_endpoints \
         WHERE account_id=$2 AND enabled=TRUE FOR SHARE",
            &[&event.event_id, &session.account_id],
        )
        .await?;
    // Transaction-start now() cannot fence a lease after a row-lock wait.
    // Session/authority rows stay locked; recheck wall time before commit.
    if tx.query_opt(
        "SELECT 1 FROM device_sessions WHERE account_id=$1 AND device_id=$2 AND lease_until>clock_timestamp()",
        &[&session.account_id, &session.device_id],
    ).await?.is_none() {
        return Err(InboundError::Unauthorized);
    }
    tx.commit().await?;
    Ok(IngestOutcome {
        created: true,
        queued_deliveries: queued,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookLease {
    pub delivery_id: Uuid,
    pub account_id: Uuid,
    pub endpoint_id: Uuid,
    pub event_id: Uuid,
    pub attempt_id: Uuid,
    pub generation: i16,
    pub attempt_number: i16,
    pub worker_id: String,
}

/// Read only through a current lease. The secret remains KEK-encrypted here;
/// the caller must decrypt it in its own protected worker context and must
/// perform full HTTPS/SSRF validation before connecting.
pub struct WebhookPayload {
    pub callback_url: String,
    pub encrypted_signing_secret: Vec<u8>,
    pub signing_secret_key_version: i32,
    pub device_id: Uuid,
    pub message_id: Uuid,
    pub attempt_id: Uuid,
    pub classification: String,
    pub observed_at_ms: i64,
    pub part_count: i16,
    pub content_kind: String,
    pub content_ciphertext: Option<Vec<u8>>,
    pub event_digest: Vec<u8>,
    pub device_signature_der: Vec<u8>,
}

pub async fn load_webhook_payload(
    client: &Client,
    lease: &WebhookLease,
) -> Result<WebhookPayload, InboundError> {
    let row = client
        .query_opt(
            "SELECT e.callback_url,e.signing_secret_ciphertext,e.signing_secret_key_version, \
         i.device_id,i.message_id,i.attempt_id,i.classification, \
         (extract(epoch FROM i.observed_at)*1000)::bigint,i.part_count,i.content_kind, \
         i.content_ciphertext,i.event_digest,i.signature_der \
         FROM webhook_deliveries d JOIN webhook_endpoints e ON \
         (e.account_id,e.id)=(d.account_id,d.endpoint_id) \
         JOIN inbound_events i ON (i.account_id,i.id)=(d.account_id,d.event_id) \
         WHERE d.id=$1 AND d.account_id=$2 AND d.endpoint_id=$3 AND d.event_id=$4 \
         AND d.status='leased' AND d.generation=$5 AND d.attempt_count=$6 AND d.lease_owner=$7 \
         AND d.lease_until>now() AND e.enabled=TRUE",
            &[
                &lease.delivery_id,
                &lease.account_id,
                &lease.endpoint_id,
                &lease.event_id,
                &lease.generation,
                &lease.attempt_number,
                &lease.worker_id,
            ],
        )
        .await?
        .ok_or(InboundError::StaleLease)?;
    Ok(WebhookPayload {
        callback_url: row.get(0),
        encrypted_signing_secret: row.get(1),
        signing_secret_key_version: row.get(2),
        device_id: row.get(3),
        message_id: row.get(4),
        attempt_id: row.get(5),
        classification: row.get(6),
        observed_at_ms: row.get(7),
        part_count: row.get(8),
        content_kind: row.get(9),
        content_ciphertext: row.get(10),
        event_digest: row.get(11),
        device_signature_der: row.get(12),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookOutcome {
    Ack,
    Timeout,
    HttpError,
    NetworkError,
    PolicyRejected,
}

impl WebhookOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ack => "ack",
            Self::Timeout => "timeout",
            Self::HttpError => "http_error",
            Self::NetworkError => "network_error",
            Self::PolicyRejected => "policy_rejected",
        }
    }
}

const RETRY_DELAY_SECONDS: [i32; 6] = [60, 300, 900, 3600, 21600, 86400];

fn retry_delay(attempt_count: i16) -> Option<i32> {
    RETRY_DELAY_SECONDS
        .get((attempt_count - 1) as usize)
        .copied()
}

/// Recover timed-out leases then claim one due delivery with SKIP LOCKED.
/// A separate egress worker must validate DNS/addresses and decrypt the
/// endpoint's signing secret before any HTTP request. No network I/O occurs.
pub async fn claim_webhook(
    client: &mut Client,
    worker_id: &str,
) -> Result<Option<WebhookLease>, InboundError> {
    if worker_id.is_empty() || worker_id.len() > 64 {
        return Err(InboundError::InvalidInput);
    }
    let tx = client.transaction().await?;
    let expired = tx
        .query(
            "SELECT id,generation,attempt_count FROM webhook_deliveries \
         WHERE status='leased' AND lease_until<=now() \
         ORDER BY lease_until,id FOR UPDATE SKIP LOCKED LIMIT 100",
            &[],
        )
        .await?;
    for row in expired {
        let delivery_id: Uuid = row.get(0);
        let generation: i16 = row.get(1);
        let attempts: i16 = row.get(2);
        tx.execute(
            "UPDATE webhook_attempts SET completed_at=now(),outcome='timeout' \
             WHERE delivery_id=$1 AND generation=$2 AND attempt_number=$3 AND completed_at IS NULL",
            &[&delivery_id, &generation, &attempts],
        )
        .await?;
        if let Some(delay) = retry_delay(attempts) {
            tx.execute(
                "UPDATE webhook_deliveries SET status='pending',lease_owner=NULL, \
                 lease_until=NULL,next_attempt_at=now()+($2::integer * interval '1 second'), \
                 updated_at=now() WHERE id=$1",
                &[&delivery_id, &delay],
            )
            .await?;
        } else {
            tx.execute(
                "UPDATE webhook_deliveries SET status='dead',terminal_reason='failed', \
                 lease_owner=NULL,lease_until=NULL,updated_at=now() WHERE id=$1",
                &[&delivery_id],
            )
            .await?;
        }
    }
    let row = tx
        .query_opt(
            "SELECT d.id,d.account_id,d.endpoint_id,d.event_id,d.generation,d.attempt_count \
         FROM webhook_deliveries d JOIN webhook_endpoints e ON \
         (e.account_id,e.id)=(d.account_id,d.endpoint_id) \
         WHERE d.status='pending' AND d.next_attempt_at<=now() AND \
         d.attempt_count<7 AND e.enabled=TRUE \
         ORDER BY d.next_attempt_at,d.id FOR UPDATE OF d SKIP LOCKED LIMIT 1",
            &[],
        )
        .await?;
    let Some(row) = row else {
        tx.commit().await?;
        return Ok(None);
    };
    let delivery_id: Uuid = row.get(0);
    let account_id: Uuid = row.get(1);
    let endpoint_id: Uuid = row.get(2);
    let event_id: Uuid = row.get(3);
    let generation: i16 = row.get(4);
    let attempt_number: i16 = row.get::<_, i16>(5) + 1;
    let attempt_id = Uuid::new_v4();
    tx.execute(
        "UPDATE webhook_deliveries SET status='leased',attempt_count=$2,lease_owner=$3, \
         lease_until=now()+interval '30 seconds',updated_at=now() WHERE id=$1",
        &[&delivery_id, &attempt_number, &worker_id],
    )
    .await?;
    tx.execute(
        "INSERT INTO webhook_attempts(id,delivery_id,generation,attempt_number) VALUES($1,$2,$3,$4)",
        &[&attempt_id, &delivery_id, &generation, &attempt_number],
    )
    .await?;
    tx.commit().await?;
    Ok(Some(WebhookLease {
        delivery_id,
        account_id,
        endpoint_id,
        event_id,
        attempt_id,
        generation,
        attempt_number,
        worker_id: worker_id.to_owned(),
    }))
}

/// Persist one transport result. HTTP redirects must be reported as errors;
/// only 2xx may become `Ack`. Attempts are bounded to seven total sends.
pub async fn finish_webhook(
    client: &mut Client,
    lease: &WebhookLease,
    outcome: WebhookOutcome,
    http_status: Option<i16>,
) -> Result<(), InboundError> {
    if !matches!(
        (outcome, http_status),
        (WebhookOutcome::Ack, Some(200..=299))
            | (
                WebhookOutcome::HttpError | WebhookOutcome::PolicyRejected,
                Some(300..=599)
            )
            | (WebhookOutcome::PolicyRejected, None)
            | (WebhookOutcome::Timeout | WebhookOutcome::NetworkError, None)
    ) {
        return Err(InboundError::InvalidInput);
    }
    let tx = client.transaction().await?;
    let row = tx
        .query_opt(
            "SELECT status,generation,attempt_count,lease_owner,coalesce(lease_until>now(),false) \
         FROM webhook_deliveries WHERE id=$1 AND account_id=$2 AND endpoint_id=$3 \
         AND event_id=$4 FOR UPDATE",
            &[
                &lease.delivery_id,
                &lease.account_id,
                &lease.endpoint_id,
                &lease.event_id,
            ],
        )
        .await?
        .ok_or(InboundError::StaleLease)?;
    let status: String = row.get(0);
    let generation: i16 = row.get(1);
    let attempts: i16 = row.get(2);
    let owner: Option<String> = row.get(3);
    let active: bool = row.get(4);
    if status != "leased"
        || generation != lease.generation
        || attempts != lease.attempt_number
        || owner.as_deref() != Some(&lease.worker_id)
        || !active
    {
        return Err(InboundError::StaleLease);
    }
    let completed = tx
        .execute(
            "UPDATE webhook_attempts SET completed_at=now(),outcome=$2,http_status=$3 \
         WHERE id=$1 AND delivery_id=$4 AND generation=$5 AND attempt_number=$6 AND completed_at IS NULL",
            &[
                &lease.attempt_id,
                &outcome.as_str(),
                &http_status,
                &lease.delivery_id,
                &lease.generation,
                &lease.attempt_number,
            ],
        )
        .await?;
    if completed != 1 {
        return Err(InboundError::StaleLease);
    }
    match (outcome, retry_delay(attempts)) {
        (WebhookOutcome::Ack, _) => {
            tx.execute(
                "UPDATE webhook_deliveries SET status='succeeded',lease_owner=NULL, \
                 lease_until=NULL,updated_at=now() WHERE id=$1",
                &[&lease.delivery_id],
            )
            .await?;
        }
        (WebhookOutcome::PolicyRejected, _) => {
            tx.execute(
                "UPDATE webhook_deliveries SET status='dead',terminal_reason='policy_rejected', \
                 lease_owner=NULL,lease_until=NULL,updated_at=now() WHERE id=$1",
                &[&lease.delivery_id],
            )
            .await?;
        }
        (_, Some(delay)) => {
            tx.execute(
                "UPDATE webhook_deliveries SET status='pending',lease_owner=NULL, \
                 lease_until=NULL,next_attempt_at=now()+($2::integer * interval '1 second'), \
                 updated_at=now() WHERE id=$1",
                &[&lease.delivery_id, &delay],
            )
            .await?;
        }
        (_, None) => {
            tx.execute(
                "UPDATE webhook_deliveries SET status='dead',terminal_reason='failed', \
                 lease_owner=NULL,lease_until=NULL,updated_at=now() WHERE id=$1",
                &[&lease.delivery_id],
            )
            .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

/// A KEK/version/ciphertext failure happens before network I/O. Return this
/// delivery to the queue without consuming one of its seven send attempts.
/// The separate failure counter leaves an operator-visible repair signal.
pub async fn defer_webhook_key_failure(
    client: &mut Client,
    lease: &WebhookLease,
) -> Result<(), InboundError> {
    let tx = client.transaction().await?;
    let row = tx
        .query_opt(
            "SELECT status,generation,attempt_count,lease_owner,coalesce(lease_until>now(),false) \
             FROM webhook_deliveries WHERE id=$1 AND account_id=$2 AND endpoint_id=$3 \
             AND event_id=$4 FOR UPDATE",
            &[
                &lease.delivery_id,
                &lease.account_id,
                &lease.endpoint_id,
                &lease.event_id,
            ],
        )
        .await?
        .ok_or(InboundError::StaleLease)?;
    let status: String = row.get(0);
    let generation: i16 = row.get(1);
    let attempts: i16 = row.get(2);
    let owner: Option<String> = row.get(3);
    let active: bool = row.get(4);
    if status != "leased"
        || generation != lease.generation
        || attempts != lease.attempt_number
        || owner.as_deref() != Some(&lease.worker_id)
        || !active
    {
        return Err(InboundError::StaleLease);
    }
    let removed = tx
        .execute(
            "DELETE FROM webhook_attempts WHERE id=$1 AND delivery_id=$2 AND generation=$3 \
             AND attempt_number=$4 AND completed_at IS NULL",
            &[
                &lease.attempt_id,
                &lease.delivery_id,
                &lease.generation,
                &lease.attempt_number,
            ],
        )
        .await?;
    if removed != 1 {
        return Err(InboundError::StaleLease);
    }
    tx.execute(
        "UPDATE webhook_deliveries SET status='pending',attempt_count=attempt_count-1, \
         key_failure_count=key_failure_count+1,lease_owner=NULL,lease_until=NULL, \
         next_attempt_at=now()+interval '5 minutes',updated_at=now() WHERE id=$1",
        &[&lease.delivery_id],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
