// SPDX-License-Identifier: AGPL-3.0-only
//! PostgreSQL single-writer transactions for the private synthetic-content alpha.
//! Callers must authenticate account/device context before invoking these methods.

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_postgres::{Client, Row, error::SqlState};
use uuid::Uuid;
use zrotext_domain::{Evidence, MessageState};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database operation failed")]
    Database(#[from] tokio_postgres::Error),
    #[error("invalid message input")]
    InvalidInput,
    #[error("idempotency key was already used for another request")]
    IdempotencyConflict,
    #[error("client message ID was already used for another request")]
    MessageIdConflict,
    #[error("tenant-owned resource not found")]
    NotFound,
    #[error("device is revoked")]
    Revoked,
    #[error("writer dispatch is disabled")]
    DispatchDisabled,
    #[error("session, worker claim, or deployment epoch is stale")]
    StaleFence,
    #[error("device has an unresolved radio operation")]
    DeviceBusy,
    #[error("message state does not permit this evidence")]
    InvalidTransition,
    #[error("event ID was reused for different evidence")]
    EventIdConflict,
}

pub struct NewMessage<'a> {
    pub account_id: Uuid,
    pub client_message_id: Uuid,
    pub device_id: Uuid,
    pub idempotency_key: &'a str,
    pub recipient_e164: &'a str,
    /// Synthetic, operator-readable private-alpha payload. Never expose in a
    /// public sealed-content endpoint or use with real customer content.
    pub synthetic_payload: &'a [u8],
    pub expires_at_ms: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptOutcome {
    pub message_id: Uuid,
    pub created: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRecord {
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub site_id: String,
    pub instance_id: String,
    pub epoch: i64,
    pub deployment_epoch: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub account_id: Uuid,
    pub message_id: Uuid,
    pub device_id: Uuid,
    pub generation: i64,
    pub worker_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRecord {
    pub account_id: Uuid,
    pub message_id: Uuid,
    pub attempt_id: Uuid,
    pub device_id: Uuid,
    pub generation: i64,
    pub session_epoch: i64,
    pub deployment_epoch: i64,
    pub recipient_digest: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadioEvent {
    pub event_id: Uuid,
    pub account_id: Uuid,
    pub message_id: Uuid,
    pub attempt_id: Uuid,
    pub evidence: Evidence,
    pub observed_at_ms: i64,
    pub segment_index: Option<i32>,
    pub segment_count: Option<i32>,
}

pub struct DeliveryStore<'a> {
    client: &'a mut Client,
}

impl<'a> DeliveryStore<'a> {
    pub fn new(client: &'a mut Client) -> Self {
        Self { client }
    }

    /// Inserts idempotency identity, message and job in one writer transaction.
    /// No HTTP 202 should be returned until this transaction commits.
    pub async fn accept(&mut self, input: NewMessage<'_>) -> Result<AcceptOutcome, StoreError> {
        validate_message(&input)?;
        let digest = request_digest(&input);
        let recipient_digest = Sha256::digest(input.recipient_e164.as_bytes()).to_vec();
        let expiry = input.expires_at_ms as f64;
        let tx = self.client.transaction().await?;
        let new_key = tx
            .query_opt(
                "INSERT INTO idempotency_keys (account_id, key, request_digest, message_id, expires_at) \
                 VALUES ($1,$2,$3,$4,now() + interval '7 days') \
                 ON CONFLICT (account_id,key) DO NOTHING RETURNING message_id",
                &[&input.account_id, &input.idempotency_key, &digest, &input.client_message_id],
            )
            .await?;
        if new_key.is_none() {
            let row = tx
                .query_one(
                    "SELECT message_id, request_digest FROM idempotency_keys WHERE account_id=$1 AND key=$2",
                    &[&input.account_id, &input.idempotency_key],
                )
                .await?;
            let saved_digest: Vec<u8> = row.get(1);
            if saved_digest != digest {
                return Err(StoreError::IdempotencyConflict);
            }
            let message_id: Uuid = row.get(0);
            tx.commit().await?;
            return Ok(AcceptOutcome {
                message_id,
                created: false,
            });
        }

        let created = tx
            .query_opt(
                "INSERT INTO messages (id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
                 VALUES ($1,$2,$3,$4,$5,'synthetic_alpha',$6,$7,'queued',to_timestamp($8::double precision / 1000)) \
                 ON CONFLICT (id) DO NOTHING RETURNING id",
                &[&input.client_message_id, &input.account_id, &input.device_id, &input.recipient_e164,
                  &recipient_digest, &input.synthetic_payload, &digest, &expiry],
            )
            .await?;
        if created.is_none() {
            let row = tx
                .query_one(
                    "SELECT account_id,request_digest FROM messages WHERE id=$1",
                    &[&input.client_message_id],
                )
                .await?;
            let owner: Uuid = row.get(0);
            let saved_digest: Vec<u8> = row.get(1);
            if owner != input.account_id || saved_digest != digest {
                return Err(StoreError::MessageIdConflict);
            }
            tx.commit().await?;
            return Ok(AcceptOutcome {
                message_id: input.client_message_id,
                created: false,
            });
        }
        tx.execute(
            "INSERT INTO dispatch_jobs (message_id,account_id,device_id) VALUES ($1,$2,$3)",
            &[
                &input.client_message_id,
                &input.account_id,
                &input.device_id,
            ],
        )
        .await?;
        tx.commit().await?;
        Ok(AcceptOutcome {
            message_id: input.client_message_id,
            created: true,
        })
    }

    /// A new authenticated socket obtains a monotonically increasing writer
    /// epoch. The previous hub's session cannot issue another grant.
    pub async fn connect_session(
        &mut self,
        account_id: Uuid,
        device_id: Uuid,
        site_id: &str,
        instance_id: &str,
        lease_seconds: i32,
    ) -> Result<SessionRecord, StoreError> {
        if site_id.is_empty() || instance_id.is_empty() || !(1..=300).contains(&lease_seconds) {
            return Err(StoreError::InvalidInput);
        }
        let tx = self.client.transaction().await?;
        let device = tx
            .query_opt(
                "SELECT revoked_at IS NOT NULL FROM devices WHERE account_id=$1 AND id=$2 FOR UPDATE",
                &[&account_id, &device_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        if device.get::<_, bool>(0) {
            return Err(StoreError::Revoked);
        }
        let deployment_epoch: i64 = tx
            .query_one(
                "SELECT epoch FROM deployment_authority WHERE singleton=TRUE",
                &[],
            )
            .await?
            .get(0);
        tx.execute(
            "INSERT INTO sites (site_id) VALUES ($1) ON CONFLICT (site_id) DO NOTHING",
            &[&site_id],
        )
        .await?;
        let row = tx
            .query_one(
                "INSERT INTO device_sessions (device_id,account_id,site_id,instance_id,connection_epoch,lease_until,deployment_epoch) \
                 VALUES ($1,$2,$3,$4,1,now()+($5::integer * interval '1 second'),$6) \
                 ON CONFLICT (device_id) DO UPDATE SET account_id=EXCLUDED.account_id,site_id=EXCLUDED.site_id, \
                 instance_id=EXCLUDED.instance_id,connection_epoch=device_sessions.connection_epoch+1, \
                 lease_until=EXCLUDED.lease_until,deployment_epoch=EXCLUDED.deployment_epoch \
                 RETURNING connection_epoch",
                &[&device_id, &account_id, &site_id, &instance_id, &lease_seconds, &deployment_epoch],
            )
            .await?;
        let epoch: i64 = row.get(0);
        tx.commit().await?;
        Ok(SessionRecord {
            account_id,
            device_id,
            site_id: site_id.to_owned(),
            instance_id: instance_id.to_owned(),
            epoch,
            deployment_epoch,
        })
    }

    /// SKIP LOCKED lets independent workers claim distinct jobs from the same
    /// writer. Claim expiry can requeue only before any execution grant.
    pub async fn claim_due(&mut self, worker_id: &str) -> Result<Option<Claim>, StoreError> {
        if worker_id.is_empty() {
            return Err(StoreError::InvalidInput);
        }
        let tx = self.client.transaction().await?;
        let row = tx
            .query_opt(
                "WITH picked AS ( \
                   SELECT j.message_id FROM dispatch_jobs j JOIN messages m ON m.id=j.message_id \
                   JOIN devices d ON d.id=j.device_id AND d.account_id=j.account_id \
                   WHERE j.next_attempt_at<=now() AND (j.lease_until IS NULL OR j.lease_until<now()) \
                     AND j.grant_issued_at IS NULL AND m.state IN ('queued','claimed') AND m.expires_at>now() \
                     AND d.revoked_at IS NULL \
                   ORDER BY j.next_attempt_at,j.message_id FOR UPDATE OF j SKIP LOCKED LIMIT 1 \
                 ) UPDATE dispatch_jobs j SET lease_owner=$1,lease_until=now()+interval '30 seconds', \
                   generation=j.generation+1 FROM picked WHERE j.message_id=picked.message_id \
                 RETURNING j.account_id,j.message_id,j.device_id,j.generation",
                &[&worker_id],
            )
            .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let claim = Claim {
            account_id: row.get(0),
            message_id: row.get(1),
            device_id: row.get(2),
            generation: row.get(3),
            worker_id: worker_id.to_owned(),
        };
        tx.execute(
            "UPDATE messages SET state='claimed',state_version=state_version+1,updated_at=now() \
             WHERE account_id=$1 AND id=$2 AND state IN ('queued','claimed')",
            &[&claim.account_id, &claim.message_id],
        )
        .await?;
        tx.commit().await?;
        Ok(Some(claim))
    }

    /// Grant transaction checks authority, session and worker generation. A
    /// unique active-device index closes races between different messages.
    pub async fn issue_grant(
        &mut self,
        claim: &Claim,
        session: &SessionRecord,
        attempt_id: Uuid,
    ) -> Result<GrantRecord, StoreError> {
        if claim.account_id != session.account_id || claim.device_id != session.device_id {
            return Err(StoreError::StaleFence);
        }
        let tx = self.client.transaction().await?;
        let authority = tx
            .query_one(
                "SELECT epoch,dispatch_enabled FROM deployment_authority WHERE singleton=TRUE FOR SHARE",
                &[],
            )
            .await?;
        let deployment_epoch: i64 = authority.get(0);
        let dispatch_enabled: bool = authority.get(1);
        if !dispatch_enabled {
            return Err(StoreError::DispatchDisabled);
        }
        if deployment_epoch != session.deployment_epoch {
            return Err(StoreError::StaleFence);
        }
        let device = tx.query_opt(
            "SELECT revoked_at IS NOT NULL FROM devices WHERE account_id=$1 AND id=$2 FOR SHARE",
            &[&claim.account_id, &claim.device_id],
        ).await?.ok_or(StoreError::StaleFence)?;
        if device.get::<_, bool>(0) {
            return Err(StoreError::Revoked);
        }
        let current_session = tx
            .query_opt(
                "SELECT ds.connection_epoch,ds.site_id,ds.instance_id,ds.lease_until>now() AS live, \
                  s.enabled,s.draining FROM device_sessions ds JOIN sites s ON s.site_id=ds.site_id \
                  WHERE ds.account_id=$1 AND ds.device_id=$2 FOR UPDATE OF ds",
                &[&session.account_id, &session.device_id],
            )
            .await?
            .ok_or(StoreError::StaleFence)?;
        if current_session.get::<_, i64>(0) != session.epoch
            || current_session.get::<_, String>(1) != session.site_id
            || current_session.get::<_, String>(2) != session.instance_id
            || !current_session.get::<_, bool>(3)
            || !current_session.get::<_, bool>(4)
            || current_session.get::<_, bool>(5)
        {
            return Err(StoreError::StaleFence);
        }
        let job = tx
            .query_opt(
                "SELECT j.generation,j.lease_owner,j.lease_until>now(),j.grant_issued_at IS NULL, \
                        m.state,m.expires_at>now(),m.recipient_digest \
                 FROM dispatch_jobs j JOIN messages m ON m.id=j.message_id \
                 WHERE j.account_id=$1 AND j.message_id=$2 AND j.device_id=$3 FOR UPDATE OF j,m",
                &[&claim.account_id, &claim.message_id, &claim.device_id],
            )
            .await?
            .ok_or(StoreError::StaleFence)?;
        if job.get::<_, i64>(0) != claim.generation
            || job.get::<_, Option<String>>(1).as_deref() != Some(claim.worker_id.as_str())
            || !job.get::<_, bool>(2)
            || !job.get::<_, bool>(3)
            || job.get::<_, String>(4) != "claimed"
            || !job.get::<_, bool>(5)
        {
            return Err(StoreError::StaleFence);
        }
        let recipient_digest: Vec<u8> = job.get(6);
        tx.execute(
            "INSERT INTO message_attempts (id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,'granted')",
            &[&attempt_id, &claim.account_id, &claim.message_id, &claim.device_id,
              &claim.generation, &session.epoch, &deployment_epoch],
        )
        .await?;
        let inserted = tx.execute(
            "INSERT INTO dispatch_fences (message_id,account_id,device_id,attempt_id,generation,session_epoch, \
              deployment_epoch,recipient_digest,grant_expires_at,outcome) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now()+interval '30 seconds','granted')",
            &[&claim.message_id, &claim.account_id, &claim.device_id, &attempt_id,
              &claim.generation, &session.epoch, &deployment_epoch, &recipient_digest],
        ).await;
        if let Err(error) = inserted {
            if error.as_db_error().is_some_and(|db| {
                db.code() == &SqlState::UNIQUE_VIOLATION
                    && db.constraint() == Some("dispatch_fences_active_device")
            }) {
                return Err(StoreError::DeviceBusy);
            }
            return Err(StoreError::Database(error));
        }
        tx.execute(
            "UPDATE dispatch_jobs SET grant_issued_at=now() WHERE message_id=$1",
            &[&claim.message_id],
        )
        .await?;
        tx.commit().await?;
        Ok(GrantRecord {
            account_id: claim.account_id,
            message_id: claim.message_id,
            attempt_id,
            device_id: claim.device_id,
            generation: claim.generation,
            session_epoch: session.epoch,
            deployment_epoch,
            recipient_digest,
        })
    }

    /// Evidence may arrive after a hub move. It is bound to the original
    /// attempt rather than the current session, so late callbacks reconcile.
    pub async fn record_radio_event(
        &mut self,
        event: RadioEvent,
    ) -> Result<MessageState, StoreError> {
        let code = evidence_code(event.evidence).ok_or(StoreError::InvalidInput)?;
        if event.observed_at_ms <= 0
            || event
                .segment_count
                .is_some_and(|count| !(1..=6).contains(&count))
            || event.segment_index.is_some_and(|index| index < 0)
            || matches!((event.segment_index, event.segment_count), (Some(index), Some(count)) if index >= count)
            || event.segment_index.is_some() != event.segment_count.is_some()
            || (matches!(
                event.evidence,
                Evidence::SentCallbackOk | Evidence::SentCallbackFailed
            ) != event.segment_index.is_some())
            || (!matches!(
                event.evidence,
                Evidence::SentCallbackOk | Evidence::SentCallbackFailed
            ) && event.segment_index.is_some())
        {
            return Err(StoreError::InvalidInput);
        }
        let digest = radio_event_digest(&event, code);
        let observed_at = event.observed_at_ms as f64;
        let tx = self.client.transaction().await?;
        let row = tx
            .query_opt(
                "SELECT state FROM messages WHERE account_id=$1 AND id=$2 FOR UPDATE",
                &[&event.account_id, &event.message_id],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let current = state_from_row(&row)?;
        if let Some(existing) = tx
            .query_opt(
                "SELECT event_digest,resulting_state FROM message_events WHERE id=$1",
                &[&event.event_id],
            )
            .await?
        {
            let saved_digest: Vec<u8> = existing.get(0);
            if saved_digest != digest {
                return Err(StoreError::EventIdConflict);
            }
            let prior_state: String = existing.get(1);
            tx.commit().await?;
            return state_from_str(&prior_state).ok_or(StoreError::InvalidTransition);
        }
        let attempt = tx
            .query_opt(
                "SELECT id FROM message_attempts WHERE id=$1 AND account_id=$2 AND message_id=$3 FOR UPDATE",
                &[&event.attempt_id, &event.account_id, &event.message_id],
            )
            .await?;
        if attempt.is_none() {
            return Err(StoreError::StaleFence);
        }
        let next = match event.evidence {
            Evidence::SentCallbackOk | Evidence::SentCallbackFailed => {
                let count = event.segment_count.ok_or(StoreError::InvalidInput)?;
                let seen = tx.query_one(
                    "SELECT count(*)::integer, count(*) FILTER (WHERE evidence_code='sent_callback_ok')::integer, \
                     count(*) FILTER (WHERE segment_count<>$2)::integer \
                     FROM message_events WHERE attempt_id=$1 AND evidence_code IN ('sent_callback_ok','sent_callback_failed')",
                    &[&event.attempt_id, &count],
                ).await?;
                let prior_count: i32 = seen.get(0);
                let prior_ok: i32 = seen.get(1);
                let inconsistent: i32 = seen.get(2);
                if inconsistent != 0 || prior_count >= count {
                    return Err(StoreError::InvalidInput);
                }
                match (event.evidence, count, prior_ok + 1) {
                    (Evidence::SentCallbackFailed, 1, _) => current.apply(Evidence::SentCallbackFailed),
                    (Evidence::SentCallbackFailed, _, _) if current == MessageState::Unknown => Ok(current),
                    (Evidence::SentCallbackFailed, _, _) => current.apply(Evidence::PartialSentCallbacks),
                    (Evidence::SentCallbackOk, _, ok) if ok == count => current.apply(Evidence::SentCallbackOk),
                    (Evidence::SentCallbackOk, _, _) if current == MessageState::Submitting || current == MessageState::Unknown => Ok(current),
                    _ => Err(zrotext_domain::InvalidTransition { from: current, evidence: event.evidence }),
                }
            }
            _ => current.apply(event.evidence),
        }.map_err(|_| StoreError::InvalidTransition)?;
        let next_name = state_name(next);
        tx.execute(
            "UPDATE messages SET state=$3,state_version=state_version+1,updated_at=now() \
             WHERE account_id=$1 AND id=$2",
            &[&event.account_id, &event.message_id, &next_name],
        )
        .await?;
        tx.execute(
            "INSERT INTO message_events (id,account_id,message_id,attempt_id,evidence_code,event_digest, \
              observed_at,resulting_state,segment_index,segment_count) \
             VALUES ($1,$2,$3,$4,$5,$6,to_timestamp($7::double precision / 1000),$8,$9,$10)",
            &[&event.event_id, &event.account_id, &event.message_id, &event.attempt_id,
              &code, &digest, &observed_at, &next_name, &event.segment_index, &event.segment_count],
        )
        .await?;
        if event.evidence == Evidence::ProvenNoSubmit {
            tx.execute(
                "UPDATE message_attempts SET status='proved_no_submit',updated_at=now() WHERE id=$1",
                &[&event.attempt_id],
            )
            .await?;
            tx.execute(
                "DELETE FROM dispatch_fences WHERE attempt_id=$1",
                &[&event.attempt_id],
            )
            .await?;
            tx.execute(
                "UPDATE dispatch_jobs SET grant_issued_at=NULL,lease_owner=NULL,lease_until=NULL,next_attempt_at=now() \
                 WHERE message_id=$1",
                &[&event.message_id],
            )
            .await?;
        } else if let Some(status) = attempt_status(next) {
            tx.execute(
                "UPDATE message_attempts SET status=$2,updated_at=now() WHERE id=$1",
                &[&event.attempt_id, &status],
            )
            .await?;
            tx.execute(
                "UPDATE dispatch_fences SET outcome=$2 WHERE attempt_id=$1",
                &[&event.attempt_id, &status],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(next)
    }
}

fn validate_message(input: &NewMessage<'_>) -> Result<(), StoreError> {
    let valid_number = input.recipient_e164.starts_with('+')
        && (3..=16).contains(&input.recipient_e164.len())
        && input.recipient_e164[1..]
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        && input.recipient_e164.as_bytes()[1] != b'0';
    if !valid_number
        || input.idempotency_key.is_empty()
        || input.idempotency_key.len() > 128
        || input.synthetic_payload.is_empty()
        || input.synthetic_payload.len() > 32768
        || input.expires_at_ms <= now_ms()
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(i64::MAX)
}

fn request_digest(input: &NewMessage<'_>) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(input.account_id.as_bytes());
    hash.update(input.client_message_id.as_bytes());
    hash.update(input.device_id.as_bytes());
    hash.update((input.recipient_e164.len() as u64).to_be_bytes());
    hash.update(input.recipient_e164.as_bytes());
    hash.update((input.synthetic_payload.len() as u64).to_be_bytes());
    hash.update(input.synthetic_payload);
    hash.update(input.expires_at_ms.to_be_bytes());
    hash.finalize().to_vec()
}

fn radio_event_digest(event: &RadioEvent, code: &str) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(event.account_id.as_bytes());
    hash.update(event.message_id.as_bytes());
    hash.update(event.attempt_id.as_bytes());
    hash.update(code.as_bytes());
    hash.update(event.observed_at_ms.to_be_bytes());
    hash.update(event.segment_index.unwrap_or(-1).to_be_bytes());
    hash.update(event.segment_count.unwrap_or(-1).to_be_bytes());
    hash.finalize().to_vec()
}

fn evidence_code(evidence: Evidence) -> Option<&'static str> {
    Some(match evidence {
        Evidence::DurableSubmitIntent => "durable_intent",
        Evidence::ProvenNoSubmit => "proved_no_submit",
        Evidence::SentCallbackOk => "sent_callback_ok",
        Evidence::SentCallbackFailed => "sent_callback_failed",
        Evidence::PartialSentCallbacks => "partial_sent_callbacks",
        Evidence::DeliveryCallbackOk => "delivery_callback_ok",
        Evidence::DeliveryTimeout => "delivery_timeout",
        Evidence::CrashWithoutCallback => "crash_no_callback",
        _ => return None,
    })
}

fn attempt_status(state: MessageState) -> Option<&'static str> {
    Some(match state {
        MessageState::Submitting => "submitting",
        MessageState::Submitted | MessageState::Delivered | MessageState::DeliveryUnknown => {
            "submitted"
        }
        MessageState::Unknown => "unknown",
        MessageState::Failed => "failed",
        _ => return None,
    })
}

fn state_name(state: MessageState) -> &'static str {
    match state {
        MessageState::Accepted => "accepted",
        MessageState::Queued => "queued",
        MessageState::Claimed => "claimed",
        MessageState::Submitting => "submitting",
        MessageState::Submitted => "submitted",
        MessageState::Delivered => "delivered",
        MessageState::DeliveryUnknown => "delivery_unknown",
        MessageState::Unknown => "unknown",
        MessageState::Failed => "failed",
        MessageState::Cancelled => "cancelled",
        MessageState::Expired => "expired",
    }
}

fn state_from_str(value: &str) -> Option<MessageState> {
    Some(match value {
        "accepted" => MessageState::Accepted,
        "queued" => MessageState::Queued,
        "claimed" => MessageState::Claimed,
        "submitting" => MessageState::Submitting,
        "submitted" => MessageState::Submitted,
        "delivered" => MessageState::Delivered,
        "delivery_unknown" => MessageState::DeliveryUnknown,
        "unknown" => MessageState::Unknown,
        "failed" => MessageState::Failed,
        "cancelled" => MessageState::Cancelled,
        "expired" => MessageState::Expired,
        _ => return None,
    })
}

fn state_from_row(row: &Row) -> Result<MessageState, StoreError> {
    state_from_str(&row.get::<_, String>(0)).ok_or(StoreError::InvalidTransition)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn postgres_fences_unknown_and_tenant_idempotency() {
        let Ok(url) = std::env::var("ZT_DELIVERY_TEST_DATABASE_URL") else {
            eprintln!("set ZT_DELIVERY_TEST_DATABASE_URL to run the database fault test");
            return;
        };
        let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("delivery_test_{}", Uuid::new_v4().simple());
        client
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await
            .unwrap();
        client
            .batch_execute(include_str!(
                "../../../deploy/compose/init/001_foundation.sql"
            ))
            .await
            .unwrap();
        client
            .batch_execute(include_str!(
                "../../../deploy/compose/migrations/002_auth.sql"
            ))
            .await
            .unwrap();
        client
            .batch_execute(include_str!(
                "../../../deploy/compose/migrations/003_delivery.sql"
            ))
            .await
            .unwrap();

        let account = Uuid::new_v4();
        let other_account = Uuid::new_v4();
        let device = Uuid::new_v4();
        for id in [account, other_account] {
            client
                .execute("INSERT INTO accounts(id) VALUES($1)", &[&id])
                .await
                .unwrap();
        }
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'test phone')",
                &[&device, &account],
            )
            .await
            .unwrap();
        client
            .execute(
                "UPDATE deployment_authority SET dispatch_enabled=TRUE WHERE singleton=TRUE",
                &[],
            )
            .await
            .unwrap();

        let message = Uuid::new_v4();
        let expiry = now_ms() + 3_600_000;
        let input = || NewMessage {
            account_id: account,
            client_message_id: message,
            device_id: device,
            idempotency_key: "one",
            recipient_e164: "+15551234567",
            synthetic_payload: b"test only",
            expires_at_ms: expiry,
        };
        {
            let mut store = DeliveryStore::new(&mut client);
            assert!(store.accept(input()).await.unwrap().created);
            assert!(!store.accept(input()).await.unwrap().created);
            assert!(matches!(
                store
                    .accept(NewMessage {
                        synthetic_payload: b"changed",
                        ..input()
                    })
                    .await,
                Err(StoreError::IdempotencyConflict)
            ));
            assert!(matches!(
                store
                    .connect_session(other_account, device, "a", "hub", 60)
                    .await,
                Err(StoreError::NotFound)
            ));
            let session = store
                .connect_session(account, device, "a", "hub", 60)
                .await
                .unwrap();
            let claim = store.claim_due("worker-a").await.unwrap().unwrap();
            assert_eq!(claim.message_id, message);
            let attempt = Uuid::new_v4();
            store.issue_grant(&claim, &session, attempt).await.unwrap();
            let event = |evidence, event_id| RadioEvent {
                event_id,
                account_id: account,
                message_id: message,
                attempt_id: attempt,
                evidence,
                observed_at_ms: now_ms(),
                segment_index: None,
                segment_count: None,
            };
            assert_eq!(
                store
                    .record_radio_event(event(Evidence::DurableSubmitIntent, Uuid::new_v4()))
                    .await
                    .unwrap(),
                MessageState::Submitting
            );
            assert_eq!(
                store
                    .record_radio_event(event(Evidence::CrashWithoutCallback, Uuid::new_v4()))
                    .await
                    .unwrap(),
                MessageState::Unknown
            );
            assert!(store.claim_due("worker-b").await.unwrap().is_none());
            let new_session = store
                .connect_session(account, device, "b", "hub-b", 60)
                .await
                .unwrap();
            assert!(matches!(
                store
                    .issue_grant(&claim, &new_session, Uuid::new_v4())
                    .await,
                Err(StoreError::StaleFence)
            ));

            let second_message = Uuid::new_v4();
            store
                .accept(NewMessage {
                    client_message_id: second_message,
                    idempotency_key: "two",
                    ..input()
                })
                .await
                .unwrap();
            let second_claim = store.claim_due("worker-b").await.unwrap().unwrap();
            assert_eq!(second_claim.message_id, second_message);
            assert!(matches!(
                store
                    .issue_grant(&second_claim, &new_session, Uuid::new_v4())
                    .await,
                Err(StoreError::DeviceBusy)
            ));
        }
        let second_device = Uuid::new_v4();
        client
            .execute(
                "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,'multipart phone')",
                &[&second_device, &account],
            )
            .await
            .unwrap();
        {
            let mut store = DeliveryStore::new(&mut client);
            let third_message = Uuid::new_v4();
            store
                .accept(NewMessage {
                    client_message_id: third_message,
                    device_id: second_device,
                    idempotency_key: "three",
                    ..input()
                })
                .await
                .unwrap();
            let third_claim = store.claim_due("worker-c").await.unwrap().unwrap();
            assert_eq!(third_claim.message_id, third_message);
            let third_session = store
                .connect_session(account, second_device, "a", "hub", 60)
                .await
                .unwrap();
            let third_attempt = Uuid::new_v4();
            store
                .issue_grant(&third_claim, &third_session, third_attempt)
                .await
                .unwrap();
            let multipart = |evidence, index, event_id| RadioEvent {
                event_id,
                account_id: account,
                message_id: third_message,
                attempt_id: third_attempt,
                evidence,
                observed_at_ms: now_ms(),
                segment_index: index,
                segment_count: index.map(|_| 2),
            };
            assert_eq!(
                store
                    .record_radio_event(multipart(
                        Evidence::DurableSubmitIntent,
                        None,
                        Uuid::new_v4()
                    ))
                    .await
                    .unwrap(),
                MessageState::Submitting
            );
            let first_segment = multipart(Evidence::SentCallbackOk, Some(0), Uuid::new_v4());
            assert_eq!(
                store.record_radio_event(first_segment).await.unwrap(),
                MessageState::Submitting
            );
            assert_eq!(
                store.record_radio_event(first_segment).await.unwrap(),
                MessageState::Submitting
            );
            assert_eq!(
                store
                    .record_radio_event(multipart(
                        Evidence::SentCallbackOk,
                        Some(1),
                        Uuid::new_v4()
                    ))
                    .await
                    .unwrap(),
                MessageState::Submitted
            );
            assert!(matches!(
                store
                    .record_radio_event(multipart(
                        Evidence::SentCallbackFailed,
                        Some(1),
                        Uuid::new_v4()
                    ))
                    .await,
                Err(StoreError::InvalidInput)
            ));
        }
        client
            .batch_execute(&format!(
                "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
            ))
            .await
            .unwrap();
    }
}
