// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded content retention. Replay identities stay in their parent rows.

use std::env;
use tokio_postgres::{Client, Error};
use uuid::Uuid;

pub const BATCH_SIZE: i64 = 100;

#[derive(Clone, Copy, Debug)]
pub struct RetentionPolicy {
    pub idempotency_days: i32,
    pub message_days: i32,
    pub message_events_days: i32,
    pub webhook_days: i32,
    pub inbound_days: i32,
    pub sealed_inbound_days: i32,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            idempotency_days: 7,
            message_days: 30,
            message_events_days: 90,
            webhook_days: 30,
            inbound_days: 30,
            sealed_inbound_days: 30,
        }
    }
}

impl RetentionPolicy {
    pub fn from_env() -> Result<Self, String> {
        let defaults = Self::default();
        Ok(Self {
            idempotency_days: days("ZT_IDEMPOTENCY_RETENTION_DAYS", defaults.idempotency_days)?,
            message_days: days("ZT_MESSAGE_CONTENT_RETENTION_DAYS", defaults.message_days)?,
            message_events_days: days(
                "ZT_MESSAGE_EVENTS_RETENTION_DAYS",
                defaults.message_events_days,
            )?,
            webhook_days: days("ZT_WEBHOOK_HISTORY_RETENTION_DAYS", defaults.webhook_days)?,
            inbound_days: days("ZT_INBOUND_CONTENT_RETENTION_DAYS", defaults.inbound_days)?,
            sealed_inbound_days: days(
                "ZT_SEALED_INBOUND_CONTENT_RETENTION_DAYS",
                defaults.sealed_inbound_days,
            )?,
        })
    }
}

fn days(key: &'static str, default: i32) -> Result<i32, String> {
    match env::var(key) {
        Err(env::VarError::NotPresent) => Ok(default),
        Ok(value) => value
            .parse::<i32>()
            .ok()
            .filter(|days| (1..=3650).contains(days))
            .ok_or_else(|| format!("{key} must be an integer from 1 to 3650")),
        Err(_) => Err(format!("{key} must be valid UTF-8")),
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct RetentionCounts {
    pub idempotency_keys: u64,
    pub messages: u64,
    pub message_events: u64,
    pub webhook_deliveries: u64,
    pub inbound_events: u64,
    pub sealed_inbound_events: u64,
}

impl RetentionCounts {
    /// Whether any table may still have due rows beyond this batch.
    pub fn any_full(&self, limit: i64) -> bool {
        let limit = limit as u64;
        [
            self.idempotency_keys,
            self.messages,
            self.message_events,
            self.webhook_deliveries,
            self.inbound_events,
            self.sealed_inbound_events,
        ]
        .into_iter()
        .any(|count| count >= limit)
    }
}

/// Each table handles at most one batch per call. Concurrent hubs skip locked
/// rows; no table-wide lock, cascade, or unbounded delete is used.
pub async fn prune(
    client: &mut Client,
    policy: RetentionPolicy,
    limit: i64,
) -> Result<RetentionCounts, Error> {
    assert!((1..=1000).contains(&limit));
    let idempotency_keys = client
        .execute(
            "WITH due AS (SELECT account_id,key FROM idempotency_keys \
         WHERE expires_at<=now() ORDER BY expires_at,account_id,key \
         FOR UPDATE SKIP LOCKED LIMIT $1) \
         DELETE FROM idempotency_keys k USING due \
         WHERE (k.account_id,k.key)=(due.account_id,due.key)",
            &[&limit],
        )
        .await?;
    let messages = client
        .execute(
            "WITH due AS (SELECT m.id FROM messages m \
         WHERE m.updated_at<=now()-$1::int * interval '1 day' \
           AND m.recipient_e164 IS NOT NULL \
           AND m.state IN ('delivered','failed','cancelled','expired') \
           AND NOT EXISTS (SELECT 1 FROM dispatch_fences f WHERE f.message_id=m.id AND f.outcome IN ('granted','submitting','unknown')) \
         ORDER BY m.updated_at,m.id FOR UPDATE OF m SKIP LOCKED LIMIT $2) \
         UPDATE messages m SET recipient_e164=NULL,transport_payload=NULL \
         FROM due WHERE m.id=due.id",
            &[&policy.message_days, &limit],
        )
        .await?;
    let message_events = client
        .execute(
            "WITH due AS (SELECT e.id FROM message_events e \
         JOIN messages m ON (m.account_id,m.id)=(e.account_id,e.message_id) \
         WHERE e.received_at<=now()-$1::int * interval '1 day' \
           AND m.recipient_e164 IS NULL \
           AND m.state IN ('delivered','failed','cancelled','expired') \
           AND NOT EXISTS (SELECT 1 FROM dispatch_fences f WHERE f.message_id=m.id AND f.outcome IN ('granted','submitting','unknown')) \
         ORDER BY e.received_at,e.id FOR UPDATE OF e SKIP LOCKED LIMIT $2) \
         DELETE FROM message_events e USING due WHERE e.id=due.id",
            &[&policy.message_events_days, &limit],
        )
        .await?;

    // Lock delivery parents while removing all three related history tables.
    // An owner replay or a worker status change cannot race the deletion.
    let tx = client.transaction().await?;
    let rows = tx
        .query(
            "SELECT d.id FROM webhook_deliveries d \
         JOIN inbound_events i ON (i.account_id,i.id)=(d.account_id,d.event_id) \
         JOIN messages m ON (m.account_id,m.id)=(i.account_id,i.message_id) \
         WHERE d.status IN ('succeeded','dead') \
           AND d.updated_at<=now()-$1::int * interval '1 day' \
           AND m.state IN ('delivered','failed','cancelled','expired') \
           AND NOT EXISTS (SELECT 1 FROM dispatch_fences f WHERE f.message_id=m.id AND f.outcome IN ('granted','submitting','unknown')) \
         ORDER BY d.updated_at,d.id FOR UPDATE OF d SKIP LOCKED LIMIT $2",
            &[&policy.webhook_days, &limit],
        )
        .await?;
    let ids: Vec<Uuid> = rows.iter().map(|row| row.get(0)).collect();
    let webhook_deliveries = if ids.is_empty() {
        0
    } else {
        tx.execute(
            "DELETE FROM webhook_attempts WHERE delivery_id=ANY($1)",
            &[&ids],
        )
        .await?;
        tx.execute(
            "DELETE FROM webhook_replay_requests WHERE delivery_id=ANY($1)",
            &[&ids],
        )
        .await?;
        tx.execute("DELETE FROM webhook_deliveries WHERE id=ANY($1)", &[&ids])
            .await?
    };
    tx.commit().await?;

    // Keep the M1 event ID, device sequence, digest and signature as replay
    // tombstones. A webhook remains replayable until its history is gone.
    let inbound_events = client
        .execute(
            "WITH due AS (SELECT i.id FROM inbound_events i \
         JOIN messages m ON (m.account_id,m.id)=(i.account_id,i.message_id) \
         WHERE i.received_at<=now()-$1::int * interval '1 day' \
           AND i.content_ciphertext IS NOT NULL \
           AND m.state IN ('delivered','failed','cancelled','expired') \
           AND NOT EXISTS (SELECT 1 FROM dispatch_fences f WHERE f.message_id=m.id AND f.outcome IN ('granted','submitting','unknown')) \
           AND NOT EXISTS (SELECT 1 FROM webhook_deliveries d WHERE d.event_id=i.id) \
         ORDER BY i.received_at,i.id FOR UPDATE OF i SKIP LOCKED LIMIT $2) \
         UPDATE inbound_events i SET content_kind='redacted',content_ciphertext=NULL \
         FROM due WHERE i.id=due.id",
            &[&policy.inbound_days, &limit],
        )
        .await?;
    let sealed_inbound_events = client
        .execute(
            "WITH due AS (SELECT id FROM sealed_inbound_events \
         WHERE received_at<=now()-$1::int * interval '1 day' AND envelope IS NOT NULL \
         ORDER BY received_at,id FOR UPDATE SKIP LOCKED LIMIT $2) \
         UPDATE sealed_inbound_events e SET envelope=NULL FROM due WHERE e.id=due.id",
            &[&policy.sealed_inbound_days, &limit],
        )
        .await?;
    Ok(RetentionCounts {
        idempotency_keys,
        messages,
        message_events,
        webhook_deliveries,
        inbound_events,
        sealed_inbound_events,
    })
}

#[cfg(test)]
mod tests;
