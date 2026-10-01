// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded content retention. Replay identities stay in their parent rows.

use std::env;
use std::future::Future;
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
    pub device_preconditions: u64,
    pub conversation_consents: u64,
    pub conversation_admissions_closed: u64,
    pub conversation_provenance: u64,
    pub conversation_intervals: u64,
    pub workflow_contexts: u64,
    pub conversation_confirmations: u64,
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
            self.device_preconditions,
            self.conversation_consents,
            self.conversation_admissions_closed,
            self.conversation_provenance,
            self.conversation_intervals,
            self.workflow_contexts,
            self.conversation_confirmations,
        ]
        .into_iter()
        .any(|count| count >= limit)
    }
}

/// How long a retention-blocked candidate is skipped before the prune
/// reconsiders it. Blocked rows carry a dispatch fence or positive sent
/// evidence inside the event window; without the stamp every fifteen-second
/// tick re-ran those existence probes for every blocked row.
/// A candidate older than the content cutoff that neither prune nor stamp
/// matched this pass: stamped here so the next recheck window skips it.
const STAMP_BLOCKED: &str = "\
WITH blocked AS (SELECT m.id FROM messages m \
 WHERE m.updated_at<=now()-$1::int * interval '1 day' \
   AND m.recipient_e164 IS NOT NULL \
   AND m.state IN ('delivered','failed','cancelled','expired') \
   AND (m.retention_blocked_at IS NULL OR m.retention_blocked_at<=now()-interval '1 hour') \
   AND (EXISTS (SELECT 1 FROM dispatch_fences f WHERE f.message_id=m.id AND f.outcome IN ('granted','submitting','unknown')) \
     OR EXISTS (SELECT 1 FROM message_events me \
         WHERE (me.account_id,me.message_id)=(m.account_id,m.id) \
           AND me.evidence_code='sent_callback_ok' \
           AND me.received_at>now()-$2::int * interval '1 day')) \
 ORDER BY m.updated_at,m.id FOR UPDATE OF m SKIP LOCKED LIMIT $3) \
UPDATE messages m SET retention_blocked_at=clock_timestamp() FROM blocked WHERE m.id=blocked.id";

/// One table's pruning, isolated from the others: a failure is logged with
/// its table name and counted as zero instead of aborting the remaining
/// tables (#654). Every step failing still surfaces as an error so the
/// worker's unavailability log stays meaningful.
async fn step<T: Default>(
    table: &'static str,
    first_error: &mut Option<Error>,
    failures: &mut u8,
    run: impl Future<Output = Result<T, Error>>,
) -> T {
    match run.await {
        Ok(count) => count,
        Err(error) => {
            eprintln!("retention prune step {table} failed: {error}");
            *failures += 1;
            if first_error.is_none() {
                *first_error = Some(error);
            }
            T::default()
        }
    }
}

/// Each table handles at most one batch per call. Concurrent hubs skip locked
/// rows; no table-wide lock, cascade, or unbounded delete is used. A message
/// past the content cutoff that is still fenced or still carries positive
/// sent evidence is stamped and skipped for the recheck interval, so such
/// rows cost one reprobe per interval instead of one per tick, and their
/// content can outlive the cutoff by at most that interval.
pub async fn prune(
    client: &mut Client,
    policy: RetentionPolicy,
    limit: i64,
) -> Result<RetentionCounts, Error> {
    assert!((1..=1000).contains(&limit));
    let mut first_error: Option<Error> = None;
    let mut failures = 0_u8;
    let mandatory_steps = 10_u8;

    let idempotency_keys = step(
        "idempotency_keys",
        &mut first_error,
        &mut failures,
        client.execute(
            "WITH due AS (SELECT account_id,key FROM idempotency_keys \
         WHERE expires_at<=now() ORDER BY expires_at,account_id,key \
         FOR UPDATE SKIP LOCKED LIMIT $1) \
         DELETE FROM idempotency_keys k USING due \
         WHERE (k.account_id,k.key)=(due.account_id,due.key)",
            &[&limit],
        ),
    )
    .await;
    // A signed STOP or START reply binds to an attempt with positive sent
    // evidence and needs the recipient to record or clear a suppression. The
    // recipient therefore outlives content retention while such evidence is
    // inside the event window; the event row is deleted below only after the
    // recipient is gone, so both cutoffs must have passed. Blocked candidates
    // are stamped so the next recheck window, not every tick, re-probes them.
    let messages = step(
        "messages",
        &mut first_error,
        &mut failures,
        client.execute(
            "WITH due AS (SELECT m.id FROM messages m \
         WHERE m.updated_at<=now()-$1::int * interval '1 day' \
           AND m.recipient_e164 IS NOT NULL \
           AND m.state IN ('delivered','failed','cancelled','expired') \
           AND (m.retention_blocked_at IS NULL OR m.retention_blocked_at<=now()-interval '1 hour') \
           AND NOT EXISTS (SELECT 1 FROM dispatch_fences f WHERE f.message_id=m.id AND f.outcome IN ('granted','submitting','unknown')) \
           AND NOT EXISTS (SELECT 1 FROM message_events me \
               WHERE (me.account_id,me.message_id)=(m.account_id,m.id) \
                 AND me.evidence_code='sent_callback_ok' \
                 AND me.received_at>now()-$3::int * interval '1 day') \
         ORDER BY m.updated_at,m.id FOR UPDATE OF m SKIP LOCKED LIMIT $2) \
         UPDATE messages m SET recipient_e164=NULL,transport_payload=NULL \
         FROM due WHERE m.id=due.id",
            &[&policy.message_days, &limit, &policy.message_events_days],
        ),
    )
    .await;
    step(
        "messages_retention_blocked",
        &mut first_error,
        &mut failures,
        client.execute(
            STAMP_BLOCKED,
            &[&policy.message_days, &policy.message_events_days, &limit],
        ),
    )
    .await;
    let message_events = step(
        "message_events",
        &mut first_error,
        &mut failures,
        client.execute(
            "WITH due AS (SELECT e.id FROM message_events e \
         JOIN messages m ON (m.account_id,m.id)=(e.account_id,e.message_id) \
         WHERE e.received_at<=now()-$1::int * interval '1 day' \
           AND m.recipient_e164 IS NULL \
           AND m.state IN ('delivered','failed','cancelled','expired') \
           AND (m.retention_blocked_at IS NULL OR m.retention_blocked_at<=now()-interval '1 hour') \
           AND NOT EXISTS (SELECT 1 FROM dispatch_fences f WHERE f.message_id=m.id AND f.outcome IN ('granted','submitting','unknown')) \
         ORDER BY e.received_at,e.id FOR UPDATE OF e SKIP LOCKED LIMIT $2) \
         DELETE FROM message_events e USING due WHERE e.id=due.id",
            &[&policy.message_events_days, &limit],
        ),
    )
    .await;

    // Lock delivery parents while removing all three related history tables.
    // An owner replay or a worker status change cannot race the deletion.
    let webhook_deliveries = step(
        "webhook_deliveries",
        &mut first_error,
        &mut failures,
        async {
            let tx = client.transaction().await?;
            let rows = tx
                .query(
                    "SELECT d.id FROM webhook_deliveries d \
         JOIN inbound_events i ON (i.account_id,i.id)=(d.account_id,d.event_id) \
         JOIN messages m ON (m.account_id,m.id)=(i.account_id,i.message_id) \
         WHERE d.status IN ('succeeded','dead') \
           AND d.updated_at<=now()-$1::int * interval '1 day' \
           AND m.state IN ('delivered','failed','cancelled','expired') \
           AND (m.retention_blocked_at IS NULL OR m.retention_blocked_at<=now()-interval '1 hour') \
           AND NOT EXISTS (SELECT 1 FROM dispatch_fences f WHERE f.message_id=m.id AND f.outcome IN ('granted','submitting','unknown')) \
         ORDER BY d.updated_at,d.id FOR UPDATE OF d SKIP LOCKED LIMIT $2",
                    &[&policy.webhook_days, &limit],
                )
                .await?;
            let ids: Vec<Uuid> = rows.iter().map(|row| row.get(0)).collect();
            let deleted = if ids.is_empty() {
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
                tx.execute(
                    "DELETE FROM webhook_deliveries WHERE id=ANY($1)",
                    &[&ids],
                )
                .await?
            };
            tx.commit().await?;
            Ok(deleted)
        },
    )
    .await;

    // Keep the M1 event ID, device sequence, digest and signature as replay
    // tombstones. A webhook remains replayable until its history is gone.
    let inbound_events = step(
        "inbound_events",
        &mut first_error,
        &mut failures,
        client.execute(
            "WITH due AS (SELECT i.id FROM inbound_events i \
         JOIN messages m ON (m.account_id,m.id)=(i.account_id,i.message_id) \
         WHERE i.received_at<=now()-$1::int * interval '1 day' \
           AND i.content_ciphertext IS NOT NULL \
           AND m.state IN ('delivered','failed','cancelled','expired') \
           AND (m.retention_blocked_at IS NULL OR m.retention_blocked_at<=now()-interval '1 hour') \
           AND NOT EXISTS (SELECT 1 FROM dispatch_fences f WHERE f.message_id=m.id AND f.outcome IN ('granted','submitting','unknown')) \
           AND NOT EXISTS (SELECT 1 FROM webhook_deliveries d WHERE d.event_id=i.id) \
         ORDER BY i.received_at,i.id FOR UPDATE OF i SKIP LOCKED LIMIT $2) \
         UPDATE inbound_events i SET content_kind='redacted',content_ciphertext=NULL \
         FROM due WHERE i.id=due.id",
            &[&policy.inbound_days, &limit],
        ),
    )
    .await;
    let sealed_inbound_events = step(
        "sealed_inbound_events",
        &mut first_error,
        &mut failures,
        client.execute(
            "WITH due AS (SELECT id FROM sealed_inbound_events \
         WHERE received_at<=now()-$1::int * interval '1 day' AND envelope IS NOT NULL \
         ORDER BY received_at,id FOR UPDATE SKIP LOCKED LIMIT $2) \
         UPDATE sealed_inbound_events e SET envelope=NULL FROM due WHERE e.id=due.id",
            &[&policy.sealed_inbound_days, &limit],
        ),
    )
    .await;
    let device_preconditions = step(
        "device_preconditions",
        &mut first_error,
        &mut failures,
        client.execute(
            "WITH due AS (SELECT device_id FROM device_preconditions \
         WHERE received_at<now()-interval '1 day' ORDER BY received_at,device_id \
         FOR UPDATE SKIP LOCKED LIMIT $1) \
         DELETE FROM device_preconditions r USING due WHERE r.device_id=due.device_id",
            &[&limit],
        ),
    )
    .await;
    let conversation_consents = step(
        "conversation_consents",
        &mut first_error,
        &mut failures,
        crate::http_owner_conversations::lifecycle::prune_withdrawn(
            client,
            policy.sealed_inbound_days,
            limit,
        ),
    )
    .await;
    let workflow_contexts = step(
        "workflow_contexts",
        &mut first_error,
        &mut failures,
        crate::http_owner_conversations::context::lifecycle::prune(
            client,
            policy.sealed_inbound_days,
            limit,
        ),
    )
    .await;
    let (conversation_admissions_closed, conversation_provenance, conversation_intervals) = step(
        "conversation_activation",
        &mut first_error,
        &mut failures,
        crate::http_owner_conversations::lifecycle::activation::prune(
            client,
            policy.sealed_inbound_days,
            limit,
        ),
    )
    .await;
    // An absent optional proof table must not turn total mandatory pruning
    // failure into a successful worker tick.
    let mandatory_unavailable = failures == mandatory_steps;
    let conversation_confirmations = step(
        "conversation_confirmation_records",
        &mut first_error,
        &mut failures,
        crate::http_owner_conversations::confirmation_records::redact(client, limit),
    )
    .await;
    if mandatory_unavailable && let Some(error) = first_error {
        return Err(error);
    }
    Ok(RetentionCounts {
        idempotency_keys,
        messages,
        message_events,
        webhook_deliveries,
        inbound_events,
        sealed_inbound_events,
        device_preconditions,
        conversation_consents,
        conversation_admissions_closed,
        conversation_provenance,
        conversation_intervals,
        workflow_contexts,
        conversation_confirmations,
    })
}

#[cfg(test)]
mod tests;
