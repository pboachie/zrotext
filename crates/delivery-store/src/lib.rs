// SPDX-License-Identifier: AGPL-3.0-only
//! PostgreSQL single-writer transactions for the private synthetic-content alpha.
//! Callers must authenticate account/device context before invoking these methods.

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_postgres::{Client, Row, Transaction, error::SqlState, types::Type};
use uuid::Uuid;
use zrotext_domain::{Evidence, MessageState};

mod recovery;
pub use recovery::{RECOVERY_BATCH, RECOVERY_BATCHES_PER_TICK, RecoveryBacklog, RecoveryPass};
pub mod sealed;

/// See [`DeliveryStore::synthetic_grant_may_be_due`]. Public so plan tests
/// can prove the recent-attempt probe stays an index range scan.
pub const SYNTHETIC_GRANT_PRECHECK: &str = "SELECT COALESCE((SELECT dispatch_enabled \
      FROM deployment_authority WHERE singleton=TRUE AND epoch=$3),FALSE) \
    AND NOT EXISTS(SELECT 1 FROM dispatch_fences WHERE account_id=$1 AND device_id=$2 \
      AND outcome IN ('granted','submitting','unknown')) \
    AND NOT EXISTS(SELECT 1 FROM message_attempts WHERE account_id=$1 AND device_id=$2 \
      AND created_at>now()-($4::integer * interval '1 second'))";

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
    #[error("pending message queue is full")]
    QueueFull,
    #[error("message state does not permit this evidence")]
    InvalidTransition,
    #[error("event ID was reused for different evidence")]
    EventIdConflict,
    #[error("outbound quota policy is not configured")]
    QuotaNotConfigured,
    #[error("outbound quota is exhausted")]
    QuotaExceeded,
    #[error("billing payment requires review")]
    PaymentHold,
    #[error("recipient is suppressed for this account")]
    RecipientSuppressed,
}

#[derive(Clone, Copy)]
enum MeteringTime {
    Unmetered,
    Database,
    Alpha {
        billing_enabled: bool,
    },
    #[cfg(test)]
    UnixMillis(i64),
}

// Admission limits protect the single writer and keep a disconnected pilot
// phone from accumulating an unbounded queue. These are operational safety
// limits, not subscription entitlements.
const MAX_PENDING_PER_DEVICE: i64 = 16;
const MAX_PENDING_PER_ACCOUNT: i64 = 128;
const MAX_ALPHA_EXPIRY_MS: i64 = 15 * 60 * 1000;
const RADIO_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

pub struct NewMessage<'a> {
    pub account_id: Uuid,
    /// Caller-chosen message identity. `accept` and `accept_metered` store it
    /// as `messages.id`; `accept_alpha` stores [`alpha_message_id`] instead.
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
pub struct MessageSnapshot {
    pub account_id: Uuid,
    pub message_id: Uuid,
    pub device_id: Uuid,
    pub state: MessageState,
    pub state_version: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
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
    pub expires_at_ms: i64,
}

/// Private synthetic-alpha content released only after a current execution
/// grant is checked again. Never log this value or expose it on a public API.
pub struct SyntheticExecutionPayload {
    pub recipient_e164: String,
    pub body: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RadioEvent {
    pub event_id: Uuid,
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub message_id: Uuid,
    pub attempt_id: Uuid,
    pub evidence: Evidence,
    pub observed_at_ms: i64,
    pub segment_index: Option<i32>,
    pub segment_count: Option<i32>,
}

pub struct DeliveryStore<'a> {
    client: &'a mut Client,
    idempotency_days: i32,
}

impl<'a> DeliveryStore<'a> {
    pub fn new(client: &'a mut Client) -> Self {
        Self {
            client,
            idempotency_days: 7,
        }
    }

    /// The runtime validates the configured window at startup. Existing keys
    /// retain their persisted expiry when this setting changes.
    pub fn with_idempotency_days(client: &'a mut Client, days: i32) -> Self {
        assert!((1..=3650).contains(&days));
        Self {
            client,
            idempotency_days: days,
        }
    }

    /// Every caller supplies the authenticated tenant ID; a cross-tenant ID
    /// has the same result as an absent message.
    pub async fn status(
        &self,
        account_id: Uuid,
        message_id: Uuid,
    ) -> Result<Option<MessageSnapshot>, StoreError> {
        let row = self
            .client
            .query_opt(
                "SELECT device_id,state,state_version, \
             (extract(epoch FROM created_at)*1000)::bigint, \
             (extract(epoch FROM updated_at)*1000)::bigint \
             FROM messages WHERE account_id=$1 AND id=$2",
                &[&account_id, &message_id],
            )
            .await?;
        row.map(|row| {
            Ok(MessageSnapshot {
                account_id,
                message_id,
                device_id: row.get(0),
                state: state_from_str(&row.get::<_, String>(1))
                    .ok_or(StoreError::InvalidTransition)?,
                state_version: row.get(2),
                created_at_ms: row.get(3),
                updated_at_ms: row.get(4),
            })
        })
        .transpose()
    }

    /// Inserts idempotency identity, message and job in one writer transaction.
    /// No HTTP 202 should be returned until this transaction commits.
    pub async fn accept(&mut self, input: NewMessage<'_>) -> Result<AcceptOutcome, StoreError> {
        let message_id = input.client_message_id;
        self.accept_inner(input, message_id, MeteringTime::Unmetered)
            .await
    }

    /// Use for a quota-governed send. The reservation, idempotency record,
    /// message and dispatch job commit together. The period is UTC calendar
    /// month at the database transaction start; replay never reserves again.
    pub async fn accept_metered(
        &mut self,
        input: NewMessage<'_>,
    ) -> Result<AcceptOutcome, StoreError> {
        let message_id = input.client_message_id;
        self.accept_inner(input, message_id, MeteringTime::Database)
            .await
    }

    /// Private alpha admission follows the runtime billing gate and any
    /// customer binding already persisted by an earlier billing run. The
    /// Binding lookup and acceptance share one transaction. Bound tenants lock
    /// the customer row before the account row to match billing ingress.
    /// The stored message ID is [`alpha_message_id`], never the caller's
    /// `client_message_id`, so one account cannot collide with or probe for
    /// another account's messages.
    pub async fn accept_alpha(
        &mut self,
        input: NewMessage<'_>,
        billing_enabled: bool,
    ) -> Result<AcceptOutcome, StoreError> {
        let message_id = alpha_message_id(input.account_id, input.client_message_id);
        self.accept_inner(input, message_id, MeteringTime::Alpha { billing_enabled })
            .await
    }

    #[cfg(test)]
    async fn accept_metered_at(
        &mut self,
        input: NewMessage<'_>,
        unix_ms: i64,
    ) -> Result<AcceptOutcome, StoreError> {
        let message_id = input.client_message_id;
        self.accept_inner(input, message_id, MeteringTime::UnixMillis(unix_ms))
            .await
    }

    /// `message_id` is the stored `messages.id`. The request digest still
    /// covers the caller's `client_message_id`, so an exact replay of a key
    /// recorded before alpha IDs were account-scoped keeps its original result.
    async fn accept_inner(
        &mut self,
        input: NewMessage<'_>,
        message_id: Uuid,
        metering: MeteringTime,
    ) -> Result<AcceptOutcome, StoreError> {
        validate_message(&input)?;
        let digest = request_digest(&input);
        let recipient_digest = Sha256::digest(input.recipient_e164.as_bytes()).to_vec();
        let expiry = input.expires_at_ms as f64;
        let tx = self.client.transaction().await?;
        let (require_reservation, bound) = if let MeteringTime::Alpha { billing_enabled } = metering
        {
            lock_billing_account(&tx, input.account_id, billing_enabled).await?
        } else {
            (!matches!(metering, MeteringTime::Unmetered), None)
        };
        // Suppression writers take this same account lock. A STOP that wins
        // before admission commits must be visible here, even across sites.
        // Take it before idempotency lookup so an exact retry cannot return
        // another successful acceptance after a suppression is recorded.
        if !matches!(metering, MeteringTime::Alpha { .. }) {
            tx.query_typed_one(
                "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
                &[(&input.account_id, Type::UUID)],
            )
            .await?;
        }
        // Owner-recorded off-channel holds use the same account lock and block
        // exactly like signed suppressions, including an exact replay.
        if tx.query_typed_opt(
            "SELECT 1 FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164=$2 AND active=TRUE \
             UNION ALL SELECT 1 FROM owner_recipient_holds \
             WHERE account_id=$1 AND recipient_e164=$2 AND released_at IS NULL LIMIT 1",
            &[(&input.account_id, Type::UUID), (&input.recipient_e164, Type::TEXT)],
        ).await?.is_some() {
            return Err(StoreError::RecipientSuppressed);
        }
        let new_key = tx
            .query_typed_opt(
                "INSERT INTO idempotency_keys (account_id, key, request_digest, message_id, expires_at) \
                 VALUES ($1,$2,$3,$4,now() + $5::int * interval '1 day') \
                 ON CONFLICT (account_id,key) DO UPDATE SET \
                   request_digest=EXCLUDED.request_digest,message_id=EXCLUDED.message_id, \
                   expires_at=EXCLUDED.expires_at \
                 WHERE idempotency_keys.expires_at<=now() RETURNING message_id",
                &[(&input.account_id, Type::UUID), (&input.idempotency_key, Type::TEXT),
                  (&digest, Type::BYTEA), (&message_id, Type::UUID),
                  (&self.idempotency_days, Type::INT4)],
            )
            .await;
        let new_key = match new_key {
            Ok(value) => value,
            Err(error)
                if error.as_db_error().is_some_and(|db| {
                    db.code() == &SqlState::UNIQUE_VIOLATION
                        && db.constraint() == Some("idempotency_message_id")
                }) =>
            {
                // Preserve expired-new-request validation precedence from #153.
                validate_new_expiry(input.expires_at_ms, metering)?;
                return Err(StoreError::MessageIdConflict);
            }
            Err(error) => return Err(StoreError::Database(error)),
        };
        if new_key.is_none() {
            let row = tx
                .query_typed_opt(
                    "SELECT message_id, request_digest FROM idempotency_keys \
                     WHERE account_id=$1 AND key=$2 AND expires_at>now()",
                    &[
                        (&input.account_id, Type::UUID),
                        (&input.idempotency_key, Type::TEXT),
                    ],
                )
                .await?;
            let Some(row) = row else {
                // The other unique constraint is message_id. A different key
                // for an expired request is invalid before its ID collision is
                // reported; neither path can create a message or dispatch job.
                validate_new_expiry(input.expires_at_ms, metering)?;
                return Err(StoreError::MessageIdConflict);
            };
            let saved_digest: Vec<u8> = row.get(1);
            if saved_digest != digest {
                return Err(StoreError::IdempotencyConflict);
            }
            let message_id: Uuid = row.get(0);
            // An exact alpha replay can predate the account's billing binding.
            // It creates no new message or radio work, so preserve the original
            // result without retroactively requiring a usage reservation. A
            // different key for that message still follows the collision guard
            // below; ordinary metered acceptance retains its reservation check.
            if require_reservation
                && !matches!(metering, MeteringTime::Alpha { .. })
                && !reservation_exists(&tx, input.account_id, message_id).await?
            {
                return Err(StoreError::IdempotencyConflict);
            }
            tx.commit().await?;
            return Ok(AcceptOutcome {
                message_id,
                created: false,
            });
        }

        // A retained key must replay even after the message expires. For a
        // newly inserted key, reject elapsed expiry before creating any work;
        // returning here rolls the uncommitted key insertion back as well.
        validate_new_expiry(input.expires_at_ms, metering)?;

        // Every new acceptance for this account takes the same row lock. The
        // counts and insert are in one transaction, so parallel API instances
        // cannot each observe one remaining slot and overfill the queue.
        let counts = tx
            .query_typed_one(
                "SELECT COUNT(*) FILTER (WHERE device_id=$2), COUNT(*) FROM messages \
             WHERE account_id=$1 AND state IN ('queued','claimed') AND expires_at>now()",
                &[
                    (&input.account_id, Type::UUID),
                    (&input.device_id, Type::UUID),
                ],
            )
            .await?;
        let device_pending: i64 = counts.get(0);
        let account_pending: i64 = counts.get(1);
        if device_pending >= MAX_PENDING_PER_DEVICE || account_pending >= MAX_PENDING_PER_ACCOUNT {
            return Err(StoreError::QueueFull);
        }

        let created = tx
            .query_typed_opt(
                "INSERT INTO messages (id,account_id,device_id,recipient_e164,recipient_digest,transport_mode,transport_payload,request_digest,state,expires_at) \
                 VALUES ($1,$2,$3,$4,$5,'synthetic_alpha',$6,$7,'queued',to_timestamp($8::double precision / 1000)) \
                 ON CONFLICT (id) DO NOTHING RETURNING id",
                &[(&message_id, Type::UUID), (&input.account_id, Type::UUID),
                  (&input.device_id, Type::UUID), (&input.recipient_e164, Type::TEXT),
                  (&recipient_digest, Type::BYTEA), (&input.synthetic_payload, Type::BYTEA),
                  (&digest, Type::BYTEA), (&expiry, Type::FLOAT8)],
            )
            .await?;
        if created.is_none() {
            let row = tx
                .query_typed_one(
                    "SELECT account_id,request_digest FROM messages WHERE id=$1",
                    &[(&message_id, Type::UUID)],
                )
                .await?;
            let owner: Uuid = row.get(0);
            let saved_digest: Vec<u8> = row.get(1);
            if owner != input.account_id || saved_digest != digest {
                return Err(StoreError::MessageIdConflict);
            }
            if require_reservation && !reservation_exists(&tx, input.account_id, message_id).await?
            {
                return Err(StoreError::IdempotencyConflict);
            }
            tx.commit().await?;
            return Ok(AcceptOutcome {
                message_id,
                created: false,
            });
        }
        match metering {
            MeteringTime::Unmetered => {}
            MeteringTime::Database => {
                reserve_outbound(&tx, input.account_id, message_id, None, None).await?
            }
            MeteringTime::Alpha { .. } if require_reservation => {
                reserve_outbound(&tx, input.account_id, message_id, None, bound).await?
            }
            MeteringTime::Alpha { .. } => {}
            #[cfg(test)]
            MeteringTime::UnixMillis(unix_ms) => {
                reserve_outbound(&tx, input.account_id, message_id, Some(unix_ms), None).await?
            }
        }
        tx.execute_typed(
            "INSERT INTO dispatch_jobs (message_id,account_id,device_id) VALUES ($1,$2,$3)",
            &[
                (&message_id, Type::UUID),
                (&input.account_id, Type::UUID),
                (&input.device_id, Type::UUID),
            ],
        )
        .await?;
        tx.commit().await?;
        Ok(AcceptOutcome {
            message_id,
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
        self.claim_due_inner(worker_id, None, None, None).await
    }

    /// A connected phone's worker must only claim jobs for that authenticated
    /// tenant/device pair; offline phones cannot be consumed by its socket.
    pub async fn claim_due_for_device(
        &mut self,
        worker_id: &str,
        account_id: Uuid,
        device_id: Uuid,
    ) -> Result<Option<Claim>, StoreError> {
        self.claim_due_inner(worker_id, Some(account_id), Some(device_id), None)
            .await
    }

    /// Unlocked pre-claim filter for a device's synthetic dispatch, in one
    /// statement: dispatch is enabled for `deployment_epoch`, the device has
    /// no active fence, and it has no attempt newer than `min_spacing_secs`.
    /// A false answer only avoids a claim that `issue_grant` would refuse or
    /// that grant spacing forbids; `issue_grant` still re-checks authority,
    /// device, account, session and the active-device fence under lock. The
    /// recent-attempt test is a range scan of
    /// `message_attempts_device_created`, so it reads only the device's
    /// recent attempts rather than its whole history.
    pub async fn synthetic_grant_may_be_due(
        &mut self,
        account_id: Uuid,
        device_id: Uuid,
        deployment_epoch: i64,
        min_spacing_secs: i32,
    ) -> Result<bool, StoreError> {
        Ok(self
            .client
            .query_typed_one(
                SYNTHETIC_GRANT_PRECHECK,
                &[
                    (&account_id, Type::UUID),
                    (&device_id, Type::UUID),
                    (&deployment_epoch, Type::INT8),
                    (&min_spacing_secs, Type::INT4),
                ],
            )
            .await?
            .get(0))
    }

    /// A one-shot phone readiness signal can narrow a claim to the exact
    /// recipient digest approved locally on that phone.
    pub async fn claim_due_for_device_and_recipient(
        &mut self,
        worker_id: &str,
        account_id: Uuid,
        device_id: Uuid,
        recipient_digest: &[u8; 32],
    ) -> Result<Option<Claim>, StoreError> {
        self.claim_due_inner(
            worker_id,
            Some(account_id),
            Some(device_id),
            Some(recipient_digest.as_slice()),
        )
        .await
    }

    async fn claim_due_inner(
        &mut self,
        worker_id: &str,
        account_id: Option<Uuid>,
        device_id: Option<Uuid>,
        recipient_digest: Option<&[u8]>,
    ) -> Result<Option<Claim>, StoreError> {
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
                     AND j.grant_issued_at IS NULL AND j.finished_at IS NULL \
                     AND m.state IN ('queued','claimed') AND m.expires_at>now() \
                     AND m.transport_mode='synthetic_alpha' \
                     AND d.revoked_at IS NULL \
                     AND ($2::uuid IS NULL OR j.account_id=$2) \
                     AND ($3::uuid IS NULL OR j.device_id=$3) \
                     AND ($4::bytea IS NULL OR m.recipient_digest=$4) \
                   ORDER BY j.next_attempt_at,j.message_id FOR UPDATE OF j SKIP LOCKED LIMIT 1 \
                 ) UPDATE dispatch_jobs j SET lease_owner=$1,lease_until=now()+interval '30 seconds', \
                   generation=j.generation+1 FROM picked WHERE j.message_id=picked.message_id \
                 RETURNING j.account_id,j.message_id,j.device_id,j.generation",
                &[&worker_id, &account_id, &device_id, &recipient_digest],
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

    /// A tenant may cancel while the queue still has proof that no execution
    /// grant was issued. A claimed job remains cancellable before that grant.
    pub async fn cancel(&mut self, account_id: Uuid, message_id: Uuid) -> Result<bool, StoreError> {
        let tx = self.client.transaction().await?;
        let job = tx.query_opt(
            "SELECT grant_issued_at IS NULL FROM dispatch_jobs WHERE account_id=$1 AND message_id=$2 FOR UPDATE",
            &[&account_id, &message_id],
        ).await?;
        let Some(job) = job else {
            return Ok(false);
        };
        if !job.get::<_, bool>(0) {
            return Err(StoreError::InvalidTransition);
        }
        let row = tx
            .query_one(
                "SELECT state FROM messages WHERE account_id=$1 AND id=$2 FOR UPDATE",
                &[&account_id, &message_id],
            )
            .await?;
        let current = state_from_row(&row)?;
        current
            .apply(Evidence::Cancel)
            .map_err(|_| StoreError::InvalidTransition)?;
        tx.execute(
            "UPDATE messages SET state='cancelled',state_version=state_version+1,updated_at=now() WHERE account_id=$1 AND id=$2",
            &[&account_id, &message_id],
        ).await?;
        tx.execute(
            "UPDATE dispatch_jobs SET lease_owner=NULL,lease_until=NULL,finished_at=now() WHERE account_id=$1 AND message_id=$2",
            &[&account_id, &message_id],
        ).await?;
        refund_outbound(&tx, account_id, message_id).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Marks expired pre-grant jobs terminal. SKIP LOCKED bounds each sweep
    /// without waiting on active claim/grant transactions.
    pub async fn expire_due(&mut self, limit: i64) -> Result<u64, StoreError> {
        if !(1..=1000).contains(&limit) {
            return Err(StoreError::InvalidInput);
        }
        let tx = self.client.transaction().await?;
        let rows = tx.query(
            "SELECT j.account_id,j.message_id FROM dispatch_jobs j JOIN messages m ON m.id=j.message_id \
             WHERE j.grant_issued_at IS NULL AND j.finished_at IS NULL \
               AND m.expires_at<=now() AND m.state IN ('queued','claimed') \
             ORDER BY m.expires_at,m.id FOR UPDATE OF j SKIP LOCKED LIMIT $1",
            &[&limit],
        ).await?;
        let mut expired = 0;
        for row in &rows {
            let account_id: Uuid = row.get(0);
            let message_id: Uuid = row.get(1);
            let updated = tx.execute(
                "UPDATE messages SET state='expired',state_version=state_version+1,updated_at=now() \
                 WHERE account_id=$1 AND id=$2 AND state IN ('queued','claimed') AND expires_at<=now()",
                &[&account_id, &message_id],
            ).await?;
            if updated != 1 {
                continue;
            }
            tx.execute(
                "UPDATE dispatch_jobs SET lease_owner=NULL,lease_until=NULL,finished_at=now() WHERE account_id=$1 AND message_id=$2",
                &[&account_id, &message_id],
            ).await?;
            refund_outbound(&tx, account_id, message_id).await?;
            expired += 1;
        }
        tx.commit().await?;
        Ok(expired)
    }

    /// Silence after a grant is ambiguous. Keep the device fence and mark the
    /// attempt unknown for late evidence or an operator-led resolution.
    /// Lock messages first, as radio evidence does, so callbacks and sweeps
    /// serialize on the same state row.
    pub async fn reconcile_silent_attempts(&mut self, limit: i64) -> Result<u64, StoreError> {
        if !(1..=1000).contains(&limit) {
            return Err(StoreError::InvalidInput);
        }
        let tx = self.client.transaction().await?;
        let rows = tx
            .query(
                "SELECT m.account_id,m.id,a.id,m.state FROM messages m \
             JOIN dispatch_fences f ON (f.account_id,f.message_id)=(m.account_id,m.id) \
             JOIN message_attempts a ON a.id=f.attempt_id \
             WHERE (m.state='claimed' AND f.outcome='granted' AND f.grant_expires_at<=now()) \
                OR (m.state='submitting' AND f.outcome='submitting' \
                    AND a.updated_at<=now()-interval '2 minutes') \
             ORDER BY m.updated_at,m.id FOR UPDATE OF m SKIP LOCKED LIMIT $1",
                &[&limit],
            )
            .await?;
        for row in &rows {
            let account_id: Uuid = row.get(0);
            let message_id: Uuid = row.get(1);
            let attempt_id: Uuid = row.get(2);
            let current =
                state_from_str(&row.get::<_, String>(3)).ok_or(StoreError::InvalidTransition)?;
            let evidence = if current == MessageState::Claimed {
                Evidence::GrantTimeout
            } else {
                Evidence::SentCallbackTimeout
            };
            let next = current
                .apply(evidence)
                .map_err(|_| StoreError::InvalidTransition)?;
            let code = match evidence {
                Evidence::GrantTimeout => "grant_timeout",
                Evidence::SentCallbackTimeout => "sent_callback_timeout",
                _ => unreachable!(),
            };
            let mut hash = Sha256::new();
            hash.update(account_id.as_bytes());
            hash.update(message_id.as_bytes());
            hash.update(attempt_id.as_bytes());
            hash.update(code.as_bytes());
            let digest = hash.finalize().to_vec();
            tx.execute(
                "UPDATE messages SET state=$3,state_version=state_version+1,updated_at=now() \
                 WHERE account_id=$1 AND id=$2",
                &[&account_id, &message_id, &state_name(next)],
            )
            .await?;
            tx.execute(
                "UPDATE message_attempts SET status='unknown',updated_at=now() WHERE id=$1",
                &[&attempt_id],
            )
            .await?;
            tx.execute(
                "UPDATE dispatch_fences SET outcome='unknown' WHERE attempt_id=$1",
                &[&attempt_id],
            )
            .await?;
            tx.execute(
                "INSERT INTO message_events (id,account_id,message_id,attempt_id,evidence_code, \
                 event_digest,observed_at,resulting_state) VALUES ($1,$2,$3,$4,$5,$6,now(),'unknown')",
                &[&Uuid::new_v4(), &account_id, &message_id, &attempt_id, &code, &digest],
            ).await?;
        }
        tx.commit().await?;
        Ok(rows.len() as u64)
    }

    /// A sent callback proves carrier acceptance, not handset delivery. Close
    /// an absent delivery receipt conservatively after 24 hours; late receipt
    /// evidence can still move delivery_unknown to delivered.
    pub async fn reconcile_delivery_timeouts(&mut self, limit: i64) -> Result<u64, StoreError> {
        if !(1..=1000).contains(&limit) {
            return Err(StoreError::InvalidInput);
        }
        let tx = self.client.transaction().await?;
        let rows = tx
            .query(
                "SELECT m.account_id,m.id,a.id FROM messages m \
             JOIN dispatch_fences f ON (f.account_id,f.message_id)=(m.account_id,m.id) \
             JOIN message_attempts a ON a.id=f.attempt_id \
             WHERE m.state='submitted' AND f.outcome='submitted' AND a.status='submitted' \
               AND m.updated_at<=now()-interval '24 hours' \
             ORDER BY m.updated_at,m.id FOR UPDATE OF m SKIP LOCKED LIMIT $1",
                &[&limit],
            )
            .await?;
        for row in &rows {
            let account_id: Uuid = row.get(0);
            let message_id: Uuid = row.get(1);
            let attempt_id: Uuid = row.get(2);
            let next = MessageState::Submitted
                .apply(Evidence::DeliveryTimeout)
                .map_err(|_| StoreError::InvalidTransition)?;
            let mut hash = Sha256::new();
            hash.update(account_id.as_bytes());
            hash.update(message_id.as_bytes());
            hash.update(attempt_id.as_bytes());
            hash.update(b"delivery_timeout");
            let digest = hash.finalize().to_vec();
            tx.execute(
                "UPDATE messages SET state=$3,state_version=state_version+1,updated_at=now() \
                 WHERE account_id=$1 AND id=$2",
                &[&account_id, &message_id, &state_name(next)],
            )
            .await?;
            tx.execute(
                "INSERT INTO message_events (id,account_id,message_id,attempt_id,evidence_code, \
                 event_digest,observed_at,resulting_state) VALUES ($1,$2,$3,$4,'delivery_timeout',$5,now(),$6)",
                &[&Uuid::new_v4(), &account_id, &message_id, &attempt_id, &digest,
                  &state_name(next)],
            ).await?;
        }
        tx.commit().await?;
        Ok(rows.len() as u64)
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
            .query_typed_one(
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
        let device = tx.query_typed_opt(
            "SELECT revoked_at IS NOT NULL FROM devices WHERE account_id=$1 AND id=$2 FOR SHARE",
            &[(&claim.account_id, Type::UUID), (&claim.device_id, Type::UUID)],
        ).await?.ok_or(StoreError::StaleFence)?;
        if device.get::<_, bool>(0) {
            return Err(StoreError::Revoked);
        }
        // Serialize dispatch with both signed opt-outs and owner holds. A
        // withdrawal that wins this lock must prevent any later radio grant.
        tx.query_typed_opt(
            "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR NO KEY UPDATE",
            &[(&claim.account_id, Type::UUID)],
        )
        .await?
        .ok_or(StoreError::StaleFence)?;
        // No session fields change here. SHARE fences reconnects while staying
        // compatible with consent-changing signed inbound ingest, which takes
        // the account lock only for STOP/START transitions.
        let current_session = tx
            .query_typed_opt(
                "SELECT ds.connection_epoch,ds.site_id,ds.instance_id,ds.lease_until>clock_timestamp() AS live, \
                  s.enabled,s.draining FROM device_sessions ds JOIN sites s ON s.site_id=ds.site_id \
                  WHERE ds.account_id=$1 AND ds.device_id=$2 FOR SHARE OF ds",
                &[(&session.account_id, Type::UUID), (&session.device_id, Type::UUID)],
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
            .query_typed_opt(
                "SELECT j.generation,j.lease_owner,j.lease_until>clock_timestamp(),j.grant_issued_at IS NULL, \
                        m.state,m.expires_at>clock_timestamp(),m.recipient_digest,m.recipient_e164 \
                 FROM dispatch_jobs j JOIN messages m ON m.id=j.message_id \
                 WHERE j.account_id=$1 AND j.message_id=$2 AND j.device_id=$3 \
                   AND m.transport_mode='synthetic_alpha' FOR UPDATE OF j,m",
                &[(&claim.account_id, Type::UUID), (&claim.message_id, Type::UUID),
                  (&claim.device_id, Type::UUID)],
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
        let recipient: Option<String> = job.get(7);
        let recipient = recipient.ok_or(StoreError::StaleFence)?;
        if tx.query_typed_opt(
            "SELECT 1 FROM recipient_suppressions WHERE account_id=$1 AND recipient_e164=$2 AND active=TRUE \
             UNION ALL SELECT 1 FROM owner_recipient_holds \
             WHERE account_id=$1 AND recipient_e164=$2 AND released_at IS NULL LIMIT 1",
            &[(&claim.account_id, Type::UUID), (&recipient, Type::TEXT)],
        ).await?.is_some() {
            cancel_pre_grant(&tx, claim.account_id, claim.message_id).await?;
            tx.commit().await?;
            return Err(StoreError::RecipientSuppressed);
        }
        let recipient_digest: Vec<u8> = job.get(6);
        tx.execute_typed(
            "INSERT INTO message_attempts (id,account_id,message_id,device_id,generation,session_epoch,deployment_epoch,status) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,'granted')",
            &[(&attempt_id, Type::UUID), (&claim.account_id, Type::UUID),
              (&claim.message_id, Type::UUID), (&claim.device_id, Type::UUID),
              (&claim.generation, Type::INT8), (&session.epoch, Type::INT8),
              (&deployment_epoch, Type::INT8)],
        )
        .await?;
        let inserted = tx.query_typed_one(
            "INSERT INTO dispatch_fences (message_id,account_id,device_id,attempt_id,generation,session_epoch, \
              deployment_epoch,recipient_digest,grant_expires_at,outcome) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp()+interval '30 seconds','granted') \
             RETURNING (extract(epoch FROM grant_expires_at)*1000)::bigint",
            &[(&claim.message_id, Type::UUID), (&claim.account_id, Type::UUID),
              (&claim.device_id, Type::UUID), (&attempt_id, Type::UUID),
              (&claim.generation, Type::INT8), (&session.epoch, Type::INT8),
              (&deployment_epoch, Type::INT8), (&recipient_digest, Type::BYTEA)],
        ).await;
        let inserted = match inserted {
            Ok(row) => row,
            Err(error) => {
                if error.as_db_error().is_some_and(|db| {
                    db.code() == &SqlState::UNIQUE_VIOLATION
                        && db.constraint() == Some("dispatch_fences_active_device")
                }) {
                    return Err(StoreError::DeviceBusy);
                }
                return Err(StoreError::Database(error));
            }
        };
        tx.execute_typed(
            "UPDATE dispatch_jobs SET grant_issued_at=now() WHERE message_id=$1",
            &[(&claim.message_id, Type::UUID)],
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
            expires_at_ms: inserted.get(0),
        })
    }

    pub async fn synthetic_payload_for_grant(
        &self,
        grant: &GrantRecord,
        session: &SessionRecord,
    ) -> Result<SyntheticExecutionPayload, StoreError> {
        if grant.account_id != session.account_id
            || grant.device_id != session.device_id
            || grant.session_epoch != session.epoch
            || grant.deployment_epoch != session.deployment_epoch
        {
            return Err(StoreError::StaleFence);
        }
        let row = self.client.query_typed_opt(
            "SELECT m.recipient_e164,m.transport_payload,m.recipient_digest,m.transport_mode, \
              m.expires_at>now(),m.state, f.grant_expires_at>now(),f.outcome, \
              s.lease_until>now(),s.site_id,s.instance_id, \
              d.revoked_at IS NULL, a.epoch,a.dispatch_enabled, st.enabled,st.draining \
             FROM dispatch_fences f JOIN messages m ON (m.account_id,m.id)=(f.account_id,f.message_id) \
              JOIN devices d ON (d.account_id,d.id)=(f.account_id,f.device_id) \
              JOIN device_sessions s ON (s.account_id,s.device_id)=(f.account_id,f.device_id) \
              JOIN sites st ON st.site_id=s.site_id \
              CROSS JOIN deployment_authority a \
             WHERE f.account_id=$1 AND f.message_id=$2 AND f.device_id=$3 AND f.attempt_id=$4 \
              AND f.generation=$5 AND f.session_epoch=$6 AND f.deployment_epoch=$7 \
              AND s.connection_epoch=$6 AND s.deployment_epoch=$7 AND a.singleton=TRUE",
            &[(&grant.account_id, Type::UUID), (&grant.message_id, Type::UUID),
              (&grant.device_id, Type::UUID), (&grant.attempt_id, Type::UUID),
              (&grant.generation, Type::INT8), (&grant.session_epoch, Type::INT8),
              (&grant.deployment_epoch, Type::INT8)],
        ).await?.ok_or(StoreError::StaleFence)?;
        let recipient: String = row
            .get::<_, Option<String>>(0)
            .ok_or(StoreError::StaleFence)?;
        let body_bytes: Vec<u8> = row
            .get::<_, Option<Vec<u8>>>(1)
            .ok_or(StoreError::StaleFence)?;
        let recipient_digest: Vec<u8> = row.get(2);
        if recipient_digest != grant.recipient_digest
            || recipient_digest != Sha256::digest(recipient.as_bytes()).as_slice()
            || row.get::<_, String>(3) != "synthetic_alpha"
            || !row.get::<_, bool>(4)
            || row.get::<_, String>(5) != "claimed"
            || !row.get::<_, bool>(6)
            || row.get::<_, String>(7) != "granted"
            || !row.get::<_, bool>(8)
            || row.get::<_, String>(9) != session.site_id
            || row.get::<_, String>(10) != session.instance_id
            || !row.get::<_, bool>(11)
            || row.get::<_, i64>(12) != grant.deployment_epoch
            || !row.get::<_, bool>(13)
            || !row.get::<_, bool>(14)
            || row.get::<_, bool>(15)
        {
            return Err(StoreError::StaleFence);
        }
        let body = String::from_utf8(body_bytes).map_err(|_| StoreError::InvalidInput)?;
        Ok(SyntheticExecutionPayload {
            recipient_e164: recipient,
            body,
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
            .query_typed_opt(
                "SELECT state,recipient_e164 IS NULL FROM messages \
                 WHERE account_id=$1 AND id=$2 FOR UPDATE",
                &[
                    (&event.account_id, Type::UUID),
                    (&event.message_id, Type::UUID),
                ],
            )
            .await?
            .ok_or(StoreError::NotFound)?;
        let current = state_from_row(&row)?;
        // After terminal content retention, a late receipt is stale even if
        // its old event ID has since been removed from the audit timeline.
        // The device stream must quarantine StaleFence instead of reconnecting
        // with the same frame (#147).
        if row.get::<_, bool>(1) {
            return Err(StoreError::StaleFence);
        }
        if let Some(existing) = tx
            .query_typed_opt(
                "SELECT event_digest,resulting_state FROM message_events WHERE id=$1",
                &[(&event.event_id, Type::UUID)],
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
            .query_typed_opt(
                "SELECT (extract(epoch FROM created_at)*1000)::bigint, \
                 (extract(epoch FROM clock_timestamp())*1000)::bigint \
                 FROM message_attempts WHERE id=$1 AND account_id=$2 AND message_id=$3 AND device_id=$4 FOR UPDATE",
                &[(&event.attempt_id, Type::UUID), (&event.account_id, Type::UUID),
                  (&event.message_id, Type::UUID), (&event.device_id, Type::UUID)],
            )
            .await?
            .ok_or(StoreError::StaleFence)?;
        // Bound new evidence before converting its timestamp in PostgreSQL.
        // Use the writer clock and original attempt, not a rolling age limit:
        // a retained attempt can still reconcile a long-offline callback.
        validate_radio_timestamp(event.observed_at_ms, attempt.get(0), attempt.get(1))?;
        // A no-submit proof releases the attempt's fence. Later evidence with
        // a fresh event ID must not change a replacement attempt's message.
        // Keep exact receipt replays above this check and allow late callbacks
        // for retained fences, including after a session or deployment move.
        let active_fence: bool = tx
            .query_typed_one(
                "SELECT EXISTS(SELECT 1 FROM dispatch_fences WHERE attempt_id=$1 AND account_id=$2 \
             AND message_id=$3 AND device_id=$4)",
                &[
                    (&event.attempt_id, Type::UUID),
                    (&event.account_id, Type::UUID),
                    (&event.message_id, Type::UUID),
                    (&event.device_id, Type::UUID),
                ],
            )
            .await?
            .get(0);
        if !active_fence {
            return Err(StoreError::StaleFence);
        }
        if event.evidence != Evidence::CallbackConflict {
            let conflicted: bool = tx.query_typed_one(
                "SELECT EXISTS(SELECT 1 FROM message_events WHERE attempt_id=$1 AND evidence_code='callback_conflict')",
                &[(&event.attempt_id, Type::UUID)],
            ).await?.get(0);
            if conflicted {
                return Err(StoreError::InvalidTransition);
            }
        }
        if event.evidence == Evidence::ProvenNoSubmit {
            // The phone's durable no-radio proof may arrive after the writer's
            // silent-attempt timeout. Never release a fence once any radio
            // callback or contradictory evidence was recorded for this attempt.
            let contrary: bool = tx.query_typed_one(
                "SELECT EXISTS(SELECT 1 FROM message_events WHERE attempt_id=$1 AND evidence_code IN \
                 ('sent_callback_ok','sent_callback_failed','delivery_callback_ok','callback_conflict'))",
                &[(&event.attempt_id, Type::UUID)],
            ).await?.get(0);
            if contrary {
                return Err(StoreError::InvalidTransition);
            }
        }
        let next = match event.evidence {
            Evidence::CallbackConflict => {
                let intent: bool = tx.query_typed_one(
                    "SELECT EXISTS(SELECT 1 FROM message_events WHERE attempt_id=$1 AND evidence_code='durable_intent')",
                    &[(&event.attempt_id, Type::UUID)],
                ).await?.get(0);
                if !intent {
                    return Err(StoreError::InvalidTransition);
                }
                current.apply(Evidence::CallbackConflict)
            }
            Evidence::SentCallbackOk | Evidence::SentCallbackFailed => {
                let intent: bool = tx.query_typed_one(
                    "SELECT EXISTS(SELECT 1 FROM message_events WHERE attempt_id=$1 AND evidence_code='durable_intent')",
                    &[(&event.attempt_id, Type::UUID)],
                ).await?.get(0);
                if !intent {
                    return Err(StoreError::InvalidTransition);
                }
                let count = event.segment_count.ok_or(StoreError::InvalidInput)?;
                let seen = tx.query_typed_one(
                    "SELECT count(*)::integer, count(*) FILTER (WHERE evidence_code='sent_callback_ok')::integer, \
                     count(*) FILTER (WHERE segment_count<>$2)::integer \
                     FROM message_events WHERE attempt_id=$1 AND evidence_code IN ('sent_callback_ok','sent_callback_failed')",
                    &[(&event.attempt_id, Type::UUID), (&count, Type::INT4)],
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
        tx.execute_typed(
            "UPDATE messages SET state=$3,state_version=state_version+1,updated_at=now() \
             WHERE account_id=$1 AND id=$2",
            &[
                (&event.account_id, Type::UUID),
                (&event.message_id, Type::UUID),
                (&next_name, Type::TEXT),
            ],
        )
        .await?;
        tx.execute_typed(
            "INSERT INTO message_events (id,account_id,message_id,attempt_id,evidence_code,event_digest, \
              observed_at,resulting_state,segment_index,segment_count) \
             VALUES ($1,$2,$3,$4,$5,$6,to_timestamp($7::double precision / 1000),$8,$9,$10)",
            &[(&event.event_id, Type::UUID), (&event.account_id, Type::UUID),
              (&event.message_id, Type::UUID), (&event.attempt_id, Type::UUID),
              (&code, Type::TEXT), (&digest, Type::BYTEA), (&observed_at, Type::FLOAT8),
              (&next_name, Type::TEXT), (&event.segment_index, Type::INT4), (&event.segment_count, Type::INT4)],
        )
        .await?;
        if event.evidence == Evidence::ProvenNoSubmit {
            tx.execute_typed(
                "UPDATE message_attempts SET status='proved_no_submit',updated_at=now() WHERE id=$1",
                &[(&event.attempt_id, Type::UUID)],
            )
            .await?;
            tx.execute_typed(
                "DELETE FROM dispatch_fences WHERE attempt_id=$1",
                &[(&event.attempt_id, Type::UUID)],
            )
            .await?;
            tx.execute_typed(
                "UPDATE dispatch_jobs SET grant_issued_at=NULL,lease_owner=NULL,lease_until=NULL,finished_at=NULL,next_attempt_at=now() \
                 WHERE message_id=$1",
                &[(&event.message_id, Type::UUID)],
            )
            .await?;
        } else if let Some(status) = attempt_status(next) {
            tx.execute_typed(
                "UPDATE message_attempts SET status=$2,updated_at=now() WHERE id=$1",
                &[(&event.attempt_id, Type::UUID), (&status, Type::TEXT)],
            )
            .await?;
            tx.execute_typed(
                "UPDATE dispatch_fences SET outcome=$2 WHERE attempt_id=$1",
                &[(&event.attempt_id, Type::UUID), (&status, Type::TEXT)],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(next)
    }
}

async fn reservation_exists(
    tx: &Transaction<'_>,
    account_id: Uuid,
    message_id: Uuid,
) -> Result<bool, StoreError> {
    Ok(tx
        .query_typed_opt(
            "SELECT 1 FROM usage_ledger WHERE account_id=$1 AND message_id=$2 AND entry_kind='reserve'",
            &[(&account_id, Type::UUID), (&message_id, Type::UUID)],
        )
        .await?
        .is_some())
}

// Shared with dormant sealed admission; preserve billing-customer/account lock order.
// Returns whether a usage reservation is required, and whether the account has
// a billing-customer binding (the caller may pass the binding on to
// `reserve_outbound` so the row is read and locked once per admission).
async fn lock_billing_account(
    tx: &Transaction<'_>,
    account_id: Uuid,
    billing_enabled: bool,
) -> Result<(bool, Option<bool>), StoreError> {
    // Billing ingress locks an existing customer row before taking
    // account-related FK locks. Follow that order for a bound tenant.
    let bound = tx
        .query_typed_opt(
            "SELECT 1 FROM billing_customers WHERE account_id=$1 FOR SHARE",
            &[(&account_id, Type::UUID)],
        )
        .await?
        .is_some();
    if bound {
        tx.query_typed_one(
            "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
            &[(&account_id, Type::UUID)],
        )
        .await?;
        Ok((true, Some(true)))
    } else {
        // The stronger lock conflicts with a concurrent new binding's
        // FK KEY SHARE. Recheck after acquiring it; if the binding won
        // the race, abort and let a later request use child-first order.
        // This recheck must not lock the customer: risk ingress may
        // already hold it and need an account FK KEY SHARE lock.
        tx.query_typed_one(
            "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
            &[(&account_id, Type::UUID)],
        )
        .await?;
        if tx
            .query_typed_opt(
                "SELECT 1 FROM billing_customers WHERE account_id=$1",
                &[(&account_id, Type::UUID)],
            )
            .await?
            .is_some()
        {
            return Err(StoreError::QuotaNotConfigured);
        }
        Ok((billing_enabled, Some(false)))
    }
}

/// `bound` carries the tenant's billing-customer binding when the caller has
/// already read (and locked) it in this transaction: `lock_billing_account`
/// passes `Some`, so the alpha path reads the row once. `None` means the
/// caller took no billing locks and the binding is queried here.
async fn reserve_outbound(
    tx: &Transaction<'_>,
    account_id: Uuid,
    message_id: Uuid,
    at_unix_ms: Option<i64>,
    bound: Option<bool>,
) -> Result<(), StoreError> {
    // Hold the tenant binding while checking pending payment risk, subscription
    // reconciliation, and policy. Risk ingestion locks the same customer row.
    let billed = match bound {
        Some(billed) => billed,
        None => tx
            .query_typed_opt(
                "SELECT 1 FROM billing_customers WHERE account_id=$1 FOR SHARE",
                &[(&account_id, Type::UUID)],
            )
            .await?
            .is_some(),
    };
    let mut past_due_rows = 0i64;
    let (limit, source) = if billed {
        // One statement takes the same FOR SHARE locks the sequential reads
        // took: the account's risk events, every reconciliation row, its
        // past-due subscription rows and the outbound policy row. The
        // account lock this transaction already holds serializes writers,
        // so intra-statement lock order cannot deadlock against them. The
        // past-due grace clock check deliberately stays its own statement:
        // it must observe a clock taken after these locks, not with them.
        let guards = tx
            .query_typed_one(
                "SELECT \
                   EXISTS(SELECT 1 FROM billing_risk_events WHERE account_id=$1 AND state IN ('queued','held','needs_review') FOR SHARE), \
                   (SELECT count(*) FROM (SELECT 1 FROM billing_reconciliations WHERE account_id=$1 FOR SHARE) recon_lock), \
                   (SELECT count(*) FROM (SELECT 1 FROM billing_reconciliations WHERE account_id=$1 AND dirty_generation=processed_generation FOR SHARE) recon_done_lock), \
                   (SELECT count(*) FROM (SELECT 1 FROM billing_subscriptions WHERE account_id=$1 AND stripe_status='past_due' FOR SHARE) past_due_lock), \
                   (SELECT limit_units FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message' FOR SHARE), \
                   (SELECT source FROM usage_quota_policies WHERE account_id=$1 AND metric='outbound_message' FOR SHARE)",
                &[(&account_id, Type::UUID)],
            )
            .await?;
        if guards.get::<_, bool>(0) {
            return Err(StoreError::PaymentHold);
        }
        let recon_total: i64 = guards.get(1);
        let recon_done: i64 = guards.get(2);
        if recon_total == 0 || recon_done != recon_total {
            return Err(StoreError::QuotaNotConfigured);
        }
        past_due_rows = guards.get(3);
        (
            guards.get::<_, Option<i64>>(4),
            guards.get::<_, Option<String>>(5),
        )
    } else {
        let policy = tx
            .query_typed_opt(
                "SELECT limit_units,source FROM usage_quota_policies \
                 WHERE account_id=$1 AND metric='outbound_message' FOR SHARE",
                &[(&account_id, Type::UUID)],
            )
            .await?;
        match policy {
            Some(policy) => (
                policy.get::<_, Option<i64>>(0),
                policy.get::<_, Option<String>>(1),
            ),
            None => return Err(StoreError::QuotaNotConfigured),
        }
    };
    if past_due_rows > 0
        && tx
            .query_typed_opt(
                "SELECT 1 FROM billing_subscriptions WHERE account_id=$1 AND stripe_status='past_due' AND (payment_grace_started_at IS NULL OR payment_grace_invoice_id IS DISTINCT FROM latest_invoice_id OR payment_grace_started_at+interval '7 days'<=clock_timestamp()) LIMIT 1",
                &[(&account_id, Type::UUID)],
            )
            .await?
            .is_some()
    {
        return Err(StoreError::QuotaExceeded);
    }
    let limit: i64 = limit.ok_or(StoreError::QuotaNotConfigured)?;
    if billed && source.as_deref() != Some("stripe_test") {
        return Err(StoreError::QuotaNotConfigured);
    }
    // One statement truncates the metering instant to its UTC month, creates
    // or advances the period, and writes the reservation ledger entry. The
    // upsert's guard keeps the exact once-only reservation semantics: a new
    // period reserves its first unit only under a positive limit, and an
    // existing period advances only below its stored limit, so an empty
    // result means QuotaExceeded exactly as the separate statements did.
    let reserved = tx
        .query_typed_one(
            "WITH period AS ( \
               SELECT date_trunc('month', COALESCE(to_timestamp($2::bigint::double precision / 1000), \
                 transaction_timestamp()) AT TIME ZONE 'UTC')::date AS p), \
             upsert AS ( \
               INSERT INTO usage_periods(account_id,metric,period_start,period_end,limit_units,reserved_units) \
               SELECT $1,'outbound_message',p,(p + interval '1 month')::date,$3,1 FROM period WHERE $3::bigint > 0 \
               ON CONFLICT(account_id,metric,period_start) DO UPDATE \
                 SET reserved_units=usage_periods.reserved_units+1 \
                 WHERE usage_periods.reserved_units-usage_periods.refunded_units < usage_periods.limit_units \
               RETURNING period_start), \
             ledger AS ( \
               INSERT INTO usage_ledger(account_id,message_id,metric,period_start,entry_kind,units) \
               SELECT $1,$4,'outbound_message',period_start,'reserve',1 FROM upsert \
               RETURNING 1) \
             SELECT count(*) FROM upsert",
            &[
                (&account_id, Type::UUID),
                (&at_unix_ms, Type::INT8),
                (&limit, Type::INT8),
                (&message_id, Type::UUID),
            ],
        )
        .await?
        .get::<_, i64>(0);
    if reserved == 0 {
        return Err(StoreError::QuotaExceeded);
    }
    Ok(())
}

/// Called only while changing a pre-grant message to a terminal state in the
/// same transaction. The unique refund entry makes repeated sweeps harmless.
async fn refund_outbound(
    tx: &Transaction<'_>,
    account_id: Uuid,
    message_id: Uuid,
) -> Result<bool, tokio_postgres::Error> {
    let refund = tx
        .query_opt(
            "INSERT INTO usage_ledger(account_id,message_id,metric,period_start,entry_kind,units) \
             SELECT account_id,message_id,metric,period_start,'refund',-1 FROM usage_ledger \
             WHERE account_id=$1 AND message_id=$2 AND entry_kind='reserve' \
             ON CONFLICT(account_id,message_id,entry_kind) DO NOTHING \
             RETURNING metric,period_start::text",
            &[&account_id, &message_id],
        )
        .await?;
    let Some(refund) = refund else {
        return Ok(false);
    };
    let metric: String = refund.get(0);
    let period_start: String = refund.get(1);
    tx.execute(
        "UPDATE usage_periods SET refunded_units=refunded_units+1 \
         WHERE account_id=$1 AND metric=$2 AND period_start=$3::text::date",
        &[&account_id, &metric, &period_start],
    )
    .await?;
    Ok(true)
}

/// Cancel queued/claimed work for a withdrawal in the same transaction as its
/// hold or suppression. Already granted work is ambiguous and stays untouched.
/// Taking the account lock before job locks matches grant issuance/admission.
pub async fn cancel_pending_recipient(
    tx: &Transaction<'_>,
    account_id: Uuid,
    recipient: &str,
) -> Result<u64, tokio_postgres::Error> {
    tx.query_one(
        "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
        &[&account_id],
    )
    .await?;
    let rows = tx
        .query(
            "SELECT j.message_id FROM dispatch_jobs j JOIN messages m ON m.id=j.message_id \
         WHERE j.account_id=$1 AND m.account_id=$1 AND m.recipient_e164=$2 \
         AND j.grant_issued_at IS NULL AND j.finished_at IS NULL \
         AND m.state IN ('queued','claimed') ORDER BY j.message_id FOR UPDATE OF j,m",
            &[&account_id, &recipient],
        )
        .await?;
    for row in &rows {
        cancel_pre_grant(tx, account_id, row.get(0)).await?;
    }
    Ok(rows.len() as u64)
}

// The caller holds the dispatch job/message locks and has verified no grant.
async fn cancel_pre_grant(
    tx: &Transaction<'_>,
    account_id: Uuid,
    message_id: Uuid,
) -> Result<(), tokio_postgres::Error> {
    tx.execute(
        "UPDATE messages SET state='cancelled',state_version=state_version+1,updated_at=clock_timestamp() \
         WHERE account_id=$1 AND id=$2",
        &[&account_id, &message_id],
    ).await?;
    tx.execute(
        "UPDATE dispatch_jobs SET lease_owner=NULL,lease_until=NULL,finished_at=clock_timestamp() \
         WHERE account_id=$1 AND message_id=$2",
        &[&account_id, &message_id],
    )
    .await?;
    refund_outbound(tx, account_id, message_id).await?;
    Ok(())
}

fn validate_new_expiry(expires_at_ms: i64, metering: MeteringTime) -> Result<(), StoreError> {
    let now = now_ms();
    if expires_at_ms <= now
        || (matches!(metering, MeteringTime::Alpha { .. })
            && expires_at_ms > now.saturating_add(MAX_ALPHA_EXPIRY_MS))
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
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
        || std::str::from_utf8(input.synthetic_payload).is_err()
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

/// Server-side `messages.id` for a private-alpha request. It is derived from
/// the authenticated account and the caller's `client_message_id`, so a retry
/// from the same account maps to the same message while another account using
/// the same client ID (or a known foreign message ID) gets an unrelated one.
/// The result is an RFC 9562 version 8 UUID.
pub fn alpha_message_id(account_id: Uuid, client_message_id: Uuid) -> Uuid {
    let mut hash = Sha256::new();
    hash.update(b"zrotext.alpha-message-id.v1");
    hash.update(account_id.as_bytes());
    hash.update(client_message_id.as_bytes());
    let digest = hash.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes).into_uuid()
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

fn validate_radio_timestamp(
    observed_at_ms: i64,
    attempt_created_ms: i64,
    now_ms: i64,
) -> Result<(), StoreError> {
    if observed_at_ms <= 0
        || observed_at_ms < attempt_created_ms.saturating_sub(RADIO_CLOCK_SKEW_MS)
        || observed_at_ms > now_ms.saturating_add(RADIO_CLOCK_SKEW_MS)
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}

fn radio_event_digest(event: &RadioEvent, code: &str) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(event.account_id.as_bytes());
    hash.update(event.device_id.as_bytes());
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
        Evidence::CallbackConflict => "callback_conflict",
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
mod tests;

#[cfg(test)]
mod metering_tests;

#[cfg(test)]
mod hold_tests;

#[cfg(test)]
mod recovery_tests;

#[cfg(test)]
mod alpha_id_tests;
