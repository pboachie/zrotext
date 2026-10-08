// SPDX-License-Identifier: AGPL-3.0-only
//! Durable default-off provider submit intent. This module records the
//! authoritative writer transaction the transport proposal requires before
//! any worker may release transport: idempotent admission of one exact
//! approved action revision, serialized with recipient suppression, tied to
//! a live conservative exposure reservation.
//!
//! No sender, provider credential, route enablement, receipt caller or
//! configuration switch exists here. `claim_intended` only leases recorded
//! intents; the network boundary and its pre-flight rechecks are separate
//! reviewed slices. `Released` from `dispatching` is a trusted in-process
//! sender assertion that no transmission was attempted.

use super::Request;
use super::receipts::ElectedWriterPermit;
use crate::http_owner_conversations::context::decisions::ActionKey;
use sha2::{Digest, Sha256};
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DispatchError {
    #[error("provider dispatch unavailable")]
    Unavailable,
    #[error("provider dispatch writer authority unavailable")]
    Authority,
    #[error("provider dispatch input invalid")]
    Invalid,
    #[error("recipient suppression refuses provider dispatch")]
    Suppressed,
    #[error("provider dispatch commitment conflicts")]
    Conflict,
    #[error("provider dispatch reservation is not live")]
    Expired,
    #[error("provider dispatch storage inconsistent")]
    Inconsistent,
    #[error("provider dispatch storage unavailable")]
    Database,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CommitOutcome {
    pub attempt_id: Uuid,
    pub created: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Lease {
    pub attempt_id: Uuid,
    pub lease_id: Uuid,
    pub lease_until_ms: i64,
}

fn route_fingerprint(request: &Request) -> [u8; 32] {
    let route = &request.route;
    let mut hash = Sha256::new();
    hash.update(b"ZT/provider-receipt-route/v1\0telnyx-sms-v2\0");
    for identity in [route.account, route.organization, route.profile] {
        hash.update(identity.as_bytes());
    }
    hash.update(route.revision.to_be_bytes());
    hash.update((route.sender.len() as u64).to_be_bytes());
    hash.update(route.sender.as_bytes());
    hash.finalize().into()
}

async fn authority(
    tx: &Transaction<'_>,
    permit: &ElectedWriterPermit,
) -> Result<(), DispatchError> {
    let (account, site, epoch) = permit.identity();
    if account.is_nil() || site.is_empty() || epoch <= 0 {
        return Err(DispatchError::Authority);
    }
    let row = tx
        .query_opt(
            "SELECT p.epoch,s.enabled,s.draining,NOT pg_is_in_recovery() \
        FROM deployment_authority p JOIN sites s ON s.site_id=$1 WHERE p.singleton \
        FOR SHARE OF p,s",
            &[&site],
        )
        .await
        .map_err(|_| DispatchError::Database)?
        .ok_or(DispatchError::Authority)?;
    if row.get::<_, i64>(0) != epoch
        || !row.get::<_, bool>(1)
        || row.get::<_, bool>(2)
        || !row.get::<_, bool>(3)
    {
        return Err(DispatchError::Authority);
    }
    Ok(())
}

async fn lock_account(tx: &Transaction<'_>, account: Uuid) -> Result<(), DispatchError> {
    tx.query_opt(
        "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE",
        &[&account],
    )
    .await
    .map_err(|_| DispatchError::Database)?
    .ok_or(DispatchError::Inconsistent)?;
    Ok(())
}

async fn now_ms(tx: &Transaction<'_>) -> Result<i64, DispatchError> {
    Ok(tx
        .query_one(
            "SELECT (extract(epoch FROM clock_timestamp())*1000)::bigint",
            &[],
        )
        .await
        .map_err(|_| DispatchError::Database)?
        .get(0))
}

/// Suppression lookup takes the same account row lock the authenticated STOP
/// path uses, so a concurrent STOP serializes before or after the whole intent.
async fn suppressed(
    tx: &Transaction<'_>,
    account: Uuid,
    recipient: &str,
) -> Result<bool, DispatchError> {
    Ok(tx
        .query_opt(
            "SELECT active FROM recipient_suppressions \
        WHERE account_id=$1 AND recipient_e164=$2 FOR UPDATE",
            &[&account, &recipient],
        )
        .await
        .map_err(|_| DispatchError::Database)?
        .map(|row| row.get(0))
        .unwrap_or(false))
}

/// The reservation must be executing under a live lease for the exact action
/// revision, on a currently enabled provider route policy and deployment.
async fn require_live_reservation(
    tx: &Transaction<'_>,
    account: Uuid,
    action: &ActionKey,
    reservation: Uuid,
    now: i64,
) -> Result<(), DispatchError> {
    let row = tx
        .query_opt(
            "SELECT r.action_id,r.revision,r.binding_digest,r.state,r.lease_until_ms,\
        r.route_policy_id,r.operation,p.enabled,d.enabled,d.period_start_ms,d.period_end_ms \
        FROM exposure_reservations r \
        JOIN exposure_route_policies p ON (p.account_id,p.id)=(r.account_id,r.route_policy_id) \
        JOIN exposure_deployment_budgets d ON d.id=p.deployment_id \
        WHERE r.account_id=$1 AND r.id=$2 FOR UPDATE OF r",
            &[&account, &reservation],
        )
        .await
        .map_err(|_| DispatchError::Database)?
        .ok_or(DispatchError::Unavailable)?;
    if row.get::<_, Uuid>(0) != action.action_id
        || row.get::<_, i64>(1) != action.revision
        || row
            .try_get::<_, Vec<u8>>(2)
            .map_err(|_| DispatchError::Inconsistent)?
            .as_slice()
            != action.binding_digest
    {
        return Err(DispatchError::Conflict);
    }
    if row.get::<_, String>(3) != "executing"
        || !row
            .try_get::<_, Option<i64>>(4)
            .map_err(|_| DispatchError::Inconsistent)?
            .is_some_and(|until| until > now)
    {
        return Err(DispatchError::Expired);
    }
    if row.get::<_, String>(6) != "provider"
        || !row.get::<_, bool>(7)
        || !row.get::<_, bool>(8)
        || !(row.get::<_, i64>(9)..row.get::<_, i64>(10)).contains(&now)
    {
        return Err(DispatchError::Unavailable);
    }
    Ok(())
}

/// Record the durable submit intent for one exact approved action revision.
/// Replays of the identical commitment are idempotent; a changed request,
/// recipient or reservation conflicts. An active suppression refuses before
/// any row is written, leaving the reservation to its own release path.
pub async fn commit_submit_intent(
    client: &mut Client,
    permit: &ElectedWriterPermit,
    action: &ActionKey,
    reservation: Uuid,
    attempt_id: Uuid,
    request: &Request,
    recipient_e164: &str,
) -> Result<CommitOutcome, DispatchError> {
    action.validate().map_err(|_| DispatchError::Invalid)?;
    if permit.account() != action.account_id
        || permit.account() != request.route.account
        || attempt_id.is_nil()
        || reservation.is_nil()
    {
        return Err(DispatchError::Invalid);
    }
    // The caller reconstructs the recipient from the approved action, never
    // from client fields; it must hash to the committed request identity.
    if Sha256::digest(recipient_e164.as_bytes()).as_slice() != request.recipient_hash() {
        return Err(DispatchError::Invalid);
    }
    let tx = client
        .transaction()
        .await
        .map_err(|_| DispatchError::Database)?;
    authority(&tx, permit).await?;
    lock_account(&tx, action.account_id).await?;
    if suppressed(&tx, action.account_id, recipient_e164).await? {
        return Err(DispatchError::Suppressed);
    }
    let now = now_ms(&tx).await?;
    require_live_reservation(&tx, action.account_id, action, reservation, now).await?;
    // Waiting on any lock cannot reuse the checks above.
    if suppressed(&tx, action.account_id, recipient_e164).await? {
        return Err(DispatchError::Suppressed);
    }
    let fingerprint = route_fingerprint(request);
    let request_digest: &[u8] = request.digest();
    let recipient_hash: &[u8] = request.recipient_hash();
    let created = tx
        .execute(
            "INSERT INTO provider_send_attempts \
        (account_id,attempt_id,provider,route_fingerprint,request_digest,recipient_hash,\
        action_id,action_revision,action_binding_digest,reservation_id,state,created_epoch,\
        intended_at,updated_at) \
        VALUES($1,$2,'telnyx_sms_v2',$3,$4,$5,$6,$7,$8,$9,'intended',$10,\
        clock_timestamp(),clock_timestamp()) \
        ON CONFLICT (account_id,action_id,action_revision) DO NOTHING",
            &[
                &action.account_id,
                &attempt_id,
                &fingerprint.as_slice(),
                &request_digest,
                &recipient_hash,
                &action.action_id,
                &action.revision,
                &action.binding_digest.as_slice(),
                &reservation,
                &permit.epoch(),
            ],
        )
        .await
        .map_err(|_| DispatchError::Database)?
        == 1;
    if !created {
        let row = tx
            .query_opt(
                "SELECT route_fingerprint,request_digest,recipient_hash,reservation_id,state,erased_at IS NOT NULL \
        FROM provider_send_attempts WHERE account_id=$1 AND action_id=$2 AND action_revision=$3 \
        FOR UPDATE",
                &[&action.account_id, &action.action_id, &action.revision],
            )
            .await
            .map_err(|_| DispatchError::Database)?
            .ok_or(DispatchError::Inconsistent)?;
        // An erased fence keeps the action revision spent forever, and only
        // a still-intended attempt replays idempotently; terminal states
        // (accepted, unknown, released) have consumed the commitment.
        if row
            .try_get::<_, bool>(5)
            .map_err(|_| DispatchError::Inconsistent)?
            || row
                .try_get::<_, String>(4)
                .map_err(|_| DispatchError::Inconsistent)?
                != "intended"
        {
            return Err(DispatchError::Conflict);
        }
        let matches = row
            .try_get::<_, Vec<u8>>(0)
            .map_err(|_| DispatchError::Inconsistent)?
            .as_slice()
            == fingerprint.as_slice()
            && row
                .try_get::<_, Vec<u8>>(1)
                .map_err(|_| DispatchError::Inconsistent)?
                .as_slice()
                == request.digest()
            && row
                .try_get::<_, Vec<u8>>(2)
                .map_err(|_| DispatchError::Inconsistent)?
                .as_slice()
                == request.recipient_hash()
            && row.get::<_, Uuid>(3) == reservation;
        if !matches {
            return Err(DispatchError::Conflict);
        }
    }
    tx.commit().await.map_err(|_| DispatchError::Database)?;
    Ok(CommitOutcome {
        attempt_id,
        created,
    })
}

/// Lease recorded intents for one account. Leasing only marks the single
/// worker entitled to attempt submission; the reviewed sender performs the
/// authoritative suppression and reservation rechecks before network I/O.
/// A lease is never replaced or renewed: a crashed dispatch conservatively
/// reconciles to `unknown`, never back to `intended`.
pub async fn claim_intended(
    client: &mut Client,
    permit: &ElectedWriterPermit,
    account: Uuid,
    limit: i64,
) -> Result<Vec<Lease>, DispatchError> {
    if account.is_nil() || permit.account() != account || !(1..=100).contains(&limit) {
        return Err(DispatchError::Invalid);
    }
    let tx = client
        .transaction()
        .await
        .map_err(|_| DispatchError::Database)?;
    authority(&tx, permit).await?;
    lock_account(&tx, account).await?;
    let rows = tx
        .query(
            "SELECT attempt_id FROM provider_send_attempts WHERE account_id=$1 AND state='intended' \
        AND erased_at IS NULL ORDER BY intended_at,attempt_id FOR UPDATE SKIP LOCKED LIMIT $2",
            &[&account, &limit],
        )
        .await
        .map_err(|_| DispatchError::Database)?;
    let now = now_ms(&tx).await?;
    let mut leases = Vec::with_capacity(rows.len());
    for row in rows {
        let attempt_id: Uuid = row.get(0);
        let lease_id = Uuid::new_v4();
        let until = now.saturating_add(30_000);
        let changed = tx
            .execute(
                "UPDATE provider_send_attempts SET state='dispatching',lease_id=$3,lease_until_ms=$4,\
        dispatched_at=clock_timestamp(),updated_at=clock_timestamp() \
        WHERE account_id=$1 AND attempt_id=$2 AND state='intended' AND erased_at IS NULL",
                &[&account, &attempt_id, &lease_id, &until],
            )
            .await
            .map_err(|_| DispatchError::Database)?;
        if changed != 1 {
            return Err(DispatchError::Inconsistent);
        }
        leases.push(Lease {
            attempt_id,
            lease_id,
            lease_until_ms: until,
        });
    }
    tx.commit().await.map_err(|_| DispatchError::Database)?;
    Ok(leases)
}

/// Trusted-sender pre-flight: while holding the leased attempt, re-verify
/// that its committed digests match the caller's reconstruction, the
/// recipient is not suppressed and the exposure reservation is still live.
/// Called immediately before network I/O; a refusal releases the attempt.
pub async fn preflight(
    client: &mut Client,
    permit: &ElectedWriterPermit,
    account: Uuid,
    attempt: Uuid,
    material: &super::sender::Material<'_>,
) -> Result<(), DispatchError> {
    if account.is_nil() || permit.account() != account {
        return Err(DispatchError::Invalid);
    }
    let recipient = material.recipient;
    let tx = client
        .transaction()
        .await
        .map_err(|_| DispatchError::Database)?;
    authority(&tx, permit).await?;
    lock_account(&tx, account).await?;
    let row = tx
        .query_opt(
            "SELECT request_digest,recipient_hash,lease_until_ms,action_id,action_revision,\
        action_binding_digest,reservation_id FROM provider_send_attempts \
        WHERE account_id=$1 AND attempt_id=$2 AND state='dispatching' AND erased_at IS NULL \
        FOR UPDATE",
            &[&account, &attempt],
        )
        .await
        .map_err(|_| DispatchError::Database)?
        .ok_or(DispatchError::Unavailable)?;
    let now = now_ms(&tx).await?;
    let digest: Vec<u8> = row.try_get(0).map_err(|_| DispatchError::Inconsistent)?;
    let recipient_hash: Vec<u8> = row.try_get(1).map_err(|_| DispatchError::Inconsistent)?;
    let lease_until: Option<i64> = row.try_get(2).map_err(|_| DispatchError::Inconsistent)?;
    if digest.as_slice() != material.request.digest()
        || recipient_hash.as_slice() != Sha256::digest(recipient.as_bytes()).as_slice()
        || lease_until.is_none_or(|until| until <= now)
    {
        return Err(DispatchError::Conflict);
    }
    if suppressed(&tx, account, recipient).await? {
        return Err(DispatchError::Suppressed);
    }
    let action = ActionKey {
        account_id: account,
        action_id: row.try_get(3).map_err(|_| DispatchError::Inconsistent)?,
        revision: row.try_get(4).map_err(|_| DispatchError::Inconsistent)?,
        binding_digest: row
            .try_get::<_, Vec<u8>>(5)
            .map_err(|_| DispatchError::Inconsistent)?
            .try_into()
            .map_err(|_| DispatchError::Inconsistent)?,
    };
    let reservation: Uuid = row.try_get(6).map_err(|_| DispatchError::Inconsistent)?;
    require_live_reservation(&tx, account, &action, reservation, now).await?;
    tx.commit().await.map_err(|_| DispatchError::Database)?;
    Ok(())
}

/// The outcome of one submission attempt from the trusted sender worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseOutcome {
    /// The provider accepted the request and returned this message identity.
    Accepted { message_id: Uuid },
    /// The response was lost or ambiguous after possible transmission. This
    /// is terminal liability, not permission to resend.
    Lost,
    /// The trusted sender refused before any network I/O.
    Released,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ResponseRecorded {
    pub state: &'static str,
    pub changed: bool,
}

/// Record the one permitted response outcome for a leased attempt. Replays
/// of the same binding are idempotent; a different provider message identity
/// conflicts. A `Lost` result after delayed correlation changes nothing.
pub async fn record_response(
    client: &mut Client,
    permit: &ElectedWriterPermit,
    account: Uuid,
    attempt: Uuid,
    outcome: ResponseOutcome,
) -> Result<ResponseRecorded, DispatchError> {
    if account.is_nil() || permit.account() != account || attempt.is_nil() {
        return Err(DispatchError::Invalid);
    }
    if let ResponseOutcome::Accepted { message_id } = outcome
        && message_id.is_nil()
    {
        return Err(DispatchError::Invalid);
    }
    let tx = client
        .transaction()
        .await
        .map_err(|_| DispatchError::Database)?;
    authority(&tx, permit).await?;
    lock_account(&tx, account).await?;
    let row = tx
        .query_opt(
            "SELECT state,provider_message_id FROM provider_send_attempts \
        WHERE account_id=$1 AND attempt_id=$2 AND erased_at IS NULL FOR UPDATE",
            &[&account, &attempt],
        )
        .await
        .map_err(|_| DispatchError::Database)?
        .ok_or(DispatchError::Unavailable)?;
    let state: String = row.get(0);
    let bound: Option<Uuid> = row.get(1);
    let result = match outcome {
        ResponseOutcome::Accepted { message_id } => match (state.as_str(), bound) {
            ("dispatching", None) => {
                set_state(&tx, account, attempt, "accepted", Some(message_id), true).await?
            }
            // Delayed verified binding of a response that was lost.
            ("unknown", None) => {
                set_state(&tx, account, attempt, "accepted", Some(message_id), false).await?
            }
            ("accepted", Some(existing)) if existing == message_id => ResponseRecorded {
                state: "accepted",
                changed: false,
            },
            _ => return Err(DispatchError::Conflict),
        },
        ResponseOutcome::Lost => match state.as_str() {
            "dispatching" => set_state(&tx, account, attempt, "unknown", None, true).await?,
            // A late lost-response record cannot downgrade recorded evidence.
            "unknown" => ResponseRecorded {
                state: "unknown",
                changed: false,
            },
            "accepted" => ResponseRecorded {
                state: "accepted",
                changed: false,
            },
            _ => return Err(DispatchError::Conflict),
        },
        ResponseOutcome::Released => match state.as_str() {
            "intended" | "dispatching" => {
                set_state(&tx, account, attempt, "released", None, true).await?
            }
            "released" => ResponseRecorded {
                state: "released",
                changed: false,
            },
            _ => return Err(DispatchError::Conflict),
        },
    };
    tx.commit().await.map_err(|_| DispatchError::Database)?;
    Ok(result)
}

async fn set_state(
    tx: &Transaction<'_>,
    account: Uuid,
    attempt: Uuid,
    state: &'static str,
    message: Option<Uuid>,
    set_resolved: bool,
) -> Result<ResponseRecorded, DispatchError> {
    let changed = tx
        .execute(
            "UPDATE provider_send_attempts SET state=$3,provider_message_id=$4,\
        resolved_at=CASE WHEN $5::boolean THEN clock_timestamp() ELSE resolved_at END,\
        updated_at=clock_timestamp() \
        WHERE account_id=$1 AND attempt_id=$2 AND provider_message_id IS NULL",
            &[&account, &attempt, &state, &message, &set_resolved],
        )
        .await
        .map_err(|_| DispatchError::Database)?;
    if changed != 1 {
        return Err(DispatchError::Inconsistent);
    }
    Ok(ResponseRecorded {
        state,
        changed: true,
    })
}

#[cfg(test)]
pub(crate) mod tests;
