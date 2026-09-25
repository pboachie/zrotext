// SPDX-License-Identifier: AGPL-3.0-only
//! Carries an SMS line activation between the owner's browser and the device.
//!
//! 1. The owner opens a challenge. The device's own stream pushes it, so this
//!    works whichever hub holds the device session.
//! 2. The device returns a signed declaration. It is verified and stored,
//!    together with the exact device session that delivered it.
//! 3. The owner signs over that declaration and approves. Activation runs
//!    under the stored session, so the delivering connection must still hold
//!    a live lease.
//! 4. The device stream sends an acknowledgement bound to the exact statement
//!    and signature digests, then clears the stored nonce.
//!
//! A signed declaration is not independent evidence of physical SIM identity.

use super::{
    LineActivationError, LineActivationProof, LineChallenge, SimObservation,
    activate_sms_line_binding, digest, issue_sms_line_challenge, proof_digest,
    sms_device_line_statement, sms_owner_line_statement, verify_der,
};
use crate::{auth::SessionPrincipal, inbound::InboundSession};
use thiserror::Error;
use tokio_postgres::{Client, Row};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("invalid SMS line activation input")]
    InvalidInput,
    #[error("SMS line activation not found")]
    NotFound,
    #[error("SMS line activation refused")]
    Refused,
    #[error("SMS line activation storage failed")]
    Database(#[from] tokio_postgres::Error),
}

impl From<LineActivationError> for ExchangeError {
    fn from(error: LineActivationError) -> Self {
        match error {
            LineActivationError::InvalidInput => Self::InvalidInput,
            LineActivationError::Unavailable => Self::Refused,
            LineActivationError::Database(error) => Self::Database(error),
        }
    }
}

/// Challenge frame content for the device stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingChallenge {
    pub challenge_id: Uuid,
    pub account_id: Uuid,
    pub line_id: Uuid,
    pub device_id: Uuid,
    pub generation: i64,
    pub nonce: [u8; 32],
    pub expires_at_ms: i64,
}

/// A device declaration as received on the device stream.
pub struct DeviceProof<'a> {
    pub challenge_id: Uuid,
    pub observation: SimObservation,
    pub signature_der: &'a [u8],
}

/// Acknowledgement content: the device installs its binding only when these
/// digests match the proof it prepared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActivationAck {
    pub challenge_id: Uuid,
    pub account_id: Uuid,
    pub line_id: Uuid,
    pub device_id: Uuid,
    pub generation: i64,
    pub device_statement_sha256: [u8; 32],
    pub device_signature_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeStatus {
    AwaitingDevice,
    AwaitingOwner,
    Activated,
    Closed,
}

impl ExchangeStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::AwaitingDevice => "awaiting_device",
            Self::AwaitingOwner => "awaiting_owner",
            Self::Activated => "activated",
            Self::Closed => "closed",
        }
    }
}

/// Owner view. The statements are present only while the owner can still
/// approve, so the browser signs exactly `owner_statement`.
pub struct ExchangeView {
    pub status: ExchangeStatus,
    pub device_id: Uuid,
    pub generation: i64,
    pub expires_at_ms: i64,
    pub observation: Option<SimObservation>,
    pub device_statement: Option<Vec<u8>>,
    pub device_signature_der: Option<Vec<u8>>,
    pub owner_statement: Option<Vec<u8>>,
}

fn observation(row: &Row, api: usize) -> Option<SimObservation> {
    let api_level: Option<i32> = row.get(api);
    let count: Option<i16> = row.get(api + 1);
    let selected: Option<i32> = row.get(api + 2);
    Some(SimObservation {
        android_api_level: u16::try_from(api_level?).ok()?,
        active_subscription_count: u8::try_from(count?).ok()?,
        selected_subscription_id: selected?,
    })
}

fn nonce(row: &Row, index: usize) -> Option<[u8; 32]> {
    row.get::<_, Option<Vec<u8>>>(index)?.try_into().ok()
}

/// Opens a challenge for an owner-assigned line and an enrolled device. A new
/// challenge supersedes any pending one for the line (see
/// [`issue_sms_line_challenge`]); its exchange then never becomes pushable.
pub async fn open(
    client: &mut Client,
    principal: &SessionPrincipal,
    line_id: Uuid,
    device_id: Uuid,
) -> Result<(LineChallenge, i64), ExchangeError> {
    let challenge = issue_sms_line_challenge(client, principal, line_id, device_id).await?;
    // Separate from the challenge transaction: a failure here leaves an
    // unpushable challenge that simply expires. The owner retries.
    let row = client
        .query_one(
            "WITH opened AS ( \
               INSERT INTO sms_line_activation_exchanges \
               (challenge_id,account_id,line_id,device_id,generation,nonce) \
               VALUES($1,$2,$3,$4,$5,$6) RETURNING challenge_id) \
             SELECT (extract(epoch FROM c.expires_at)*1000)::bigint \
             FROM line_activation_challenges c JOIN opened o ON o.challenge_id=c.id",
            &[
                &challenge.id,
                &challenge.account_id,
                &challenge.line_id,
                &challenge.device_id,
                &challenge.generation,
                &&challenge.nonce[..],
            ],
        )
        .await?;
    Ok((challenge, row.get(0)))
}

/// The oldest live challenge not yet pushed on this connection.
pub async fn next_challenge(
    client: &Client,
    session: InboundSession<'_>,
) -> Result<Option<PendingChallenge>, tokio_postgres::Error> {
    let Some(row) = client
        .query_opt(
            "SELECT e.challenge_id,e.line_id,e.generation,e.nonce, \
                    (extract(epoch FROM c.expires_at)*1000)::bigint \
             FROM sms_line_activation_exchanges e \
             JOIN line_activation_challenges c ON c.id=e.challenge_id \
             JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation) \
               =(e.account_id,e.line_id,e.device_id,e.generation) \
             WHERE e.account_id=$1 AND e.device_id=$2 AND e.proof_received_at IS NULL \
               AND e.nonce IS NOT NULL \
               AND e.pushed_connection_epoch IS DISTINCT FROM $3 \
               AND c.consumed_at IS NULL AND c.expires_at>clock_timestamp() \
               AND b.state='pending' AND b.purpose='sms' \
             ORDER BY e.created_at LIMIT 1",
            &[
                &session.account_id,
                &session.device_id,
                &session.connection_epoch,
            ],
        )
        .await?
    else {
        return Ok(None);
    };
    let Some(nonce) = nonce(&row, 3) else {
        return Ok(None);
    };
    Ok(Some(PendingChallenge {
        challenge_id: row.get(0),
        account_id: session.account_id,
        line_id: row.get(1),
        device_id: session.device_id,
        generation: row.get(2),
        nonce,
        expires_at_ms: row.get(4),
    }))
}

/// Records a successful push so this connection does not resend it. A later
/// connection pushes the same live challenge again.
pub async fn mark_challenge_pushed(
    client: &Client,
    session: InboundSession<'_>,
    challenge_id: Uuid,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "UPDATE sms_line_activation_exchanges SET pushed_connection_epoch=$4 \
             WHERE challenge_id=$1 AND account_id=$2 AND device_id=$3 \
               AND proof_received_at IS NULL",
            &[
                &challenge_id,
                &session.account_id,
                &session.device_id,
                &session.connection_epoch,
            ],
        )
        .await?;
    Ok(())
}

/// Verifies and stores the device declaration. Returns `false` for a proof
/// that cannot be accepted (unknown, closed or expired challenge, invalid
/// declaration or signature); the stored state is then unchanged. An exact
/// replay of the stored proof is accepted again.
pub async fn record_device_proof(
    client: &mut Client,
    session: InboundSession<'_>,
    proof: DeviceProof<'_>,
) -> Result<bool, tokio_postgres::Error> {
    let tx = client.transaction().await?;
    let Some(device_key) = tx
        .query_opt(
            "SELECT k.signing_key_sec1 FROM device_sessions s \
             JOIN devices d ON (d.account_id,d.id)=(s.account_id,s.device_id) \
             JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
             JOIN sites t ON t.site_id=s.site_id \
             JOIN deployment_authority p ON p.singleton=TRUE \
             WHERE s.account_id=$1 AND s.device_id=$2 AND s.site_id=$3 \
               AND s.instance_id=$4 AND s.connection_epoch=$5 \
               AND s.deployment_epoch=$6 AND s.lease_until>clock_timestamp() \
               AND d.revoked_at IS NULL AND k.revoked_at IS NULL \
               AND t.enabled=TRUE AND t.draining=FALSE AND p.epoch=$6 \
               AND NOT pg_is_in_recovery() FOR SHARE OF s,d,k,t,p",
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
    else {
        return Ok(false);
    };
    let device_sec1: Vec<u8> = device_key.get(0);
    let Some(row) = tx
        .query_opt(
            "SELECT e.line_id,e.generation,e.nonce, \
                    e.android_api_level,e.active_subscription_count,e.selected_subscription_id, \
                    e.device_signature_der, \
                    (c.consumed_at IS NULL AND c.expires_at>clock_timestamp() \
                     AND b.state='pending' AND b.purpose='sms') \
             FROM sms_line_activation_exchanges e \
             JOIN line_activation_challenges c ON c.id=e.challenge_id \
             JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation) \
               =(e.account_id,e.line_id,e.device_id,e.generation) \
             WHERE e.challenge_id=$1 AND e.account_id=$2 AND e.device_id=$3 \
             FOR UPDATE OF e",
            &[&proof.challenge_id, &session.account_id, &session.device_id],
        )
        .await?
    else {
        return Ok(false);
    };
    if let Some(stored) = row.get::<_, Option<Vec<u8>>>(6) {
        return Ok(stored == proof.signature_der && observation(&row, 3) == Some(proof.observation));
    }
    let live: bool = row.get(7);
    let Some(nonce) = nonce(&row, 2).filter(|_| live) else {
        return Ok(false);
    };
    let challenge = LineChallenge {
        id: proof.challenge_id,
        account_id: session.account_id,
        line_id: row.get(0),
        device_id: session.device_id,
        generation: row.get(1),
        nonce,
    };
    let Ok(statement) = sms_device_line_statement(&challenge, proof.observation) else {
        return Ok(false);
    };
    if !verify_der(&device_sec1, &statement, proof.signature_der) {
        return Ok(false);
    }
    tx.execute(
        "UPDATE sms_line_activation_exchanges SET android_api_level=$2, \
           active_subscription_count=$3,selected_subscription_id=$4,device_signature_der=$5, \
           proof_site_id=$6,proof_instance_id=$7,proof_connection_epoch=$8, \
           proof_deployment_epoch=$9,proof_received_at=clock_timestamp() \
         WHERE challenge_id=$1",
        &[
            &proof.challenge_id,
            &i32::from(proof.observation.android_api_level),
            &i16::from(proof.observation.active_subscription_count),
            &proof.observation.selected_subscription_id,
            &proof.signature_der,
            &session.site_id,
            &session.instance_id,
            &session.connection_epoch,
            &session.deployment_epoch,
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

struct StoredProof {
    line_id: Uuid,
    device_id: Uuid,
    generation: i64,
    nonce: [u8; 32],
    observation: SimObservation,
    signature_der: Vec<u8>,
    site_id: String,
    instance_id: String,
    connection_epoch: i64,
    deployment_epoch: i64,
}

impl StoredProof {
    fn challenge(&self, challenge_id: Uuid, account_id: Uuid) -> LineChallenge {
        LineChallenge {
            id: challenge_id,
            account_id,
            line_id: self.line_id,
            device_id: self.device_id,
            generation: self.generation,
            nonce: self.nonce,
        }
    }
}

const STORED_PROOF_COLUMNS: &str = "e.line_id,e.device_id,e.generation,e.nonce, \
    e.android_api_level,e.active_subscription_count,e.selected_subscription_id, \
    e.device_signature_der,e.proof_site_id,e.proof_instance_id, \
    e.proof_connection_epoch,e.proof_deployment_epoch";

fn stored_proof(row: &Row) -> Option<StoredProof> {
    Some(StoredProof {
        line_id: row.get(0),
        device_id: row.get(1),
        generation: row.get(2),
        nonce: nonce(row, 3)?,
        observation: observation(row, 4)?,
        signature_der: row.get::<_, Option<Vec<u8>>>(7)?,
        site_id: row.get::<_, Option<String>>(8)?,
        instance_id: row.get::<_, Option<String>>(9)?,
        connection_epoch: row.get::<_, Option<i64>>(10)?,
        deployment_epoch: row.get::<_, Option<i64>>(11)?,
    })
}

/// Current state for the signed-in owner. Account- and line-scoped.
pub async fn view(
    client: &Client,
    principal: &SessionPrincipal,
    line_id: Uuid,
    challenge_id: Uuid,
) -> Result<ExchangeView, ExchangeError> {
    let account_id = principal.tenant.account_id();
    let row = client
        .query_opt(
            &format!(
                "SELECT {STORED_PROOF_COLUMNS}, \
                   (extract(epoch FROM c.expires_at)*1000)::bigint, \
                   (c.consumed_at IS NULL AND c.expires_at>clock_timestamp() \
                    AND b.state='pending'), \
                   b.state='active' AND b.activated_at IS NOT NULL, \
                   b.device_confirmation_digest, e.ack_sent_at IS NOT NULL \
                 FROM sms_line_activation_exchanges e \
                 JOIN line_activation_challenges c ON c.id=e.challenge_id \
                 JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation) \
                   =(e.account_id,e.line_id,e.device_id,e.generation) \
                 WHERE e.challenge_id=$1 AND e.account_id=$2 AND e.line_id=$3"
            ),
            &[&challenge_id, &account_id, &line_id],
        )
        .await?
        .ok_or(ExchangeError::NotFound)?;
    let expires_at_ms: i64 = row.get(12);
    let live: bool = row.get(13);
    let active: bool = row.get(14);
    let confirmation: Option<Vec<u8>> = row.get(15);
    let acked: bool = row.get(16);
    let stored = stored_proof(&row);
    let statement = stored.as_ref().and_then(|stored| {
        sms_device_line_statement(
            &stored.challenge(challenge_id, account_id),
            stored.observation,
        )
        .ok()
    });
    let activated_by_this_proof = match (&stored, &statement, &confirmation) {
        (Some(stored), Some(statement), Some(confirmation)) => {
            active && proof_digest(statement, &stored.signature_der)[..] == confirmation[..]
        }
        _ => false,
    };
    // After the acknowledgement clears the nonce the statement cannot be
    // rebuilt; an acknowledgement is only sent for this exact proof.
    let acked_active = active && acked;
    let status = if activated_by_this_proof || acked_active {
        ExchangeStatus::Activated
    } else if !live {
        ExchangeStatus::Closed
    } else if stored.is_some() {
        ExchangeStatus::AwaitingOwner
    } else {
        ExchangeStatus::AwaitingDevice
    };
    let approvable = status == ExchangeStatus::AwaitingOwner;
    let (device_statement, device_signature_der, owner_statement) =
        match (approvable, &stored, statement) {
            (true, Some(stored), Some(statement)) => {
                let owner = sms_owner_line_statement(&statement, &stored.signature_der);
                (
                    Some(statement),
                    Some(stored.signature_der.clone()),
                    Some(owner),
                )
            }
            _ => (None, None, None),
        };
    Ok(ExchangeView {
        status,
        device_id: row.get(1),
        generation: row.get(2),
        expires_at_ms,
        observation: stored.as_ref().map(|stored| stored.observation),
        device_statement,
        device_signature_der,
        owner_statement,
    })
}

/// Activates the line with the owner's signature over the stored device
/// declaration. The device connection that delivered the proof must still be
/// live; activation rechecks every fence in one transaction.
pub async fn approve(
    client: &mut Client,
    principal: &SessionPrincipal,
    line_id: Uuid,
    challenge_id: Uuid,
    owner_signature_der: &[u8],
) -> Result<(), ExchangeError> {
    let account_id = principal.tenant.account_id();
    let row = client
        .query_opt(
            &format!(
                "SELECT {STORED_PROOF_COLUMNS} FROM sms_line_activation_exchanges e \
                 WHERE e.challenge_id=$1 AND e.account_id=$2 AND e.line_id=$3"
            ),
            &[&challenge_id, &account_id, &line_id],
        )
        .await?
        .ok_or(ExchangeError::NotFound)?;
    let stored = stored_proof(&row).ok_or(ExchangeError::Refused)?;
    let session = InboundSession {
        account_id,
        device_id: stored.device_id,
        site_id: &stored.site_id,
        instance_id: &stored.instance_id,
        connection_epoch: stored.connection_epoch,
        deployment_epoch: stored.deployment_epoch,
    };
    activate_sms_line_binding(
        client,
        principal,
        session,
        line_id,
        stored.generation,
        LineActivationProof {
            challenge_id,
            nonce: stored.nonce,
            observation: stored.observation,
            device_signature_der: &stored.signature_der,
            owner_signature_der,
        },
    )
    .await?;
    Ok(())
}

/// The next activation this device has not been told about. Only an
/// activation made from this exchange's exact proof is acknowledged.
pub async fn next_ack(
    client: &Client,
    session: InboundSession<'_>,
) -> Result<Option<ActivationAck>, tokio_postgres::Error> {
    let rows = client
        .query(
            &format!(
                "SELECT {STORED_PROOF_COLUMNS},e.challenge_id,b.device_confirmation_digest \
                 FROM sms_line_activation_exchanges e \
                 JOIN device_line_bindings b ON (b.account_id,b.line_id,b.device_id,b.generation) \
                   =(e.account_id,e.line_id,e.device_id,e.generation) \
                 WHERE e.account_id=$1 AND e.device_id=$2 AND e.ack_sent_at IS NULL \
                   AND e.proof_received_at IS NOT NULL AND b.state='active' \
                   AND b.activated_at IS NOT NULL AND b.purpose='sms' \
                 ORDER BY e.created_at LIMIT 4"
            ),
            &[&session.account_id, &session.device_id],
        )
        .await?;
    for row in rows {
        let challenge_id: Uuid = row.get(12);
        let confirmation: Option<Vec<u8>> = row.get(13);
        let Some(stored) = stored_proof(&row) else {
            continue;
        };
        let Ok(statement) = sms_device_line_statement(
            &stored.challenge(challenge_id, session.account_id),
            stored.observation,
        ) else {
            continue;
        };
        if confirmation.as_deref() != Some(&proof_digest(&statement, &stored.signature_der)[..]) {
            continue;
        }
        return Ok(Some(ActivationAck {
            challenge_id,
            account_id: session.account_id,
            line_id: stored.line_id,
            device_id: stored.device_id,
            generation: stored.generation,
            device_statement_sha256: digest(&statement),
            device_signature_sha256: digest(&stored.signature_der),
        }));
    }
    Ok(None)
}

/// Records the sent acknowledgement and discards the nonce.
pub async fn mark_ack_sent(
    client: &Client,
    session: InboundSession<'_>,
    challenge_id: Uuid,
) -> Result<(), tokio_postgres::Error> {
    client
        .execute(
            "UPDATE sms_line_activation_exchanges SET ack_sent_at=clock_timestamp(),nonce=NULL \
             WHERE challenge_id=$1 AND account_id=$2 AND device_id=$3 AND ack_sent_at IS NULL",
            &[&challenge_id, &session.account_id, &session.device_id],
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests;
