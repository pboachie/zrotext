// SPDX-License-Identifier: AGPL-3.0-only
//! Signed line-binding transaction. Only the dormant SMS exchange in
//! [`exchange`] calls the SMS functions; no route calls the sealed ones.
//! A signed device declaration is not independent evidence of physical SIM
//! identity. The owner-key bootstrap and Android observation remain open gates.

use crate::{auth::SessionPrincipal, inbound::InboundSession};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio_postgres::Client;
use uuid::Uuid;

const CHALLENGE_LIFETIME_SECS: i32 = 300;
const DEVICE_DOMAIN: &[u8] = b"ZTSE/line/device-confirm/v1\0";
const OWNER_DOMAIN: &[u8] = b"ZTSE/line/owner-approve/v1\0";
const SMS_DEVICE_DOMAIN: &[u8] = b"ZTSMS/line/device-confirm/v1\0";
const SMS_OWNER_DOMAIN: &[u8] = b"ZTSMS/line/owner-approve/v1\0";

#[derive(Clone, Copy, PartialEq, Eq)]
enum LinePurpose {
    Sealed,
    Sms,
}

impl LinePurpose {
    fn label(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Sms => "sms",
        }
    }

    fn device_domain(self) -> &'static [u8] {
        match self {
            Self::Sealed => DEVICE_DOMAIN,
            Self::Sms => SMS_DEVICE_DOMAIN,
        }
    }

    fn owner_domain(self) -> &'static [u8] {
        match self {
            Self::Sealed => OWNER_DOMAIN,
            Self::Sms => SMS_OWNER_DOMAIN,
        }
    }
}

#[derive(Debug, Error)]
pub enum LineActivationError {
    #[error("invalid line activation input")]
    InvalidInput,
    #[error("line activation unavailable")]
    Unavailable,
    #[error("line activation storage failed")]
    Database(#[from] tokio_postgres::Error),
}

#[derive(Clone, Copy)]
pub struct LineChallenge {
    pub id: Uuid,
    pub account_id: Uuid,
    pub line_id: Uuid,
    pub device_id: Uuid,
    pub generation: i64,
    pub nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimObservation {
    pub android_api_level: u16,
    pub active_subscription_count: u8,
    pub selected_subscription_id: i32,
}

pub struct LineActivationProof<'a> {
    pub challenge_id: Uuid,
    pub nonce: [u8; 32],
    /// A signed device declaration. The server cannot independently observe
    /// the physical SIM; multi-SIM declarations currently fail closed.
    pub observation: SimObservation,
    pub device_signature_der: &'a [u8],
    pub owner_signature_der: &'a [u8],
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn proof_digest(statement: &[u8], signature: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(statement);
    hash.update(signature);
    hash.finalize().into()
}

fn verify_der(sec1: &[u8], statement: &[u8], signature_der: &[u8]) -> bool {
    if !(8..=80).contains(&signature_der.len()) {
        return false;
    }
    let Ok(key) = VerifyingKey::from_sec1_bytes(sec1) else {
        return false;
    };
    let Ok(signature) = Signature::from_der(signature_der) else {
        return false;
    };
    signature.to_der().as_bytes() == signature_der && key.verify(statement, &signature).is_ok()
}

/// Exact bytes signed with the enrolled device's P-256 key. The Android
/// subscription ID is a *local, mutable observation*, not the stable line ID.
/// It is not persisted in the line registry. The app must compare it with a
/// fresh local observation before any future sealed radio or inbound action.
pub fn device_line_statement(
    challenge: &LineChallenge,
    observation: SimObservation,
) -> Result<Vec<u8>, LineActivationError> {
    line_statement(challenge, observation, LinePurpose::Sealed)
}

/// SMS-only scope accepts the gateway's Android API 28 floor. It cannot be
/// substituted for the sealed statement, which retains its API 31 floor.
pub fn sms_device_line_statement(
    challenge: &LineChallenge,
    observation: SimObservation,
) -> Result<Vec<u8>, LineActivationError> {
    line_statement(challenge, observation, LinePurpose::Sms)
}

fn line_statement(
    challenge: &LineChallenge,
    observation: SimObservation,
    purpose: LinePurpose,
) -> Result<Vec<u8>, LineActivationError> {
    if challenge.account_id.is_nil()
        || challenge.line_id.is_nil()
        || challenge.device_id.is_nil()
        || challenge.id.is_nil()
        || challenge.generation <= 0
        || observation.android_api_level
            < if purpose == LinePurpose::Sealed {
                31
            } else {
                28
            }
        || observation.active_subscription_count != 1
        || observation.selected_subscription_id < 0
    {
        return Err(LineActivationError::InvalidInput);
    }
    let mut bytes = Vec::with_capacity(purpose.device_domain().len() + 16 * 4 + 8 + 32 + 2 + 1 + 4);
    bytes.extend_from_slice(purpose.device_domain());
    bytes.extend_from_slice(challenge.account_id.as_bytes());
    bytes.extend_from_slice(challenge.line_id.as_bytes());
    bytes.extend_from_slice(challenge.device_id.as_bytes());
    bytes.extend_from_slice(&challenge.generation.to_be_bytes());
    bytes.extend_from_slice(challenge.id.as_bytes());
    bytes.extend_from_slice(&challenge.nonce);
    bytes.extend_from_slice(&observation.android_api_level.to_be_bytes());
    bytes.push(observation.active_subscription_count);
    bytes.extend_from_slice(&observation.selected_subscription_id.to_be_bytes());
    Ok(bytes)
}

/// The owner signs the exact device statement and the digest of its DER
/// signature. A different signature or SIM declaration needs a new approval.
pub fn owner_line_statement(device_statement: &[u8], device_signature_der: &[u8]) -> Vec<u8> {
    owner_statement(device_statement, device_signature_der, LinePurpose::Sealed)
}

pub fn sms_owner_line_statement(device_statement: &[u8], device_signature_der: &[u8]) -> Vec<u8> {
    owner_statement(device_statement, device_signature_der, LinePurpose::Sms)
}

fn owner_statement(
    device_statement: &[u8],
    device_signature_der: &[u8],
    purpose: LinePurpose,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(purpose.owner_domain().len() + device_statement.len() + 32);
    bytes.extend_from_slice(purpose.owner_domain());
    bytes.extend_from_slice(device_statement);
    bytes.extend_from_slice(&digest(device_signature_der));
    bytes
}

async fn owner_session_active(
    tx: &tokio_postgres::Transaction<'_>,
    principal: &SessionPrincipal,
) -> Result<bool, tokio_postgres::Error> {
    Ok(tx
        .query_opt(
            "SELECT 1 FROM sessions s \
             JOIN users u ON u.id=s.user_id \
             JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) \
             WHERE s.id=$1 AND s.account_id=$2 AND s.user_id=$3 \
               AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() \
               AND u.email_verified_at IS NOT NULL AND m.role='owner' \
             FOR SHARE OF s,u,m",
            &[
                &principal.session_id,
                &principal.tenant.account_id(),
                &principal.user_id,
            ],
        )
        .await?
        .is_some())
}

/// Prepares the next binding generation and issues a five-minute nonce. This
/// still requires a trusted owner key provisioned outside this module. An old
/// active generation remains active until a fully verified replacement wins.
pub async fn issue_line_challenge(
    client: &mut Client,
    principal: &SessionPrincipal,
    line_id: Uuid,
    device_id: Uuid,
) -> Result<LineChallenge, LineActivationError> {
    issue_line_challenge_with_lifetime(
        client,
        principal,
        line_id,
        device_id,
        CHALLENGE_LIFETIME_SECS,
    )
    .await
}

/// SMS-only challenge. Called only by the dormant [`exchange`] owner route.
pub async fn issue_sms_line_challenge(
    client: &mut Client,
    principal: &SessionPrincipal,
    line_id: Uuid,
    device_id: Uuid,
) -> Result<LineChallenge, LineActivationError> {
    issue_challenge_for_purpose(
        client,
        principal,
        line_id,
        device_id,
        CHALLENGE_LIFETIME_SECS,
        LinePurpose::Sms,
    )
    .await
}

async fn issue_line_challenge_with_lifetime(
    client: &mut Client,
    principal: &SessionPrincipal,
    line_id: Uuid,
    device_id: Uuid,
    lifetime_secs: i32,
) -> Result<LineChallenge, LineActivationError> {
    issue_challenge_for_purpose(
        client,
        principal,
        line_id,
        device_id,
        lifetime_secs,
        LinePurpose::Sealed,
    )
    .await
}

async fn issue_challenge_for_purpose(
    client: &mut Client,
    principal: &SessionPrincipal,
    line_id: Uuid,
    device_id: Uuid,
    lifetime_secs: i32,
    purpose: LinePurpose,
) -> Result<LineChallenge, LineActivationError> {
    if line_id.is_nil() || device_id.is_nil() || lifetime_secs <= 0 {
        return Err(LineActivationError::InvalidInput);
    }
    let account_id = principal.tenant.account_id();
    let tx = client.transaction().await?;
    if tx
        .query_opt(
            "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR SHARE",
            &[&account_id],
        )
        .await?
        .is_none()
        || !owner_session_active(&tx, principal).await?
    {
        return Err(LineActivationError::Unavailable);
    }
    let owner_key_query = match purpose {
        LinePurpose::Sealed => {
            "SELECT 1 FROM line_owner_approval_keys WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE"
        }
        LinePurpose::Sms => {
            "SELECT 1 FROM sms_line_owner_approval_keys WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE"
        }
    };
    if tx
        .query_opt(owner_key_query, &[&account_id])
        .await?
        .is_none()
        || tx
            .query_opt(
                "SELECT 1 FROM devices d JOIN device_keys k ON \
                 (k.account_id,k.device_id)=(d.account_id,d.id) \
                 WHERE d.account_id=$1 AND d.id=$2 \
                   AND d.revoked_at IS NULL AND k.revoked_at IS NULL \
                 FOR SHARE OF d,k",
                &[&account_id, &device_id],
            )
            .await?
            .is_none()
    {
        return Err(LineActivationError::Unavailable);
    }
    tx.execute(
        "INSERT INTO phone_lines(id,account_id) VALUES($1,$2) ON CONFLICT(id) DO NOTHING",
        &[&line_id, &account_id],
    )
    .await?;
    let Some(line) = tx
        .query_opt(
            "SELECT state,last_issued_generation FROM phone_lines \
             WHERE account_id=$1 AND id=$2 FOR UPDATE",
            &[&account_id, &line_id],
        )
        .await?
    else {
        return Err(LineActivationError::Unavailable);
    };
    let state: String = line.get(0);
    let issued: i64 = line.get(1);
    if state == "revoked" {
        return Err(LineActivationError::Unavailable);
    }
    if purpose == LinePurpose::Sms
        && tx
            .query_opt(
                "SELECT 1 FROM device_line_bindings WHERE account_id=$1 AND line_id=$2 \
             AND purpose='sealed' AND activated_at IS NOT NULL LIMIT 1",
                &[&account_id, &line_id],
            )
            .await?
            .is_some()
    {
        return Err(LineActivationError::Unavailable);
    }
    let generation = issued
        .checked_add(1)
        .ok_or(LineActivationError::Unavailable)?;
    // A superseded pending challenge can never later activate. Preserve its
    // revoked binding and challenge rows as generation/replay tombstones.
    tx.execute(
        "UPDATE device_line_bindings SET state='revoked' \
         WHERE account_id=$1 AND line_id=$2 AND state='pending'",
        &[&account_id, &line_id],
    )
    .await?;
    tx.execute(
        "UPDATE phone_lines SET last_issued_generation=$3 \
         WHERE account_id=$1 AND id=$2",
        &[&account_id, &line_id, &generation],
    )
    .await?;
    let inserted = tx
        .execute(
            "INSERT INTO device_line_bindings(account_id,line_id,device_id,generation,purpose) \
         VALUES($1,$2,$3,$4,$5)",
            &[
                &account_id,
                &line_id,
                &device_id,
                &generation,
                &purpose.label(),
            ],
        )
        .await?;
    if inserted != 1 {
        return Err(LineActivationError::Unavailable);
    }
    let id = Uuid::new_v4();
    let nonce: [u8; 32] = rand::random();
    let nonce_digest = digest(&nonce);
    tx.execute(
        "INSERT INTO line_activation_challenges \
         (id,account_id,line_id,device_id,generation,nonce_digest,expires_at) \
         VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()+($7::integer * interval '1 second'))",
        &[
            &id,
            &account_id,
            &line_id,
            &device_id,
            &generation,
            &&nonce_digest[..],
            &lifetime_secs,
        ],
    )
    .await?;
    if !owner_session_active(&tx, principal).await? {
        return Err(LineActivationError::Unavailable);
    }
    tx.commit().await?;
    Ok(LineChallenge {
        id,
        account_id,
        line_id,
        device_id,
        generation,
        nonce,
    })
}

/// Atomically activates a pending binding after checking both signatures and
/// current owner/device sessions. No transport invokes the sealed variant.
pub async fn activate_line_binding(
    client: &mut Client,
    principal: &SessionPrincipal,
    session: InboundSession<'_>,
    line_id: Uuid,
    generation: i64,
    proof: LineActivationProof<'_>,
) -> Result<(), LineActivationError> {
    activate_for_purpose(
        client,
        principal,
        session,
        line_id,
        generation,
        proof,
        LinePurpose::Sealed,
    )
    .await
}

pub async fn activate_sms_line_binding(
    client: &mut Client,
    principal: &SessionPrincipal,
    session: InboundSession<'_>,
    line_id: Uuid,
    generation: i64,
    proof: LineActivationProof<'_>,
) -> Result<(), LineActivationError> {
    activate_for_purpose(
        client,
        principal,
        session,
        line_id,
        generation,
        proof,
        LinePurpose::Sms,
    )
    .await
}

async fn activate_for_purpose(
    client: &mut Client,
    principal: &SessionPrincipal,
    session: InboundSession<'_>,
    line_id: Uuid,
    generation: i64,
    proof: LineActivationProof<'_>,
    purpose: LinePurpose,
) -> Result<(), LineActivationError> {
    let account_id = principal.tenant.account_id();
    if account_id != session.account_id {
        return Err(LineActivationError::Unavailable);
    }
    let challenge = LineChallenge {
        id: proof.challenge_id,
        account_id,
        line_id,
        device_id: session.device_id,
        generation,
        nonce: proof.nonce,
    };
    let device_statement = line_statement(&challenge, proof.observation, purpose)?;
    let owner_statement = owner_statement(&device_statement, proof.device_signature_der, purpose);
    let nonce_digest = digest(&proof.nonce);
    let tx = client.transaction().await?;
    if tx
        .query_opt(
            "SELECT id FROM accounts WHERE id=$1 AND disabled_at IS NULL FOR SHARE",
            &[&account_id],
        )
        .await?
        .is_none()
        || !owner_session_active(&tx, principal).await?
    {
        return Err(LineActivationError::Unavailable);
    }
    let Some(line) = tx
        .query_opt(
            "SELECT state,current_binding_generation,last_issued_generation FROM phone_lines \
             WHERE account_id=$1 AND id=$2 FOR UPDATE",
            &[&account_id, &line_id],
        )
        .await?
    else {
        return Err(LineActivationError::Unavailable);
    };
    let line_state: String = line.get(0);
    let current: i64 = line.get(1);
    let issued: i64 = line.get(2);
    if line_state == "revoked" || current >= generation || issued != generation {
        return Err(LineActivationError::Unavailable);
    }
    if purpose == LinePurpose::Sms
        && tx
            .query_opt(
                "SELECT 1 FROM device_line_bindings WHERE account_id=$1 AND line_id=$2 \
             AND purpose='sealed' AND activated_at IS NOT NULL LIMIT 1",
                &[&account_id, &line_id],
            )
            .await?
            .is_some()
    {
        return Err(LineActivationError::Unavailable);
    }
    if tx
        .query_opt(
            "SELECT 1 FROM device_line_bindings WHERE account_id=$1 AND line_id=$2 \
             AND device_id=$3 AND generation=$4 AND state='pending' AND purpose=$5 FOR UPDATE",
            &[
                &account_id,
                &line_id,
                &session.device_id,
                &generation,
                &purpose.label(),
            ],
        )
        .await?
        .is_none()
        || tx
            .query_opt(
                "SELECT 1 FROM line_activation_challenges \
                 WHERE id=$1 AND account_id=$2 AND line_id=$3 AND device_id=$4 \
                   AND generation=$5 AND nonce_digest=$6 \
                   AND consumed_at IS NULL AND expires_at>clock_timestamp() FOR UPDATE",
                &[
                    &proof.challenge_id,
                    &account_id,
                    &line_id,
                    &session.device_id,
                    &generation,
                    &&nonce_digest[..],
                ],
            )
            .await?
            .is_none()
    {
        return Err(LineActivationError::Unavailable);
    }
    let owner_key_query = match purpose {
        LinePurpose::Sealed => {
            "SELECT signing_key_sec1,fingerprint FROM line_owner_approval_keys WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE"
        }
        LinePurpose::Sms => {
            "SELECT signing_key_sec1,fingerprint FROM sms_line_owner_approval_keys WHERE account_id=$1 AND revoked_at IS NULL FOR SHARE"
        }
    };
    let Some(owner_key) = tx.query_opt(owner_key_query, &[&account_id]).await? else {
        return Err(LineActivationError::Unavailable);
    };
    let owner_sec1: Vec<u8> = owner_key.get(0);
    let owner_fingerprint: Vec<u8> = owner_key.get(1);
    if digest(&owner_sec1).as_slice() != owner_fingerprint.as_slice() {
        return Err(LineActivationError::Unavailable);
    }
    // The same physical key cannot claim both owner roles, even with distinct
    // transcript domains. A future provisioning ceremony must enforce this at
    // registration too; this transaction is the last activation boundary.
    let cross_role_query = match purpose {
        LinePurpose::Sealed => {
            "SELECT 1 FROM sms_line_owner_approval_keys WHERE account_id=$1 AND signing_key_sec1=$2 LIMIT 1"
        }
        LinePurpose::Sms => {
            "SELECT 1 FROM line_owner_approval_keys WHERE account_id=$1 AND signing_key_sec1=$2 LIMIT 1"
        }
    };
    if tx
        .query_opt(cross_role_query, &[&account_id, &owner_sec1])
        .await?
        .is_some()
    {
        return Err(LineActivationError::Unavailable);
    }
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
        return Err(LineActivationError::Unavailable);
    };
    let device_sec1: Vec<u8> = device_key.get(0);
    // A different enrolled device must not alias the owner role either. The
    // account lock serializes this check with ordinary device approval.
    let owner_key_used_for_device = tx
        .query_opt(
            "SELECT 1 FROM device_keys WHERE account_id=$1 \
             AND signing_key_sec1=$2 LIMIT 1",
            &[&account_id, &owner_sec1],
        )
        .await?
        .is_some();
    if owner_key_used_for_device
        || owner_sec1 == device_sec1
        || !verify_der(&device_sec1, &device_statement, proof.device_signature_der)
        || !verify_der(&owner_sec1, &owner_statement, proof.owner_signature_der)
    {
        return Err(LineActivationError::Unavailable);
    }
    let device_digest = proof_digest(&device_statement, proof.device_signature_der);
    let owner_digest = proof_digest(&owner_statement, proof.owner_signature_der);
    tx.execute(
        "UPDATE device_line_bindings SET state='revoked' \
         WHERE account_id=$1 AND line_id=$2 AND state='active'",
        &[&account_id, &line_id],
    )
    .await?;
    tx.execute(
        "UPDATE device_line_bindings SET state='active',activated_at=clock_timestamp(), \
         owner_approval_digest=$5,device_confirmation_digest=$6 \
         WHERE account_id=$1 AND line_id=$2 AND device_id=$3 \
           AND generation=$4 AND state='pending' AND purpose=$7",
        &[
            &account_id,
            &line_id,
            &session.device_id,
            &generation,
            &&owner_digest[..],
            &&device_digest[..],
            &purpose.label(),
        ],
    )
    .await?;
    tx.execute(
        "UPDATE phone_lines SET state='active',approved_at=coalesce(approved_at,clock_timestamp()), \
         current_binding_generation=$3 WHERE account_id=$1 AND id=$2",
        &[&account_id, &line_id, &generation],
    )
    .await?;
    tx.execute(
        "UPDATE line_activation_challenges SET consumed_at=clock_timestamp() WHERE id=$1",
        &[&proof.challenge_id],
    )
    .await?;
    // PostgreSQL now() is fixed at transaction start. Recheck *after* any
    // row-lock wait and all updates; an expired challenge/session/lease must
    // roll the whole transition back even if it was fresh on entry.
    if tx
        .query_opt(
            "SELECT 1 FROM sessions o \
             JOIN device_sessions s ON s.account_id=o.account_id \
             JOIN line_activation_challenges c ON c.account_id=o.account_id \
             WHERE o.id=$1 AND s.device_id=$2 AND c.id=$3 \
               AND o.revoked_at IS NULL AND o.expires_at>clock_timestamp() \
               AND s.lease_until>clock_timestamp() \
               AND c.expires_at>clock_timestamp()",
            &[
                &principal.session_id,
                &session.device_id,
                &proof.challenge_id,
            ],
        )
        .await?
        .is_none()
    {
        return Err(LineActivationError::Unavailable);
    }
    tx.commit().await?;
    Ok(())
}

pub mod exchange;

#[cfg(test)]
mod tests;
