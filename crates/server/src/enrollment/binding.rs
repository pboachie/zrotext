// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only recovery by a fresh proof from the original phone key. Public
//! locators and past enrollment signatures never authorize binding discovery.
use super::*;

#[derive(Clone)]
pub struct BindingChallenge {
    pub account_id: Uuid,
    pub pairing_id: Uuid,
    pub challenge_id: Uuid,
    pub nonce: [u8; 32],
    pub fingerprint: [u8; 32],
}

#[derive(serde::Serialize)]
pub struct BindingView {
    pub schema_version: u8,
    pub status: &'static str,
    pub account_id: Uuid,
    pub pairing_id: Uuid,
    pub device_id: Option<Uuid>,
    pub comparison_code: Option<String>,
    pub key_fingerprint: String,
}

struct Candidate {
    account: Uuid,
    key: Vec<u8>,
    fingerprint: [u8; 32],
    device: Option<Uuid>,
    status: &'static str,
    comparison: Option<String>,
}

/// The only observation available before a candidate key is attached. A
/// cancelled/expired unclaimed ticket cannot approve a device, so this coarse
/// terminal result lets an interrupted phone stop waiting without granting a
/// binding. Missing rows and every claimed/approved ceremony stay unknown.
pub async fn unclaimed_terminal(
    client: &Client,
    pairing: Uuid,
) -> Result<Option<&'static str>, EnrollmentError> {
    if client
        .query_one("SELECT pg_is_in_recovery()", &[])
        .await?
        .get(0)
    {
        return Err(EnrollmentError::AuthorityUnavailable);
    }
    let row=client.query_opt("SELECT p.cancelled_at IS NOT NULL FROM pairing_requests p JOIN accounts a ON a.id=p.account_id WHERE p.id=$1 AND p.claimed_at IS NULL AND p.approved_at IS NULL AND p.device_id IS NULL AND a.disabled_at IS NULL AND (p.cancelled_at IS NOT NULL OR p.expires_at<=clock_timestamp())",&[&pairing]).await?;
    Ok(row.map(|r| {
        if r.get(0) {
            "pairing_cancelled"
        } else {
            "pairing_expired"
        }
    }))
}

pub fn parse_fingerprint(value: &str) -> Result<[u8; 32], EnrollmentError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    {
        return Err(EnrollmentError::InvalidInput);
    }
    let mut bytes = [0; 32];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let hex = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'A' + 10
            }
        };
        bytes[i] = hex(pair[0]) * 16 + hex(pair[1]);
    }
    Ok(bytes)
}

/// Domain separation prevents replay of enrollment or socket signatures.
pub fn challenge_bytes(c: &BindingChallenge) -> Vec<u8> {
    let mut bytes = b"ZROTEXT-PAIRING-BINDING-V1\0".to_vec();
    bytes.extend_from_slice(c.account_id.as_bytes());
    bytes.extend_from_slice(c.pairing_id.as_bytes());
    bytes.extend_from_slice(c.challenge_id.as_bytes());
    bytes.extend_from_slice(&c.fingerprint);
    bytes.extend_from_slice(&c.nonce);
    bytes
}

fn nonce(hasher: &EnrollmentHasher, c: &BindingChallenge) -> [u8; 32] {
    let mut binding = Vec::with_capacity(80);
    binding.extend_from_slice(c.account_id.as_bytes());
    binding.extend_from_slice(c.pairing_id.as_bytes());
    binding.extend_from_slice(c.challenge_id.as_bytes());
    binding.extend_from_slice(&c.fingerprint);
    hasher.digest(b"pairing-binding-challenge-v1", &binding)
}

pub fn challenge_is_current(hasher: &EnrollmentHasher, c: &BindingChallenge, now_ms: u64) -> bool {
    let issued = challenge_id_timestamp_ms(c.challenge_id);
    let expected_nonce = nonce(hasher, c);
    expected_nonce.len() == c.nonce.len() && bool::from(expected_nonce.ct_eq(&c.nonce))
        && now_ms.saturating_add(SOCKET_CHALLENGE_SKEW_MS) >= issued
        && issued.saturating_add(SOCKET_CHALLENGE_LIFETIME_MS + SOCKET_CHALLENGE_SKEW_MS) >= now_ms
}

async fn candidate(client: &Client, pairing: Uuid) -> Result<Candidate, EnrollmentError> {
    // Writer observations only. Revocation must never be hidden by a replica.
    if client
        .query_one("SELECT pg_is_in_recovery()", &[])
        .await?
        .get(0)
    {
        return Err(EnrollmentError::AuthorityUnavailable);
    }
    if let Some(r) = client.query_opt(
        "SELECT k.account_id,k.signing_key_sec1,k.fingerprint,k.device_id,p.comparison_code FROM device_keys k JOIN devices d ON (d.account_id,d.id)=(k.account_id,k.device_id) JOIN accounts a ON a.id=k.account_id LEFT JOIN pairing_requests p ON p.id=k.source_pairing_id AND p.account_id=k.account_id AND p.device_id=k.device_id WHERE k.source_pairing_id=$1 AND k.revoked_at IS NULL AND d.revoked_at IS NULL AND a.disabled_at IS NULL",
        &[&pairing],
    ).await? {
        return Ok(Candidate {account:r.get(0),key:r.get(1),fingerprint:r.get::<_,Vec<u8>>(2).try_into().map_err(|_|EnrollmentError::Unavailable)?,device:Some(r.get(3)),status:"approved",comparison:r.get(4)});
    }
    let r = client.query_opt(
        "SELECT p.account_id,p.signing_key_sec1,p.key_fingerprint,p.comparison_code,p.cancelled_at IS NOT NULL,p.expires_at<=clock_timestamp(),p.proof_verified_at IS NOT NULL,p.challenge_consumed_at IS NOT NULL,p.approval_failures>=5 FROM pairing_requests p JOIN accounts a ON a.id=p.account_id WHERE p.id=$1 AND p.claimed_at IS NOT NULL AND p.approved_at IS NULL AND a.disabled_at IS NULL",
        &[&pairing],
    ).await?.ok_or(EnrollmentError::Unavailable)?;
    let verified: bool = r.get(6);
    let status = if r.get(4) {
        "cancelled"
    } else if r.get(5) {
        "expired"
    } else if r.get::<_, bool>(8) || (!verified && r.get(7)) {
        "proof_rejected"
    } else if !verified {
        "awaiting_proof"
    } else {
        "pending"
    };
    Ok(Candidate {
        account: r.get(0),
        key: r.get(1),
        fingerprint: r
            .get::<_, Vec<u8>>(2)
            .try_into()
            .map_err(|_| EnrollmentError::Unavailable)?,
        device: None,
        status,
        comparison: if status == "pending" { r.get(3) } else { None },
    })
}

pub async fn issue(
    client: &Client,
    hasher: &EnrollmentHasher,
    pairing_id: Uuid,
    fingerprint: [u8; 32],
    now_ms: u64,
) -> Result<BindingChallenge, EnrollmentError> {
    let value = candidate(client, pairing_id).await?;
    if value.fingerprint.len() != fingerprint.len() || !bool::from(value.fingerprint.ct_eq(&fingerprint)) {
        return Err(EnrollmentError::Unavailable);
    }
    let mut challenge = BindingChallenge {
        account_id: value.account,
        pairing_id,
        challenge_id: timestamped_challenge_id(now_ms),
        nonce: [0; 32],
        fingerprint,
    };
    challenge.nonce = nonce(hasher, &challenge);
    Ok(challenge)
}

pub async fn read(
    client: &Client,
    hasher: &EnrollmentHasher,
    c: BindingChallenge,
    signature: &[u8],
    now_ms: u64,
) -> Result<BindingView, EnrollmentError> {
    if !challenge_is_current(hasher, &c, now_ms) {
        return Err(EnrollmentError::Unavailable);
    }
    let value = candidate(client, c.pairing_id).await?;
    if value.account != c.account_id
        || value.fingerprint.len() != c.fingerprint.len()
        || !bool::from(value.fingerprint.ct_eq(&c.fingerprint))
        || !verify_signature(&value.key, &challenge_bytes(&c), signature)
    {
        return Err(EnrollmentError::Unavailable);
    }
    Ok(BindingView {
        schema_version: 1,
        status: value.status,
        account_id: value.account,
        pairing_id: c.pairing_id,
        device_id: value.device,
        comparison_code: value.comparison,
        key_fingerprint: fingerprint_string(&value.fingerprint),
    })
}

#[cfg(test)]
mod tests;
