// SPDX-License-Identifier: AGPL-3.0-only
//! One-use device enrollment and per-connection proof of possession.
//! HTTP callers must authenticate the owner, enforce origin/CSRF, rate limit
//! pairing operations, and keep pairing tokens and nonces out of logs and URLs.

use crate::auth::SessionPrincipal;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac, digest::KeyInit};
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio_postgres::Client;
use uuid::Uuid;

const PAIRING_LIFETIME_SECS: i32 = 300;
const AUTH_CHALLENGE_LIFETIME_SECS: i32 = 60;
const PAST_DUE_OUTSIDE_GRACE_SQL: &str = "SELECT 1 FROM billing_subscriptions WHERE account_id=$1 AND stripe_status='past_due' AND (payment_grace_started_at IS NULL OR payment_grace_invoice_id IS DISTINCT FROM latest_invoice_id OR payment_grace_started_at+interval '7 days'<=clock_timestamp()) LIMIT 1";

/// Remove at most 500 rows from each table per maintenance tick. Challenges
/// have a one-hour grace period; pairing requests are retained for 24 hours
/// after expiry (or cancellation, if that happened later). Approved pairings
/// use the same window: the durable device/key records hold their active state.
pub async fn prune_expired(client: &Client) -> Result<u64, tokio_postgres::Error> {
    let challenges = client.execute(
        "WITH stale AS (SELECT id FROM device_auth_challenges WHERE expires_at < now()-interval '1 hour' ORDER BY expires_at,id LIMIT 500 FOR UPDATE SKIP LOCKED) DELETE FROM device_auth_challenges c USING stale s WHERE c.id=s.id",
        &[],
    ).await?;
    let pairings = client.execute(
        "WITH stale AS (SELECT id FROM pairing_requests WHERE expires_at < now()-interval '24 hours' AND (cancelled_at IS NULL OR cancelled_at < now()-interval '24 hours') ORDER BY expires_at,id LIMIT 500 FOR UPDATE SKIP LOCKED) DELETE FROM pairing_requests p USING stale s WHERE p.id=s.id",
        &[],
    ).await?;
    Ok(challenges + pairings)
}

#[derive(Debug, Error)]
pub enum EnrollmentError {
    #[error("invalid input")]
    InvalidInput,
    #[error("pairing or challenge unavailable")]
    Unavailable,
    #[error("device unauthorized")]
    Unauthorized,
    #[error("active-device plan cap reached")]
    DeviceLimitReached,
    #[error("authoritative writer unavailable")]
    AuthorityUnavailable,
    #[error("enrollment storage failed")]
    Database(#[from] tokio_postgres::Error),
}

/// Use a dedicated secret from operational secret storage, independent of
/// session and API-key peppers. The clear token is returned exactly once.
pub struct EnrollmentHasher(Vec<u8>);

impl EnrollmentHasher {
    pub fn new(pepper: Vec<u8>) -> Result<Self, EnrollmentError> {
        if pepper.len() < 32 {
            return Err(EnrollmentError::InvalidInput);
        }
        Ok(Self(pepper))
    }

    fn digest(&self, domain: &[u8], input: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("valid HMAC key");
        mac.update(domain);
        mac.update(&[0]);
        mac.update(input);
        mac.finalize().into_bytes().into()
    }
}

pub struct PairingTicket {
    pub id: Uuid,
    pub token: String,
}

pub struct ClaimedPairing {
    pub id: Uuid,
    pub account_id: Uuid,
    pub challenge_nonce: [u8; 32],
    pub comparison_code: String,
    pub key_fingerprint: String,
}

pub struct PairingView {
    pub claimed: bool,
    pub proof_verified: bool,
    pub approved_device_id: Option<Uuid>,
    pub comparison_code: Option<String>,
    pub key_fingerprint: Option<String>,
}

pub struct OwnerDevice {
    pub id: Uuid,
    pub display_name: String,
    pub revoked: bool,
    /// A current authenticated hub lease, not evidence of SIM or SMS readiness.
    pub active_socket_lease: bool,
}

pub struct OwnerDevicePage {
    pub devices: Vec<OwnerDevice>,
    pub next_cursor: Option<Uuid>,
}

const OWNER_DEVICE_PAGE_SIZE: usize = 50;

pub struct DeviceChallenge {
    pub id: Uuid,
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub nonce: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedDevice {
    pub account_id: Uuid,
    pub device_id: Uuid,
}

fn random_bytes() -> [u8; 32] {
    rand::random()
}

fn random_comparison_code() -> String {
    let bytes: [u8; 4] = rand::random();
    format!("{:08}", u32::from_be_bytes(bytes) % 100_000_000)
}

fn fingerprint_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn parse_public_key(spki_der: &[u8]) -> Result<(VerifyingKey, Vec<u8>, [u8; 32]), EnrollmentError> {
    if !(80..=160).contains(&spki_der.len()) {
        return Err(EnrollmentError::InvalidInput);
    }
    // Android's PublicKey.getEncoded() is X.509 SubjectPublicKeyInfo DER.
    let key =
        VerifyingKey::from_public_key_der(spki_der).map_err(|_| EnrollmentError::InvalidInput)?;
    let sec1 = key.to_sec1_point(false).as_bytes().to_vec();
    if sec1.len() != 65 {
        return Err(EnrollmentError::InvalidInput);
    }
    let fingerprint: [u8; 32] = Sha256::digest(&sec1).into();
    Ok((key, sec1, fingerprint))
}

fn verify_signature(sec1: &[u8], payload: &[u8], signature_der: &[u8]) -> bool {
    if !(8..=80).contains(&signature_der.len()) {
        return false;
    }
    let Ok(key) = VerifyingKey::from_sec1_bytes(sec1) else {
        return false;
    };
    let Ok(signature) = Signature::from_der(signature_der) else {
        return false;
    };
    key.verify(payload, &signature).is_ok()
}

/// Exact bytes signed by Android `SHA256withECDSA` for enrollment. UUIDs are
/// network-order 16-byte values; key fingerprint and nonce are 32 bytes each.
pub fn enrollment_challenge_bytes(
    account_id: Uuid,
    pairing_id: Uuid,
    key_fingerprint: &[u8; 32],
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut bytes = b"zrotext-enrollment-v1\0".to_vec();
    bytes.extend_from_slice(account_id.as_bytes());
    bytes.extend_from_slice(pairing_id.as_bytes());
    bytes.extend_from_slice(key_fingerprint);
    bytes.extend_from_slice(nonce);
    bytes
}

/// Exact bytes signed by Android `SHA256withECDSA` at socket connection.
pub fn device_challenge_bytes(challenge: &DeviceChallenge) -> Vec<u8> {
    let mut bytes = b"zrotext-device-auth-v1\0".to_vec();
    bytes.extend_from_slice(challenge.account_id.as_bytes());
    bytes.extend_from_slice(challenge.device_id.as_bytes());
    bytes.extend_from_slice(challenge.id.as_bytes());
    bytes.extend_from_slice(&challenge.nonce);
    bytes
}

async fn owner_session_active(
    client: &Client,
    principal: &SessionPrincipal,
) -> Result<bool, EnrollmentError> {
    Ok(client
        .query_opt(
            "SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id JOIN accounts a ON a.id=s.account_id WHERE s.id=$1 AND s.account_id=$2 AND s.user_id=$3 AND s.revoked_at IS NULL AND s.expires_at>now() AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL",
            &[&principal.session_id, &principal.tenant.account_id(), &principal.user_id],
        )
        .await?
        .is_some())
}

/// Creates a five-minute, one-use QR token. Only an authenticated owner may
/// call this, and the endpoint must return the token in a no-store response.
pub async fn create_pairing(
    client: &Client,
    hasher: &EnrollmentHasher,
    principal: &SessionPrincipal,
    display_name: &str,
) -> Result<PairingTicket, EnrollmentError> {
    let display_name = display_name.trim();
    if display_name.is_empty()
        || display_name.chars().count() > 64
        || display_name.chars().any(char::is_control)
    {
        return Err(EnrollmentError::InvalidInput);
    }
    if !owner_session_active(client, principal).await? {
        return Err(EnrollmentError::Unauthorized);
    }
    let token = format!("ztp_{}", URL_SAFE_NO_PAD.encode(random_bytes()));
    let digest = hasher.digest(b"pairing-token-v1", token.as_bytes());
    let id = Uuid::new_v4();
    let inserted = client.execute(
        "INSERT INTO pairing_requests(id,account_id,created_by_user_id,token_digest,display_name,expires_at) SELECT $1,$2,$3,$4,$5,now()+($6::integer * interval '1 second') FROM sessions s WHERE s.id=$7 AND s.account_id=$2 AND s.user_id=$3 AND s.revoked_at IS NULL AND s.expires_at>now()",
        &[&id, &principal.tenant.account_id(), &principal.user_id, &&digest[..], &display_name, &PAIRING_LIFETIME_SECS, &principal.session_id],
    ).await?;
    if inserted != 1 {
        return Err(EnrollmentError::Unauthorized);
    }
    Ok(PairingTicket { id, token })
}

fn valid_pairing_token(token: &str) -> bool {
    token.starts_with("ztp_")
        && token.len() == 47
        && URL_SAFE_NO_PAD
            .decode(&token[4..])
            .is_ok_and(|b| b.len() == 32)
}

// Liveness probes let real phones through after anonymous callers exhaust a
// route budget. Each is one indexed read with no signature work or writes;
// the pairing and challenge probes also require the caller's one-use secret.

/// True while this QR token can still claim its pairing.
pub async fn pairing_claim_is_live(
    client: &Client,
    hasher: &EnrollmentHasher,
    pairing_id: Uuid,
    token: &str,
) -> Result<bool, EnrollmentError> {
    if !valid_pairing_token(token) {
        return Ok(false);
    }
    let digest = hasher.digest(b"pairing-token-v1", token.as_bytes());
    Ok(client.query_one(
        "SELECT EXISTS(SELECT 1 FROM pairing_requests WHERE id=$1 AND token_digest=$2 AND expires_at>now() AND claimed_at IS NULL AND cancelled_at IS NULL)",
        &[&pairing_id, &&digest[..]],
    ).await?.get(0))
}

/// True while this claim nonce can still be proven for its pairing.
pub async fn pairing_proof_is_live(
    client: &Client,
    hasher: &EnrollmentHasher,
    pairing_id: Uuid,
    nonce: &[u8; 32],
) -> Result<bool, EnrollmentError> {
    let digest = hasher.digest(b"enrollment-nonce-v1", nonce);
    Ok(client.query_one(
        "SELECT EXISTS(SELECT 1 FROM pairing_requests WHERE id=$1 AND challenge_digest=$2 AND claimed_at IS NOT NULL AND challenge_consumed_at IS NULL AND expires_at>now() AND cancelled_at IS NULL)",
        &[&pairing_id, &&digest[..]],
    ).await?.get(0))
}

/// True when `issue_device_challenge` would issue a challenge for this device.
pub async fn device_is_live(client: &Client, device_id: Uuid) -> Result<bool, EnrollmentError> {
    Ok(client.query_one(
        "SELECT EXISTS(SELECT 1 FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id WHERE d.id=$1 AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL)",
        &[&device_id],
    ).await?.get(0))
}

/// True while this exact challenge and nonce are unused and unexpired.
pub async fn device_challenge_is_live(
    client: &Client,
    hasher: &EnrollmentHasher,
    challenge: &DeviceChallenge,
) -> Result<bool, EnrollmentError> {
    let digest = hasher.digest(b"device-auth-nonce-v1", &challenge.nonce);
    Ok(client.query_one(
        "SELECT EXISTS(SELECT 1 FROM device_auth_challenges WHERE id=$1 AND account_id=$2 AND device_id=$3 AND nonce_digest=$4 AND used_at IS NULL AND expires_at>now())",
        &[&challenge.id, &challenge.account_id, &challenge.device_id, &&digest[..]],
    ).await?.get(0))
}

/// Consumes the QR token once and binds the candidate Keystore public key.
/// `spki_der` is Android `PublicKey.getEncoded()` for a P-256 signing key.
pub async fn claim_pairing(
    client: &mut Client,
    hasher: &EnrollmentHasher,
    pairing_id: Uuid,
    token: &str,
    spki_der: &[u8],
) -> Result<ClaimedPairing, EnrollmentError> {
    if !valid_pairing_token(token) {
        return Err(EnrollmentError::Unavailable);
    }
    let (_, sec1, fingerprint) = parse_public_key(spki_der)?;
    let digest = hasher.digest(b"pairing-token-v1", token.as_bytes());
    let nonce = random_bytes();
    let nonce_digest = hasher.digest(b"enrollment-nonce-v1", &nonce);
    let code = random_comparison_code();
    let tx = client.transaction().await?;
    let row = tx.query_opt(
        "SELECT account_id FROM pairing_requests WHERE id=$1 AND token_digest=$2 AND expires_at>now() AND claimed_at IS NULL AND cancelled_at IS NULL FOR UPDATE",
        &[&pairing_id, &&digest[..]],
    ).await?;
    let Some(row) = row else {
        return Err(EnrollmentError::Unavailable);
    };
    let account_id: Uuid = row.get(0);
    tx.execute(
        "UPDATE pairing_requests SET claimed_at=now(),signing_key_sec1=$2,key_fingerprint=$3,comparison_code=$4,challenge_digest=$5 WHERE id=$1",
        &[&pairing_id, &sec1, &&fingerprint[..], &code, &&nonce_digest[..]],
    ).await?;
    tx.commit().await?;
    Ok(ClaimedPairing {
        id: pairing_id,
        account_id,
        challenge_nonce: nonce,
        comparison_code: code,
        key_fingerprint: fingerprint_string(&fingerprint),
    })
}

/// Consumes the challenge on the first signature attempt, including a bad
/// signature. A phone must start a new pairing after an invalid proof.
pub async fn prove_pairing_key(
    client: &mut Client,
    hasher: &EnrollmentHasher,
    pairing_id: Uuid,
    nonce: &[u8; 32],
    signature_der: &[u8],
) -> Result<bool, EnrollmentError> {
    let digest = hasher.digest(b"enrollment-nonce-v1", nonce);
    let tx = client.transaction().await?;
    let row = tx.query_opt(
        "SELECT account_id,signing_key_sec1,key_fingerprint,challenge_digest FROM pairing_requests WHERE id=$1 AND claimed_at IS NOT NULL AND challenge_consumed_at IS NULL AND expires_at>now() AND cancelled_at IS NULL FOR UPDATE",
        &[&pairing_id],
    ).await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let expected: Vec<u8> = row.get(3);
    if !bool::from(digest.as_slice().ct_eq(&expected)) {
        return Ok(false);
    }
    let account_id: Uuid = row.get(0);
    let sec1: Vec<u8> = row.get(1);
    let fingerprint_vec: Vec<u8> = row.get(2);
    let fingerprint: [u8; 32] = fingerprint_vec
        .try_into()
        .map_err(|_| EnrollmentError::Unavailable)?;
    let payload = enrollment_challenge_bytes(account_id, pairing_id, &fingerprint, nonce);
    let valid = verify_signature(&sec1, &payload, signature_der);
    tx.execute(
        "UPDATE pairing_requests SET challenge_consumed_at=now(),proof_verified_at=CASE WHEN $2 THEN now() ELSE NULL END WHERE id=$1",
        &[&pairing_id, &valid],
    ).await?;
    tx.commit().await?;
    Ok(valid)
}

pub async fn pairing_view(
    client: &Client,
    principal: &SessionPrincipal,
    pairing_id: Uuid,
) -> Result<Option<PairingView>, EnrollmentError> {
    if !owner_session_active(client, principal).await? {
        return Err(EnrollmentError::Unauthorized);
    }
    let row = client.query_opt(
        "SELECT claimed_at IS NOT NULL,proof_verified_at IS NOT NULL,device_id,comparison_code,key_fingerprint FROM pairing_requests WHERE id=$1 AND account_id=$2 AND cancelled_at IS NULL AND expires_at>now()",
        &[&pairing_id, &principal.tenant.account_id()],
    ).await?;
    Ok(row.map(|r| {
        let fingerprint: Option<Vec<u8>> = r.get(4);
        PairingView {
            claimed: r.get(0),
            proof_verified: r.get(1),
            approved_device_id: r.get(2),
            comparison_code: r.get(3),
            key_fingerprint: fingerprint.map(|b| fingerprint_string(&b)),
        }
    }))
}

/// List only devices enrolled into the authenticated owner's account. A
/// revoked device remains visible so the UI never implies it disappeared.
pub async fn list_owner_devices(
    client: &Client,
    principal: &SessionPrincipal,
    before: Option<Uuid>,
) -> Result<OwnerDevicePage, EnrollmentError> {
    if !owner_session_active(client, principal).await? {
        return Err(EnrollmentError::Unauthorized);
    }
    // A standby can lag the writer's lease/epoch state. Never render its view
    // as an authoritative absence of an authenticated socket.
    if client
        .query_one("SELECT pg_is_in_recovery()", &[])
        .await?
        .get(0)
    {
        return Err(EnrollmentError::AuthorityUnavailable);
    }
    let rows = client
        .query(
            "SELECT d.id,d.display_name,(d.revoked_at IS NOT NULL OR k.revoked_at IS NOT NULL) AS revoked, \
               COALESCE(d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL \
                 AND ds.lease_until>now() AND ds.connection_epoch>0 \
                 AND ds.deployment_epoch=p.epoch AND s.enabled=TRUE AND s.draining=FALSE \
                 AND NOT pg_is_in_recovery(),FALSE) AS active_socket_lease \
             FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) \
             JOIN accounts a ON a.id=d.account_id \
             LEFT JOIN device_sessions ds ON (ds.account_id,ds.device_id)=(d.account_id,d.id) \
             LEFT JOIN sites s ON s.site_id=ds.site_id \
             LEFT JOIN deployment_authority p ON p.singleton=TRUE \
             WHERE d.account_id=$1 AND ($2::uuid IS NULL OR (d.created_at,d.id) < \
               (SELECT c.created_at,c.id FROM devices c JOIN device_keys ck \
                ON (ck.account_id,ck.device_id)=(c.account_id,c.id) \
                WHERE c.account_id=$1 AND c.id=$2)) \
             ORDER BY d.created_at DESC,d.id DESC LIMIT $3",
            &[&principal.tenant.account_id(), &before, &((OWNER_DEVICE_PAGE_SIZE + 1) as i64)],
        )
        .await?;
    let has_more = rows.len() > OWNER_DEVICE_PAGE_SIZE;
    let devices: Vec<_> = rows
        .into_iter()
        .take(OWNER_DEVICE_PAGE_SIZE)
        .map(|row| OwnerDevice {
            id: row.get(0),
            display_name: row.get(1),
            revoked: row.get(2),
            active_socket_lease: row.get(3),
        })
        .collect();
    Ok(OwnerDevicePage {
        next_cursor: has_more.then(|| devices.last().expect("page is nonempty").id),
        devices,
    })
}

/// The owner must compare both values as shown on the phone and in the browser.
/// Five failed approvals lock the pairing. Returns the new tenant-owned device.
pub async fn approve_pairing(
    client: &mut Client,
    principal: &SessionPrincipal,
    pairing_id: Uuid,
    comparison_code: &str,
    key_fingerprint: &str,
) -> Result<Uuid, EnrollmentError> {
    if !owner_session_active(client, principal).await? {
        return Err(EnrollmentError::Unauthorized);
    }
    let tx = client.transaction().await?;
    // Serialize approvals and subscription cap changes for this account.
    tx.query_one(
        "SELECT id FROM accounts WHERE id=$1 FOR UPDATE",
        &[&principal.tenant.account_id()],
    )
    .await?;
    // The preflight may precede a wait for the account lock. Reauthorize
    // inside this transaction and hold the owner rows against revocation.
    if tx.query_opt(
        "SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON (m.account_id,m.user_id)=(s.account_id,s.user_id) JOIN accounts a ON a.id=s.account_id WHERE s.id=$1 AND s.account_id=$2 AND s.user_id=$3 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND u.email_verified_at IS NOT NULL AND a.disabled_at IS NULL AND m.role='owner' FOR SHARE OF s,u,m",
        &[&principal.session_id, &principal.tenant.account_id(), &principal.user_id],
    ).await?.is_none() {
        return Err(EnrollmentError::Unauthorized);
    }
    let row = tx.query_opt(
        "SELECT display_name,comparison_code,key_fingerprint,signing_key_sec1 FROM pairing_requests WHERE id=$1 AND account_id=$2 AND proof_verified_at IS NOT NULL AND approved_at IS NULL AND cancelled_at IS NULL AND expires_at>now() AND approval_failures<5 FOR UPDATE",
        &[&pairing_id, &principal.tenant.account_id()],
    ).await?;
    let Some(row) = row else {
        return Err(EnrollmentError::Unavailable);
    };
    let expected_code: String = row.get(1);
    let fingerprint: Vec<u8> = row.get(2);
    let expected_fingerprint = fingerprint_string(&fingerprint);
    if comparison_code.len() != 8
        || key_fingerprint.len() != 64
        || !bool::from(comparison_code.as_bytes().ct_eq(expected_code.as_bytes()))
        || !bool::from(
            key_fingerprint
                .as_bytes()
                .ct_eq(expected_fingerprint.as_bytes()),
        )
    {
        tx.execute(
            "UPDATE pairing_requests SET approval_failures=approval_failures+1 WHERE id=$1",
            &[&pairing_id],
        )
        .await?;
        tx.commit().await?;
        return Err(EnrollmentError::Unavailable);
    }
    let device_caps_enabled: bool = tx
        .query_one(
            "SELECT enabled FROM billing_device_cap_config WHERE singleton=true",
            &[],
        )
        .await?
        .get(0);
    if device_caps_enabled {
        // A projected cap can outlive payment grace without another webhook.
        // Recheck the trusted deadline at approval, under the account lock.
        if tx
            .query_opt(
                PAST_DUE_OUTSIDE_GRACE_SQL,
                &[&principal.tenant.account_id()],
            )
            .await?
            .is_some()
        {
            return Err(EnrollmentError::DeviceLimitReached);
        }
        if let Some(cap) = tx
            .query_opt(
                "SELECT limit_devices FROM billing_device_caps WHERE account_id=$1",
                &[&principal.tenant.account_id()],
            )
            .await?
        {
            let pending = tx
            .query_opt(
                "SELECT 1 FROM billing_reconciliations WHERE account_id=$1 AND dirty_generation>processed_generation LIMIT 1",
                &[&principal.tenant.account_id()],
            )
            .await?
            .is_some();
            let active: i64 = tx
                .query_one(
                    "SELECT count(*) FROM devices WHERE account_id=$1 AND revoked_at IS NULL",
                    &[&principal.tenant.account_id()],
                )
                .await?
                .get(0);
            if pending || active >= cap.get::<_, i64>(0) {
                return Err(EnrollmentError::DeviceLimitReached);
            }
        } else {
            // A cap-enabled account waits for its first provider projection.
            // This includes accounts that have not yet bound a customer.
            return Err(EnrollmentError::DeviceLimitReached);
        }
    }
    let device_id = Uuid::new_v4();
    let display_name: String = row.get(0);
    let sec1: Vec<u8> = row.get(3);
    tx.execute(
        "INSERT INTO devices(id,account_id,display_name) VALUES($1,$2,$3)",
        &[&device_id, &principal.tenant.account_id(), &display_name],
    )
    .await?;
    tx.execute(
        "INSERT INTO device_keys(device_id,account_id,signing_key_sec1,fingerprint) VALUES($1,$2,$3,$4)",
        &[&device_id, &principal.tenant.account_id(), &sec1, &fingerprint],
    ).await?;
    tx.execute(
        "UPDATE pairing_requests SET approved_at=now(),device_id=$2 WHERE id=$1",
        &[&pairing_id, &device_id],
    )
    .await?;
    // Locks serialize revocation but do not stop wall time. Check expiry
    // again after all potentially blocking writes before issuing the key.
    if tx.query_opt(
        "SELECT 1 FROM sessions s JOIN pairing_requests p ON p.account_id=s.account_id WHERE s.id=$1 AND p.id=$2 AND s.expires_at>clock_timestamp() AND p.expires_at>clock_timestamp()",
        &[&principal.session_id, &pairing_id],
    ).await?.is_none() {
        return Err(EnrollmentError::Unavailable);
    }
    if device_caps_enabled
        && tx
            .query_opt(
                PAST_DUE_OUTSIDE_GRACE_SQL,
                &[&principal.tenant.account_id()],
            )
            .await?
            .is_some()
    {
        return Err(EnrollmentError::DeviceLimitReached);
    }
    tx.commit().await?;
    Ok(device_id)
}

pub async fn cancel_pairing(
    client: &Client,
    principal: &SessionPrincipal,
    pairing_id: Uuid,
) -> Result<bool, EnrollmentError> {
    if !owner_session_active(client, principal).await? {
        return Err(EnrollmentError::Unauthorized);
    }
    Ok(client.execute(
        "UPDATE pairing_requests SET cancelled_at=now() WHERE id=$1 AND account_id=$2 AND approved_at IS NULL AND cancelled_at IS NULL",
        &[&pairing_id, &principal.tenant.account_id()],
    ).await? == 1)
}

/// A public challenge may be issued for an active device. It cannot authorize
/// a socket without a one-use P-256 proof from the enrolled Keystore key.
pub async fn issue_device_challenge(
    client: &Client,
    hasher: &EnrollmentHasher,
    device_id: Uuid,
) -> Result<DeviceChallenge, EnrollmentError> {
    let nonce = random_bytes();
    let digest = hasher.digest(b"device-auth-nonce-v1", &nonce);
    let challenge_id = Uuid::new_v4();
    let row = client.query_opt(
        "INSERT INTO device_auth_challenges(id,account_id,device_id,nonce_digest,expires_at) SELECT $1,d.account_id,d.id,$3,now()+($4::integer * interval '1 second') FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id WHERE d.id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL RETURNING account_id",
        &[&challenge_id, &device_id, &&digest[..], &AUTH_CHALLENGE_LIFETIME_SECS],
    ).await?;
    let Some(row) = row else {
        return Err(EnrollmentError::Unauthorized);
    };
    Ok(DeviceChallenge {
        id: challenge_id,
        account_id: row.get(0),
        device_id,
        nonce,
    })
}

/// Consumes the one-use socket challenge even when the provided signature is
/// invalid. Existing sockets must also call `device_still_active` before work.
pub async fn authenticate_device_challenge(
    client: &mut Client,
    hasher: &EnrollmentHasher,
    challenge: &DeviceChallenge,
    signature_der: &[u8],
) -> Result<AuthenticatedDevice, EnrollmentError> {
    let digest = hasher.digest(b"device-auth-nonce-v1", &challenge.nonce);
    let tx = client.transaction().await?;
    let row = tx.query_opt(
        "SELECT k.signing_key_sec1 FROM device_auth_challenges c JOIN devices d ON (d.account_id,d.id)=(c.account_id,c.device_id) JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id WHERE c.id=$1 AND c.account_id=$2 AND c.device_id=$3 AND c.nonce_digest=$4 AND c.used_at IS NULL AND c.expires_at>now() AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL FOR UPDATE OF c",
        &[&challenge.id, &challenge.account_id, &challenge.device_id, &&digest[..]],
    ).await?;
    let Some(row) = row else {
        return Err(EnrollmentError::Unauthorized);
    };
    let sec1: Vec<u8> = row.get(0);
    let valid = verify_signature(&sec1, &device_challenge_bytes(challenge), signature_der);
    tx.execute(
        "UPDATE device_auth_challenges SET used_at=now() WHERE id=$1",
        &[&challenge.id],
    )
    .await?;
    tx.commit().await?;
    if !valid {
        return Err(EnrollmentError::Unauthorized);
    }
    Ok(AuthenticatedDevice {
        account_id: challenge.account_id,
        device_id: challenge.device_id,
    })
}

pub async fn device_still_active(
    client: &Client,
    identity: AuthenticatedDevice,
) -> Result<bool, EnrollmentError> {
    Ok(client.query_opt(
        "SELECT 1 FROM devices d JOIN device_keys k ON (k.account_id,k.device_id)=(d.account_id,d.id) JOIN accounts a ON a.id=d.account_id WHERE d.account_id=$1 AND d.id=$2 AND d.revoked_at IS NULL AND k.revoked_at IS NULL AND a.disabled_at IS NULL",
        &[&identity.account_id, &identity.device_id],
    ).await?.is_some())
}

/// Revocation takes effect for new socket challenges immediately and removes
/// the current database session lease. Socket handlers must check active state
/// before accepting events or issuing dispatch grants.
pub async fn revoke_device(
    client: &mut Client,
    principal: &SessionPrincipal,
    device_id: Uuid,
) -> Result<bool, EnrollmentError> {
    if !owner_session_active(client, principal).await? {
        return Err(EnrollmentError::Unauthorized);
    }
    let tx = client.transaction().await?;
    let updated = tx.execute(
        "UPDATE devices SET revoked_at=now() WHERE id=$1 AND account_id=$2 AND revoked_at IS NULL",
        &[&device_id, &principal.tenant.account_id()],
    ).await?;
    if updated == 0 {
        return Ok(false);
    }
    tx.execute(
        "UPDATE device_keys SET revoked_at=now() WHERE device_id=$1 AND account_id=$2 AND revoked_at IS NULL",
        &[&device_id, &principal.tenant.account_id()],
    ).await?;
    tx.execute(
        "DELETE FROM device_auth_challenges WHERE device_id=$1 AND account_id=$2",
        &[&device_id, &principal.tenant.account_id()],
    )
    .await?;
    tx.execute(
        "DELETE FROM device_sessions WHERE device_id=$1 AND account_id=$2",
        &[&device_id, &principal.tenant.account_id()],
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests;
