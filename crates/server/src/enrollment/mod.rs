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

#[derive(Debug, Error)]
pub enum EnrollmentError {
    #[error("invalid input")]
    InvalidInput,
    #[error("pairing or challenge unavailable")]
    Unavailable,
    #[error("device unauthorized")]
    Unauthorized,
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
    let sec1 = key.to_encoded_point(false).as_bytes().to_vec();
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

/// Consumes the QR token once and binds the candidate Keystore public key.
/// `spki_der` is Android `PublicKey.getEncoded()` for a P-256 signing key.
pub async fn claim_pairing(
    client: &mut Client,
    hasher: &EnrollmentHasher,
    pairing_id: Uuid,
    token: &str,
    spki_der: &[u8],
) -> Result<ClaimedPairing, EnrollmentError> {
    if !token.starts_with("ztp_")
        || token.len() != 47
        || URL_SAFE_NO_PAD
            .decode(&token[4..])
            .map_or(true, |b| b.len() != 32)
    {
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
mod tests {
    use super::*;
    use crate::auth::{TokenHasher, authenticate_session, login, register, verify_email};
    use p256::ecdsa::{SigningKey, signature::Signer};
    use p256::elliptic_curve::rand_core::OsRng;
    use p256::pkcs8::EncodePublicKey;

    #[test]
    fn p256_android_spki_and_der_signature_round_trip() {
        let signing_key = SigningKey::random(&mut OsRng);
        let spki = signing_key.verifying_key().to_public_key_der().unwrap();
        let (_, sec1, fingerprint) = parse_public_key(spki.as_bytes()).unwrap();
        let bytes = enrollment_challenge_bytes(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &fingerprint,
            &random_bytes(),
        );
        let signature: Signature = signing_key.sign(&bytes);
        assert!(verify_signature(
            &sec1,
            &bytes,
            signature.to_der().as_bytes()
        ));
        let mut tampered = bytes.clone();
        tampered[0] ^= 1;
        assert!(!verify_signature(
            &sec1,
            &tampered,
            signature.to_der().as_bytes()
        ));
    }

    #[tokio::test]
    async fn postgres_one_use_tenant_replay_expiry_and_revocation() {
        let Ok(url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (mut client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("enrollment_test_{}", Uuid::new_v4().simple());
        client
            .batch_execute(&format!(
                "CREATE SCHEMA {schema}; SET search_path TO {schema}"
            ))
            .await
            .unwrap();
        for sql in [
            include_str!("../../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../../deploy/compose/migrations/005_verification_outbox.sql"),
        ] {
            client.batch_execute(sql).await.unwrap();
        }
        let auth_hasher = TokenHasher::new(vec![17; 32]).unwrap();
        let hasher = EnrollmentHasher::new(vec![19; 32]).unwrap();
        let a = register(
            &mut client,
            &auth_hasher,
            "enroll-a@example.test",
            "correct horse 123",
        )
        .await
        .unwrap();
        let b = register(
            &mut client,
            &auth_hasher,
            "enroll-b@example.test",
            "correct horse 456",
        )
        .await
        .unwrap();
        verify_email(&mut client, &auth_hasher, &a.verification_token)
            .await
            .unwrap();
        verify_email(&mut client, &auth_hasher, &b.verification_token)
            .await
            .unwrap();
        let sa = login(
            &client,
            &auth_hasher,
            "enroll-a@example.test",
            "correct horse 123",
        )
        .await
        .unwrap();
        let sb = login(
            &client,
            &auth_hasher,
            "enroll-b@example.test",
            "correct horse 456",
        )
        .await
        .unwrap();
        let pa = authenticate_session(&client, &auth_hasher, &sa.token)
            .await
            .unwrap();
        let pb = authenticate_session(&client, &auth_hasher, &sb.token)
            .await
            .unwrap();
        let signing = SigningKey::random(&mut OsRng);
        let spki = signing.verifying_key().to_public_key_der().unwrap();

        let expired = create_pairing(&client, &hasher, &pa, "Expired")
            .await
            .unwrap();
        client.execute(
            "UPDATE pairing_requests SET created_at=now()-interval '10 minutes', expires_at=now()-interval '5 minutes' WHERE id=$1",
            &[&expired.id],
        ).await.unwrap();
        assert!(matches!(
            claim_pairing(
                &mut client,
                &hasher,
                expired.id,
                &expired.token,
                spki.as_bytes()
            )
            .await,
            Err(EnrollmentError::Unavailable)
        ));

        let bad = create_pairing(&client, &hasher, &pa, "Bad proof")
            .await
            .unwrap();
        let claimed_bad = claim_pairing(&mut client, &hasher, bad.id, &bad.token, spki.as_bytes())
            .await
            .unwrap();
        assert!(matches!(
            claim_pairing(&mut client, &hasher, bad.id, &bad.token, spki.as_bytes()).await,
            Err(EnrollmentError::Unavailable)
        ));
        let other_signing = SigningKey::random(&mut OsRng);
        let (_, _, bad_fingerprint) = parse_public_key(spki.as_bytes()).unwrap();
        let bad_payload = enrollment_challenge_bytes(
            a.account_id,
            bad.id,
            &bad_fingerprint,
            &claimed_bad.challenge_nonce,
        );
        let wrong_sig: Signature = other_signing.sign(&bad_payload);
        assert!(
            !prove_pairing_key(
                &mut client,
                &hasher,
                bad.id,
                &claimed_bad.challenge_nonce,
                wrong_sig.to_der().as_bytes()
            )
            .await
            .unwrap()
        );
        let good_sig: Signature = signing.sign(&bad_payload);
        assert!(
            !prove_pairing_key(
                &mut client,
                &hasher,
                bad.id,
                &claimed_bad.challenge_nonce,
                good_sig.to_der().as_bytes()
            )
            .await
            .unwrap()
        );

        let ticket = create_pairing(&client, &hasher, &pa, "Test Samsung")
            .await
            .unwrap();
        let claimed = claim_pairing(
            &mut client,
            &hasher,
            ticket.id,
            &ticket.token,
            spki.as_bytes(),
        )
        .await
        .unwrap();
        assert_eq!(claimed.account_id, a.account_id);
        let (_, _, fingerprint) = parse_public_key(spki.as_bytes()).unwrap();
        let payload = enrollment_challenge_bytes(
            a.account_id,
            ticket.id,
            &fingerprint,
            &claimed.challenge_nonce,
        );
        let signature: Signature = signing.sign(&payload);
        assert!(
            prove_pairing_key(
                &mut client,
                &hasher,
                ticket.id,
                &claimed.challenge_nonce,
                signature.to_der().as_bytes()
            )
            .await
            .unwrap()
        );
        assert!(
            !prove_pairing_key(
                &mut client,
                &hasher,
                ticket.id,
                &claimed.challenge_nonce,
                signature.to_der().as_bytes()
            )
            .await
            .unwrap()
        );
        assert!(
            pairing_view(&client, &pb, ticket.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            approve_pairing(
                &mut client,
                &pb,
                ticket.id,
                &claimed.comparison_code,
                &claimed.key_fingerprint
            )
            .await,
            Err(EnrollmentError::Unavailable)
        ));
        assert!(matches!(
            approve_pairing(
                &mut client,
                &pa,
                ticket.id,
                "00000000",
                &claimed.key_fingerprint
            )
            .await,
            Err(EnrollmentError::Unavailable)
        ));
        let device_id = approve_pairing(
            &mut client,
            &pa,
            ticket.id,
            &claimed.comparison_code,
            &claimed.key_fingerprint,
        )
        .await
        .unwrap();
        assert!(matches!(
            approve_pairing(
                &mut client,
                &pa,
                ticket.id,
                &claimed.comparison_code,
                &claimed.key_fingerprint
            )
            .await,
            Err(EnrollmentError::Unavailable)
        ));

        let challenge = issue_device_challenge(&client, &hasher, device_id)
            .await
            .unwrap();
        assert_eq!(challenge.account_id, a.account_id);
        let wrong_sig: Signature = other_signing.sign(&device_challenge_bytes(&challenge));
        assert!(matches!(
            authenticate_device_challenge(
                &mut client,
                &hasher,
                &challenge,
                wrong_sig.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));
        let good_sig: Signature = signing.sign(&device_challenge_bytes(&challenge));
        assert!(matches!(
            authenticate_device_challenge(
                &mut client,
                &hasher,
                &challenge,
                good_sig.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));
        let challenge = issue_device_challenge(&client, &hasher, device_id)
            .await
            .unwrap();
        let good_sig: Signature = signing.sign(&device_challenge_bytes(&challenge));
        let identity = authenticate_device_challenge(
            &mut client,
            &hasher,
            &challenge,
            good_sig.to_der().as_bytes(),
        )
        .await
        .unwrap();
        assert!(device_still_active(&client, identity).await.unwrap());
        assert!(matches!(
            authenticate_device_challenge(
                &mut client,
                &hasher,
                &challenge,
                good_sig.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));
        let expired_challenge = issue_device_challenge(&client, &hasher, device_id)
            .await
            .unwrap();
        client
            .execute(
                "UPDATE device_auth_challenges SET created_at=now()-interval '2 minutes', expires_at=now()-interval '1 minute' WHERE id=$1",
                &[&expired_challenge.id],
            )
            .await
            .unwrap();
        let expired_signature: Signature =
            signing.sign(&device_challenge_bytes(&expired_challenge));
        assert!(matches!(
            authenticate_device_challenge(
                &mut client,
                &hasher,
                &expired_challenge,
                expired_signature.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));
        let outstanding_challenge = issue_device_challenge(&client, &hasher, device_id)
            .await
            .unwrap();
        let outstanding_signature: Signature =
            signing.sign(&device_challenge_bytes(&outstanding_challenge));
        assert!(!revoke_device(&mut client, &pb, device_id).await.unwrap());
        assert!(revoke_device(&mut client, &pa, device_id).await.unwrap());
        assert!(!device_still_active(&client, identity).await.unwrap());
        assert!(matches!(
            authenticate_device_challenge(
                &mut client,
                &hasher,
                &outstanding_challenge,
                outstanding_signature.to_der().as_bytes()
            )
            .await,
            Err(EnrollmentError::Unauthorized)
        ));
        assert!(matches!(
            issue_device_challenge(&client, &hasher, device_id).await,
            Err(EnrollmentError::Unauthorized)
        ));
        client
            .batch_execute(&format!(
                "SET search_path TO public; DROP SCHEMA {schema} CASCADE"
            ))
            .await
            .unwrap();
    }
}
