// SPDX-License-Identifier: AGPL-3.0-only
//! Disabled-by-default webhook dispatcher. Endpoint creation and inbound WSS
//! upload are separate gates; this module only consumes existing outbox rows.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use thiserror::Error;
use tokio_postgres::Client;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    inbound::{self, WebhookLease, WebhookOutcome, WebhookPayload},
    webhook_egress::{self, EgressError},
};

const SECRET_FORMAT: u8 = 1;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("invalid webhook key or encrypted signing secret")]
    Secret,
    #[error("webhook payload exceeds the sender limit")]
    Payload,
    #[error("webhook storage failed")]
    Storage(#[from] inbound::InboundError),
}

/// Operational endpoint-secret KEK. This is distinct from the M2 content-key
/// protocol. Load the key from an external secret source, never the database.
pub struct WebhookSecretVault {
    version: i32,
    key: Zeroizing<[u8; 32]>,
    secondary: Option<(i32, Zeroizing<[u8; 32]>)>,
}

#[derive(Debug, Error)]
pub enum RewrapError {
    #[error("invalid webhook key or encrypted signing secret")]
    Secret(#[from] WorkerError),
    #[error("webhook key rewrap storage failed")]
    Database(#[from] tokio_postgres::Error),
    #[error("webhook key rewrap batch size must be 1..=500")]
    BatchSize,
}

impl WebhookSecretVault {
    pub fn new(version: i32, key: Zeroizing<Vec<u8>>) -> Result<Self, WorkerError> {
        Self::with_secondary(version, key, None)
    }

    /// Both sites can read the old and new ciphertext during a staged KEK
    /// change. Only the active key is used to seal newly created endpoints.
    pub fn with_secondary(
        version: i32,
        key: Zeroizing<Vec<u8>>,
        secondary: Option<(i32, Zeroizing<Vec<u8>>)>,
    ) -> Result<Self, WorkerError> {
        if version <= 0 || key.len() != 32 {
            return Err(WorkerError::Secret);
        }
        let mut fixed = Zeroizing::new([0_u8; 32]);
        fixed.copy_from_slice(&key);
        let secondary = match secondary {
            Some((other_version, other_key)) => {
                if other_version <= 0
                    || other_version == version
                    || other_key.len() != 32
                    || other_key.as_slice() == key.as_slice()
                {
                    return Err(WorkerError::Secret);
                }
                let mut other_fixed = Zeroizing::new([0_u8; 32]);
                other_fixed.copy_from_slice(&other_key);
                Some((other_version, other_fixed))
            }
            None => None,
        };
        Ok(Self {
            version,
            key: fixed,
            secondary,
        })
    }

    pub fn version(&self) -> i32 {
        self.version
    }

    pub fn secondary_version(&self) -> Option<i32> {
        self.secondary.as_ref().map(|(version, _)| *version)
    }

    /// The authenticated context prevents moving a ciphertext to another
    /// tenant, endpoint or key version.
    pub fn seal(
        &self,
        account_id: Uuid,
        endpoint_id: Uuid,
        secret: &[u8],
    ) -> Result<Vec<u8>, WorkerError> {
        if !(32..=256).contains(&secret.len()) {
            return Err(WorkerError::Secret);
        }
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| WorkerError::Secret)?;
        let nonce = Nonce::generate();
        let aad = secret_aad(account_id, endpoint_id, self.version);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: secret,
                    aad: &aad,
                },
            )
            .map_err(|_| WorkerError::Secret)?;
        let mut packed = Vec::with_capacity(1 + NONCE_BYTES + ciphertext.len());
        packed.push(SECRET_FORMAT);
        packed.extend_from_slice(&nonce);
        packed.extend_from_slice(&ciphertext);
        Ok(packed)
    }

    pub fn open(
        &self,
        account_id: Uuid,
        endpoint_id: Uuid,
        version: i32,
        packed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, WorkerError> {
        if packed.len() < 1 + NONCE_BYTES + TAG_BYTES + 32
            || packed.len() > 1 + NONCE_BYTES + TAG_BYTES + 256
            || packed[0] != SECRET_FORMAT
        {
            return Err(WorkerError::Secret);
        }
        let key = if version == self.version {
            self.key.as_ref()
        } else if let Some((other_version, other_key)) = &self.secondary {
            if version != *other_version {
                return Err(WorkerError::Secret);
            }
            other_key.as_ref()
        } else {
            return Err(WorkerError::Secret);
        };
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| WorkerError::Secret)?;
        let aad = secret_aad(account_id, endpoint_id, version);
        let nonce =
            Nonce::try_from(&packed[1..1 + NONCE_BYTES]).map_err(|_| WorkerError::Secret)?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &packed[1 + NONCE_BYTES..],
                    aad: &aad,
                },
            )
            .map_err(|_| WorkerError::Secret)?;
        if !(32..=256).contains(&plaintext.len()) {
            return Err(WorkerError::Secret);
        }
        Ok(Zeroizing::new(plaintext))
    }
}

/// Re-encrypt one bounded batch with the active KEK while preserving the
/// endpoint signing secret. Row locks serialize this with owner rotation;
/// a failed decrypt rolls back the entire batch. The secondary key must stay
/// configured on both sites until every stored row uses the active version.
pub async fn rewrap_endpoint_secrets(
    client: &mut Client,
    vault: &WebhookSecretVault,
    batch_size: i64,
) -> Result<u64, RewrapError> {
    if !(1..=500).contains(&batch_size) {
        return Err(RewrapError::BatchSize);
    }
    let tx = client.transaction().await?;
    let rows = tx
        .query(
            "SELECT id,account_id,signing_secret_ciphertext,signing_secret_key_version
             FROM webhook_endpoints WHERE signing_secret_key_version<>$1
             ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED",
            &[&vault.version(), &batch_size],
        )
        .await?;
    for row in &rows {
        let endpoint_id: Uuid = row.get(0);
        let account_id: Uuid = row.get(1);
        let ciphertext: Vec<u8> = row.get(2);
        let old_version: i32 = row.get(3);
        let secret = vault.open(account_id, endpoint_id, old_version, &ciphertext)?;
        let replacement = vault.seal(account_id, endpoint_id, &secret)?;
        tx.execute(
            "UPDATE webhook_endpoints SET signing_secret_ciphertext=$3,
             signing_secret_key_version=$4 WHERE id=$1 AND account_id=$2",
            &[&endpoint_id, &account_id, &replacement, &vault.version()],
        )
        .await?;
    }
    tx.commit().await?;
    Ok(rows.len() as u64)
}

fn secret_aad(account_id: Uuid, endpoint_id: Uuid, version: i32) -> Vec<u8> {
    let mut aad = b"zrotext-webhook-secret-v1\0".to_vec();
    aad.extend_from_slice(account_id.as_bytes());
    aad.extend_from_slice(endpoint_id.as_bytes());
    aad.extend_from_slice(&version.to_be_bytes());
    aad
}

fn event_body(lease: &WebhookLease, payload: &WebhookPayload) -> Result<Vec<u8>, WorkerError> {
    let body = serde_json::to_vec(&json!({
        "v": 1,
        "type": "inbound.message",
        "event_id": lease.event_id,
        "delivery_id": lease.delivery_id,
        "account_id": lease.account_id,
        "device_id": payload.device_id,
        "message_id": payload.message_id,
        "attempt_id": payload.attempt_id,
        "classification": payload.classification,
        "observed_at_ms": payload.observed_at_ms,
        "part_count": payload.part_count,
        "content_kind": payload.content_kind,
        "content_ciphertext_b64": payload.content_ciphertext.as_ref().map(|bytes| STANDARD.encode(bytes)),
        "event_digest_b64": STANDARD.encode(&payload.event_digest),
        "device_signature_der_b64": STANDARD.encode(&payload.device_signature_der),
    }))
    .map_err(|_| WorkerError::Payload)?;
    if body.is_empty() || body.len() > 65_536 {
        return Err(WorkerError::Payload);
    }
    Ok(body)
}

/// Claims at most one row. A failed store operation leaves the lease to be
/// recovered by the outbox; transport failures are recorded for bounded retry.
pub async fn dispatch_one(
    client: &mut Client,
    vault: &WebhookSecretVault,
    worker_id: &str,
) -> Result<bool, WorkerError> {
    let Some(lease) = inbound::claim_webhook(client, worker_id).await? else {
        return Ok(false);
    };
    let payload = inbound::load_webhook_payload(client, &lease).await?;
    let outcome = dispatch_payload(vault, &lease, &payload).await;
    let (result, status) = match outcome {
        Ok(response) if response.acknowledged => {
            (WebhookOutcome::Ack, Some(response.status as i16))
        }
        Ok(response) if (300..=599).contains(&response.status) => {
            (WebhookOutcome::HttpError, Some(response.status as i16))
        }
        Ok(_) => (WebhookOutcome::NetworkError, None),
        Err(DispatchError::Policy) => (WebhookOutcome::PolicyRejected, None),
        Err(DispatchError::Network) => (WebhookOutcome::NetworkError, None),
    };
    inbound::finish_webhook(client, &lease, result, status).await?;
    Ok(true)
}

enum DispatchError {
    Policy,
    Network,
}

async fn dispatch_payload(
    vault: &WebhookSecretVault,
    lease: &WebhookLease,
    payload: &WebhookPayload,
) -> Result<webhook_egress::DeliveryResponse, DispatchError> {
    let secret = vault
        .open(
            lease.account_id,
            lease.endpoint_id,
            payload.signing_secret_key_version,
            &payload.encrypted_signing_secret,
        )
        .map_err(|_| DispatchError::Policy)?;
    let body = event_body(lease, payload).map_err(|_| DispatchError::Policy)?;
    webhook_egress::post_signed(&payload.callback_url, &body, &secret)
        .await
        .map_err(|error| match error {
            EgressError::InvalidInput | EgressError::UnsafeResolution => DispatchError::Policy,
            EgressError::ResolutionUnavailable | EgressError::Transport => DispatchError::Network,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_postgres::NoTls;

    #[test]
    fn endpoint_secret_is_bound_to_tenant_endpoint_and_key_version() {
        let vault = WebhookSecretVault::new(7, Zeroizing::new(vec![3; 32])).unwrap();
        let account = Uuid::new_v4();
        let endpoint = Uuid::new_v4();
        let sealed = vault.seal(account, endpoint, &[9; 32]).unwrap();
        assert_ne!(&sealed[1 + NONCE_BYTES..1 + NONCE_BYTES + 32], &[9; 32]);
        assert_eq!(
            &*vault.open(account, endpoint, 7, &sealed).unwrap(),
            &[9; 32]
        );
        assert!(vault.open(Uuid::new_v4(), endpoint, 7, &sealed).is_err());
        assert!(vault.open(account, Uuid::new_v4(), 7, &sealed).is_err());
        assert!(vault.open(account, endpoint, 8, &sealed).is_err());
        let mut tampered = sealed;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(vault.open(account, endpoint, 7, &tampered).is_err());
    }

    #[test]
    fn secondary_key_can_read_but_only_active_key_seals() {
        let old = WebhookSecretVault::new(7, Zeroizing::new(vec![3; 32])).unwrap();
        let rotated = WebhookSecretVault::with_secondary(
            8,
            Zeroizing::new(vec![4; 32]),
            Some((7, Zeroizing::new(vec![3; 32]))),
        )
        .unwrap();
        let account = Uuid::new_v4();
        let endpoint = Uuid::new_v4();
        let old_ciphertext = old.seal(account, endpoint, &[9; 32]).unwrap();
        assert_eq!(
            &*rotated.open(account, endpoint, 7, &old_ciphertext).unwrap(),
            &[9; 32]
        );
        let new_ciphertext = rotated.seal(account, endpoint, &[9; 32]).unwrap();
        assert_eq!(
            &*rotated.open(account, endpoint, 8, &new_ciphertext).unwrap(),
            &[9; 32]
        );
        let staged = WebhookSecretVault::with_secondary(
            7,
            Zeroizing::new(vec![3; 32]),
            Some((8, Zeroizing::new(vec![4; 32]))),
        )
        .unwrap();
        assert_eq!(
            &*staged.open(account, endpoint, 8, &new_ciphertext).unwrap(),
            &[9; 32]
        );
        assert!(old.open(account, endpoint, 8, &new_ciphertext).is_err());
        assert!(
            WebhookSecretVault::with_secondary(
                8,
                Zeroizing::new(vec![4; 32]),
                Some((7, Zeroizing::new(vec![4; 32])))
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn postgres_rewrap_preserves_secret_and_unknown_version_rolls_back() {
        let Ok(base_url) = std::env::var("ZT_AUTH_TEST_DATABASE_URL") else {
            return;
        };
        let (setup, connection) = tokio_postgres::connect(&base_url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        let schema = format!("webhook_rewrap_test_{}", Uuid::new_v4().simple());
        setup
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await
            .unwrap();
        let separator = if base_url.contains('?') { '&' } else { '?' };
        let url = format!("{base_url}{separator}options=-csearch_path%3D{schema}");
        let (mut db, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        for sql in [
            include_str!("../../../deploy/compose/migrations/001_foundation.sql"),
            include_str!("../../../deploy/compose/migrations/002_auth.sql"),
            include_str!("../../../deploy/compose/migrations/003_delivery.sql"),
            include_str!("../../../deploy/compose/migrations/004_enrollment.sql"),
            include_str!("../../../deploy/compose/migrations/005_verification_outbox.sql"),
            include_str!("../../../deploy/compose/migrations/006_usage_metering.sql"),
            include_str!("../../../deploy/compose/migrations/007_inbound_webhook_foundation.sql"),
        ] {
            db.batch_execute(sql).await.unwrap();
        }
        let account = Uuid::new_v4();
        let endpoint = Uuid::new_v4();
        db.execute("INSERT INTO accounts(id) VALUES($1)", &[&account])
            .await
            .unwrap();
        let old = WebhookSecretVault::new(7, Zeroizing::new(vec![3; 32])).unwrap();
        let rotated = WebhookSecretVault::with_secondary(
            8,
            Zeroizing::new(vec![4; 32]),
            Some((7, Zeroizing::new(vec![3; 32]))),
        )
        .unwrap();
        let old_ciphertext = old.seal(account, endpoint, &[9; 32]).unwrap();
        db.execute(
            "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version) VALUES($1,$2,'https://example.test/hook',$3,7)",
            &[&endpoint, &account, &old_ciphertext],
        ).await.unwrap();
        assert_eq!(
            rewrap_endpoint_secrets(&mut db, &rotated, 100)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            rewrap_endpoint_secrets(&mut db, &rotated, 100)
                .await
                .unwrap(),
            0
        );
        let row = db.query_one("SELECT signing_secret_ciphertext,signing_secret_key_version FROM webhook_endpoints WHERE id=$1", &[&endpoint]).await.unwrap();
        let new_ciphertext: Vec<u8> = row.get(0);
        assert_ne!(new_ciphertext, old_ciphertext);
        assert_eq!(row.get::<_, i32>(1), 8);
        let active_only = WebhookSecretVault::new(8, Zeroizing::new(vec![4; 32])).unwrap();
        assert_eq!(
            &*active_only
                .open(account, endpoint, 8, &new_ciphertext)
                .unwrap(),
            &[9; 32]
        );

        let unknown_endpoint = Uuid::new_v4();
        db.execute(
            "INSERT INTO webhook_endpoints(id,account_id,callback_url,signing_secret_ciphertext,signing_secret_key_version) VALUES($1,$2,'https://example.test/hook',$3,99)",
            &[&unknown_endpoint, &account, &old_ciphertext],
        ).await.unwrap();
        assert!(
            rewrap_endpoint_secrets(&mut db, &rotated, 100)
                .await
                .is_err()
        );
        let row = db.query_one("SELECT signing_secret_ciphertext,signing_secret_key_version FROM webhook_endpoints WHERE id=$1", &[&unknown_endpoint]).await.unwrap();
        assert_eq!(row.get::<_, Vec<u8>>(0), old_ciphertext);
        assert_eq!(row.get::<_, i32>(1), 99);
        setup
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await
            .unwrap();
    }
}
