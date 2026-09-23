// SPDX-License-Identifier: AGPL-3.0-only
//! Disabled-by-default webhook dispatcher. Endpoint creation and inbound WSS
//! upload are separate gates; this module only consumes existing outbox rows.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use std::future::Future;
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
}

impl WebhookSecretVault {
    pub fn new(version: i32, key: Zeroizing<Vec<u8>>) -> Result<Self, WorkerError> {
        if version <= 0 || key.len() != 32 {
            return Err(WorkerError::Secret);
        }
        let mut fixed = Zeroizing::new([0_u8; 32]);
        fixed.copy_from_slice(&key);
        Ok(Self {
            version,
            key: fixed,
        })
    }

    pub fn version(&self) -> i32 {
        self.version
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
        if version != self.version
            || packed.len() < 1 + NONCE_BYTES + TAG_BYTES + 32
            || packed.len() > 1 + NONCE_BYTES + TAG_BYTES + 256
            || packed[0] != SECRET_FORMAT
        {
            return Err(WorkerError::Secret);
        }
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| WorkerError::Secret)?;
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
    dispatch_one_with(client, vault, worker_id, |url, body, secret| async move {
        webhook_egress::post_signed(&url, &body, &secret).await
    })
    .await
}

/// The transport seam keeps the real sender fixed above while a test can
/// exercise claim, authenticated payload preparation and retry accounting.
pub(crate) async fn dispatch_one_with<F, Fut>(
    client: &mut Client,
    vault: &WebhookSecretVault,
    worker_id: &str,
    sender: F,
) -> Result<bool, WorkerError>
where
    F: FnOnce(String, Vec<u8>, Zeroizing<Vec<u8>>) -> Fut,
    Fut: Future<Output = Result<webhook_egress::DeliveryResponse, EgressError>>,
{
    let Some(lease) = inbound::claim_webhook(client, worker_id).await? else {
        return Ok(false);
    };
    let payload = inbound::load_webhook_payload(client, &lease).await?;
    let outcome = dispatch_payload_with(vault, &lease, &payload, sender).await;
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

async fn dispatch_payload_with<F, Fut>(
    vault: &WebhookSecretVault,
    lease: &WebhookLease,
    payload: &WebhookPayload,
    sender: F,
) -> Result<webhook_egress::DeliveryResponse, DispatchError>
where
    F: FnOnce(String, Vec<u8>, Zeroizing<Vec<u8>>) -> Fut,
    Fut: Future<Output = Result<webhook_egress::DeliveryResponse, EgressError>>,
{
    webhook_egress::validate_target(&payload.callback_url).map_err(|_| DispatchError::Policy)?;
    let secret = vault
        .open(
            lease.account_id,
            lease.endpoint_id,
            payload.signing_secret_key_version,
            &payload.encrypted_signing_secret,
        )
        .map_err(|_| DispatchError::Policy)?;
    let body = event_body(lease, payload).map_err(|_| DispatchError::Policy)?;
    sender(payload.callback_url.clone(), body, secret)
        .await
        .map_err(|error| match error {
            EgressError::InvalidInput | EgressError::UnsafeResolution => DispatchError::Policy,
            EgressError::ResolutionUnavailable | EgressError::Transport => DispatchError::Network,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
