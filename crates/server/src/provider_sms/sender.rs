// SPDX-License-Identifier: AGPL-3.0-only
//! Default-off provider SMS sender worker. The transport is the one network
//! boundary: bounded timeouts, no retry, no redirect and no retransmission
//! after a possibly-transmitted attempt. A disabled configuration refuses
//! before the credential is read or any transport is constructed.
//!
//! The trusted seam is `SubmitTransport`: production wiring can only build
//! `TelnyxHttps` against the documented SMS-v2 endpoint; the scripted
//! transport exists only in test builds, mirroring the synthetic permit and
//! TEST exposure candidates elsewhere in this crate.

use super::dispatch::{self, DispatchError, Lease, ResponseOutcome};
use super::receipts::ElectedWriterPermit;
use super::submit_codec;
use super::{Content, Request};
use std::net::SocketAddr;
use std::time::Duration;
use tokio_postgres::Client;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The documented Telnyx SMS-v2 endpoint. No arbitrary or caller-supplied
/// URL, region or pool is supported anywhere in this module.
const TELNYX_MESSAGES_URL: &str = "https://api.telnyx.com/v2/messages";
const TELNYX_HOST: &str = "api.telnyx.com";
const MAX_DNS_ADDRESSES: usize = 4;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Provider credential. Never logged, never Debug, and only read after the
/// enabled gate has passed.
#[derive(Clone)]
pub struct ApiKey(Zeroizing<String>);
impl ApiKey {
    pub fn new(value: &str) -> Result<Self, SenderError> {
        let trimmed = value.trim();
        if trimmed.len() < 20
            || trimmed.len() > 256
            || !trimmed.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(SenderError::InvalidInput);
        }
        Ok(Self(Zeroizing::new(trimmed.to_owned())))
    }
    fn header_value(&self) -> String {
        format!("Bearer {}", self.0.as_str())
    }
}

/// Default-off. `SenderConfig::default()` carries no credential and no
/// network capability; every send path checks `enabled` before anything else.
#[derive(Default)]
pub struct SenderConfig {
    enabled: bool,
    key: Option<ApiKey>,
}
impl SenderConfig {
    /// The only production constructor: enabling requires the credential up
    /// front, so a missing credential can never reach the network boundary.
    pub fn enable(mut self, key: ApiKey) -> Self {
        self.key = Some(key);
        self.enabled = true;
        self
    }
    pub fn authorize(&self) -> Result<&ApiKey, SenderError> {
        if !self.enabled {
            return Err(SenderError::Disabled);
        }
        self.key.as_ref().ok_or(SenderError::Disabled)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SenderError {
    #[error("provider sending is disabled by configuration")]
    Disabled,
    #[error("provider sender input invalid")]
    InvalidInput,
    #[error("provider sender material failed the commitment check")]
    Material,
    #[error("provider sender storage unavailable")]
    Database(#[from] DispatchError),
}

/// The one submission attempt's network outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportOutcome {
    /// The provider accepted the message and returned its identity.
    Accepted { message_id: Uuid },
    /// The provider answered with a definitive pre-transmission refusal.
    Refused { status: u16 },
    /// Timeout, transport failure or a non-definitive answer after possible
    /// transmission. This is terminal liability and never a retry permit.
    Lost,
}

/// Trusted seam between the worker and the network. Production code can only
/// reach `TelnyxHttps`; the scripted implementation is `#[cfg(test)]`.
pub trait SubmitTransport: Send + Sync {
    fn submit(
        &self,
        key: &ApiKey,
        body: &[u8],
    ) -> impl std::future::Future<Output = TransportOutcome> + Send;
}

/// Production transport: one bounded HTTPS attempt against the documented
/// endpoint, no retry, no redirect, fresh client per attempt.
pub struct TelnyxHttps;
impl TelnyxHttps {
    async fn resolved_addrs() -> Result<Vec<SocketAddr>, SenderError> {
        let answers = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::lookup_host((TELNYX_HOST, 443)),
        )
        .await
        .map_err(|_| SenderError::Disabled)? // resolution failure is not transmit permission
        .map_err(|_| SenderError::Disabled)?;
        let addrs: Vec<SocketAddr> = answers.take(MAX_DNS_ADDRESSES + 1).collect();
        if addrs.is_empty()
            || addrs.len() > MAX_DNS_ADDRESSES
            || addrs
                .iter()
                .any(|a| a.ip().is_loopback() || a.ip().is_unspecified())
        {
            return Err(SenderError::Disabled);
        }
        Ok(addrs)
    }
}
impl SubmitTransport for TelnyxHttps {
    async fn submit(&self, key: &ApiKey, body: &[u8]) -> TransportOutcome {
        let addrs = match Self::resolved_addrs().await {
            Ok(addrs) => addrs,
            Err(_) => return TransportOutcome::Lost,
        };
        let client = match reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .https_only(true)
            .http1_only()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .pool_max_idle_per_host(0)
            .resolve_to_addrs(TELNYX_HOST, &addrs)
            .build()
        {
            Ok(client) => client,
            Err(_) => return TransportOutcome::Lost,
        };
        let response = client
            .post(TELNYX_MESSAGES_URL)
            .header("authorization", key.header_value())
            .header("content-type", "application/json")
            .body(body.to_vec())
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let payload = response.bytes().await.unwrap_or_default();
                classify(status, &payload)
            }
            Err(_) => TransportOutcome::Lost,
        }
    }
}

/// Pure response classification: a 2xx body with a parseable provider id
/// accepts; any 4xx is a definitive refusal; everything else is lost.
fn classify(status: u16, body: &[u8]) -> TransportOutcome {
    if body.len() > 65_536 {
        return TransportOutcome::Lost;
    }
    if (200..300).contains(&status) {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body)
            && let Some(id) = value["data"]["id"].as_str()
            && let Ok(message_id) = Uuid::parse_str(id)
            && !message_id.is_nil()
        {
            return TransportOutcome::Accepted { message_id };
        }
        return TransportOutcome::Lost;
    }
    if (400..500).contains(&status) {
        return TransportOutcome::Refused { status };
    }
    TransportOutcome::Lost
}

/// One worker tick: claim at most one recorded intent, recheck authority
/// under the same locks as the intent writer, then release transport once.
#[derive(Debug, PartialEq, Eq)]
pub enum Tick {
    /// No recorded intent was claimable.
    Idle,
    /// Pre-flight authority refused; the attempt is released, nothing sent.
    Released { attempt: Uuid },
    /// The provider answered before transmission; nothing was sent.
    Refused { attempt: Uuid, status: u16 },
    /// The provider accepted and the message identity is bound.
    Accepted { attempt: Uuid, message_id: Uuid },
    /// Response lost after possible transmission; conservative terminal state.
    Lost { attempt: Uuid },
}

pub async fn send_one<T: SubmitTransport>(
    client: &mut Client,
    permit: &ElectedWriterPermit,
    key: &ApiKey,
    transport: &T,
    account: Uuid,
    material: &Material<'_>,
) -> Result<Tick, SenderError> {
    let [lease]: [Lease; 1] = match dispatch::claim_intended(client, permit, account, 1).await? {
        leases if leases.is_empty() => return Ok(Tick::Idle),
        leases => leases
            .try_into()
            .map_err(|_| SenderError::Database(DispatchError::Inconsistent))?,
    };
    let attempt = lease.attempt_id;
    // The committed request identity must match the caller's reconstruction
    // of the approved action before anything leaves the process.
    let encoded = submit_codec::encode(
        material.request,
        material.recipient,
        match &material.content {
            Content::ProviderPlaintext(text) => Content::ProviderPlaintext(text),
            Content::SealedPhoneEnvelope(bytes) => Content::SealedPhoneEnvelope(bytes),
        },
    )
    .map_err(|_| SenderError::Material)?;
    if let Err(DispatchError::Suppressed | DispatchError::Expired | DispatchError::Unavailable) =
        dispatch::preflight(client, permit, account, attempt, material).await
    {
        dispatch::record_response(client, permit, account, attempt, ResponseOutcome::Released)
            .await?;
        return Ok(Tick::Released { attempt });
    }
    let outcome = transport.submit(key, encoded.as_bytes()).await;
    let recorded = match outcome {
        TransportOutcome::Accepted { message_id } => {
            dispatch::record_response(
                client,
                permit,
                account,
                attempt,
                ResponseOutcome::Accepted { message_id },
            )
            .await?;
            Tick::Accepted {
                attempt,
                message_id,
            }
        }
        // A definitive provider refusal proves no transmission; the trusted
        // sender asserts exactly that by mapping it to Released.
        TransportOutcome::Refused { status } => {
            dispatch::record_response(client, permit, account, attempt, ResponseOutcome::Released)
                .await?;
            Tick::Refused { attempt, status }
        }
        TransportOutcome::Lost => {
            dispatch::record_response(client, permit, account, attempt, ResponseOutcome::Lost)
                .await?;
            Tick::Lost { attempt }
        }
    };
    Ok(recorded)
}

/// Caller-reconstructed send material for one attempt: the approved action's
/// committed request identity plus the recipient and body it resolves to.
/// Reconstruction from trusted sources only; the codec re-verifies the whole
/// commitment before the transport sees any bytes.
pub struct Material<'a> {
    pub request: &'a Request,
    pub recipient: &'a str,
    pub content: Content<'a>,
}

#[cfg(test)]
mod tests;
