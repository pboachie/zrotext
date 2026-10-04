// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant provider SMS contracts. No provider network caller or send authority.
//! Known receipt persistence is a separate, manually installed proposal with
//! no production writer-permit issuer or correlation creator.
//!
//! Snapshots are trusted caller inputs, NOT proof of authorization. A future
//! writer transaction must enforce account authority, shared suppression,
//! budgets, durable request idempotency and atomic receipt deduplication. This
//! bounded in-memory model deliberately cannot resume dispatch after a crash.

pub mod action_descriptor;
mod telnyx;
pub use telnyx::verify_receipt;
pub mod receipts;

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;
use zrotext_domain::{Evidence, MessageState};

const MAX_EVENTS: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    TelnyxSmsV2,
}

/// An explicit, immutable configured route; never inferred from a callback.
/// No Debug implementation: a sender is private data.
#[derive(Clone, PartialEq, Eq)]
pub struct Route {
    account: Uuid,
    organization: Uuid,
    profile: Uuid,
    sender: String,
    revision: u64,
}

impl Route {
    pub fn telnyx(
        account: Uuid,
        organization: Uuid,
        profile: Uuid,
        sender: &str,
        revision: u64,
    ) -> Result<Self, Rejection> {
        if [account, organization, profile].iter().any(Uuid::is_nil)
            || revision == 0
            || !e164(sender)
        {
            return Err(Rejection::InvalidInput);
        }
        Ok(Self {
            account,
            organization,
            profile,
            sender: sender.into(),
            revision,
        })
    }
    pub fn provider(&self) -> Provider {
        Provider::TelnyxSmsV2
    }
}

fn e164(value: &str) -> bool {
    (3..=16).contains(&value.len())
        && value.starts_with('+')
        && value.as_bytes()[1] != b'0'
        && value.as_bytes()[1..].iter().all(u8::is_ascii_digit)
}

/// Explicit disclosure intent, not a content classifier. No encoder or decryptor.
pub enum Content<'a> {
    ProviderPlaintext(&'a str),
    SealedPhoneEnvelope(&'a [u8]),
}

/// Identity only: plaintext and recipient are not retained or exposed in Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    route: Route,
    recipient: [u8; 32],
    digest: [u8; 32],
}
impl Request {
    pub fn new(route: Route, recipient: &str, content: Content<'_>) -> Result<Self, Rejection> {
        let Content::ProviderPlaintext(body) = content else {
            return Err(Rejection::SealedContent);
        };
        if !e164(recipient) || body.is_empty() || body.len() > 4096 {
            return Err(Rejection::InvalidInput);
        }
        let recipient = Sha256::digest(recipient.as_bytes()).into();
        let mut hash = Sha256::new();
        hash.update(b"ZT/provider-request/v1\0telnyx-sms-v2\0");
        for id in [route.account, route.organization, route.profile] {
            hash.update(id.as_bytes());
        }
        hash.update(route.revision.to_be_bytes());
        hash.update((route.sender.len() as u64).to_be_bytes());
        hash.update(route.sender.as_bytes());
        hash.update(recipient);
        hash.update(Sha256::digest(body.as_bytes()));
        Ok(Self {
            route,
            recipient,
            digest: hash.finalize().into(),
        })
    }
    /// Store with the existing account-scoped idempotency key; a mismatch is a conflict.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn check_replay(&self, existing: &Self) -> Result<(), Rejection> {
        if self == existing {
            Ok(())
        } else {
            Err(Rejection::RequestConflict)
        }
    }
}

/// Model input sampled at the authoritative writer, never client-supplied.
/// Expiry/revision checks here cannot close a real database or network race.
pub struct AdmissionSnapshot {
    pub account: Uuid,
    pub route_revision: u64,
    pub observed_ms: u64,
    pub expires_ms: u64,
    pub writer_enabled: bool,
    pub suppressed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    InvalidInput,
    SealedContent,
    RequestConflict,
    Authority,
    Suppressed,
    InvalidState,
    InvalidSignature,
    InvalidTimestamp,
    InvalidCallback,
    RouteMismatch,
    MessageConflict,
    EventConflict,
    EvidenceConflict,
    EventCapacity,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptEffect {
    Applied,
    Duplicate,
    AwaitingCorrelation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptFact {
    CarrierSubmitted,
    Delivered,
    DeliveryUnconfirmed,
    SendingFailed,
    DeliveryFailed,
    Unrecognized,
}

/// Constructible only after provider signature, bounds and route verification.
/// Verification does not authorize sending, trust arbitrary accounts or prove handset delivery.
pub struct VerifiedReceipt {
    event_id: Uuid,
    message_id: Uuid,
    request: Request,
    fact: ReceiptFact,
    identity: [u8; 32],
}

/// In-memory acceptance model using the existing domain states. No persistence,
/// HTTP sender, provider credential, cancellation or generic Evidence escape.
pub struct Attempt {
    request: Request,
    attempt_id: Uuid,
    state: MessageState,
    provider_id: Option<Uuid>,
    events: BTreeMap<Uuid, [u8; 32]>,
    delivery_failed: bool,
}
impl Attempt {
    pub fn new(request: Request, attempt_id: Uuid) -> Result<Self, Rejection> {
        if attempt_id.is_nil() {
            return Err(Rejection::InvalidInput);
        }
        Ok(Self {
            request,
            attempt_id,
            state: MessageState::Queued,
            provider_id: None,
            events: BTreeMap::new(),
            delivery_failed: false,
        })
    }
    pub fn id(&self) -> Uuid {
        self.attempt_id
    }
    pub fn state(&self) -> MessageState {
        self.state
    }
    pub fn provider_accepted(&self) -> bool {
        self.provider_id.is_some()
    }
    pub fn delivery_failed(&self) -> bool {
        self.delivery_failed
    }
    pub fn begin(&mut self, gate: &AdmissionSnapshot, now_ms: u64) -> Result<(), Rejection> {
        if !gate.writer_enabled
            || gate.account != self.request.route.account
            || gate.route_revision != self.request.route.revision
            || gate.observed_ms > now_ms
            || gate.expires_ms <= now_ms
            || gate.expires_ms <= gate.observed_ms
            || gate.expires_ms - gate.observed_ms > 5_000
        {
            return Err(Rejection::Authority);
        }
        if gate.suppressed {
            return Err(Rejection::Suppressed);
        }
        if self.state != MessageState::Queued {
            return Err(Rejection::InvalidState);
        }
        self.state = self
            .state
            .apply(Evidence::Claim)
            .and_then(|s| s.apply(Evidence::DurableSubmitIntent))
            .map_err(|_| Rejection::InvalidState)?;
        Ok(())
    }
    /// Must be recorded durably before interpreting HTTP acceptance. This only
    /// records provider queue acceptance; it does NOT claim carrier submission.
    pub fn accept_response(&mut self, provider_id: Uuid) -> Result<(), Rejection> {
        if provider_id.is_nil() {
            return Err(Rejection::InvalidInput);
        }
        if let Some(existing) = self.provider_id {
            return if existing == provider_id {
                Ok(())
            } else {
                Err(Rejection::MessageConflict)
            };
        }
        if !matches!(self.state, MessageState::Submitting | MessageState::Unknown) {
            return Err(Rejection::InvalidState);
        }
        self.provider_id = Some(provider_id);
        Ok(())
    }
    /// No retry/fallback operation exists, even if the provider ID is unknown.
    pub fn response_lost(&mut self) -> Result<(), Rejection> {
        self.state = self
            .state
            .apply(Evidence::CrashWithoutCallback)
            .map_err(|_| Rejection::InvalidState)?;
        Ok(())
    }
    pub fn receipt(&mut self, event: &VerifiedReceipt) -> Result<ReceiptEffect, Rejection> {
        if event.request != self.request {
            return Err(Rejection::RouteMismatch);
        }
        let Some(provider_id) = self.provider_id else {
            return Ok(ReceiptEffect::AwaitingCorrelation);
        };
        if provider_id != event.message_id {
            return Err(Rejection::MessageConflict);
        }
        if let Some(identity) = self.events.get(&event.event_id) {
            return if *identity == event.identity {
                Ok(ReceiptEffect::Duplicate)
            } else {
                Err(Rejection::EventConflict)
            };
        }
        if self.events.len() >= MAX_EVENTS {
            return Err(Rejection::EventCapacity);
        }
        let mut state = self.state;
        let mut delivery_failed = self.delivery_failed;
        match event.fact {
            ReceiptFact::SendingFailed => {
                if !matches!(
                    state,
                    MessageState::Submitting | MessageState::Unknown | MessageState::Failed
                ) {
                    return Err(Rejection::EvidenceConflict);
                }
                if state != MessageState::Failed {
                    state = state
                        .apply(Evidence::SentCallbackFailed)
                        .map_err(|_| Rejection::InvalidState)?;
                }
            }
            ReceiptFact::CarrierSubmitted
            | ReceiptFact::Delivered
            | ReceiptFact::DeliveryUnconfirmed
            | ReceiptFact::DeliveryFailed => {
                if state == MessageState::Failed {
                    return Err(Rejection::EvidenceConflict);
                }
                if matches!(state, MessageState::Submitting | MessageState::Unknown) {
                    state = state
                        .apply(Evidence::SentCallbackOk)
                        .map_err(|_| Rejection::InvalidState)?;
                }
                if event.fact == ReceiptFact::Delivered {
                    if delivery_failed {
                        return Err(Rejection::EvidenceConflict);
                    }
                    if state != MessageState::Delivered {
                        state = state
                            .apply(Evidence::DeliveryCallbackOk)
                            .map_err(|_| Rejection::InvalidState)?;
                    }
                } else if event.fact == ReceiptFact::DeliveryFailed {
                    if state == MessageState::Delivered {
                        return Err(Rejection::EvidenceConflict);
                    }
                    delivery_failed = true;
                } else if event.fact == ReceiptFact::DeliveryUnconfirmed
                    && state == MessageState::Submitted
                    && !delivery_failed
                {
                    state = state
                        .apply(Evidence::DeliveryTimeout)
                        .map_err(|_| Rejection::InvalidState)?;
                }
            }
            ReceiptFact::Unrecognized => {}
        }
        self.state = state;
        self.delivery_failed = delivery_failed;
        self.events.insert(event.event_id, event.identity);
        Ok(ReceiptEffect::Applied)
    }
}

#[cfg(test)]
mod tests;
