// SPDX-License-Identifier: AGPL-3.0-only
//! M0 delivery rules. This is a pure model; PostgreSQL transactions in M1 must
//! enforce the same invariants at the authoritative writer.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageState {
    Accepted,
    Queued,
    Claimed,
    Submitting,
    Submitted,
    Delivered,
    DeliveryUnknown,
    Unknown,
    Failed,
    Cancelled,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evidence {
    Enqueue,
    Claim,
    DurableSubmitIntent,
    ProvenNoSubmit,
    SentCallbackOk,
    SentCallbackFailed,
    PartialSentCallbacks,
    DeliveryCallbackOk,
    DeliveryTimeout,
    CrashWithoutCallback,
    GrantTimeout,
    SentCallbackTimeout,
    CallbackConflict,
    Cancel,
    Expire,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidTransition {
    pub from: MessageState,
    pub evidence: Evidence,
}

impl MessageState {
    pub fn apply(self, evidence: Evidence) -> Result<Self, InvalidTransition> {
        use Evidence::*;
        use MessageState::*;
        let next = match (self, evidence) {
            (Accepted, Enqueue) => Queued,
            (Queued, Claim) => Claimed,
            (Claimed, DurableSubmitIntent) => Submitting,
            (Claimed, ProvenNoSubmit) => Queued,
            (Submitting, SentCallbackOk) => Submitted,
            (Submitting, SentCallbackFailed) => Failed,
            (Submitting, PartialSentCallbacks) => Unknown,
            (Submitting, CrashWithoutCallback) => Unknown,
            (Claimed, GrantTimeout) => Unknown,
            (Submitting, SentCallbackTimeout) => Unknown,
            (Unknown, SentCallbackOk) => Submitted,
            (Unknown, SentCallbackFailed) => Failed,
            (Submitted, DeliveryCallbackOk) => Delivered,
            (Submitted, DeliveryTimeout) => DeliveryUnknown,
            (DeliveryUnknown, DeliveryCallbackOk) => Delivered,
            (
                Submitting | Submitted | Delivered | DeliveryUnknown | Unknown | Failed,
                CallbackConflict,
            ) => Unknown,
            (Accepted | Queued | Claimed, Cancel) => Cancelled,
            (Accepted | Queued | Claimed, Expire) => Expired,
            _ => {
                return Err(InvalidTransition {
                    from: self,
                    evidence,
                });
            }
        };
        Ok(next)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub device_id: Uuid,
    pub site_id: String,
    pub instance_id: String,
    pub epoch: u64,
    pub lease_until_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub message_id: Uuid,
    pub attempt_id: Uuid,
    pub device_id: Uuid,
    pub session_epoch: u64,
    pub deployment_epoch: u64,
    pub generation: u64,
    pub recipient_digest: String,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    WriterUnavailable,
    DispatchDisabled,
    SessionStale,
    LeaseExpired,
    GrantAlreadyIssued,
    DeviceBusy,
    DuplicateKeyDifferentRequest,
    InvalidState,
}

/// Deterministic stand-in for transactions against one writer. No radio API is
/// called here. Two hubs share this authority in the M0 fault suite.
#[derive(Default)]
pub struct Authority {
    pub writer_available: bool,
    pub dispatch_enabled: bool,
    pub deployment_epoch: u64,
    sessions: BTreeMap<Uuid, Session>,
    messages: BTreeMap<Uuid, MessageState>,
    grants: BTreeMap<Uuid, Grant>,
    idempotency: BTreeMap<(Uuid, String), (String, Uuid)>,
}

impl Authority {
    pub fn new(deployment_epoch: u64) -> Self {
        Self {
            writer_available: true,
            dispatch_enabled: true,
            deployment_epoch,
            ..Self::default()
        }
    }

    pub fn accept(
        &mut self,
        account_id: Uuid,
        key: &str,
        request_digest: &str,
        message_id: Uuid,
    ) -> Result<Uuid, Rejection> {
        if !self.writer_available {
            return Err(Rejection::WriterUnavailable);
        }
        let entry = self
            .idempotency
            .entry((account_id, key.to_owned()))
            .or_insert_with(|| (request_digest.to_owned(), message_id));
        if entry.0 != request_digest {
            return Err(Rejection::DuplicateKeyDifferentRequest);
        }
        self.messages.entry(entry.1).or_insert(MessageState::Queued);
        Ok(entry.1)
    }

    pub fn connect(
        &mut self,
        device_id: Uuid,
        site_id: &str,
        instance_id: &str,
        now_ms: u64,
        lease_ms: u64,
    ) -> Result<Session, Rejection> {
        if !self.writer_available {
            return Err(Rejection::WriterUnavailable);
        }
        let epoch = self
            .sessions
            .get(&device_id)
            .map_or(1, |prior| prior.epoch + 1);
        let session = Session {
            device_id,
            site_id: site_id.to_owned(),
            instance_id: instance_id.to_owned(),
            epoch,
            lease_until_ms: now_ms + lease_ms,
        };
        self.sessions.insert(device_id, session.clone());
        Ok(session)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn grant(
        &mut self,
        session: &Session,
        message_id: Uuid,
        attempt_id: Uuid,
        generation: u64,
        recipient_digest: &str,
        now_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Grant, Rejection> {
        if !self.writer_available {
            return Err(Rejection::WriterUnavailable);
        }
        if !self.dispatch_enabled {
            return Err(Rejection::DispatchDisabled);
        }
        if self.sessions.get(&session.device_id) != Some(session) {
            return Err(Rejection::SessionStale);
        }
        if session.lease_until_ms <= now_ms || expires_at_ms <= now_ms {
            return Err(Rejection::LeaseExpired);
        }
        if self.grants.contains_key(&message_id) {
            return Err(Rejection::GrantAlreadyIssued);
        }
        if self.grants.values().any(|grant| {
            grant.device_id == session.device_id
                && matches!(
                    self.messages.get(&grant.message_id),
                    Some(MessageState::Claimed | MessageState::Submitting | MessageState::Unknown)
                )
        }) {
            return Err(Rejection::DeviceBusy);
        }
        if self.messages.get(&message_id) != Some(&MessageState::Queued) {
            return Err(Rejection::InvalidState);
        }
        let grant = Grant {
            message_id,
            attempt_id,
            device_id: session.device_id,
            session_epoch: session.epoch,
            deployment_epoch: self.deployment_epoch,
            generation,
            recipient_digest: recipient_digest.to_owned(),
            expires_at_ms,
        };
        self.grants.insert(message_id, grant.clone());
        self.messages.insert(message_id, MessageState::Claimed);
        Ok(grant)
    }

    pub fn event(
        &mut self,
        message_id: Uuid,
        evidence: Evidence,
    ) -> Result<MessageState, Rejection> {
        if !self.writer_available {
            return Err(Rejection::WriterUnavailable);
        }
        if matches!(evidence, Evidence::Cancel | Evidence::Expire)
            && self.grants.contains_key(&message_id)
        {
            return Err(Rejection::GrantAlreadyIssued);
        }
        let state = self
            .messages
            .get(&message_id)
            .ok_or(Rejection::InvalidState)?;
        let next = state.apply(evidence).map_err(|_| Rejection::InvalidState)?;
        self.messages.insert(message_id, next);
        if evidence == Evidence::ProvenNoSubmit {
            self.grants.remove(&message_id);
        }
        Ok(next)
    }

    pub fn state(&self, message_id: Uuid) -> Option<MessageState> {
        self.messages.get(&message_id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn ambiguous_submit_is_unknown_and_cannot_be_regranted() {
        let mut authority = Authority::new(7);
        let message = authority.accept(id(1), "key", "digest", id(2)).unwrap();
        let session = authority.connect(id(3), "a", "hub-a", 0, 60).unwrap();
        authority
            .grant(&session, message, id(4), 1, "recipient-hash", 0, 100)
            .unwrap();
        authority
            .event(message, Evidence::DurableSubmitIntent)
            .unwrap();
        assert_eq!(
            authority.event(message, Evidence::CrashWithoutCallback),
            Ok(MessageState::Unknown)
        );
        let new_session = authority.connect(id(3), "b", "hub-b", 10, 60).unwrap();
        assert_eq!(
            authority.grant(&new_session, message, id(5), 2, "recipient-hash", 10, 100),
            Err(Rejection::GrantAlreadyIssued)
        );
        assert_eq!(authority.state(message), Some(MessageState::Unknown));
    }

    #[test]
    fn callback_after_unknown_reconciles_without_retry() {
        let state = MessageState::Submitting
            .apply(Evidence::CrashWithoutCallback)
            .unwrap();
        let state = state.apply(Evidence::SentCallbackOk).unwrap();
        assert_eq!(state, MessageState::Submitted);
        assert_eq!(
            state.apply(Evidence::DeliveryTimeout),
            Ok(MessageState::DeliveryUnknown)
        );
    }

    #[test]
    fn contradictory_callback_retracts_delivery_claim_without_retry() {
        assert_eq!(
            MessageState::Delivered.apply(Evidence::CallbackConflict),
            Ok(MessageState::Unknown)
        );
        assert_eq!(
            MessageState::Failed.apply(Evidence::CallbackConflict),
            Ok(MessageState::Unknown)
        );
        assert!(MessageState::Unknown.apply(Evidence::Claim).is_err());
        assert!(
            MessageState::Claimed
                .apply(Evidence::CallbackConflict)
                .is_err()
        );
    }

    #[test]
    fn pre_submit_evidence_can_requeue() {
        assert_eq!(
            MessageState::Claimed.apply(Evidence::ProvenNoSubmit),
            Ok(MessageState::Queued)
        );
        assert!(
            MessageState::Submitting
                .apply(Evidence::ProvenNoSubmit)
                .is_err()
        );
    }

    #[test]
    fn one_device_cannot_hold_two_active_grants_and_proven_no_submit_releases_it() {
        let mut authority = Authority::new(1);
        authority.accept(id(1), "a", "body-a", id(2)).unwrap();
        authority.accept(id(1), "b", "body-b", id(5)).unwrap();
        let session = authority.connect(id(3), "a", "hub-a", 0, 60).unwrap();
        authority
            .grant(&session, id(2), id(4), 1, "r1", 0, 100)
            .unwrap();
        assert_eq!(
            authority.grant(&session, id(5), id(6), 1, "r2", 0, 100),
            Err(Rejection::DeviceBusy)
        );
        authority.event(id(2), Evidence::ProvenNoSubmit).unwrap();
        assert!(
            authority
                .grant(&session, id(5), id(6), 1, "r2", 0, 100)
                .is_ok()
        );
    }

    #[test]
    fn session_epoch_and_writer_fence_both_hubs() {
        let mut authority = Authority::new(9);
        authority.accept(id(1), "key", "digest", id(2)).unwrap();
        let old = authority.connect(id(3), "a", "hub-a", 0, 60).unwrap();
        let current = authority.connect(id(3), "b", "hub-b", 1, 60).unwrap();
        assert_eq!(
            authority.grant(&old, id(2), id(4), 1, "r", 2, 100),
            Err(Rejection::SessionStale)
        );
        authority.writer_available = false;
        assert_eq!(
            authority.grant(&current, id(2), id(4), 1, "r", 2, 100),
            Err(Rejection::WriterUnavailable)
        );
        authority.writer_available = true;
        assert!(
            authority
                .grant(&current, id(2), id(4), 1, "r", 2, 100)
                .is_ok()
        );
    }

    #[test]
    fn idempotency_is_global_per_account_and_rejects_changed_body() {
        let mut authority = Authority::new(1);
        assert_eq!(authority.accept(id(1), "key", "body-a", id(2)), Ok(id(2)));
        assert_eq!(authority.accept(id(1), "key", "body-a", id(99)), Ok(id(2)));
        assert_eq!(
            authority.accept(id(1), "key", "body-b", id(99)),
            Err(Rejection::DuplicateKeyDifferentRequest)
        );
        assert_eq!(authority.accept(id(3), "key", "body-b", id(99)), Ok(id(99)));
    }

    #[test]
    fn submitted_is_not_delivered() {
        let state = MessageState::Submitting
            .apply(Evidence::SentCallbackOk)
            .unwrap();
        assert_eq!(state, MessageState::Submitted);
        assert_ne!(state, MessageState::Delivered);
        assert!(state.apply(Evidence::Claim).is_err());
    }

    #[test]
    fn multipart_partial_result_is_ambiguous_and_not_retryable() {
        let state = MessageState::Submitting
            .apply(Evidence::PartialSentCallbacks)
            .unwrap();
        assert_eq!(state, MessageState::Unknown);
        assert!(state.apply(Evidence::Claim).is_err());
    }

    #[test]
    fn claimed_can_cancel_only_before_grant() {
        assert_eq!(
            MessageState::Claimed.apply(Evidence::Cancel),
            Ok(MessageState::Cancelled)
        );
        let mut authority = Authority::new(1);
        authority.accept(id(1), "key", "digest", id(2)).unwrap();
        let session = authority.connect(id(3), "a", "hub", 0, 60).unwrap();
        authority
            .grant(&session, id(2), id(4), 1, "r", 0, 100)
            .unwrap();
        assert_eq!(
            authority.event(id(2), Evidence::Cancel),
            Err(Rejection::GrantAlreadyIssued)
        );
    }
}
