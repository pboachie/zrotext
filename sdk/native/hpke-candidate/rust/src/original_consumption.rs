//! Explicit descriptor-null consumption and exact saved-intent reconciliation.
use crate::{
    original_checkpoint::scope_hash,
    original_current::{OriginalCurrentClient, VerifiedOriginalCurrent, uuid},
    original_http::{HttpError, Request},
};
use serde::Deserialize;
use serde_json::value::RawValue;

/// Caller-persisted immutable owner-review request, never a proposal descriptor.
pub struct OriginalOwnerReviewIntent {
    record: [u8; 151],
}
impl OriginalOwnerReviewIntent {
    pub fn bytes(&self) -> Vec<u8> {
        self.record.to_vec()
    }
}
pub struct OriginalOwnerReviewConsumption {
    pub event: [u8; 16],
    pub consumption: [u8; 16],
    pub active_request: Option<[u8; 16]>,
    pub authority: VerifiedOriginalCurrent,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultWire {
    event_id: String,
    consumption_id: String,
    disposition: String,
    active_request_id: Box<RawValue>,
    action: Box<RawValue>,
}
fn need(v: bool) -> Result<(), HttpError> {
    if v {
        Ok(())
    } else {
        Err(HttpError::Unavailable)
    }
}
impl OriginalCurrentClient {
    /// Parse only the exact persisted format bound to this enrollment and scope.
    pub fn restore_owner_review_intent(
        &self,
        raw: &[u8],
    ) -> Result<OriginalOwnerReviewIntent, HttpError> {
        need(raw.len() == 151)?;
        need(
            &raw[..5] == b"ZTOR\x01"
                && raw[5..70] == self.root_binding
                && raw[70..102] == scope_hash(&self.scope).map_err(|_| HttpError::Unavailable)?,
        )?;
        need(
            raw[102..118] != [0; 16]
                && raw[118..134] != [0; 16]
                && raw[134] <= 1
                && (raw[134] == 0) == (raw[135..] == [0; 16]),
        )?;
        let mut record = [0; 151];
        record.copy_from_slice(raw);
        Ok(OriginalOwnerReviewIntent { record })
    }
    /// No network or persistence. Durably save these bytes before effect dispatch;
    /// the library never generates or replaces the caller's consumption identity.
    pub fn prepare_owner_review(
        &self,
        event: [u8; 16],
        request: [u8; 16],
        active: Option<[u8; 16]>,
    ) -> Result<OriginalOwnerReviewIntent, HttpError> {
        let mut raw = [0; 151];
        raw[..5].copy_from_slice(b"ZTOR\x01");
        raw[5..70].copy_from_slice(&self.root_binding);
        raw[70..102].copy_from_slice(&scope_hash(&self.scope).map_err(|_| HttpError::Unavailable)?);
        raw[102..118].copy_from_slice(&event);
        raw[118..134].copy_from_slice(&request);
        if let Some(active) = active {
            raw[134] = 1;
            raw[135..].copy_from_slice(&active)
        }
        self.restore_owner_review_intent(&raw)
    }
    /// Exactly one owner-review attempt. Unavailable means no consume was dispatched
    /// in this call; it does not establish the saved identity's prior history.
    pub fn consume_owner_review(
        &self,
        grant: &str,
        intent: &OriginalOwnerReviewIntent,
        clock: impl Fn() -> u64,
    ) -> Result<OriginalOwnerReviewConsumption, HttpError> {
        self.owner_review(grant, intent, clock, true)
    }
    /// Reconcile the same saved intent. Never sends consume, including after 404.
    pub fn status_owner_review(
        &self,
        grant: &str,
        intent: &OriginalOwnerReviewIntent,
        clock: impl Fn() -> u64,
    ) -> Result<OriginalOwnerReviewConsumption, HttpError> {
        self.owner_review(grant, intent, clock, false)
    }
    fn owner_review(
        &self,
        grant: &str,
        intent: &OriginalOwnerReviewIntent,
        clock: impl Fn() -> u64,
        effect: bool,
    ) -> Result<OriginalOwnerReviewConsumption, HttpError> {
        let bad = HttpError::Unavailable;
        let saved = self.restore_owner_review_intent(&intent.record)?;
        let mut state = self.state.try_lock().map_err(|_| bad)?;
        let before = self.current_locked(grant, &clock, &mut state)?;
        let event: [u8; 16] = saved.record[102..118].try_into().map_err(|_| bad)?;
        let consumption: [u8; 16] = saved.record[118..134].try_into().map_err(|_| bad)?;
        let active_request = if saved.record[134] == 0 {
            None
        } else {
            Some(saved.record[135..].try_into().map_err(|_| bad)?)
        };
        let request = if effect {
            Request::OwnerReview {
                event_id: uuid(&event),
                request_id: uuid(&consumption),
                active_request_id: active_request.as_ref().map(uuid),
            }
        } else {
            Request::Status {
                consumption_id: uuid(&consumption),
            }
        };
        let wire =
            self.transport
                .exchange(grant, before.authority().manifest.version(), request)?;
        let after_dispatch = if effect { HttpError::Unknown } else { bad };
        let result: ResultWire =
            serde_json::from_str(wire.json.get()).map_err(|_| after_dispatch)?;
        if result.event_id != uuid(&event)
            || result.consumption_id != uuid(&consumption)
            || result.disposition != "owner_review"
            || result.action.get().trim() != "null"
        {
            return Err(after_dispatch);
        }
        let active: Option<String> =
            serde_json::from_str(result.active_request_id.get()).map_err(|_| after_dispatch)?;
        if active != active_request.as_ref().map(uuid) {
            return Err(after_dispatch);
        }
        let authority = self
            .current_locked(grant, &clock, &mut state)
            .map_err(|_| after_dispatch)?;
        Ok(OriginalOwnerReviewConsumption {
            event,
            consumption,
            active_request,
            authority,
        })
    }
}
