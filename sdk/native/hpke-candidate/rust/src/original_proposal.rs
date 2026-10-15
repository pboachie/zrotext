//! Saved typed proposals, never approval or dispatch authority.
use crate::{
    original_current::{OriginalCurrentClient, VerifiedOriginalCurrent, uuid},
    original_http::{HttpError, Request, output_credential},
    workflow_action::WorkflowAction,
};
use serde::Deserialize;
use serde_json::value::RawValue;
pub struct OriginalProposalIntent {
    record: Vec<u8>,
    action: WorkflowAction,
}
impl OriginalProposalIntent {
    pub fn bytes(&self) -> Vec<u8> {
        self.record.clone()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowActionKey {
    pub account_id: String,
    pub action_id: String,
    pub revision: u64,
    pub binding_digest: String,
}
pub struct OriginalProposalConsumption {
    pub event: [u8; 16],
    pub consumption: [u8; 16],
    pub active_request: [u8; 16],
    pub action: Option<WorkflowActionKey>,
    pub authority: VerifiedOriginalCurrent,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    event_id: String,
    consumption_id: String,
    active_request_id: String,
    disposition: String,
    action: Box<RawValue>,
}
impl OriginalCurrentClient {
    pub fn prepare_proposal(
        &self,
        event: [u8; 16],
        request: [u8; 16],
        active: [u8; 16],
        action: &WorkflowAction,
    ) -> Result<OriginalProposalIntent, HttpError> {
        let mut raw = self
            .prepare_owner_review(event, request, Some(active))?
            .bytes();
        raw[..5].copy_from_slice(b"ZTOP\x01");
        raw.extend(action.canonical());
        self.restore_proposal_intent(&raw)
    }
    pub fn restore_proposal_intent(&self, raw: &[u8]) -> Result<OriginalProposalIntent, HttpError> {
        let bad = HttpError::Unavailable;
        if raw.len() <= 151 || raw.len() > 4096 || &raw[..5] != b"ZTOP\x01" || raw[134] != 1 {
            return Err(bad);
        }
        let mut owner = raw[..151].to_vec();
        owner[..5].copy_from_slice(b"ZTOR\x01");
        self.restore_owner_review_intent(&owner)?;
        let action = WorkflowAction::parse(&raw[151..])?;
        if !action.production()
            || raw[151..] != action.canonical()
            || action.account() != uuid(&self.scope.account)
            || action.line() != uuid(&self.scope.line)
        {
            return Err(bad);
        }
        Ok(OriginalProposalIntent {
            record: raw.to_vec(),
            action,
        })
    }
    /// Caller must sync the exact intent before invoking this single effect attempt.
    pub fn consume_proposal(
        &self,
        grant: &str,
        output: &str,
        intent: &OriginalProposalIntent,
        clock: impl Fn() -> u64,
    ) -> Result<OriginalProposalConsumption, HttpError> {
        self.proposal(grant, Some(output), intent, clock)
    }
    /// Status never resubmits and needs no output credential.
    pub fn status_proposal(
        &self,
        grant: &str,
        intent: &OriginalProposalIntent,
        clock: impl Fn() -> u64,
    ) -> Result<OriginalProposalConsumption, HttpError> {
        self.proposal(grant, None, intent, clock)
    }
    fn proposal(
        &self,
        grant: &str,
        output: Option<&str>,
        intent: &OriginalProposalIntent,
        clock: impl Fn() -> u64,
    ) -> Result<OriginalProposalConsumption, HttpError> {
        let bad = HttpError::Unavailable;
        let effect = output.is_some();
        if output.is_some_and(|s| !output_credential(s)) {
            return Err(bad);
        }
        let saved = self.restore_proposal_intent(&intent.record)?;
        let mut state = self.state.try_lock().map_err(|_| bad)?;
        let before = self.current_locked(grant, &clock, &mut state)?;
        let event: [u8; 16] = saved.record[102..118].try_into().map_err(|_| bad)?;
        let consumption: [u8; 16] = saved.record[118..134].try_into().map_err(|_| bad)?;
        let active_request: [u8; 16] = saved.record[135..151].try_into().map_err(|_| bad)?;
        let request = if effect {
            Request::OwnerReview {
                event_id: uuid(&event),
                request_id: uuid(&consumption),
                active_request_id: Some(uuid(&active_request)),
            }
        } else {
            Request::Status {
                consumption_id: uuid(&consumption),
            }
        };
        let wire = self.transport.exchange_proposal(
            grant,
            before.authority().manifest.version(),
            request,
            if effect { Some(&saved.action) } else { None },
            output,
        )?;
        let fail = if effect { HttpError::Unknown } else { bad };
        let result: Wire = serde_json::from_str(wire.json.get()).map_err(|_| fail)?;
        if result.event_id != uuid(&event)
            || result.consumption_id != uuid(&consumption)
            || result.active_request_id != uuid(&active_request)
        {
            return Err(fail);
        }
        let action: Option<WorkflowActionKey> =
            serde_json::from_str(result.action.get()).map_err(|_| fail)?;
        match (&action, result.disposition.as_str()) {
            (None, "owner_review") => {}
            (Some(key), "proposal")
                if key.account_id == saved.action.account()
                    && key.action_id == saved.action.action()
                    && key.revision == saved.action.revision()
                    && key.binding_digest == saved.action.digest() => {}
            _ => return Err(fail),
        }
        let authority = self
            .current_locked(grant, &clock, &mut state)
            .map_err(|_| fail)?;
        Ok(OriginalProposalConsumption {
            event,
            consumption,
            active_request,
            action,
            authority,
        })
    }
}
