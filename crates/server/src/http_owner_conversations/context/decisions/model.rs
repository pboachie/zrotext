// SPDX-License-Identifier: AGPL-3.0-only
//! Pure transitions. The durable store supplies independently checked authority.
use super::{super::ConversationError, Descriptor};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Proposed,
    Approved,
    Invalidated,
    Cancelled,
    Expired,
    Dispatching,
    Unknown,
    Succeeded,
    Failed,
}
impl Phase {
    pub fn editable(self) -> bool {
        matches!(self, Self::Proposed | Self::Approved | Self::Invalidated)
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Approved => "approved",
            Self::Invalidated => "invalidated",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Dispatching => "dispatching",
            Self::Unknown => "unknown",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
    pub fn parse(value: &str) -> Result<Self, ConversationError> {
        match value {
            "proposed" => Ok(Self::Proposed),
            "approved" => Ok(Self::Approved),
            "invalidated" => Ok(Self::Invalidated),
            "cancelled" => Ok(Self::Cancelled),
            "expired" => Ok(Self::Expired),
            "dispatching" => Ok(Self::Dispatching),
            "unknown" => Ok(Self::Unknown),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            _ => Err(ConversationError::Unavailable),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Cancel,
}
pub fn decide(phase: Phase, operation: Decision) -> Result<Phase, ConversationError> {
    match (phase, operation) {
        (Phase::Proposed | Phase::Invalidated, Decision::Approve) => Ok(Phase::Approved),
        (value, Decision::Cancel) if value.editable() => Ok(Phase::Cancelled),
        _ => Err(ConversationError::Conflict),
    }
}
pub fn edit(
    previous: &Descriptor,
    next: &Descriptor,
    phase: Phase,
) -> Result<(), ConversationError> {
    if !phase.editable()
        || previous.account_id != next.account_id
        || previous.action_id != next.action_id
        || previous.content_ref != next.content_ref
        || previous.routine_id != next.routine_id
        || previous.revision.checked_add(1) != Some(next.revision)
    {
        return Err(ConversationError::Conflict);
    }
    next.canonical()?;
    let mut unchanged = next.clone();
    unchanged.revision = previous.revision;
    if unchanged == *previous {
        return Err(ConversationError::Conflict);
    }
    Ok(())
}

/// Internal full-profile edit; no projection or cross-profile relabelling.
pub(crate) fn edit_provider(
    previous: &super::action_profile::ProviderAction,
    next: &super::action_profile::ProviderAction,
    phase: Phase,
) -> Result<(), ConversationError> {
    let old = previous.common();
    let new = next.common();
    if !phase.editable()
        || old.account_id != new.account_id
        || old.action_id != new.action_id
        || old.content_ref != new.content_ref
        || old.routine_id != new.routine_id
        || old.revision.checked_add(1) != Some(new.revision)
    {
        return Err(ConversationError::Conflict);
    }
    let before: serde_json::Value =
        serde_json::from_slice(&previous.canonical()).map_err(|_| ConversationError::Invalid)?;
    let mut after: serde_json::Value =
        serde_json::from_slice(&next.canonical()).map_err(|_| ConversationError::Invalid)?;
    after["action"]["revision"] = before["action"]["revision"].clone();
    if before == after {
        return Err(ConversationError::Conflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn silence_receipts_uncertainty_and_irreversible_phases_cannot_approve_or_cancel() {
        for phase in [
            Phase::Dispatching,
            Phase::Unknown,
            Phase::Succeeded,
            Phase::Failed,
            Phase::Cancelled,
            Phase::Expired,
        ] {
            assert!(decide(phase, Decision::Approve).is_err());
            assert!(decide(phase, Decision::Cancel).is_err());
        }
        assert!(decide(Phase::Approved, Decision::Approve).is_err());
        assert_eq!(
            decide(Phase::Proposed, Decision::Approve).unwrap(),
            Phase::Approved
        );
        assert_eq!(
            decide(Phase::Invalidated, Decision::Approve).unwrap(),
            Phase::Approved
        );
    }
}
