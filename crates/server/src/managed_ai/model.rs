// SPDX-License-Identifier: AGPL-3.0-only
use super::Error;
use crate::workflow_runtime::Purpose;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    WorkflowContextV1,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub kind: SourceKind,
    pub id: Uuid,
    pub version: i64,
    pub digest: [u8; 32],
}

/// Immutable service policy identity pins its reader, provider and budget policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyIdentity {
    pub id: Uuid,
    pub version: i64,
    pub digest: [u8; 32],
    pub reader: Uuid,
    pub reader_generation: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub policy: PolicyIdentity,
    pub contact: Uuid,
    pub purpose: Purpose,
    /// Public commitment to instructions. No instructions or plaintext stored here.
    pub instruction_digest: [u8; 32],
    pub expires_ms: i64,
    pub max_calls: i64,
    pub max_input_bytes: i64,
    pub max_cost_microunits: i64,
    pub selections: Vec<Selection>,
}
impl GrantRequest {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if [self.policy.id, self.policy.reader, self.contact]
            .iter()
            .any(Uuid::is_nil)
            || self.policy.version <= 0
            || self.policy.reader_generation <= 0
            || self.policy.digest == [0; 32]
            || self.instruction_digest == [0; 32]
            || self.expires_ms <= 0
            || self.max_calls < 0
            || self.max_input_bytes < 0
            || self.max_cost_microunits < 0
            || self.selections.len() > 32
            || self
                .selections
                .iter()
                .any(|s| s.id.is_nil() || !(1..=128).contains(&s.version) || s.digest == [0; 32])
            || self.selections.windows(2).any(|w| w[0] >= w[1])
            || self.selections.windows(2).any(|w| w[0].id == w[1].id)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    /// No authority freshness here: reduction must work after expiry or purge.
    pub(crate) fn narrows(&self, old: &Self) -> bool {
        self.policy == old.policy
            && self.contact == old.contact
            && self.purpose == old.purpose
            && self.instruction_digest == old.instruction_digest
            && self.expires_ms <= old.expires_ms
            && self.max_calls <= old.max_calls
            && self.max_input_bytes <= old.max_input_bytes
            && self.max_cost_microunits <= old.max_cost_microunits
            && self
                .selections
                .iter()
                .all(|s| old.selections.binary_search(s).is_ok())
    }
}
