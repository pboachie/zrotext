// SPDX-License-Identifier: AGPL-3.0-only
use super::contracts::{OfferKey, OpeningKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Closed metadata receipt. It never echoes source/contact/response bodies or
/// permission DTOs, so the request ledger does not become a content store.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub opening: OpeningKey,
    pub offer: Option<OfferKey>,
    pub allocation_id: Option<Uuid>,
    pub allocation_version: Option<i64>,
    pub phase: String,
    pub pending: i64,
    pub confirmed: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub receipt: Receipt,
    /// False for historical replay or an already-terminal status observation.
    pub applied: bool,
    /// A terminal no-op adds no journal row and reserves no mutation nonce.
    pub recorded: bool,
}

#[derive(Default, Clone, Copy, Debug, Serialize)]
pub(crate) struct ClosureCounts {
    pub(crate) openings: i64,
    pub(crate) offers: i64,
    pub(crate) pending_allocations: i64,
    pub(crate) preserved_confirmed: i64,
}

/// Overflow stops increasing authority. An irreversible terminal reduction is
/// still possible at MAX without evaluating MAX+1 or resetting the version.
pub(crate) fn next_version(version: i64, reducing: bool) -> Option<i64> {
    if version <= 0 {
        return None;
    }
    version
        .checked_add(1)
        .or_else(|| reducing.then_some(version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saturated_version_never_blocks_reduction_or_authorizes_an_increase() {
        assert_eq!(next_version(i64::MAX, false), None);
        assert_eq!(next_version(i64::MAX, true), Some(i64::MAX));
        assert_eq!(next_version(1, false), Some(2));
        assert_eq!(next_version(0, true), None);
    }

    #[test]
    fn receipt_refuses_deleted_authority_payload_instead_of_echoing_it() {
        let receipt = Receipt {
            opening: OpeningKey {
                opening_id: Uuid::new_v4(),
                definition_version: 1,
                state_version: 1,
            },
            offer: None,
            allocation_id: None,
            allocation_version: None,
            phase: "closed".into(),
            pending: 0,
            confirmed: 1,
        };
        let mut forged = serde_json::to_value(receipt).unwrap();
        forged
            .as_object_mut()
            .unwrap()
            .insert("context_digest".into(), serde_json::json!("ab".repeat(32)));
        assert!(serde_json::from_value::<Receipt>(forged).is_err());
    }
}
