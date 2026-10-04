// SPDX-License-Identifier: AGPL-3.0-only
//! Closed owner requests. Every identity is an assertion, never authority.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_CAPACITY: i16 = 100;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub context_id: Uuid,
    pub revision: i64,
    pub digest: String,
}
impl Source {
    pub fn validate(&self) -> bool {
        !self.context_id.is_nil() && (1..=128).contains(&self.revision) && digest(&self.digest)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpeningKey {
    pub opening_id: Uuid,
    pub definition_version: i64,
    pub state_version: i64,
}
impl OpeningKey {
    pub fn validate(self) -> bool {
        !self.opening_id.is_nil() && self.definition_version > 0 && self.state_version > 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferKey {
    pub offer_id: Uuid,
    pub state_version: i64,
}
impl OfferKey {
    pub fn validate(self) -> bool {
        !self.offer_id.is_nil() && self.state_version > 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Transactional,
    Operational,
    Marketing,
}
impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transactional => "transactional",
            Self::Operational => "operational",
            Self::Marketing => "marketing",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    pub request_id: Uuid,
    pub opening_id: Uuid,
    pub capacity: i16,
    pub description: Source,
    pub decision_deadline_ms: i64,
}
impl Create {
    pub fn validate(&self) -> bool {
        !self.request_id.is_nil()
            && !self.opening_id.is_nil()
            && (1..=MAX_CAPACITY).contains(&self.capacity)
            && self.description.validate()
            && self.decision_deadline_ms > 0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub request_id: Uuid,
    pub opening: OpeningKey,
    pub offer_id: Uuid,
    pub contact_id: Uuid,
    pub purpose: Purpose,
    pub source: Source,
    pub expires_ms: i64,
}
impl Offer {
    pub fn validate(&self) -> bool {
        !self.request_id.is_nil()
            && self.opening.validate()
            && !self.offer_id.is_nil()
            && !self.contact_id.is_nil()
            && self.source.validate()
            && self.expires_ms > 0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reserve {
    pub request_id: Uuid,
    pub opening: OpeningKey,
    pub offer: OfferKey,
    pub allocation_id: Uuid,
    pub event_id: Uuid,
    pub event_digest: String,
}
impl Reserve {
    pub fn validate(&self) -> bool {
        !self.request_id.is_nil()
            && self.opening.validate()
            && self.offer.validate()
            && !self.allocation_id.is_nil()
            && !self.event_id.is_nil()
            && digest(&self.event_digest)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationMutation {
    pub request_id: Uuid,
    pub opening: OpeningKey,
    pub allocation_id: Uuid,
    pub allocation_version: i64,
}
impl AllocationMutation {
    pub fn validate(self) -> bool {
        !self.request_id.is_nil()
            && self.opening.validate()
            && !self.allocation_id.is_nil()
            && self.allocation_version > 0
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
        && value.bytes().any(|v| v != b'0')
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpeningMutation {
    pub request_id: Uuid,
    pub opening: OpeningKey,
}
impl OpeningMutation {
    pub fn validate(self) -> bool {
        !self.request_id.is_nil() && self.opening.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_or_model_authority_cannot_enter_a_closed_owner_allocation_request() {
        let request = Reserve {
            request_id: Uuid::new_v4(),
            opening: OpeningKey {
                opening_id: Uuid::new_v4(),
                definition_version: 1,
                state_version: 1,
            },
            offer: OfferKey {
                offer_id: Uuid::new_v4(),
                state_version: 1,
            },
            allocation_id: Uuid::new_v4(),
            event_id: Uuid::new_v4(),
            event_digest: "ab".repeat(32),
        };
        assert!(request.validate());
        for field in [
            "account_id",
            "owner_id",
            "action_key",
            "delivered",
            "accepted",
            "model_approved",
        ] {
            let mut forged = serde_json::to_value(&request).unwrap();
            forged
                .as_object_mut()
                .unwrap()
                .insert(field.into(), serde_json::json!(true));
            assert!(serde_json::from_value::<Reserve>(forged).is_err());
        }
    }

    #[test]
    fn source_identity_and_capacity_refuse_aliases_and_unbounded_values() {
        let mut source = Source {
            context_id: Uuid::new_v4(),
            revision: 1,
            digest: "ab".repeat(32),
        };
        assert!(source.validate());
        source.digest = "AB".repeat(32);
        assert!(!source.validate());
        source.digest = "00".repeat(32);
        assert!(!source.validate());
        source.digest = "ab".repeat(32);
        source.revision = 129;
        assert!(!source.validate());
        source.revision = 1;
        let mut request = Create {
            request_id: Uuid::new_v4(),
            opening_id: Uuid::new_v4(),
            capacity: 1,
            description: source,
            decision_deadline_ms: 1,
        };
        assert!(request.validate());
        for capacity in [0, -1, MAX_CAPACITY + 1, i16::MAX] {
            request.capacity = capacity;
            assert!(!request.validate());
        }
    }
}
