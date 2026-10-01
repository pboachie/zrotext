// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit integration scopes for the shared, dormant workflow service.
//! Computing a descriptor or naming a scope never authorizes an operation.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

mod authentication;
mod contacts;
mod status;
pub use status::read_action_status;
#[cfg(test)]
mod database_tests;
mod grants;
pub(crate) mod lifecycle;
mod reads;
mod scope;
pub use authentication::{IntegrationPrincipal, authenticate};
pub use contacts::{ContactScope, read_contact};
pub use grants::{GrantRequest, IssuedCredential, issue_grant, revoke_grant};
pub use reads::{read_context_content, read_context_metadata};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    ContactRead,
    ContextMetadata,
    ContextContent,
    Propose,
    Status,
    Schedule,
    Send,
}
impl Operation {
    pub(crate) fn bit(self) -> i16 {
        match self {
            Self::ContactRead => 1,
            Self::ContextMetadata => 2,
            Self::ContextContent => 4,
            Self::Propose => 8,
            Self::Status => 16,
            Self::Schedule => 32,
            Self::Send => 64,
        }
    }
}

/// Owner-requested permissions. Approval and takeover are owner operations,
/// so neither exists in this integration permission vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions(i16);
impl Permissions {
    pub fn new(operations: &[Operation]) -> Result<Self, &'static str> {
        let mut bits = 0;
        for operation in operations {
            let bit = operation.bit();
            if bits & bit != 0 {
                return Err("duplicate workflow permission");
            }
            bits |= bit;
        }
        if bits == 0 {
            return Err("empty workflow permissions");
        }
        Ok(Self(bits))
    }
    pub fn allows(self, operation: Operation) -> bool {
        self.0 & operation.bit() != 0
    }
    pub fn bits(self) -> i16 {
        self.0
    }
    pub fn from_stored(bits: i16) -> Result<Self, &'static str> {
        if !(1..=127).contains(&bits) {
            return Err("invalid stored workflow permissions");
        }
        Ok(Self(bits))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Transactional,
    Operational,
    Marketing,
}
impl Purpose {
    /// Closed mapping for the existing exact-action purpose identity. These
    /// ids do not themselves constitute a contact consent or permission.
    pub fn action_id(self) -> Uuid {
        Uuid::from_u128(match self {
            Self::Transactional => 1,
            Self::Operational => 2,
            Self::Marketing => 3,
        })
    }
    pub fn slug(self) -> &'static str {
        match self {
            Self::Transactional => "transactional",
            Self::Operational => "operational",
            Self::Marketing => "marketing",
        }
    }
    pub fn from_action_id(id: Uuid) -> Result<Self, &'static str> {
        match id.as_u128() {
            1 => Ok(Self::Transactional),
            2 => Ok(Self::Operational),
            3 => Ok(Self::Marketing),
            _ => Err("unknown workflow purpose"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_integration_permission_remains_independent() {
        let operations = [
            Operation::ContactRead,
            Operation::ContextMetadata,
            Operation::ContextContent,
            Operation::Propose,
            Operation::Status,
            Operation::Schedule,
            Operation::Send,
        ];
        for allowed in operations {
            let permissions = Permissions::new(&[allowed]).unwrap();
            for operation in operations {
                assert_eq!(permissions.allows(operation), operation == allowed);
            }
        }
        assert!(Permissions::new(&[]).is_err());
        assert!(Permissions::new(&[Operation::Send, Operation::Send]).is_err());
        for invalid in [-1, 0, 128, i16::MAX] {
            assert!(Permissions::from_stored(invalid).is_err());
        }
        assert_eq!(Permissions::from_stored(127).unwrap().bits(), 127);
        assert!(serde_json::from_str::<Operation>("\"approve\"").is_err());
        assert!(serde_json::from_str::<Operation>("\"takeover\"").is_err());
    }

    #[test]
    fn purpose_identity_names_only_existing_consent_classes() {
        for purpose in [
            Purpose::Transactional,
            Purpose::Operational,
            Purpose::Marketing,
        ] {
            assert_eq!(
                Purpose::from_action_id(purpose.action_id()).unwrap(),
                purpose
            );
            assert_eq!(serde_json::to_value(purpose).unwrap(), purpose.slug());
        }
        assert!(Purpose::from_action_id(Uuid::nil()).is_err());
        assert!(Purpose::from_action_id(Uuid::from_u128(4)).is_err());
        assert!(Purpose::from_action_id(Uuid::new_v4()).is_err());
    }
}
