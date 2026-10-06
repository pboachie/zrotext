// SPDX-License-Identifier: AGPL-3.0-only
//! Complete provider metadata ownership; never a phone descriptor or effect permit.
use super::super::ConversationError;
use super::{
    ActionKey, Descriptor,
    descriptor::{decode_digest, identifier},
};
use crate::provider_sms::action_descriptor::ProposedDescriptor;
use serde::Deserialize;
use uuid::Uuid;

/// Index/fence projections remain attached to their complete validated owner.
/// They cannot be converted into the legacy Descriptor or a checked permit.
#[derive(Deserialize)]
pub(crate) struct Common {
    pub account_id: String,
    pub action_id: String,
    pub revision: i64,
    pub line_id: String,
    pub recipient_id: String,
    pub purpose_id: String,
    pub content_ref: String,
    pub content_digest: String,
    pub content_version: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub routine_id: String,
    pub authority_generation: i64,
}

pub(crate) struct ProviderAction {
    proposed: ProposedDescriptor,
    common: Common,
}
impl ProviderAction {
    pub(crate) fn parse(raw: &[u8]) -> Result<Self, ConversationError> {
        let proposed =
            ProposedDescriptor::parse_wire(raw).map_err(|_| ConversationError::Invalid)?;
        Self::validated(proposed)
    }
    fn validated(proposed: ProposedDescriptor) -> Result<Self, ConversationError> {
        // This is a projection of already validated canonical bytes, not ingress
        // normalization. Full ownership/digest always remains with `proposed`.
        let v: serde_json::Value = serde_json::from_slice(&proposed.canonical_wire())
            .map_err(|_| ConversationError::Invalid)?;
        let common =
            serde_json::from_value(v["action"].clone()).map_err(|_| ConversationError::Invalid)?;
        Ok(Self { proposed, common })
    }
    pub(crate) fn proposal(raw: &[u8]) -> Result<(Uuid, Self), ConversationError> {
        let proposed = ProposedDescriptor::parse_owner_proposal_wire(raw)
            .map_err(|_| ConversationError::Invalid)?;
        // Extract request identity only AFTER the protected complete original
        // body parser established all keys, duplicates and canonical equality.
        let v: serde_json::Value =
            serde_json::from_slice(raw).map_err(|_| ConversationError::Invalid)?;
        let request = identifier(v["request_id"].as_str().ok_or(ConversationError::Invalid)?)?;
        Ok((request, Self::validated(proposed)?))
    }
    pub(crate) fn canonical(&self) -> Vec<u8> {
        self.proposed.canonical_wire()
    }
    pub(crate) fn common(&self) -> &Common {
        &self.common
    }
    pub(crate) fn key(&self) -> Result<ActionKey, ConversationError> {
        let key = ActionKey {
            account_id: identifier(&self.common.account_id)?,
            action_id: identifier(&self.common.action_id)?,
            revision: self.common.revision,
            binding_digest: self.proposed.binding_digest(),
        };
        key.validate()?;
        Ok(key)
    }
    pub(crate) fn expires_ms(&self) -> Result<i64, ConversationError> {
        self.common
            .expires_at
            .checked_mul(1000)
            .ok_or(ConversationError::Invalid)
    }
    pub(crate) fn content_digest(&self) -> Result<[u8; 32], ConversationError> {
        decode_digest(&self.common.content_digest)
    }
    pub(crate) fn purpose(&self) -> Result<&'static str, ConversationError> {
        match self.common.purpose_id.as_str() {
            "00000000-0000-0000-0000-000000000001" => Ok("transactional"),
            "00000000-0000-0000-0000-000000000002" => Ok("operational"),
            "00000000-0000-0000-0000-000000000003" => Ok("marketing"),
            _ => Err(ConversationError::Invalid),
        }
    }
}
pub(crate) enum StoredProfile {
    Phone(Descriptor),
    Provider(ProviderAction),
}
impl StoredProfile {
    pub(crate) fn parse(raw: &[u8], key: ActionKey) -> Result<Self, ConversationError> {
        key.validate()?;
        if let Ok(provider) = ProviderAction::parse(raw) {
            if provider.key()? != key {
                return Err(ConversationError::Unavailable);
            }
            return Ok(Self::Provider(provider));
        }
        let phone: Descriptor =
            serde_json::from_slice(raw).map_err(|_| ConversationError::Unavailable)?;
        if phone.key()? != key {
            return Err(ConversationError::Unavailable);
        }
        Ok(Self::Phone(phone))
    }
    pub(crate) fn phone(self) -> Result<Descriptor, ConversationError> {
        match self {
            Self::Phone(d) => Ok(d),
            Self::Provider(_) => Err(ConversationError::Unavailable),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
