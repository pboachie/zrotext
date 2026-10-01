// SPDX-License-Identifier: AGPL-3.0-only
use super::super::ConversationError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Precisely the normative workflow-action-01 fields; no caller-selected subset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
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
    pub timezone: String,
    pub window_id: String,
    pub routine_id: String,
    pub authority_generation: i64,
    pub commitment: String,
}

impl Descriptor {
    pub fn canonical(&self) -> Result<Vec<u8>, ConversationError> {
        for value in [
            &self.account_id,
            &self.action_id,
            &self.line_id,
            &self.recipient_id,
            &self.purpose_id,
            &self.content_ref,
            &self.content_digest,
            &self.timezone,
            &self.window_id,
            &self.routine_id,
            &self.commitment,
        ] {
            if value.is_empty() || value.len() > 128 || !value.is_ascii() {
                return Err(ConversationError::Invalid);
            }
        }
        if self.revision < 1
            || self.content_version < 1
            || self.authority_generation < 1
            || self.not_before < 0
            || self.not_before >= self.expires_at
            || !matches!(self.commitment.as_str(), "informational" | "sensitive")
        {
            return Err(ConversationError::Invalid);
        }
        decode_digest(&self.content_digest)?;
        let fields: BTreeMap<String, serde_json::Value> = serde_json::from_value(
            serde_json::to_value(self).map_err(|_| ConversationError::Invalid)?,
        )
        .map_err(|_| ConversationError::Invalid)?;
        let json = serde_json::to_vec(&fields).map_err(|_| ConversationError::Invalid)?;
        // Python's normative ensure_ascii=True also escapes ASCII DEL.
        let mut bytes = Vec::with_capacity(json.len());
        for value in json {
            if value == 127 {
                bytes.extend_from_slice(b"\\u007f");
            } else {
                bytes.push(value);
            }
        }
        Ok(bytes)
    }
    pub fn digest(&self) -> Result<[u8; 32], ConversationError> {
        Ok(Sha256::digest(self.canonical()?).into())
    }
    pub fn key(&self) -> Result<ActionKey, ConversationError> {
        Ok(ActionKey {
            account_id: identifier(&self.account_id)?,
            action_id: identifier(&self.action_id)?,
            revision: self.revision,
            binding_digest: self.digest()?,
        })
    }
    pub fn expires_at_ms(&self) -> Result<i64, ConversationError> {
        self.expires_at
            .checked_mul(1000)
            .ok_or(ConversationError::Invalid)
    }
    /// Production identities have one UUID encoding, unlike synthetic vector names.
    pub fn identities(&self) -> Result<Identities, ConversationError> {
        self.key()?;
        if self.revision > 128
            || self.content_version > 128
            || !matches!(
                self.purpose_id.as_str(),
                "transactional" | "operational" | "marketing"
            )
            || self.timezone.bytes().any(|c| c < 33 || c == 127)
            || self.timezone == "unknown"
        {
            return Err(ConversationError::Invalid);
        }
        self.expires_at_ms()?;
        self.not_before
            .checked_mul(1000)
            .ok_or(ConversationError::Invalid)?;
        Ok(Identities {
            line: identifier(&self.line_id)?,
            recipient: identifier(&self.recipient_id)?,
            content: identifier(&self.content_ref)?,
            routine: identifier(&self.routine_id)?,
        })
    }
}
/// Parsed routing identities only; these values confer no checked authority.
pub struct Identities {
    pub line: Uuid,
    pub recipient: Uuid,
    pub content: Uuid,
    pub routine: Uuid,
}
pub(crate) fn identifier(value: &str) -> Result<Uuid, ConversationError> {
    let id = Uuid::parse_str(value).map_err(|_| ConversationError::Invalid)?;
    if id.is_nil() || id.to_string() != value {
        return Err(ConversationError::Invalid);
    }
    Ok(id)
}
pub fn decode_digest(value: &str) -> Result<[u8; 32], ConversationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(ConversationError::Invalid);
    }
    let mut digest = [0; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)
            .map_err(|_| ConversationError::Invalid)?;
    }
    Ok(digest)
}
pub fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionKey {
    pub account_id: Uuid,
    pub action_id: Uuid,
    pub revision: i64,
    pub binding_digest: [u8; 32],
}
impl ActionKey {
    pub fn validate(&self) -> Result<(), ConversationError> {
        if self.account_id.is_nil()
            || self.action_id.is_nil()
            || !(1..=128).contains(&self.revision)
        {
            return Err(ConversationError::Invalid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
