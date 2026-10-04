// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub(crate) const HEADS: i64 = 64;
pub(crate) const VERSIONS: i16 = 16;
pub(crate) const MUTATIONS: i64 = 1024;
pub(crate) const BODY: usize = 8192;

pub(crate) fn identity(value: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(value).map_err(|_| ConversationError::Invalid)?;
    if id.is_nil() || id.to_string() != value {
        return Err(ConversationError::Invalid);
    }
    Ok(id)
}
fn text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|b| (33..=126).contains(&b))
}

/// Unverified owner input, not a trusted route or policy. No Debug implementation.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    pub adapter: String,
    pub organization_id: String,
    pub messaging_profile_id: String,
    pub sender: String,
    pub owner_label: String,
    pub intended_region: String,
    pub retention_policy_ref: Option<String>,
    pub eligibility_policy_ref: Option<String>,
    pub cost_policy_ref: Option<String>,
}
impl Declaration {
    pub(crate) fn bytes(&self) -> Result<Vec<u8>> {
        identity(&self.organization_id)?;
        identity(&self.messaging_profile_id)?;
        for id in [
            &self.retention_policy_ref,
            &self.eligibility_policy_ref,
            &self.cost_policy_ref,
        ]
        .into_iter()
        .flatten()
        {
            identity(id)?;
        }
        if self.adapter != "telnyx-sms-v2"
            || !(3..=16).contains(&self.sender.len())
            || !self.sender.starts_with('+')
            || self.sender.as_bytes()[1] == b'0'
            || !self.sender.as_bytes()[1..].iter().all(u8::is_ascii_digit)
            || !text(&self.owner_label)
            || !text(&self.intended_region)
        {
            return Err(ConversationError::Invalid);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| ConversationError::Invalid)?;
        if bytes.len() > BODY {
            return Err(ConversationError::Invalid);
        }
        Ok(bytes)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mutation {
    pub request_id: String,
    pub config_id: String,
    pub expected_record_version: i64,
    pub declaration: Declaration,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Withdrawal {
    pub request_id: String,
    pub config_id: String,
    pub expected_record_version: i64,
}

/// Metadata-only immutable acknowledgment. This never establishes current authority.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Acknowledgment {
    pub config_id: Uuid,
    pub config_version: i16,
    pub record_version: i64,
    pub state: String,
    pub acceptance: &'static str,
}
impl Acknowledgment {
    pub(crate) fn row(row: &tokio_postgres::Row) -> Result<Self> {
        let value = Self {
            config_id: row.try_get(0)?,
            config_version: row.try_get(1)?,
            record_version: row.try_get(2)?,
            state: row.try_get(3)?,
            acceptance: "unavailable",
        };
        if value.config_id.is_nil()
            || !(1..=VERSIONS).contains(&value.config_version)
            || value.record_version < 1
            || !["draft", "withdrawn"].contains(&value.state.as_str())
        {
            return Err(ConversationError::Unavailable);
        }
        Ok(value)
    }
}
#[derive(Serialize)]
pub struct Details {
    #[serde(flatten)]
    pub metadata: Acknowledgment,
    pub declaration: Option<Declaration>,
    pub unavailable_reasons: [&'static str; 4],
}
pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
pub(crate) fn request_digest(
    account: Uuid,
    config: Uuid,
    operation: &str,
    expected: i64,
    bytes: Option<&[u8]>,
) -> Result<[u8; 32]> {
    Ok(digest(
        &serde_json::to_vec(&(account, config, operation, expected, bytes))
            .map_err(|_| ConversationError::Invalid)?,
    ))
}
