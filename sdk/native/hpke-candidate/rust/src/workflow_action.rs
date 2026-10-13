//! Exact workflow-action-01 bytes. Computing a digest grants no authority.
use crate::original_http::HttpError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Fields {
    account_id: String,
    action_id: String,
    #[serde(deserialize_with = "integer")]
    authority_generation: u64,
    commitment: String,
    content_digest: String,
    content_ref: String,
    #[serde(deserialize_with = "integer")]
    content_version: u64,
    #[serde(deserialize_with = "integer")]
    expires_at: u64,
    line_id: String,
    #[serde(deserialize_with = "integer")]
    not_before: u64,
    purpose_id: String,
    recipient_id: String,
    #[serde(deserialize_with = "integer")]
    revision: u64,
    routine_id: String,
    timezone: String,
    window_id: String,
}
fn integer<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let n = serde_json::Number::deserialize(d)?
        .as_f64()
        .ok_or_else(|| serde::de::Error::custom("invalid integer"))?;
    if !n.is_finite() || !(0.0..=9007199254740991.0).contains(&n) || n.fract() != 0.0 {
        return Err(serde::de::Error::custom("invalid integer"));
    }
    Ok(n as u64)
}
pub struct WorkflowAction {
    canonical: Vec<u8>,
    fields: Fields,
}
impl WorkflowAction {
    pub fn parse(raw: &[u8]) -> Result<Self, HttpError> {
        let bad = HttpError::Unavailable;
        if raw.len() > 4096 {
            return Err(bad);
        }
        let f: Fields = serde_json::from_slice(raw).map_err(|_| bad)?;
        let strings = [
            &f.account_id,
            &f.action_id,
            &f.commitment,
            &f.content_digest,
            &f.content_ref,
            &f.line_id,
            &f.purpose_id,
            &f.recipient_id,
            &f.routine_id,
            &f.timezone,
            &f.window_id,
        ];
        if strings
            .iter()
            .any(|s| s.is_empty() || s.len() > 128 || !s.is_ascii())
            || [
                f.authority_generation,
                f.content_version,
                f.expires_at,
                f.revision,
            ]
            .iter()
            .any(|n| !(1..=9007199254740991).contains(n))
            || f.not_before >= f.expires_at
            || f.content_digest.len() != 64
            || !f
                .content_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !matches!(f.commitment.as_str(), "informational" | "sensitive")
        {
            return Err(bad);
        }
        let canonical = serde_json::to_string(&f)
            .map_err(|_| bad)?
            .replace('\u{7f}', "\\u007f")
            .into_bytes();
        Ok(Self {
            canonical,
            fields: f,
        })
    }
    pub fn canonical(&self) -> Vec<u8> {
        self.canonical.clone()
    }
    pub fn digest(&self) -> String {
        Sha256::digest(&self.canonical)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    pub(crate) fn production(&self) -> bool {
        let f = &self.fields;
        [
            &f.account_id,
            &f.action_id,
            &f.line_id,
            &f.recipient_id,
            &f.purpose_id,
            &f.content_ref,
            &f.routine_id,
        ]
        .iter()
        .all(|s| crate::original_http::uuid(s))
            && f.revision <= 128
    }
    pub(crate) fn account(&self) -> &str {
        &self.fields.account_id
    }
    pub(crate) fn line(&self) -> &str {
        &self.fields.line_id
    }
    pub(crate) fn action(&self) -> &str {
        &self.fields.action_id
    }
    pub(crate) fn revision(&self) -> u64 {
        self.fields.revision
    }
}
