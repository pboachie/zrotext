// SPDX-License-Identifier: AGPL-3.0-only
//! Closed public metadata/requests. Cookie candidates and private locators are
//! never DTO fields. Deserializing a request supplies no authenticated context.
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Version1;
impl Serialize for Version1 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(1)
    }
}
impl<'de> Deserialize<'de> for Version1 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if u8::deserialize(d)? == 1 {
            Ok(Self)
        } else {
            Err(D::Error::custom("version"))
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Decimal(pub u64);
impl Serialize for Decimal {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Decimal {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        let n = raw
            .parse::<u64>()
            .map_err(|_| D::Error::custom("decimal"))?;
        if n == 0 || n > i64::MAX as u64 || n.to_string() != raw {
            return Err(D::Error::custom("decimal"));
        }
        Ok(Self(n))
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RequestUuid(pub Uuid);
impl Serialize for RequestUuid {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for RequestUuid {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        let value = Uuid::parse_str(&raw).map_err(|_| D::Error::custom("uuid"))?;
        if value.is_nil() || value.to_string() != raw {
            return Err(D::Error::custom("uuid"));
        }
        Ok(Self(value))
    }
}

// No Debug or Serialize; password remains a bounded owned/zeroizing HTTP input.
pub struct Password(pub(crate) Zeroizing<String>);
impl<'de> Deserialize<'de> for Password {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = Zeroizing::new(String::deserialize(d)?);
        if raw.is_empty() || raw.len() > 1024 {
            return Err(D::Error::custom("password bounds"));
        }
        Ok(Self(raw))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestIdentity {
    pub version: Version1,
    pub request_id: RequestUuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedIdentity {
    pub version: Version1,
    pub request_id: RequestUuid,
    pub preparation_id: RequestUuid,
    pub generation: Decimal,
}
#[derive(Deserialize)]
#[serde(untagged)]
pub enum PreparationStatusRequest {
    Exact(PreparedIdentity),
    HeldStaging(RequestIdentity),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    pub version: Version1,
    pub request_id: RequestUuid,
    pub preparation_id: RequestUuid,
    pub generation: Decimal,
    pub alias: String,
    pub password: Password,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserConfirmRequest {
    pub version: Version1,
    pub request_id: RequestUuid,
    pub browser_context_commitment_b64: String,
}
#[derive(Serialize)]
pub struct BrowserContext {
    pub version: Version1,
    pub request_id: Uuid,
    pub browser_context_commitment_b64: String,
    pub issued_ms: Decimal,
    pub expires_ms: Decimal,
    pub server_now_ms: Decimal,
    pub outstanding: Option<OperationResponse>,
    pub owner_session_issued: bool,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrepareOperation {
    InitialBootstrap {
        alias: String,
    },
    BrokerForResume {
        alias: String,
    },
    RootIssue {
        root_pin_b64: String,
        independently_compared_fingerprint_b64: String,
        encrypted_backup_b64: String,
        public_card_b64: String,
    },
    RootComplete {
        root_challenge_id: RequestUuid,
        reauth_challenge_id: RequestUuid,
        reauth_nonce_b64: String,
        unsigned_enrollment_b64: String,
        enrollment_signature_b64: String,
        custody_signature_b64: String,
        independently_compared_fingerprint_b64: String,
        encrypted_backup_b64: String,
        public_card_b64: String,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequest {
    pub version: Version1,
    pub request_id: RequestUuid,
    pub operation: PrepareOperation,
}
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Prepared,
    Confirmed,
    BusyUnknown,
    CancelledNoEffect,
    RejectedNoEffect,
    CommittedKnown,
    Unavailable,
}
#[derive(Serialize)]
pub struct OperationResponse {
    pub version: Version1,
    pub request_id: Uuid,
    pub preparation_id: Uuid,
    pub generation: Decimal,
    pub state: OperationState,
    pub create_deadline_ms: Decimal,
    pub delivery_deadline_ms: Decimal,
    pub server_now_ms: Decimal,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    BootstrapSession,
    RootIssue,
    RootComplete,
    RootReceipt,
    RootCustodyExport,
}

/// Guidance from actual current fenced rows. Pending/history never permits
/// fresh Create; issue/complete must independently recheck the same invariant.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RootState {
    NoRootHistory,
    PendingEnrollment {
        challenge_id: Uuid,
        root_pin_b64: String,
        root_fingerprint_b64: String,
        encrypted_backup_sha256_b64: String,
        public_card_sha256_b64: String,
        unsigned_enrollment_sha256_b64: String,
        custody_statement_sha256_b64: String,
        expires_ms: Decimal,
    },
    Enrolled {
        root_pin_b64: String,
        root_fingerprint_b64: String,
        generation: Decimal,
    },
    History,
    Unavailable,
}

/// Response-only metadata: cannot be deserialized into an authenticated owner.
#[derive(Serialize)]
pub struct TypedSessionContext {
    pub version: Version1,
    pub request_id: Uuid,
    pub realm: Uuid,
    pub database_commitment_b64: String,
    pub config_digest_b64: String,
    pub config_revision: Decimal,
    pub origin: String,
    pub account: Uuid,
    pub owner_user: Uuid,
    pub review_owner_session: Uuid,
    pub broker_principal: Uuid,
    pub credential_id: Uuid,
    pub credential_revision: Decimal,
    pub broker_session: Uuid,
    pub auth_event: Uuid,
    pub issued_ms: Decimal,
    pub absolute_expiry_ms: Decimal,
    pub idle_deadline_ms: Decimal,
    pub server_now_ms: Decimal,
    pub capabilities: [Capability; 5],
    pub locator_retained: bool,
    pub root_state: RootState,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootIssueRequest {
    pub version: Version1,
    pub request_id: RequestUuid,
    pub preparation_id: RequestUuid,
    pub generation: Decimal,
    pub root_pin_b64: String,
    pub independently_compared_fingerprint_b64: String,
    pub encrypted_backup_b64: String,
    pub public_card_b64: String,
}
#[derive(Serialize)]
pub struct RootIssueResponse {
    pub version: Version1,
    pub request_id: Uuid,
    pub preparation_id: Uuid,
    pub generation: Decimal,
    pub root_challenge_id: Uuid,
    pub reauth_challenge_id: Uuid,
    pub reauth_nonce_b64: String,
    pub unsigned_enrollment_b64: String,
    pub custody_statement_b64: String,
    pub root_pin_b64: String,
    pub request_commitment_b64: String,
    pub expires_ms: Decimal,
    pub server_now_ms: Decimal,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCompleteRequest {
    pub version: Version1,
    pub request_id: RequestUuid,
    pub preparation_id: RequestUuid,
    pub generation: Decimal,
    pub root_challenge_id: RequestUuid,
    pub reauth_challenge_id: RequestUuid,
    pub reauth_nonce_b64: String,
    pub unsigned_enrollment_b64: String,
    pub enrollment_signature_b64: String,
    pub custody_signature_b64: String,
    pub independently_compared_fingerprint_b64: String,
    pub encrypted_backup_b64: String,
    pub public_card_b64: String,
    pub password: Password,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootReadRequest {
    pub version: Version1,
    pub request_id: RequestUuid,
    pub independently_compared_fingerprint_b64: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocatorRetentionRequest {
    pub version: Version1,
    pub request_id: RequestUuid,
    pub preparation_id: RequestUuid,
    /// SHA256 of the exact canonical ASCII selector cookie value, not the
    /// locator or a public card. Native sends this only after private readback.
    pub selector_cookie_sha256_b64: String,
}
#[derive(Serialize)]
pub struct LocatorRetentionResponse {
    pub version: Version1,
    pub request_id: Uuid,
    pub preparation_id: Uuid,
    pub selector_cookie_sha256_b64: String,
    pub retained: bool,
}
#[derive(Serialize)]
pub struct RootReceipt {
    pub version: Version1,
    pub request_id: Uuid,
    pub account: Uuid,
    pub actor_owner_user: Uuid,
    pub actor_review_owner_session: Uuid,
    pub root_challenge_id: Uuid,
    pub root_pin_b64: String,
    pub root_fingerprint_b64: String,
    pub completed_ms: Decimal,
    pub server_now_ms: Decimal,
}
#[derive(Serialize)]
pub struct RootCustodyExport {
    pub version: Version1,
    pub request_id: Uuid,
    pub account: Uuid,
    pub root_challenge_id: Uuid,
    pub backup_id: Uuid,
    pub generation: Decimal,
    pub root_pin_b64: String,
    pub root_fingerprint_b64: String,
    pub encrypted_backup_b64: String,
    pub public_card_b64: String,
    pub unsigned_enrollment_b64: String,
    pub custody_signature_b64: String,
    pub committed_ms: Decimal,
    pub server_now_ms: Decimal,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_request_scalars_refuse_coercion_and_unknown_fields() {
        for raw in ["1", "\"01\"", "\"0\"", "\"-1\"", "\"9223372036854775808\""] {
            assert!(serde_json::from_str::<Decimal>(raw).is_err());
        }
        let id = Uuid::new_v4().to_string();
        assert!(
            serde_json::from_str::<RequestUuid>(&format!("\"{}\"", id.replace('-', ""))).is_err()
        );
        assert!(serde_json::from_str::<PreparedIdentity>(&format!(r#"{{"version":1,"request_id":"{id}","preparation_id":"{id}","generation":"1","authority":true}}"#)).is_err());
        assert!(serde_json::from_str::<Version1>("\"1\"").is_err());
        assert!(
            serde_json::from_str::<Password>(&serde_json::to_string(&"x".repeat(1025)).unwrap())
                .is_err()
        );
    }
}
