// SPDX-License-Identifier: AGPL-3.0-only
//! Exact optional grant/fetch identities. No payload or bearer travels in a URL.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const PROTOCOL: &str = "zrotext-device-status-v2+sealed-dispatch-v1";
pub const PROTOCOL_V2: &str = "zrotext-device-status-v2+sealed-dispatch-v2";
pub const SEGMENT_LIMIT_HEADER: &str = "x-zrotext-sealed-segment-limit";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantFrame {
    pub v: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub grant_version: u8,
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub line_id: Uuid,
    pub message_id: Uuid,
    pub attempt_id: Uuid,
    pub connection_epoch: i64,
    pub deployment_epoch: i64,
    pub binding_generation: i64,
    pub attempt_generation: i64,
    pub reader_role: u8,
    pub reader_key_id: String,
    pub envelope_sha256: String,
    pub unsigned_sha256: String,
    pub expires_at_ms: i64,
    /// Authorized maximum; never an inference about encrypted plaintext.
    pub segment_count: u8,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    pub grant_version: u8,
    pub connection_epoch: i64,
    pub line_id: Uuid,
    pub binding_generation: i64,
    pub reader_key_id: String,
}
impl Ready {
    pub fn validate(&self, epoch: i64) -> Result<[u8; 32], &'static str> {
        if self.grant_version != 1
            || self.connection_epoch != epoch
            || epoch <= 0
            || self.line_id.is_nil()
            || self.binding_generation <= 0
        {
            return Err("sealed negotiation");
        }
        digest(&self.reader_key_id)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fetch {
    pub grant: GrantFrame,
    pub signature_der: String,
}

pub fn digest(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 43 {
        return Err("digest bound");
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "digest encoding")?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err("digest encoding");
    }
    bytes.try_into().map_err(|_| "digest width")
}

/// Device enrollment-key signature binds the complete immutable grant.
pub fn fetch_transcript(grant: &GrantFrame) -> Result<Vec<u8>, &'static str> {
    if grant.v != 1
        || grant.kind != "sealed_execution_grant"
        || grant.grant_version != 1
        || grant.reader_role != 1
        || !(1..=6).contains(&grant.segment_count)
    {
        return Err("grant profile");
    }
    let mut bytes = b"ZT/sealed-envelope-fetch/v1\0".to_vec();
    bytes.extend_from_slice(&[
        grant.v,
        grant.grant_version,
        grant.reader_role,
        grant.segment_count,
    ]);
    for id in [
        grant.account_id,
        grant.device_id,
        grant.line_id,
        grant.message_id,
        grant.attempt_id,
    ] {
        if id.is_nil() {
            return Err("grant identity");
        }
        bytes.extend_from_slice(id.as_bytes());
    }
    for number in [
        grant.connection_epoch,
        grant.deployment_epoch,
        grant.binding_generation,
        grant.attempt_generation,
        grant.expires_at_ms,
    ] {
        if number <= 0 {
            return Err("grant fence");
        }
        bytes.extend_from_slice(&number.to_be_bytes());
    }
    for value in [
        &grant.reader_key_id,
        &grant.envelope_sha256,
        &grant.unsigned_sha256,
    ] {
        bytes.extend_from_slice(&digest(value)?);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> GrantFrame {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../protocol/v1/vectors/sealed-execution-grant-01.json"
        ))
        .unwrap();
        serde_json::from_value(vector["frame"].clone()).unwrap()
    }

    #[test]
    fn fetch_signature_binds_every_grant_identity() {
        let original = grant();
        let transcript = fetch_transcript(&original).unwrap();
        assert!(transcript.starts_with(b"ZT/sealed-envelope-fetch/v1\0"));
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../protocol/v1/vectors/sealed-dispatch-01.json"
        ))
        .unwrap();
        let actual = transcript
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(actual, vector["transcriptHex"].as_str().unwrap());
        for index in 0..15 {
            let mut changed = original.clone();
            match index {
                0 => changed.account_id = Uuid::from_bytes([11; 16]),
                1 => changed.device_id = Uuid::from_bytes([12; 16]),
                2 => changed.line_id = Uuid::from_bytes([13; 16]),
                3 => changed.message_id = Uuid::from_bytes([14; 16]),
                4 => changed.attempt_id = Uuid::from_bytes([15; 16]),
                5 => changed.connection_epoch += 1,
                6 => changed.deployment_epoch += 1,
                7 => changed.binding_generation += 1,
                8 => changed.attempt_generation += 1,
                9 => changed.expires_at_ms += 1,
                10 => changed.reader_key_id = URL_SAFE_NO_PAD.encode([11; 32]),
                11 => changed.envelope_sha256 = URL_SAFE_NO_PAD.encode([12; 32]),
                12 => changed.unsigned_sha256 = URL_SAFE_NO_PAD.encode([13; 32]),
                13 => changed.segment_count = 2,
                14 => changed.reader_role = 2,
                _ => unreachable!(),
            }
            assert!(!fetch_transcript(&changed).is_ok_and(|value| value == transcript));
        }
    }

    #[test]
    fn malformed_or_noncanonical_fetch_identity_is_refused() {
        for field in [
            "connection_epoch",
            "deployment_epoch",
            "binding_generation",
            "attempt_generation",
            "expires_at_ms",
        ] {
            let mut json = serde_json::to_value(grant()).unwrap();
            json[field] = 0.into();
            assert!(fetch_transcript(&serde_json::from_value(json).unwrap()).is_err());
        }
        assert!(digest(&URL_SAFE_NO_PAD.encode([0; 31])).is_err());
        assert!(digest(&(URL_SAFE_NO_PAD.encode([0; 32]) + "=")).is_err());
        let mut json = serde_json::to_value(grant()).unwrap();
        json["fetch_token"] = "unexpected".into();
        assert!(serde_json::from_value::<GrantFrame>(json).is_err());
    }

    #[test]
    fn readiness_requires_current_epoch_and_exact_reader_identity() {
        let mut ready = Ready {
            grant_version: 1,
            connection_epoch: 3,
            line_id: Uuid::from_bytes([3; 16]),
            binding_generation: 2,
            reader_key_id: URL_SAFE_NO_PAD.encode([4; 32]),
        };
        assert_eq!(ready.validate(3).unwrap(), [4; 32]);
        assert!(ready.validate(4).is_err());
        ready.binding_generation = 0;
        assert!(ready.validate(3).is_err());
    }
}
