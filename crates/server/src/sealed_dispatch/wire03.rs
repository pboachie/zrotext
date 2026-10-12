// SPDX-License-Identifier: AGPL-3.0-only
//! Independent profile03 syntax and device-signature evidence, never live authority.
//! No route, negotiation, grant issuer, clock, database or effect permission is mounted here.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

pub const MAX_JSON_BYTES: usize = 4096;
pub const FETCH_TRANSCRIPT_BYTES: usize = 362;
const FETCH_DOMAIN: &[u8] = b"ZT/sealed-envelope-fetch/v3\0";

// A derived struct also accepts a positional sequence. Stream maps directly
// into the derived visitor instead, retaining decoded duplicate/unknown checks.
struct MapOnly<T>(T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for MapOnly<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Object<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
            type Value = MapOnly<T>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> Result<Self::Value, M::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(MapOnly)
            }
        }
        deserializer.deserialize_map(Object(std::marker::PhantomData))
    }
}

fn decode_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_JSON_BYTES {
        return Err("wire03 JSON bound");
    }
    serde_json::from_slice::<MapOnly<T>>(bytes)
        .map(|decoded| decoded.0)
        .map_err(|_| "wire03 closed JSON")
}

fn identity(value: &str) -> Result<Uuid, &'static str> {
    let id = Uuid::parse_str(value).map_err(|_| "wire03 UUID")?;
    if value.len() != 36 || id.is_nil() || id.hyphenated().to_string() != value {
        return Err("wire03 canonical UUID");
    }
    Ok(id)
}

fn digest(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 43 {
        return Err("wire03 digest bound");
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "wire03 digest encoding")?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err("wire03 canonical digest");
    }
    bytes.try_into().map_err(|_| "wire03 digest width")
}

fn positive(values: &[i64]) -> Result<(), &'static str> {
    if values.iter().any(|number| *number <= 0) {
        return Err("wire03 positive storage integer");
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantWire03 {
    v: u8,
    #[serde(rename = "type")]
    kind: String,
    grant_version: u8,
    envelope_profile: u8,
    manifest_profile: u8,
    reader_role: u8,
    segment_count: u8,
    account_id: String,
    device_id: String,
    line_id: String,
    message_id: String,
    attempt_id: String,
    connection_epoch: i64,
    deployment_epoch: i64,
    binding_generation: i64,
    attempt_generation: i64,
    expires_at_ms: i64,
    trust_generation: i64,
    manifest_version: i64,
    reader_key_id: String,
    envelope_sha256: String,
    unsigned_sha256: String,
    manifest_digest: String,
    root_fingerprint: String,
    election_digest: String,
}

/// Owned syntax claims only. These values do not authenticate their origin or currentness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantClaims03 {
    pub account_id: Uuid,
    pub device_id: Uuid,
    pub line_id: Uuid,
    pub message_id: Uuid,
    pub attempt_id: Uuid,
    pub connection_epoch: i64,
    pub deployment_epoch: i64,
    pub binding_generation: i64,
    pub attempt_generation: i64,
    pub expires_at_ms: i64,
    pub trust_generation: i64,
    pub manifest_version: i64,
    pub reader_key_id: [u8; 32],
    pub envelope_sha256: [u8; 32],
    pub unsigned_sha256: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub root_fingerprint: [u8; 32],
    pub election_digest: [u8; 32],
    /// Claimed maximum, not measured encrypted plaintext or radio authorization.
    pub segment_count: u8,
}

/// A privately constructed validated Grant03 grammar object, not an issued grant.
#[derive(Clone, Debug)]
pub struct GrantFrame03 {
    wire: GrantWire03,
    claims: GrantClaims03,
}

impl GrantFrame03 {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        Self::checked(decode_json(bytes)?)
    }

    fn checked(wire: GrantWire03) -> Result<Self, &'static str> {
        if wire.v != 1
            || wire.kind != "sealed_execution_grant"
            || wire.grant_version != 3
            || wire.envelope_profile != 3
            || wire.manifest_profile != 3
            || wire.reader_role != 1
            || !(1..=6).contains(&wire.segment_count)
        {
            return Err("wire03 grant profile");
        }
        positive(&[
            wire.connection_epoch,
            wire.deployment_epoch,
            wire.binding_generation,
            wire.attempt_generation,
            wire.expires_at_ms,
            wire.trust_generation,
            wire.manifest_version,
        ])?;
        let claims = GrantClaims03 {
            account_id: identity(&wire.account_id)?,
            device_id: identity(&wire.device_id)?,
            line_id: identity(&wire.line_id)?,
            message_id: identity(&wire.message_id)?,
            attempt_id: identity(&wire.attempt_id)?,
            connection_epoch: wire.connection_epoch,
            deployment_epoch: wire.deployment_epoch,
            binding_generation: wire.binding_generation,
            attempt_generation: wire.attempt_generation,
            expires_at_ms: wire.expires_at_ms,
            trust_generation: wire.trust_generation,
            manifest_version: wire.manifest_version,
            reader_key_id: digest(&wire.reader_key_id)?,
            envelope_sha256: digest(&wire.envelope_sha256)?,
            unsigned_sha256: digest(&wire.unsigned_sha256)?,
            manifest_digest: digest(&wire.manifest_digest)?,
            root_fingerprint: digest(&wire.root_fingerprint)?,
            election_digest: digest(&wire.election_digest)?,
            segment_count: wire.segment_count,
        };
        Ok(Self { wire, claims })
    }

    pub fn claims(&self) -> &GrantClaims03 {
        &self.claims
    }

    /// Emit the same checked field values; formatting/order are not signature bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, &'static str> {
        serde_json::to_vec(&self.wire).map_err(|_| "wire03 JSON serialization")
    }

    /// The exact v3 transcript, independently of JSON member order or spelling escapes.
    pub fn fetch_transcript(&self) -> [u8; FETCH_TRANSCRIPT_BYTES] {
        let c = &self.claims;
        let mut bytes = [0; FETCH_TRANSCRIPT_BYTES];
        let mut cursor = 0;
        let mut append = |part: &[u8]| {
            bytes[cursor..cursor + part.len()].copy_from_slice(part);
            cursor += part.len();
        };
        append(FETCH_DOMAIN);
        append(&[1, 3, 3, 3, 1, c.segment_count]);
        for id in [
            c.account_id,
            c.device_id,
            c.line_id,
            c.message_id,
            c.attempt_id,
        ] {
            append(id.as_bytes());
        }
        for value in [
            c.connection_epoch,
            c.deployment_epoch,
            c.binding_generation,
            c.attempt_generation,
            c.expires_at_ms,
            c.trust_generation,
            c.manifest_version,
        ] {
            append(&value.to_be_bytes());
        }
        for value in [
            &c.reader_key_id,
            &c.envelope_sha256,
            &c.unsigned_sha256,
            &c.manifest_digest,
            &c.root_fingerprint,
            &c.election_digest,
        ] {
            append(value);
        }
        debug_assert_eq!(cursor, FETCH_TRANSCRIPT_BYTES);
        bytes
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReadyWire03 {
    v: u8,
    #[serde(rename = "type")]
    kind: String,
    grant_version: u8,
    envelope_profile: u8,
    manifest_profile: u8,
    connection_epoch: i64,
    deployment_epoch: i64,
    binding_generation: i64,
    trust_generation: i64,
    manifest_version: i64,
    line_id: String,
    reader_key_id: String,
    manifest_digest: String,
    root_fingerprint: String,
    election_digest: String,
}

/// Unsigned readiness claims. Account/device identity must come from the authenticated session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadyClaims03 {
    pub connection_epoch: i64,
    pub deployment_epoch: i64,
    pub binding_generation: i64,
    pub trust_generation: i64,
    pub manifest_version: i64,
    pub line_id: Uuid,
    pub reader_key_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub root_fingerprint: [u8; 32],
    pub election_digest: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ReadyFrame03 {
    wire: ReadyWire03,
    claims: ReadyClaims03,
}
impl ReadyFrame03 {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        let wire: ReadyWire03 = decode_json(bytes)?;
        if wire.v != 1
            || wire.kind != "sealed_ready"
            || wire.grant_version != 3
            || wire.envelope_profile != 3
            || wire.manifest_profile != 3
        {
            return Err("wire03 ready profile");
        }
        positive(&[
            wire.connection_epoch,
            wire.deployment_epoch,
            wire.binding_generation,
            wire.trust_generation,
            wire.manifest_version,
        ])?;
        let claims = ReadyClaims03 {
            connection_epoch: wire.connection_epoch,
            deployment_epoch: wire.deployment_epoch,
            binding_generation: wire.binding_generation,
            trust_generation: wire.trust_generation,
            manifest_version: wire.manifest_version,
            line_id: identity(&wire.line_id)?,
            reader_key_id: digest(&wire.reader_key_id)?,
            manifest_digest: digest(&wire.manifest_digest)?,
            root_fingerprint: digest(&wire.root_fingerprint)?,
            election_digest: digest(&wire.election_digest)?,
        };
        Ok(Self { wire, claims })
    }
    pub fn claims(&self) -> &ReadyClaims03 {
        &self.claims
    }
    pub fn to_json(&self) -> Result<Vec<u8>, &'static str> {
        serde_json::to_vec(&self.wire).map_err(|_| "wire03 JSON serialization")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchWire03 {
    grant: MapOnly<GrantWire03>,
    signature_der: String,
}

fn signature(value: &str) -> Result<Signature, &'static str> {
    if !(11..=95).contains(&value.len()) {
        return Err("wire03 DER encoding bound");
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "wire03 DER encoding")?;
    if !(8..=71).contains(&bytes.len()) || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err("wire03 canonical DER encoding");
    }
    let sig = Signature::from_der(&bytes).map_err(|_| "wire03 DER scalar/grammar")?;
    if sig.to_der().as_bytes() != bytes {
        return Err("wire03 minimal DER");
    }
    if sig.normalize_s().to_bytes() != sig.to_bytes() {
        return Err("wire03 low-S DER");
    }
    Ok(sig)
}

/// Checked Fetch03 syntax, including strict scalar/canonical/low-S DER; not yet a verified signature.
#[derive(Clone, Debug)]
pub struct Fetch03 {
    grant: GrantFrame03,
    signature: Signature,
}
impl Fetch03 {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        let wire: FetchWire03 = decode_json(bytes)?;
        Ok(Self {
            grant: GrantFrame03::checked(wire.grant.0)?,
            signature: signature(&wire.signature_der)?,
        })
    }
    pub fn grant(&self) -> &GrantFrame03 {
        &self.grant
    }
    pub fn signature_der(&self) -> Vec<u8> {
        self.signature.to_der().as_bytes().to_vec()
    }

    /// Verify only this transcript against a caller-selected enrolled key. The caller must
    /// independently authenticate key selection, current session/binding, deadlines and fences.
    pub fn verify(
        &self,
        enrolled_device_key: &VerifyingKey,
    ) -> Result<VerifiedFetchProof03, &'static str> {
        enrolled_device_key
            .verify(&self.grant.fetch_transcript(), &self.signature)
            .map_err(|_| "wire03 fetch signature mismatch")?;
        Ok(VerifiedFetchProof03 {
            fetch: self.clone(),
        })
    }
}

/// Cryptographic evidence only; cannot authorize issuance, fetching, consumption or radio effects.
#[derive(Clone, Debug)]
pub struct VerifiedFetchProof03 {
    fetch: Fetch03,
}
impl VerifiedFetchProof03 {
    pub fn fetch(&self) -> &Fetch03 {
        &self.fetch
    }
}

#[cfg(test)]
#[path = "wire03_tests.rs"]
mod tests;
