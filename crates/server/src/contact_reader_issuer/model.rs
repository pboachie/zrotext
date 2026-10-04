// SPDX-License-Identifier: AGPL-3.0-only
//! Closed public wire values and projections. None of these values is authority.

use super::Error;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) const MAX_BODY: usize = 8192;
pub(crate) const MAX_RESPONSE: usize = 20 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Id(pub Uuid);
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = String::deserialize(d)?;
        let id = Uuid::parse_str(&value).map_err(D::Error::custom)?;
        if id.is_nil() || value.len() != 36 || id.to_string() != value {
            return Err(D::Error::custom("invalid identity"));
        }
        Ok(Self(id))
    }
}
impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

/// Signed-63 canonical decimal string; individual live fields require >0.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Number(pub i64);
impl<'de> Deserialize<'de> for Number {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = String::deserialize(d)?;
        if value.is_empty() || value.len() > 19 || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(D::Error::custom("invalid integer"));
        }
        let n: i64 = value.parse().map_err(D::Error::custom)?;
        if n < 0 || n.to_string() != value {
            return Err(D::Error::custom("invalid integer"));
        }
        Ok(Self(n))
    }
}
impl Serialize for Number {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.to_string())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fixed<const N: usize>(pub [u8; N]);
impl<'de, const N: usize> Deserialize<'de> for Fixed<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = String::deserialize(d)?;
        if value.len() != N.div_ceil(3) * 4 {
            return Err(D::Error::custom("invalid bytes"));
        }
        let bytes: [u8; N] = STANDARD
            .decode(&value)
            .map_err(D::Error::custom)?
            .try_into()
            .map_err(|_| D::Error::custom("invalid bytes"))?;
        if bytes == [0; N] || STANDARD.encode(bytes) != value {
            return Err(D::Error::custom("invalid bytes"));
        }
        Ok(Self(bytes))
    }
}
impl<const N: usize> Serialize for Fixed<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(self.0))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Packed<const MIN: usize, const MAX: usize>(pub Vec<u8>);
impl<'de, const MIN: usize, const MAX: usize> Deserialize<'de> for Packed<MIN, MAX> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = String::deserialize(d)?;
        if value.len() > MAX.div_ceil(3) * 4 {
            return Err(D::Error::custom("invalid bytes"));
        }
        let bytes = STANDARD.decode(&value).map_err(D::Error::custom)?;
        if !(MIN..=MAX).contains(&bytes.len()) || STANDARD.encode(&bytes) != value {
            return Err(D::Error::custom("invalid bytes"));
        }
        Ok(Self(bytes))
    }
}
impl<const MIN: usize, const MAX: usize> Serialize for Packed<MIN, MAX> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(&self.0))
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "phase", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Prior {
    Empty {},
    Active {
        authorization: Id,
        generation: Number,
        digest: Fixed<32>,
    },
    Withdrawn {
        authorization: Id,
        generation: Number,
        digest: Fixed<32>,
    },
}
impl Prior {
    pub(crate) fn tuple(&self) -> (&'static str, Option<Uuid>, Option<i64>, Option<[u8; 32]>) {
        match self {
            Self::Empty {} => ("EMPTY", None, None, None),
            Self::Active {
                authorization,
                generation,
                digest,
            } => (
                "ACTIVE",
                Some(authorization.0),
                Some(generation.0),
                Some(digest.0),
            ),
            Self::Withdrawn {
                authorization,
                generation,
                digest,
            } => (
                "WITHDRAWN",
                Some(authorization.0),
                Some(generation.0),
                Some(digest.0),
            ),
        }
    }
    fn valid(&self) -> bool {
        self.tuple().2.is_none_or(|n| n > 0)
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Create {
    pub create_request: Id,
    pub expected_revision: Number,
    pub prior: Prior,
    pub selected_reader_id: Fixed<32>,
    pub compared_root_fingerprint: Fixed<32>,
    pub requested_until_ms: Number,
}
impl Create {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.requested_until_ms.0 <= 0 || !self.prior.valid() {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    /// Internal equality encoding, not a signature domain or approval source.
    pub(crate) fn commitment(&self, account: Uuid, origin: &str) -> Result<[u8; 32], Error> {
        self.validate()?;
        if account.is_nil() || !crate::sealed_root_enrollment::canonical_origin(origin) {
            return Err(Error::Invalid);
        }
        let (phase, id, generation, digest) = self.prior.tuple();
        let mut b = Vec::with_capacity(172 + origin.len());
        b.push(1);
        b.extend_from_slice(account.as_bytes());
        b.extend_from_slice(&(origin.len() as u16).to_be_bytes());
        b.extend_from_slice(origin.as_bytes());
        b.extend_from_slice(self.create_request.0.as_bytes());
        b.extend_from_slice(&self.expected_revision.0.to_be_bytes());
        b.push(match phase {
            "EMPTY" => 0,
            "ACTIVE" => 1,
            _ => 2,
        });
        b.extend_from_slice(id.unwrap_or(Uuid::nil()).as_bytes());
        b.extend_from_slice(&generation.unwrap_or(0).to_be_bytes());
        b.extend_from_slice(&digest.unwrap_or([0; 32]));
        b.extend_from_slice(&self.selected_reader_id.0);
        b.extend_from_slice(&self.compared_root_fingerprint.0);
        b.extend_from_slice(&self.requested_until_ms.0.to_be_bytes());
        if b.len() != 172 + origin.len() {
            return Err(Error::Invalid);
        }
        Ok(Sha256::digest(b).into())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lookup {
    pub create: Create,
    pub expected_input_digest: Fixed<32>,
}

/// No Debug/Serialize implementation; factors never enter public projections.
pub(crate) struct Code(pub Zeroizing<String>);
impl<'de> Deserialize<'de> for Code {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = Zeroizing::new(String::deserialize(d)?);
        let totp = value.len() == 6 && value.bytes().all(|b| b.is_ascii_digit());
        let recovery = value.len() == 26
            && value
                .strip_prefix("zrc_")
                .and_then(|v| URL_SAFE_NO_PAD.decode(v).ok())
                .is_some_and(|b| b.len() == 16);
        if value.len() > 128 || !(totp || recovery) {
            return Err(D::Error::custom("invalid factor"));
        }
        Ok(Self(value))
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Complete {
    pub generation: Number,
    pub create_request: Id,
    pub creation_expected_revision: Number,
    pub unsigned_digest: Fixed<32>,
    pub signed_statement: Packed<314, 817>,
    pub code: Code,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cancel {
    pub generation: Number,
    pub create_request: Id,
    pub unsigned_digest: Fixed<32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Withdraw {
    pub expected_revision: Number,
    pub expected_authorization: Id,
    pub expected_generation: Number,
    pub expected_digest: Fixed<32>,
}

pub(crate) fn parse<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T, Error> {
    if raw.is_empty() || raw.len() > MAX_BODY || std::str::from_utf8(raw).is_err() {
        return Err(Error::Invalid);
    }
    serde_json::from_slice(raw).map_err(|_| Error::Invalid)
}
pub(crate) fn status_query(raw: Option<&str>) -> Result<i64, Error> {
    let value = raw
        .and_then(|v| v.strip_prefix("generation="))
        .ok_or(Error::Invalid)?;
    if value.is_empty() || value.len() > 19 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Invalid);
    }
    let n: i64 = value.parse().map_err(|_| Error::Invalid)?;
    if n <= 0 || n.to_string() != value {
        return Err(Error::Invalid);
    }
    Ok(n)
}

#[derive(Clone, Serialize, PartialEq, Eq)]
pub(crate) struct KeyView {
    pub key_id_b64: Fixed<32>,
    pub public_point_b64: Fixed<65>,
    pub from_ms: Number,
    pub until_ms: Number,
}
#[derive(Clone, Serialize, PartialEq, Eq)]
pub(crate) struct CreationSource {
    pub kind: &'static str,
    pub account_id: Id,
    pub root_pin_b64: Fixed<94>,
    pub root_fingerprint_b64: Fixed<32>,
    pub trust_generation: Number,
    pub manifest_version: Number,
    pub manifest_digest_b64: Fixed<32>,
    pub manifest_b64: Packed<364, 9751>,
    pub observed_ms: Number,
    pub manifest_issued_ms: Number,
    pub manifest_expires_ms: Number,
    pub signed_until_ms: Number,
    pub reader: KeyView,
    pub root_writer: KeyView,
}
#[derive(Clone, Serialize)]
pub(crate) struct Current {
    pub phase: &'static str,
    pub mutation_revision: Number,
    pub allocation_generation: Number,
    pub observed_ms: Number,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<Number>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_digest: Option<Fixed<32>>,
}
#[derive(Serialize)]
pub(crate) struct PendingView {
    pub kind: &'static str,
    pub create_input_digest: Fixed<32>,
    pub create_request: Id,
    pub authorization: Id,
    pub generation: Number,
    pub creation_expected_revision: Number,
    pub allocated_revision: Number,
    pub unsigned_digest: Fixed<32>,
    pub unsigned: Packed<250, 753>,
    pub issued_ms: Number,
    pub expires_ms: Number,
    pub until_ms: Number,
    pub created_by_user: Id,
    pub created_session: Id,
    pub creation_source: CreationSource,
    pub current: Current,
}
#[derive(Serialize)]
pub(crate) struct ReceiptView {
    pub kind: &'static str,
    pub create_input_digest: Fixed<32>,
    pub create_request: Id,
    pub authorization: Id,
    pub generation: Number,
    pub creation_expected_revision: Number,
    pub unsigned_digest: Fixed<32>,
    pub terminal_ms: Number,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_statement: Option<Packed<314, 817>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_digest: Option<Fixed<32>>,
    pub current: Current,
}
#[derive(Serialize)]
pub(crate) struct WithdrawView {
    pub kind: &'static str,
    pub authorization: Id,
    pub generation: Number,
    pub statement_digest: Fixed<32>,
    pub mutation_revision: Number,
    pub observed_ms: Number,
}
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum ResultView {
    Pending(Box<PendingView>),
    Receipt(Box<ReceiptView>),
    Withdraw(WithdrawView),
    Unavailable { kind: &'static str },
}
impl ResultView {
    pub(crate) fn unavailable() -> Self {
        Self::Unavailable {
            kind: "unavailable",
        }
    }
}
pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Unavailable)?;
    if bytes.len() > MAX_RESPONSE {
        return Err(Error::Unavailable);
    }
    Ok(bytes)
}
