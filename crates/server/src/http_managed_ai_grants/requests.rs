// SPDX-License-Identifier: AGPL-3.0-only
use crate::managed_ai::GrantRequest;
use serde::{Deserialize, Deserializer, Serialize, de::Error};
use uuid::Uuid;
use zeroize::Zeroizing;

// Owned parsed copies only. This cannot clear the original HTTP/serde buffers.
pub(super) struct Secret<const MIN: usize, const MAX: usize>(pub(super) Zeroizing<String>);
impl<'de, const MIN: usize, const MAX: usize> Deserialize<'de> for Secret<MIN, MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Zeroizing::new(String::deserialize(deserializer)?);
        if !(MIN..=MAX).contains(&value.len()) {
            return Err(D::Error::custom("invalid_request"));
        }
        Ok(Self(value))
    }
}

pub(super) struct Version(pub(super) i64);
impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = i64::deserialize(deserializer)?;
        if !(1..=127).contains(&value) {
            return Err(D::Error::custom("invalid_request"));
        }
        Ok(Self(value))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Create {
    pub(super) password: Secret<12, 1024>,
    pub(super) factor: Secret<1, 256>,
    pub(super) request: GrantRequest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Replace {
    pub(super) expected_version: Version,
    pub(super) password: Secret<12, 1024>,
    pub(super) factor: Secret<1, 256>,
    pub(super) request: GrantRequest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Narrow {
    pub(super) expected_version: Version,
    pub(super) request: GrantRequest,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Revoke {}

#[derive(Serialize)]
pub(super) struct GrantVersion {
    pub(super) grant_id: Uuid,
    pub(super) current_version: i64,
}

pub(super) fn grant_id(value: &str) -> Result<Uuid, ()> {
    let id = Uuid::parse_str(value).map_err(|_| ())?;
    if id.is_nil() || id.to_string() != value {
        return Err(());
    }
    Ok(id)
}
