// SPDX-License-Identifier: AGPL-3.0-only
//! Unmounted complete-set declaration codec. These bytes and signature results
//! do not authenticate a session, prove local observation currentness, or grant
//! activation or installation authority. A future consumer must bind the
//! immutable challenge version and purpose and retain the existing transaction
//! and issuer checks. The concealed set digest is a signed declaration, not
//! independent evidence of a physical SIM or eSIM profile.

use super::{LineChallenge, digest, proof_digest as combined_digest, verify_der};
use p256::ecdsa::Signature;
use thiserror::Error;
use uuid::Uuid;

pub(crate) const OBSERVATION_BYTES: usize = 121;
const CHALLENGE_BYTES: usize = 104;
const VERSION: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PurposeV2 {
    Sms,
    Sealed,
}

impl PurposeV2 {
    fn code(self) -> u8 {
        match self {
            Self::Sms => 1,
            Self::Sealed => 2,
        }
    }

    fn device_domain(self) -> &'static [u8] {
        match self {
            Self::Sms => b"ZTSMS/line/device-confirm/v2\0",
            Self::Sealed => b"ZTSE/line/device-confirm/v2\0",
        }
    }

    fn owner_domain(self) -> &'static [u8] {
        match self {
            Self::Sms => b"ZTSMS/line/owner-approve/v2\0",
            Self::Sealed => b"ZTSE/line/owner-approve/v2\0",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SelectedKindV2 {
    Physical,
    Embedded,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum CodecError {
    #[error("invalid v2 line activation encoding")]
    InvalidInput,
}

/// Structurally valid declaration data. No constructor certifies that the
/// declared count, tokens, epoch or digest came from a current Android issuer.
/// Profile identity is distinct from the card shared by multiple eSIM ports.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ObservationV2 {
    android_api_level: u16,
    active_subscription_count: u16,
    selected_subscription_id: i32,
    selected_kind: SelectedKindV2,
    selected_card_token: Uuid,
    selected_profile_token: Uuid,
    selected_port_index: i32,
    selected_slot_index: i32,
    monitor_lifetime_id: Uuid,
    observer_epoch: i64,
    selected_lease_id: Uuid,
    complete_set_sha256: [u8; 32],
}

impl ObservationV2 {
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, CodecError> {
        let bytes: &[u8; OBSERVATION_BYTES] =
            raw.try_into().map_err(|_| CodecError::InvalidInput)?;
        let selected_kind = match bytes[8] {
            1 => SelectedKindV2::Physical,
            2 => SelectedKindV2::Embedded,
            _ => return Err(CodecError::InvalidInput),
        };
        let value = Self {
            android_api_level: u16::from_be_bytes(take(bytes, 0)),
            active_subscription_count: u16::from_be_bytes(take(bytes, 2)),
            selected_subscription_id: i32::from_be_bytes(take(bytes, 4)),
            selected_kind,
            selected_card_token: Uuid::from_bytes(take(bytes, 9)),
            selected_profile_token: Uuid::from_bytes(take(bytes, 25)),
            selected_port_index: i32::from_be_bytes(take(bytes, 41)),
            selected_slot_index: i32::from_be_bytes(take(bytes, 45)),
            monitor_lifetime_id: Uuid::from_bytes(take(bytes, 49)),
            observer_epoch: i64::from_be_bytes(take(bytes, 65)),
            selected_lease_id: Uuid::from_bytes(take(bytes, 73)),
            complete_set_sha256: take(bytes, 89),
        };
        if value.android_api_level < 33
            || !(1..=256).contains(&value.active_subscription_count)
            || value.selected_subscription_id < 0
            || value.selected_card_token.is_nil()
            || value.selected_profile_token.is_nil()
            || value.selected_port_index < 0
            || value.selected_slot_index < 0
            || value.monitor_lifetime_id.is_nil()
            || value.observer_epoch <= 0
            || value.selected_lease_id.is_nil()
        {
            return Err(CodecError::InvalidInput);
        }
        Ok(value)
    }

    pub(crate) fn encode(&self) -> [u8; OBSERVATION_BYTES] {
        let mut bytes = [0; OBSERVATION_BYTES];
        bytes[0..2].copy_from_slice(&self.android_api_level.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.active_subscription_count.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.selected_subscription_id.to_be_bytes());
        bytes[8] = match self.selected_kind {
            SelectedKindV2::Physical => 1,
            SelectedKindV2::Embedded => 2,
        };
        bytes[9..25].copy_from_slice(self.selected_card_token.as_bytes());
        bytes[25..41].copy_from_slice(self.selected_profile_token.as_bytes());
        bytes[41..45].copy_from_slice(&self.selected_port_index.to_be_bytes());
        bytes[45..49].copy_from_slice(&self.selected_slot_index.to_be_bytes());
        bytes[49..65].copy_from_slice(self.monitor_lifetime_id.as_bytes());
        bytes[65..73].copy_from_slice(&self.observer_epoch.to_be_bytes());
        bytes[73..89].copy_from_slice(self.selected_lease_id.as_bytes());
        bytes[89..121].copy_from_slice(&self.complete_set_sha256);
        bytes
    }

    pub(crate) fn android_api_level(&self) -> u16 {
        self.android_api_level
    }

    pub(crate) fn active_subscription_count(&self) -> u16 {
        self.active_subscription_count
    }

    pub(crate) fn selected_subscription_id(&self) -> i32 {
        self.selected_subscription_id
    }

    pub(crate) fn selected_kind(&self) -> SelectedKindV2 {
        self.selected_kind
    }

    pub(crate) fn selected_card_token(&self) -> Uuid {
        self.selected_card_token
    }

    pub(crate) fn selected_profile_token(&self) -> Uuid {
        self.selected_profile_token
    }

    pub(crate) fn selected_port_index(&self) -> i32 {
        self.selected_port_index
    }

    pub(crate) fn selected_slot_index(&self) -> i32 {
        self.selected_slot_index
    }

    pub(crate) fn monitor_lifetime_id(&self) -> Uuid {
        self.monitor_lifetime_id
    }

    pub(crate) fn observer_epoch(&self) -> i64 {
        self.observer_epoch
    }

    pub(crate) fn selected_lease_id(&self) -> Uuid {
        self.selected_lease_id
    }

    pub(crate) fn complete_set_sha256(&self) -> [u8; 32] {
        self.complete_set_sha256
    }
}

fn take<const N: usize>(bytes: &[u8; OBSERVATION_BYTES], offset: usize) -> [u8; N] {
    let mut value = [0; N];
    value.copy_from_slice(&bytes[offset..offset + N]);
    value
}

/// Encoding data only. Private owned bytes prevent mutation after construction.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DeviceStatementBytesV2 {
    purpose: PurposeV2,
    bytes: Vec<u8>,
}

impl DeviceStatementBytesV2 {
    pub(crate) fn decode(purpose: PurposeV2, raw: &[u8]) -> Result<Self, CodecError> {
        let domain = purpose.device_domain();
        let offset = domain.len() + 2;
        if raw.len() != offset + CHALLENGE_BYTES + OBSERVATION_BYTES
            || !raw.starts_with(domain)
            || raw[domain.len()] != VERSION
            || raw[domain.len() + 1] != purpose.code()
        {
            return Err(CodecError::InvalidInput);
        }
        let tuple = &raw[offset..offset + CHALLENGE_BYTES];
        if [0, 16, 32, 56]
            .into_iter()
            .any(|start| tuple[start..start + 16].iter().all(|byte| *byte == 0))
            || i64::from_be_bytes(
                tuple[48..56]
                    .try_into()
                    .map_err(|_| CodecError::InvalidInput)?,
            ) <= 0
        {
            return Err(CodecError::InvalidInput);
        }
        ObservationV2::decode(&raw[offset + CHALLENGE_BYTES..])?;
        Ok(Self {
            purpose,
            bytes: raw.to_vec(),
        })
    }

    pub(crate) fn purpose(&self) -> PurposeV2 {
        self.purpose
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

/// Owner signing data, never an approval, installation or currentness receipt.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OwnerStatementBytesV2 {
    purpose: PurposeV2,
    bytes: Vec<u8>,
}

impl OwnerStatementBytesV2 {
    pub(crate) fn purpose(&self) -> PurposeV2 {
        self.purpose
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

pub(crate) fn device_statement(
    purpose: PurposeV2,
    challenge: &LineChallenge,
    observation: &ObservationV2,
) -> Result<DeviceStatementBytesV2, CodecError> {
    if challenge.account_id.is_nil()
        || challenge.line_id.is_nil()
        || challenge.device_id.is_nil()
        || challenge.id.is_nil()
        || challenge.generation <= 0
    {
        return Err(CodecError::InvalidInput);
    }
    let mut bytes =
        Vec::with_capacity(purpose.device_domain().len() + 2 + CHALLENGE_BYTES + OBSERVATION_BYTES);
    bytes.extend_from_slice(purpose.device_domain());
    bytes.extend_from_slice(&[VERSION, purpose.code()]);
    bytes.extend_from_slice(challenge.account_id.as_bytes());
    bytes.extend_from_slice(challenge.line_id.as_bytes());
    bytes.extend_from_slice(challenge.device_id.as_bytes());
    bytes.extend_from_slice(&challenge.generation.to_be_bytes());
    bytes.extend_from_slice(challenge.id.as_bytes());
    bytes.extend_from_slice(&challenge.nonce);
    bytes.extend_from_slice(&observation.encode());
    Ok(DeviceStatementBytesV2 { purpose, bytes })
}

fn require_canonical_der(der: &[u8]) -> Result<(), CodecError> {
    if !(8..=80).contains(&der.len()) {
        return Err(CodecError::InvalidInput);
    }
    let signature = Signature::from_der(der).map_err(|_| CodecError::InvalidInput)?;
    if signature.to_der().as_bytes() != der {
        return Err(CodecError::InvalidInput);
    }
    Ok(())
}

pub(crate) fn owner_statement(
    device: &DeviceStatementBytesV2,
    canonical_device_der: &[u8],
) -> Result<OwnerStatementBytesV2, CodecError> {
    require_canonical_der(canonical_device_der)?;
    let mut bytes =
        Vec::with_capacity(device.purpose.owner_domain().len() + device.bytes.len() + 32);
    bytes.extend_from_slice(device.purpose.owner_domain());
    bytes.extend_from_slice(&device.bytes);
    bytes.extend_from_slice(&digest(canonical_device_der));
    Ok(OwnerStatementBytesV2 {
        purpose: device.purpose,
        bytes,
    })
}

/// Matches the existing audit digest, without claiming verified proof authority.
pub(crate) fn proof_digest(
    device: &DeviceStatementBytesV2,
    canonical_device_der: &[u8],
) -> Result<[u8; 32], CodecError> {
    require_canonical_der(canonical_device_der)?;
    Ok(combined_digest(&device.bytes, canonical_device_der))
}

/// Cryptographic result only: the caller still needs actual current role keys,
/// immutable version/purpose, session/lease, expiry and post-lock checks.
pub(crate) fn verify_device_signature(
    sec1: &[u8],
    statement: &DeviceStatementBytesV2,
    der: &[u8],
) -> bool {
    verify_der(sec1, &statement.bytes, der)
}

pub(crate) fn verify_owner_signature(
    sec1: &[u8],
    statement: &OwnerStatementBytesV2,
    der: &[u8],
) -> bool {
    verify_der(sec1, &statement.bytes, der)
}

#[cfg(test)]
mod tests;
