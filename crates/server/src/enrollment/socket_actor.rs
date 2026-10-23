// SPDX-License-Identifier: AGPL-3.0-only
//! Read-only identity retained from an actual socket signature verification.

use super::{AuthenticatedDevice, DeviceChallenge, EnrollmentError};
use sha2::{Digest, Sha256};

/// The enrolled key which verified a particular authenticated socket proof.
///
/// This is not a current lease or content permission. Session claim and every
/// new protected control must independently compare the held current key.
#[derive(Clone, Copy)]
pub struct VerifiedDevice {
    identity: AuthenticatedDevice,
    point: [u8; 65],
    key_id: [u8; 32],
}

impl VerifiedDevice {
    pub fn identity(&self) -> AuthenticatedDevice {
        self.identity
    }
    pub fn signing_point(&self) -> &[u8; 65] {
        &self.point
    }
    pub fn signing_key_id(&self) -> &[u8; 32] {
        &self.key_id
    }
    pub fn matches_point(&self, point: &[u8]) -> bool {
        self.point.as_slice() == point
    }
}

// No constructor accepts IDs or a later SELECT as signature provenance.
// The parent already checked the stateless challenge's HMAC and validity.
pub(super) fn verify(
    challenge: &DeviceChallenge,
    point: &[u8],
    signature_der: &[u8],
) -> Result<VerifiedDevice, EnrollmentError> {
    let point: [u8; 65] = point
        .try_into()
        .map_err(|_| EnrollmentError::Unauthorized)?;
    if point[0] != 4
        || !super::verify_signature(
            &point,
            &super::device_challenge_bytes(challenge),
            signature_der,
        )
    {
        return Err(EnrollmentError::Unauthorized);
    }
    let mut key_id = Sha256::new();
    key_id.update(b"ZTSE/key/v1\0");
    key_id.update([1, 1]);
    key_id.update(point);
    Ok(VerifiedDevice {
        identity: AuthenticatedDevice {
            account_id: challenge.account_id,
            device_id: challenge.device_id,
        },
        point,
        key_id: key_id.finalize().into(),
    })
}

#[cfg(test)]
mod tests;
