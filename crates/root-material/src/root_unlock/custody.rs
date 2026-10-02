// SPDX-License-Identifier: AGPL-3.0-only
//! One immutable, identity-bound custody publication; never an arbitrary signer.
use super::{UnlockError, inspect_challenge, sign_statement, signing_key};
use crate::{
    recovery_kit,
    root_backup::{self, ExpectedIdentity, RootSecret},
    sealed_root_enrollment::Challenge,
};
use sha2::{Digest, Sha256};

/// Owned public snapshots. Expected identity and bundle ID must come from the
/// owner's independent kit, never from downloaded challenge/card metadata.
pub struct ReviewedCustody {
    unsigned: Vec<u8>,
    statement: Vec<u8>,
    expected: ExpectedIdentity,
}

/// Two distinct canonical low-s signatures for the same reviewed challenge.
pub struct Signatures {
    pub enrollment: [u8; 64],
    pub custody: [u8; 64],
}

impl ReviewedCustody {
    pub fn inspect(
        unsigned: &[u8],
        backup: &[u8],
        card: &[u8],
        expected: &ExpectedIdentity,
        bundle_id: &[u8; 16],
        now_ms: u64,
    ) -> Result<Self, UnlockError> {
        inspect_challenge(unsigned, expected, now_ms)?;
        if backup.len() > 748 || card.len() > 645 {
            return Err(UnlockError::InvalidInput);
        }
        let actual = root_backup::validate_public_header(backup, expected)
            .map_err(|_| UnlockError::ContextRejected)?;
        if actual != *bundle_id || *bundle_id == [0; 16] {
            return Err(UnlockError::ContextRejected);
        }
        recovery_kit::decode_public_card(card, expected, &Sha256::digest(backup).into())
            .map_err(|_| UnlockError::ContextRejected)?;
        let mut statement = Vec::with_capacity(23 + unsigned.len() + 96);
        statement.extend_from_slice(b"ZTSE/root-custody/v1\0");
        statement.extend_from_slice(&(unsigned.len() as u32).to_be_bytes());
        statement.extend_from_slice(unsigned);
        statement.extend_from_slice(&Sha256::digest(backup));
        statement.extend_from_slice(&Sha256::digest(card));
        statement.extend_from_slice(&expected.root_fingerprint);
        Ok(Self {
            unsigned: unsigned.to_vec(),
            statement,
            expected: expected.clone(),
        })
    }

    pub fn challenge(&self, now_ms: u64) -> Result<Challenge, UnlockError> {
        inspect_challenge(&self.unsigned, &self.expected, now_ms)
    }

    /// Call only after explicit owner consent and authenticated recovery. The
    /// caller supplies fresh time after secret entry; no output on expiry.
    /// Consumes the reviewed snapshot and retains no private root material.
    pub fn sign(self, root: &RootSecret, now_ms: u64) -> Result<Signatures, UnlockError> {
        self.challenge(now_ms)?;
        let key = signing_key(root, &self.expected)?;
        let enrollment = crate::sealed_root_enrollment::transcript(&self.unsigned)
            .map_err(|_| UnlockError::InvalidInput)?;
        Ok(Signatures {
            enrollment: sign_statement(key.clone(), &enrollment),
            custody: sign_statement(key, &self.statement),
        })
    }
}

#[cfg(test)]
mod tests;
