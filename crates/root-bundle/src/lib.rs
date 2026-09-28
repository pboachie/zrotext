// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant local Windows NTFS adapter for immutable encrypted/public bundles.
//! No root generation, recovery token, decryption, terminal or network operations.

use sha2::{Digest, Sha256};
use zrotext_root_material::{recovery_kit::decode_public_card, root_backup};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid public bundle input")]
    InvalidInput,
    #[error("unsupported or unsafe bundle store")]
    UnsafeStore,
    #[error("bundle storage operation failed; pending data may remain")]
    Storage,
    #[error("bundle name already exists; inspect it separately")]
    Collision,
    #[error("bundle publication outcome is indeterminate; reconcile separately")]
    Indeterminate,
}

/// Bounded ciphertext and public card with matching public framing and digest.
/// This is not an authentication or restore result. No Debug/Display byte output.
pub struct EncryptedBundle {
    backup: Vec<u8>,
    card: Vec<u8>,
    id: [u8; 16],
}

impl EncryptedBundle {
    pub fn encrypted_backup(&self) -> &[u8] {
        &self.backup
    }

    pub fn public_card(&self) -> &[u8] {
        &self.card
    }

    pub fn new(
        backup: &[u8],
        card: &[u8],
        expected: &root_backup::ExpectedIdentity,
    ) -> Result<Self, Error> {
        let id = root_backup::validate_public_header(backup, expected)
            .map_err(|_| Error::InvalidInput)?;
        let digest = Sha256::digest(backup).into();
        decode_public_card(card, expected, &digest).map_err(|_| Error::InvalidInput)?;
        Ok(Self {
            backup: backup.to_vec(),
            card: card.to_vec(),
            id,
        })
    }

    /// Public immutable directory name, never a secret or a full filesystem path.
    pub fn name(&self) -> String {
        let mut name = String::from("bundle-");
        for byte in self.id {
            use std::fmt::Write;
            write!(name, "{byte:02x}").expect("writing into a String cannot fail");
        }
        name
    }
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::Store;

#[cfg(test)]
mod tests;
