// SPDX-License-Identifier: AGPL-3.0-only
//! Server-side encryption of contact display names and free-text notes.
//!
//! The contacts key-encryption key (KEK) is configured like the webhook KEK:
//! a version and a 32-byte base64 key, optionally with a secondary pair
//! during rotation. Each field is sealed with AES-256-GCM under an
//! account/contact/field/version binding, so a ciphertext cannot be moved
//! to another tenant, another contact or another column without failing
//! authentication. Plaintext is never persisted; only the owner-scoped
//! HTTP handlers and the owner export open it.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Generate, Payload},
};
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Version byte every packed ciphertext starts with.
const FIELD_FORMAT: u8 = 1;
/// Packed layout: format byte, big-endian i32 key version, nonce, then the
/// AES-GCM ciphertext with its tag. The stored version selects the key; the
/// AAD authenticates it, so editing the version only fails the tag.
const VERSION_BYTES: usize = 4;
/// AES-GCM nonce and tag sizes, fixed by the algorithm.
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
/// Sealed plaintext bound: names and notes are validated to this before
/// sealing, so a packed column can never hold more than this plus overhead.
pub const FIELD_PLAINTEXT_MAX: usize = 2048;
pub const FIELD_PLAINTEXT_MIN: usize = 1;

/// Which column a ciphertext belongs to; part of the AAD binding so a name
/// cannot be swapped into the notes column and vice versa.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactField {
    DisplayName,
    Notes,
}

impl ContactField {
    fn aad_byte(self) -> u8 {
        match self {
            Self::DisplayName => 1,
            Self::Notes => 2,
        }
    }
}

#[derive(Debug)]
pub enum VaultError {
    InvalidKey,
    OpenFailed,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid contacts key-encryption key"),
            Self::OpenFailed => write!(f, "stored contact ciphertext cannot be opened"),
        }
    }
}

impl std::error::Error for VaultError {}

pub struct ContactFieldVault {
    version: i32,
    key: Zeroizing<[u8; 32]>,
    secondary: Option<(i32, Zeroizing<[u8; 32]>)>,
}

impl ContactFieldVault {
    pub fn new(version: i32, key: Zeroizing<Vec<u8>>) -> Result<Self, VaultError> {
        Self::with_secondary(version, key, None)
    }

    /// Both keys may read during a staged KEK rotation; only the active
    /// version seals new ciphertext, exactly like the webhook vault.
    pub fn with_secondary(
        version: i32,
        key: Zeroizing<Vec<u8>>,
        secondary: Option<(i32, Zeroizing<Vec<u8>>)>,
    ) -> Result<Self, VaultError> {
        let fixed = fixed_key(version, key)?;
        let secondary = secondary
            .map(|(other_version, other_key)| {
                Ok((other_version, fixed_key(other_version, other_key)?))
            })
            .transpose()?;
        if let Some((other_version, other_key)) = &secondary
            && (other_version == &version || other_key == &fixed)
        {
            return Err(VaultError::InvalidKey);
        }
        Ok(Self {
            version,
            key: fixed,
            secondary,
        })
    }

    pub fn version(&self) -> i32 {
        self.version
    }

    fn key_for(&self, version: i32) -> Result<&Zeroizing<[u8; 32]>, VaultError> {
        if version == self.version {
            return Ok(&self.key);
        }
        if let Some((other_version, other_key)) = &self.secondary
            && version == *other_version
        {
            return Ok(other_key);
        }
        Err(VaultError::OpenFailed)
    }

    /// Seals one field. The AAD binds the ciphertext to the key version,
    /// account, contact and column.
    pub fn seal(
        &self,
        account_id: Uuid,
        contact_id: Uuid,
        field: ContactField,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        if !(FIELD_PLAINTEXT_MIN..=FIELD_PLAINTEXT_MAX).contains(&plaintext.len()) {
            return Err(VaultError::OpenFailed);
        }
        let cipher = Aes256Gcm::new_from_slice(&*self.key).map_err(|_| VaultError::InvalidKey)?;
        let nonce = Nonce::generate();
        let aad = field_aad(account_id, contact_id, field, self.version);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::OpenFailed)?;
        let mut packed = Vec::with_capacity(1 + VERSION_BYTES + NONCE_BYTES + ciphertext.len());
        packed.push(FIELD_FORMAT);
        packed.extend_from_slice(&self.version.to_be_bytes());
        packed.extend_from_slice(&nonce);
        packed.extend_from_slice(&ciphertext);
        Ok(packed)
    }

    /// Opens one field, selecting the key by the stored version (active or
    /// rotation secondary). Any tampering, truncation or binding mismatch
    /// fails closed.
    pub fn open(
        &self,
        account_id: Uuid,
        contact_id: Uuid,
        field: ContactField,
        packed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if packed.len() < 1 + VERSION_BYTES + NONCE_BYTES + TAG_BYTES + FIELD_PLAINTEXT_MIN
            || packed.len() > 1 + VERSION_BYTES + NONCE_BYTES + TAG_BYTES + FIELD_PLAINTEXT_MAX
            || packed[0] != FIELD_FORMAT
        {
            return Err(VaultError::OpenFailed);
        }
        let mut version_bytes = [0_u8; VERSION_BYTES];
        version_bytes.copy_from_slice(&packed[1..1 + VERSION_BYTES]);
        let version = i32::from_be_bytes(version_bytes);
        let key = self.key_for(version)?;
        let cipher = Aes256Gcm::new_from_slice(&**key).map_err(|_| VaultError::InvalidKey)?;
        let aad = field_aad(account_id, contact_id, field, version);
        let nonce = Nonce::try_from(&packed[1 + VERSION_BYTES..1 + VERSION_BYTES + NONCE_BYTES])
            .map_err(|_| VaultError::OpenFailed)?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &packed[1 + VERSION_BYTES + NONCE_BYTES..],
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::OpenFailed)?;
        if !(FIELD_PLAINTEXT_MIN..=FIELD_PLAINTEXT_MAX).contains(&plaintext.len()) {
            return Err(VaultError::OpenFailed);
        }
        Ok(Zeroizing::new(plaintext))
    }
}

fn fixed_key(version: i32, key: Zeroizing<Vec<u8>>) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    if version <= 0 || key.len() != 32 {
        return Err(VaultError::InvalidKey);
    }
    let mut fixed = Zeroizing::new([0_u8; 32]);
    fixed.copy_from_slice(&key);
    Ok(fixed)
}

/// The authenticated context: domain tag, key version, account, contact and
/// column. Cross-tenant, cross-contact and cross-column moves all fail.
fn field_aad(account_id: Uuid, contact_id: Uuid, field: ContactField, version: i32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(57);
    aad.extend_from_slice(b"ZTCONTACTS/field/v1");
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(account_id.as_bytes());
    aad.extend_from_slice(contact_id.as_bytes());
    aad.push(field.aad_byte());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> ContactFieldVault {
        ContactFieldVault::new(1, Zeroizing::new(vec![7_u8; 32])).unwrap()
    }

    #[test]
    fn seal_and_open_round_trip_the_same_field() {
        let (account, contact) = (Uuid::new_v4(), Uuid::new_v4());
        let vault = vault();
        let packed = vault
            .seal(account, contact, ContactField::Notes, b"prefers morning")
            .unwrap();
        let opened = vault
            .open(account, contact, ContactField::Notes, &packed)
            .unwrap();
        assert_eq!(opened.as_slice(), b"prefers morning");
    }

    #[test]
    fn sealed_plaintext_never_appears_in_the_ciphertext() {
        let (account, contact) = (Uuid::new_v4(), Uuid::new_v4());
        let secret = "synthetic secret note";
        let packed = vault()
            .seal(
                account,
                contact,
                ContactField::DisplayName,
                secret.as_bytes(),
            )
            .unwrap();
        assert!(
            !packed
                .windows(secret.len())
                .any(|window| window == secret.as_bytes())
        );
    }

    #[test]
    fn ciphertext_bound_to_account_contact_and_column() {
        let (account, contact) = (Uuid::new_v4(), Uuid::new_v4());
        let vault = vault();
        let packed = vault
            .seal(account, contact, ContactField::DisplayName, b"named")
            .unwrap();
        let other = Uuid::new_v4();
        assert!(
            vault
                .open(other, contact, ContactField::DisplayName, &packed)
                .is_err()
        );
        assert!(
            vault
                .open(account, other, ContactField::DisplayName, &packed)
                .is_err()
        );
        assert!(
            vault
                .open(account, contact, ContactField::Notes, &packed)
                .is_err()
        );
        let mut tampered = packed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            vault
                .open(account, contact, ContactField::DisplayName, &tampered)
                .is_err()
        );
        // Editing the stored key version must not select another key
        // silently; the authenticated AAD makes the tag fail.
        let mut reversioned = packed.clone();
        reversioned[1] = 0;
        reversioned[2] = 0;
        reversioned[3] = 0;
        reversioned[4] = 2;
        assert!(
            vault
                .open(account, contact, ContactField::DisplayName, &reversioned)
                .is_err()
        );
    }

    #[test]
    fn secondary_key_opens_and_active_key_seals_during_rotation() {
        let account = Uuid::new_v4();
        let contact = Uuid::new_v4();
        let old = ContactFieldVault::new(1, Zeroizing::new(vec![1_u8; 32])).unwrap();
        let packed = old
            .seal(account, contact, ContactField::Notes, b"rotation note")
            .unwrap();
        let rotated = ContactFieldVault::with_secondary(
            2,
            Zeroizing::new(vec![2_u8; 32]),
            Some((1, Zeroizing::new(vec![1_u8; 32]))),
        )
        .unwrap();
        let resealed = rotated
            .seal(account, contact, ContactField::Notes, b"new note")
            .unwrap();
        assert!(
            rotated
                .open(account, contact, ContactField::Notes, &packed)
                .is_ok()
        );
        assert!(
            rotated
                .open(account, contact, ContactField::Notes, &resealed)
                .is_ok()
        );
        assert_eq!(
            rotated
                .open(account, contact, ContactField::Notes, &packed)
                .unwrap()
                .as_slice(),
            b"rotation note"
        );
        // After rotation the old key alone can no longer read new rows.
        assert!(
            old.open(account, contact, ContactField::Notes, &resealed)
                .is_err()
        );
    }

    #[test]
    fn rejects_bad_keys_and_out_of_bound_plaintexts() {
        assert!(ContactFieldVault::new(0, Zeroizing::new(vec![1_u8; 32])).is_err());
        assert!(ContactFieldVault::new(1, Zeroizing::new(vec![1_u8; 31])).is_err());
        assert!(
            ContactFieldVault::with_secondary(
                1,
                Zeroizing::new(vec![1_u8; 32]),
                Some((1, Zeroizing::new(vec![1_u8; 32]))),
            )
            .is_err()
        );
        let (account, contact) = (Uuid::new_v4(), Uuid::new_v4());
        let vault = vault();
        assert!(
            vault
                .seal(account, contact, ContactField::Notes, b"")
                .is_err()
        );
        assert!(
            vault
                .seal(
                    account,
                    contact,
                    ContactField::Notes,
                    &vec![0_u8; FIELD_PLAINTEXT_MAX + 1]
                )
                .is_err()
        );
        assert!(
            vault
                .open(account, contact, ContactField::Notes, &[])
                .is_err()
        );
        assert!(
            vault
                .open(account, contact, ContactField::Notes, &[9_u8; 8])
                .is_err()
        );
    }
}
