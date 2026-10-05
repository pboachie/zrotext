// SPDX-License-Identifier: AGPL-3.0-only
//! Recoverable software owner-root creation and fresh, identity-bound recovery.
//!
//! These operations perform no storage, enrollment, publication, UI or networking.
//! Creation cannot establish that an independently retained kit can be restored.
//! Private root material stays in native zeroizing values and is never a bridge result.

use p256::{
    NonZeroScalar, SecretKey,
    elliptic_curve::{Generate, sec1::ToSec1Point},
};
use rand::{TryCryptoRng, rngs::SysRng};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zrotext_root_material::{
    recovery_kit::{self, KitContext},
    root_backup::{self, BackupError, RecoverySecret},
    sealed_root_enrollment::{canonical_origin, root_fingerprint},
};

pub use zrotext_root_material::root_backup::{ExpectedIdentity, RootSecret};

/// Errors never contain root material, recovery input, decoder details or paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CustodyError {
    #[error("invalid owner custody input")]
    InvalidInput,
    #[error("owner recovery authentication or identity failed")]
    Rejected,
    #[error("owner custody randomness unavailable")]
    Randomness,
    #[error("owner custody cryptographic operation failed")]
    Crypto,
}

impl From<BackupError> for CustodyError {
    fn from(error: BackupError) -> Self {
        match error {
            BackupError::InvalidInput => Self::InvalidInput,
            BackupError::Rejected => Self::Rejected,
            BackupError::Randomness => Self::Randomness,
            BackupError::Crypto => Self::Crypto,
        }
    }
}

/// A newly created kit, with no recovery-ready, enrolled or signing authority.
///
/// The caller must deliberately retain the encrypted backup and public card,
/// separately retain the token and fingerprint, discard creation state, and
/// perform a fresh recovery check. The token is the sole intentional secret
/// result; it has no implicit serialization or nonzeroizing string conversion.
pub struct CreatedKit {
    pub identity: ExpectedIdentity,
    pub root_pin: [u8; 94],
    pub encrypted_backup: Vec<u8>,
    pub public_card: Vec<u8>,
    pub recovery_token: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for CreatedKit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedKit")
            .field("encrypted_backup_length", &self.encrypted_backup.len())
            .field("public_card_length", &self.public_card.len())
            .field("recovery_token", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

fn validate_identity(expected: &ExpectedIdentity) -> Result<(), CustodyError> {
    validate_creation_context(expected.account_id, &expected.origin)
}

fn validate_creation_context(account_id: [u8; 16], origin: &str) -> Result<(), CustodyError> {
    if account_id == [0; 16] || !canonical_origin(origin) {
        return Err(CustodyError::InvalidInput);
    }
    Ok(())
}

fn root_pin(root: &RootSecret, account_id: [u8; 16]) -> Result<[u8; 94], CustodyError> {
    let key = SecretKey::from_slice(root.as_bytes()).map_err(|_| CustodyError::Crypto)?;
    let public = key.public_key().to_sec1_point(false);
    let mut pin = [0; 94];
    pin[..5].copy_from_slice(b"ZTRP\x02");
    pin[5..21].copy_from_slice(&account_id);
    pin[21..29].copy_from_slice(&1_u64.to_be_bytes());
    pin[29..].copy_from_slice(public.as_bytes());
    Ok(pin)
}

/// Generate a new software owner root and an independently random recovery key.
///
/// Uses the existing RootBackup01, PublicRootCard01 and RecoveryToken01 codecs.
/// The software root is distinct from Android hardware device/content keys and
/// is dropped before returning. A codec readback checks newly created bytes but
/// cannot prove export success, independent retention or subsequent recovery.
pub fn create(account_id: [u8; 16], origin: &str) -> Result<CreatedKit, CustodyError> {
    create_with_sources(account_id, origin, &mut SysRng, root_backup::seal)
}

fn create_with_sources<R, S>(
    account_id: [u8; 16],
    origin: &str,
    rng: &mut R,
    seal: S,
) -> Result<CreatedKit, CustodyError>
where
    R: TryCryptoRng,
    S: FnOnce(&RootSecret, &RecoverySecret, &ExpectedIdentity) -> Result<Vec<u8>, BackupError>,
{
    // Reject ambiguous account/origin input before requesting any secret entropy.
    validate_creation_context(account_id, origin)?;
    let scalar = Zeroizing::new(
        NonZeroScalar::try_generate_from_rng(rng).map_err(|_| CustodyError::Randomness)?,
    );
    let key = SecretKey::from(&*scalar);
    let encoded_scalar = Zeroizing::new(key.to_bytes());
    let mut root_bytes = Zeroizing::new([0; 32]);
    root_bytes.copy_from_slice(encoded_scalar.as_slice());
    let root = RootSecret::new(root_bytes).map_err(|_| CustodyError::Crypto)?;
    // Do not retain a second native signing key during backup processing.
    drop(encoded_scalar);
    drop(key);
    drop(scalar);

    let pin = root_pin(&root, account_id)?;
    let identity = ExpectedIdentity {
        account_id,
        origin: origin.to_owned(),
        root_fingerprint: root_fingerprint(&pin, &account_id).map_err(|_| CustodyError::Crypto)?,
    };
    let mut recovery_bytes = Zeroizing::new([0; 32]);
    rng.try_fill_bytes(recovery_bytes.as_mut_slice())
        .map_err(|_| CustodyError::Randomness)?;
    if *recovery_bytes == [0; 32] {
        return Err(CustodyError::Randomness);
    }
    let recovery = RecoverySecret::new(recovery_bytes);
    let encrypted_backup = seal(&root, &recovery, &identity)?;
    let backup_id = root_backup::validate_public_header(&encrypted_backup, &identity)?;
    let context =
        KitContext::new(identity.clone(), &pin, backup_id).map_err(|_| CustodyError::Crypto)?;
    let digest = Sha256::digest(&encrypted_backup).into();
    let public_card = recovery_kit::encode_public_card(&pin, &identity, &digest)
        .map_err(|_| CustodyError::Crypto)?;
    let encoded_token = recovery_kit::encode_token(&recovery, &context);
    let recovery_token = Zeroizing::new(encoded_token.expose_ascii().to_vec());
    drop(encoded_token);
    drop(recovery);

    // Authenticate both backup tags and the actual decrypted public identity.
    // This is deliberately separate from a later retained-kit recovery check.
    let readback = recover(&encrypted_backup, &public_card, &recovery_token, &identity)?;
    if readback.as_bytes() != root.as_bytes() {
        return Err(CustodyError::Crypto);
    }
    drop(readback);
    drop(root);
    Ok(CreatedKit {
        identity,
        root_pin: pin,
        encrypted_backup,
        public_card,
        recovery_token,
    })
}

/// Fresh recovery from independently retained files, token and expected identity.
///
/// No app state, creation object, local wrapper key, password or stored readiness
/// is consulted. The expected account, canonical origin and full fingerprint must
/// come from independent owner intent/comparison, never the files themselves.
/// Success returns native-only zeroizing root material for one approved operation;
/// it does not confer enrollment, trust, replay permission or retained authority.
/// The caller owns and must clear the recovery input buffer as well.
pub fn recover(
    encrypted_backup: &[u8],
    public_card: &[u8],
    recovery_token: &[u8],
    expected: &ExpectedIdentity,
) -> Result<RootSecret, CustodyError> {
    validate_identity(expected)?;
    let backup_id = root_backup::validate_public_header(encrypted_backup, expected)
        .map_err(|_| CustodyError::Rejected)?;
    let digest = Sha256::digest(encrypted_backup).into();
    let card = recovery_kit::decode_public_card(public_card, expected, &digest)
        .map_err(|_| CustodyError::Rejected)?;
    let context = KitContext::new(expected.clone(), card.root_pin(), backup_id)
        .map_err(|_| CustodyError::Rejected)?;
    let recovery =
        recovery_kit::decode_token(recovery_token, &context).map_err(|_| CustodyError::Rejected)?;
    root_backup::open(encrypted_backup, &recovery, expected).map_err(|_| CustodyError::Rejected)
}

#[cfg(test)]
mod tests;
