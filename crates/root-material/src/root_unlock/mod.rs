// SPDX-License-Identifier: AGPL-3.0-only
//! Candidate one-challenge unlock and typed custody signing from a recovered root.
//!
//! This module turns an already recovered root and an independently intended
//! identity into one enrollment possession signature. It does not enroll a
//! root, contact a server, persist or cache any unlock state, or establish
//! custody. The server re-exports nothing from here; possession remains
//! non-authority. The root exists only in caller memory, and no hardware-backed
//! key custody is involved or claimed anywhere in this crate.

use crate::{
    root_backup::{ExpectedIdentity, RootSecret},
    sealed_root_enrollment::{self, Challenge},
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::sec1::ToSec1Point,
};

pub mod custody;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UnlockError {
    #[error("invalid unlock challenge input")]
    InvalidInput,
    #[error("unlock challenge does not match the independently expected identity")]
    ContextRejected,
    #[error("unlock challenge expired or not yet valid")]
    TimeRejected,
    #[error("unlock signing operation failed")]
    Crypto,
}

/// Bind public challenge bytes to an independently supplied identity and clock.
/// Returns the parsed public challenge for display. Only the three fields an
/// owner can know independently (account, origin, root fingerprint) are bound;
/// user, session and challenge identities stay inside the signed transcript and
/// remain server-side obligations. Never derive the expected identity from the
/// challenge itself.
pub fn inspect_challenge(
    unsigned: &[u8],
    expected: &ExpectedIdentity,
    now_ms: u64,
) -> Result<Challenge, UnlockError> {
    let challenge =
        sealed_root_enrollment::parse(unsigned).map_err(|_| UnlockError::InvalidInput)?;
    if challenge.account_id != expected.account_id
        || challenge.origin != expected.origin
        || challenge.root_fingerprint != expected.root_fingerprint
    {
        return Err(UnlockError::ContextRejected);
    }
    if now_ms < challenge.issued_ms || now_ms >= challenge.expires_ms {
        return Err(UnlockError::TimeRejected);
    }
    Ok(challenge)
}

/// Sign one exact enrollment challenge with a recovered root. The challenge is
/// first bound to the independently expected identity and signing time, and the
/// root must own that expected fingerprint (the same 94-byte RootPin02
/// construction as `root_backup::check_root`). Returns the canonical low-s
/// 64-byte `r || s` signature for `sealed_root_enrollment::verify`. This grants
/// no authority; one-time challenge consumption stays a server obligation.
pub fn sign_enrollment(
    root: &RootSecret,
    unsigned: &[u8],
    expected: &ExpectedIdentity,
    now_ms: u64,
) -> Result<[u8; 64], UnlockError> {
    inspect_challenge(unsigned, expected, now_ms)?;
    let key = signing_key(root, expected)?;
    let statement =
        sealed_root_enrollment::transcript(unsigned).map_err(|_| UnlockError::InvalidInput)?;
    Ok(sign_statement(key, &statement))
}

fn signing_key(root: &RootSecret, expected: &ExpectedIdentity) -> Result<SigningKey, UnlockError> {
    let secret = p256::SecretKey::from_slice(root.as_bytes()).map_err(|_| UnlockError::Crypto)?;
    let mut pin = Vec::with_capacity(94);
    pin.extend_from_slice(b"ZTRP\x02");
    pin.extend_from_slice(&expected.account_id);
    pin.extend_from_slice(&1_u64.to_be_bytes());
    pin.extend_from_slice(secret.public_key().to_sec1_point(false).as_bytes());
    if sealed_root_enrollment::root_fingerprint(&pin, &expected.account_id)
        .map_err(|_| UnlockError::Crypto)?
        != expected.root_fingerprint
    {
        return Err(UnlockError::ContextRejected);
    }
    Ok(SigningKey::from(secret))
}

fn sign_statement(key: SigningKey, statement: &[u8]) -> [u8; 64] {
    // Signers may canonicalize their own signatures; receivers never normalize.
    let signature: Signature = key.sign(statement);
    let signature = signature.normalize_s();
    let mut output = [0_u8; 64];
    output.copy_from_slice(signature.to_bytes().as_slice());
    output
}

#[cfg(test)]
mod tests;
