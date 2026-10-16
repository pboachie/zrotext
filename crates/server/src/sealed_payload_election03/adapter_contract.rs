// SPDX-License-Identifier: AGPL-3.0-only
//! Candidate canonical identity bytes, not an authenticated production adapter.
//!
//! Callers must reconstruct these fields from independently locked records and
//! recheck current permission. No constructor here authenticates caller input,
//! verifies a receipt, reserves a generation, or installs a database fence.
use super::{Check, framed, nonzero, sha, time};

fn id(value: &[u8; 16]) -> Check<()> {
    nonzero(value)
}

fn text(bytes: &mut Vec<u8>, value: &str) -> Check<()> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err("session identifier text");
    }
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

/// The configured canonical HTTPS origin, after independent request-origin
/// validation. An untrusted request string cannot establish this provenance.
pub fn origin_digest(origin: &str) -> Check<[u8; 32]> {
    let parsed = url::Url::parse(origin).map_err(|_| "canonical origin")?;
    if parsed.scheme() != "https"
        || !parsed.has_host()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.origin().ascii_serialization() != origin
    {
        return Err("canonical origin");
    }
    Ok(sha(origin.as_bytes()))
}

/// Derive the protocol signing-key identity from the independently read
/// current enrolled point. The database fingerprint uses a different domain.
/// This consistency check does not authenticate the row or its currentness.
pub fn enrollment_signing_key_id(point: &[u8], stored_fingerprint: &[u8; 32]) -> Check<[u8; 32]> {
    if point.len() != 65 || point[0] != 4 || sha(point) != *stored_fingerprint {
        return Err("enrollment point/fingerprint");
    }
    p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|_| "enrollment point curve")?;
    Ok(crate::sealed_manifest::key_id(4, point))
}

/// Stable identity only. Membership/role, MFA, idle timeout, CSRF and expiry
/// remain separate current database predicates, never signed booleans here.
pub struct OwnerSessionIdentity03 {
    pub account_id: [u8; 16],
    pub user_id: [u8; 16],
    pub session_id: [u8; 16],
}

impl OwnerSessionIdentity03 {
    pub fn canonical(&self) -> Check<Vec<u8>> {
        let mut bytes = Vec::with_capacity(48);
        for value in [&self.account_id, &self.user_id, &self.session_id] {
            id(value)?;
            bytes.extend_from_slice(value);
        }
        framed(b"ZTSE/line/payload-profile/owner-session/v1\0", &bytes)
    }

    pub fn digest(&self) -> Check<[u8; 32]> {
        Ok(sha(&self.canonical()?))
    }
}

/// Full authenticated lease identity. A copied DeviceSession's account,
/// device and connection epoch alone cannot populate this record faithfully.
pub struct DeviceSessionIdentity03<'a> {
    pub account_id: [u8; 16],
    pub device_id: [u8; 16],
    pub site_id: &'a str,
    pub instance_id: &'a str,
    pub connection_epoch: u64,
    pub deployment_epoch: u64,
    pub line_activation_version: u16,
    pub enrollment_signing_key_id: [u8; 32],
}

impl DeviceSessionIdentity03<'_> {
    pub fn canonical(&self) -> Check<Vec<u8>> {
        id(&self.account_id)?;
        id(&self.device_id)?;
        time(self.connection_epoch)?;
        time(self.deployment_epoch)?;
        nonzero(&self.enrollment_signing_key_id)?;
        if self.line_activation_version != 2 {
            return Err("unsupported line activation origin");
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.account_id);
        bytes.extend_from_slice(&self.device_id);
        text(&mut bytes, self.site_id)?;
        text(&mut bytes, self.instance_id)?;
        bytes.extend_from_slice(&self.connection_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.deployment_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.line_activation_version.to_be_bytes());
        bytes.extend_from_slice(&self.enrollment_signing_key_id);
        framed(b"ZTSE/line/payload-profile/device-session/v1\0", &bytes)
    }

    pub fn digest(&self) -> Check<[u8; 32]> {
        Ok(sha(&self.canonical()?))
    }
}

/// Inputs from an insert-once binding mapping and verified immutable v2
/// activation/registration evidence. Hashing unverified rows is not acceptance.
pub struct OldBindingIdentity03 {
    pub binding_id: [u8; 16],
    pub account_id: [u8; 16],
    pub device_id: [u8; 16],
    pub line_id: [u8; 16],
    pub generation: u64,
    pub activation_challenge_id: [u8; 16],
    pub registration_id: [u8; 16],
    pub registration_evidence_sha256: [u8; 32],
    pub owner_approval_digest: [u8; 32],
    pub device_confirmation_digest: [u8; 32],
    pub selected_reader_key_id: [u8; 32],
}

impl OldBindingIdentity03 {
    pub fn canonical(&self) -> Check<Vec<u8>> {
        time(self.generation)?;
        let mut bytes = vec![2, 2]; // Envelope02, actual line-activation origin2.
        for value in [
            &self.binding_id,
            &self.account_id,
            &self.device_id,
            &self.line_id,
        ] {
            id(value)?;
            bytes.extend_from_slice(value);
        }
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        for value in [&self.activation_challenge_id, &self.registration_id] {
            id(value)?;
            bytes.extend_from_slice(value);
        }
        for value in [
            &self.registration_evidence_sha256,
            &self.owner_approval_digest,
            &self.device_confirmation_digest,
            &self.selected_reader_key_id,
        ] {
            nonzero(value)?;
            bytes.extend_from_slice(value);
        }
        framed(b"ZTSE/line/payload-profile/old-binding/v1\0", &bytes)
    }

    pub fn digest(&self) -> Check<[u8; 32]> {
        Ok(sha(&self.canonical()?))
    }
}

/// Byte-exact immutable columns of sealed_line_key_receipts. The production
/// adapter must separately verify the existing RootLineRegister transcript,
/// both received signatures, key fingerprints and authenticated acceptance.
pub struct RegistrationEvidence03<'a> {
    pub transcript: &'a [u8],
    pub root_signature: &'a [u8; 64],
    pub approval_signature: &'a [u8; 64],
    pub approval_point: &'a [u8; 65],
    pub approval_fingerprint: &'a [u8; 32],
    pub paired_fingerprint: &'a [u8; 32],
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub completed_ms: u64,
}

impl RegistrationEvidence03<'_> {
    pub fn canonical(&self) -> Check<Vec<u8>> {
        for value in [self.issued_ms, self.expires_ms, self.completed_ms] {
            time(value)?;
        }
        if self.transcript.is_empty()
            || self.transcript.len() > 1024
            || self.expires_ms <= self.issued_ms
            || self.expires_ms - self.issued_ms > 300_000
            || self.completed_ms < self.issued_ms
            || self.completed_ms >= self.expires_ms
        {
            return Err("registration evidence bounds");
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.transcript.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.transcript);
        bytes.extend_from_slice(self.root_signature);
        bytes.extend_from_slice(self.approval_signature);
        bytes.extend_from_slice(self.approval_point);
        bytes.extend_from_slice(self.approval_fingerprint);
        bytes.extend_from_slice(self.paired_fingerprint);
        bytes.extend_from_slice(&self.issued_ms.to_be_bytes());
        bytes.extend_from_slice(&self.expires_ms.to_be_bytes());
        bytes.extend_from_slice(&self.completed_ms.to_be_bytes());
        framed(
            b"ZTSE/line/payload-profile/registration-evidence/v1\0",
            &bytes,
        )
    }

    pub fn digest(&self) -> Check<[u8; 32]> {
        Ok(sha(&self.canonical()?))
    }
}

/// Candidate exclusion resource only, never an identity or permission proof.
/// A collision can cause contention/refusal; row account checks remain exact.
pub fn account_fence_key(account: &[u8; 16]) -> Check<i64> {
    id(account)?;
    let digest = sha(&framed(
        b"ZTSE/line/payload-profile/account-fence/v1\0",
        account,
    )?);
    Ok(i64::from_be_bytes(digest[..8].try_into().unwrap()))
}

#[cfg(test)]
mod catalog_tests;
#[cfg(test)]
mod fence_tests;
#[cfg(test)]
mod snapshot_tests;
#[cfg(test)]
mod tests;
