// SPDX-License-Identifier: AGPL-3.0-only
//! Exact original SEALED-v2 signature evidence. This codec supplies no accepted
//! database receipt, binding allocation, current session or effect permission.
use super::{
    Check,
    adapter_contract::{self, OldBindingIdentity03, RegistrationEvidence03},
    nonzero, time,
};
use crate::sealed_inbound::line_activation::v2::{self, PurposeV2};
use crate::sealed_manifest03::{framed, sha};
use p256::ecdsa::{Signature, VerifyingKey};
use zrotext_root_material::line_key_registration as registration;

const LABEL: &[u8] = b"ZTSE/line/payload-profile/activation-evidence/v1\0";
const REGISTRATION_LABEL: &[u8] = b"ZTSE/line/payload-profile/registration-evidence/v1\0";
const FIXED_PAYLOAD: usize = 743;

/// Owned structural fields only. Constructing or decoding this value does not
/// authenticate either point, a historical checkpoint or the binding UUID.
#[derive(Clone)]
pub struct ActivationEvidence03 {
    pub registration_id: [u8; 16],
    pub old_binding_id: [u8; 16],
    pub device_point: [u8; 65],
    pub owner_point: [u8; 65],
    pub device_statement: [u8; 255],
    pub device_signature_der: Vec<u8>,
    pub owner_statement: [u8; 314],
    pub owner_signature_der: Vec<u8>,
    pub accepted_ms: u64,
}

/// Expectations from independently selected original registration/binding
/// records and configured origin. Caller input cannot establish their provenance.
pub struct ExpectedActivation03<'a> {
    pub identity: super::registration_reader::OriginalIdentity,
    pub old_binding_id: [u8; 16],
    pub root_fingerprint: [u8; 32],
    pub paired_signing_key_id: [u8; 32],
    pub selected_reader_key_id: [u8; 32],
    pub canonical_origin: &'a str,
}

/// Cryptographic historical proof relative to explicit original expectations.
/// No current permission, allocation or committed acceptance is inferred.
pub struct VerifiedActivationEvidence03 {
    canonical: Vec<u8>,
    old_binding_digest: [u8; 32],
}
impl VerifiedActivationEvidence03 {
    pub fn canonical_evidence(&self) -> &[u8] {
        &self.canonical
    }
    pub fn old_binding_proof_digest(&self) -> &[u8; 32] {
        &self.old_binding_digest
    }
}

fn der(bytes: &[u8]) -> Check<()> {
    if !(8..=80).contains(&bytes.len()) {
        return Err("activation DER size");
    }
    let parsed = Signature::from_der(bytes).map_err(|_| "activation DER")?;
    if parsed.to_der().as_bytes() != bytes {
        return Err("activation DER canonical");
    }
    // Existing v2 accepts high-S. Never normalize or silently change its policy.
    Ok(())
}
fn point(bytes: &[u8; 65]) -> Check<()> {
    if bytes[0] != 4 || VerifyingKey::from_sec1_bytes(bytes).is_err() {
        return Err("activation point");
    }
    Ok(())
}
impl ActivationEvidence03 {
    fn shape(&self) -> Check<v2::DeviceStatementBytesV2> {
        nonzero(&self.registration_id)?;
        nonzero(&self.old_binding_id)?;
        time(self.accepted_ms)?;
        point(&self.device_point)?;
        point(&self.owner_point)?;
        if self.device_point == self.owner_point
            || self.device_statement[86..102] == self.old_binding_id
        {
            return Err("activation role/binding identity");
        }
        der(&self.device_signature_der)?;
        der(&self.owner_signature_der)?;
        let statement =
            v2::DeviceStatementBytesV2::decode(PurposeV2::Sealed, &self.device_statement)
                .map_err(|_| "activation device statement")?;
        let owner = v2::owner_statement(&statement, &self.device_signature_der)
            .map_err(|_| "activation owner statement")?;
        if owner.bytes() != self.owner_statement {
            return Err("activation owner commitment");
        }
        Ok(statement)
    }

    pub fn canonical(&self) -> Check<Vec<u8>> {
        self.shape()?;
        let mut payload = Vec::with_capacity(
            FIXED_PAYLOAD + self.device_signature_der.len() + self.owner_signature_der.len(),
        );
        for bytes in [
            &self.registration_id[..],
            &self.old_binding_id,
            &self.device_point,
            &self.owner_point,
            &self.device_statement,
        ] {
            payload.extend_from_slice(bytes);
        }
        payload.extend_from_slice(&(self.device_signature_der.len() as u16).to_be_bytes());
        payload.extend_from_slice(&self.device_signature_der);
        payload.extend_from_slice(&self.owner_statement);
        payload.extend_from_slice(&(self.owner_signature_der.len() as u16).to_be_bytes());
        payload.extend_from_slice(&self.owner_signature_der);
        payload.extend_from_slice(&self.accepted_ms.to_be_bytes());
        framed(LABEL, &payload)
    }

    pub fn decode(bytes: &[u8]) -> Check<Self> {
        let mut payload = Cursor::frame(bytes, LABEL, FIXED_PAYLOAD + 16, FIXED_PAYLOAD + 160)?;
        let registration_id = payload.fixed()?;
        let old_binding_id = payload.fixed()?;
        let device_point = payload.fixed()?;
        let owner_point = payload.fixed()?;
        let device_statement = payload.fixed()?;
        let n = usize::from(u16::from_be_bytes(payload.fixed()?));
        if !(8..=80).contains(&n) {
            return Err("activation DER size");
        }
        let device_signature_der = payload.take(n)?.to_vec();
        let owner_statement = payload.fixed()?;
        let n = usize::from(u16::from_be_bytes(payload.fixed()?));
        if !(8..=80).contains(&n) {
            return Err("activation DER size");
        }
        let owner_signature_der = payload.take(n)?.to_vec();
        let accepted_ms = u64::from_be_bytes(payload.fixed()?);
        payload.end()?;
        let evidence = Self {
            registration_id,
            old_binding_id,
            device_point,
            owner_point,
            device_statement,
            device_signature_der,
            owner_statement,
            owner_signature_der,
            accepted_ms,
        };
        if evidence.canonical()? != bytes {
            return Err("activation canonical encoding");
        }
        Ok(evidence)
    }

    /// Reverify the exact original registration and both activation signatures.
    /// The caller still owns actual immutable receipt/mapping provenance and all
    /// present owner/session/lease/election/state authorization checks.
    pub fn verify_original(
        &self,
        registration_evidence: &[u8],
        expected: &ExpectedActivation03<'_>,
    ) -> Check<VerifiedActivationEvidence03> {
        let device = self.shape()?;
        adapter_contract::origin_digest(expected.canonical_origin)?;
        let original = original_registration(registration_evidence)?;
        let r = &original.statement;
        let scope = r.scope();
        let id = expected.identity;
        if scope.account != *id.account.as_bytes()
            || scope.user != *id.user.as_bytes()
            || scope.owner_session != *id.owner_session.as_bytes()
            || scope.device != *id.device.as_bytes()
            || scope.line != *id.line.as_bytes()
            || scope.challenge != *id.registration.as_bytes()
            || scope.next_generation != id.generation
            || scope.origin != expected.canonical_origin
            || self.registration_id != *id.registration.as_bytes()
            || self.old_binding_id != expected.old_binding_id
            || r.root_fingerprint() != &expected.root_fingerprint
            || original.completed_ms > self.accepted_ms
            || self.accepted_ms >= scope.expires_ms
            || self.owner_point != *r.approval_point()
            || sha(&self.device_point) != scope.paired_signing_fingerprint
            || self.device_point.as_slice() == &r.root_pin()[29..]
            || crate::sealed_manifest::key_id(4, &self.device_point)
                != expected.paired_signing_key_id
        {
            return Err("activation registration/selection mismatch");
        }
        let bytes = &self.device_statement;
        if bytes[30..46] != scope.account
            || bytes[46..62] != scope.line
            || bytes[62..78] != scope.device
            || u64::from_be_bytes(
                bytes[78..86]
                    .try_into()
                    .map_err(|_| "activation generation")?,
            ) != scope.next_generation
        {
            return Err("activation original scope");
        }
        let owner = v2::owner_statement(&device, &self.device_signature_der)
            .map_err(|_| "activation owner statement")?;
        if !v2::verify_device_signature(&self.device_point, &device, &self.device_signature_der)
            || !v2::verify_owner_signature(&self.owner_point, &owner, &self.owner_signature_der)
        {
            return Err("activation original signatures");
        }
        let identity = OldBindingIdentity03 {
            binding_id: self.old_binding_id,
            account_id: scope.account,
            device_id: scope.device,
            line_id: scope.line,
            generation: scope.next_generation,
            activation_challenge_id: bytes[86..102]
                .try_into()
                .map_err(|_| "activation challenge")?,
            registration_id: self.registration_id,
            registration_evidence_sha256: sha(registration_evidence),
            owner_approval_digest: sha(&[
                self.owner_statement.as_slice(),
                &self.owner_signature_der,
            ]
            .concat()),
            device_confirmation_digest: sha(
                &[bytes.as_slice(), &self.device_signature_der].concat()
            ),
            selected_reader_key_id: expected.selected_reader_key_id,
        };
        Ok(VerifiedActivationEvidence03 {
            canonical: self.canonical()?,
            old_binding_digest: identity.digest()?,
        })
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn frame(bytes: &'a [u8], label: &[u8], min: usize, max: usize) -> Check<Self> {
        if bytes.len() < label.len() + 4 + min
            || bytes.len() > label.len() + 4 + max
            || !bytes.starts_with(label)
        {
            return Err("evidence frame");
        }
        let n = u32::from_be_bytes(
            bytes[label.len()..label.len() + 4]
                .try_into()
                .map_err(|_| "evidence length")?,
        ) as usize;
        if n != bytes.len() - label.len() - 4 {
            return Err("evidence length");
        }
        Ok(Self {
            bytes: &bytes[label.len() + 4..],
            at: 0,
        })
    }
    fn take(&mut self, n: usize) -> Check<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or("evidence offset")?;
        let bytes = self.bytes.get(self.at..end).ok_or("evidence truncated")?;
        self.at = end;
        Ok(bytes)
    }
    fn fixed<const N: usize>(&mut self) -> Check<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| "evidence field")
    }
    fn end(&self) -> Check<()> {
        if self.at != self.bytes.len() {
            return Err("evidence trailing");
        }
        Ok(())
    }
}

struct OriginalRegistration {
    statement: registration::Statement,
    completed_ms: u64,
}
fn original_registration(bytes: &[u8]) -> Check<OriginalRegistration> {
    let mut c = Cursor::frame(bytes, REGISTRATION_LABEL, 286, 1309)?;
    let n = u32::from_be_bytes(c.fixed()?) as usize;
    if n == 0 || n > registration::MAX_TRANSCRIPT {
        return Err("registration transcript bounds");
    }
    let transcript = c.take(n)?;
    let root_signature = c.fixed::<64>()?;
    let approval_signature = c.fixed::<64>()?;
    let approval_point = c.fixed::<65>()?;
    let approval_fingerprint = c.fixed::<32>()?;
    let paired_fingerprint = c.fixed::<32>()?;
    let issued_ms = u64::from_be_bytes(c.fixed()?);
    let expires_ms = u64::from_be_bytes(c.fixed()?);
    let completed_ms = u64::from_be_bytes(c.fixed()?);
    c.end()?;
    let evidence = RegistrationEvidence03 {
        transcript,
        root_signature: &root_signature,
        approval_signature: &approval_signature,
        approval_point: &approval_point,
        approval_fingerprint: &approval_fingerprint,
        paired_fingerprint: &paired_fingerprint,
        issued_ms,
        expires_ms,
        completed_ms,
    };
    if evidence.canonical()? != bytes {
        return Err("registration canonical encoding");
    }
    let statement = registration::decode(transcript).map_err(|_| "registration transcript")?;
    let scope = statement.scope();
    if registration::encode(&statement).map_err(|_| "registration encoding")? != transcript
        || statement.approval_point() != &approval_point
        || scope.approval_fingerprint != approval_fingerprint
        || scope.paired_signing_fingerprint != paired_fingerprint
        || scope.issued_ms != issued_ms
        || scope.expires_ms != expires_ms
    {
        return Err("registration original metadata");
    }
    statement
        .verify_root(&root_signature)
        .map_err(|_| "registration root signature")?;
    statement
        .verify_approval(&approval_signature)
        .map_err(|_| "registration approval signature")?;
    Ok(OriginalRegistration {
        statement,
        completed_ms,
    })
}

#[cfg(test)]
mod tests;
