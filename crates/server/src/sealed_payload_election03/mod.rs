// SPDX-License-Identifier: AGPL-3.0-only
//! Historical cryptographic proof relative to explicit authenticated adapter
//! inputs. This does not prove a commit, sessions/MFA, allocation or permission.

pub mod activation_evidence;
pub mod activation_records;
pub mod adapter_contract;
pub mod device_context;
pub mod live;
pub mod owner_records;
pub mod registration_reader;

#[cfg(test)]
mod test_database;

use crate::sealed_manifest;
use crate::sealed_manifest03::{
    Check, MAX, VerifiedCheckpoint02, VerifiedManifest03, framed, number, sha, signature, time,
    verify_from_02,
};

/// Trusted immutable accepted record. Its origin is an adapter obligation, not
/// a signature conferred by this Rust type or by received digest equality.
#[derive(Clone)]
pub struct DurableAcceptedElection03 {
    pub account_id: [u8; 16],
    pub device_id: [u8; 16],
    pub line_id: [u8; 16],
    pub root_fingerprint: [u8; 32],
    pub vault_generation: u64,
    pub old_binding_id: [u8; 16],
    pub old_binding_generation: u64,
    pub old_binding_proof_digest: [u8; 32],
    pub new_binding_id: [u8; 16],
    pub new_binding_generation: u64,
    pub selected_reader_key_id: [u8; 32],
    pub prior_manifest_version: u64,
    pub prior_manifest_digest: [u8; 32],
    pub prior_signed_manifest_sha256: [u8; 32],
    pub accepted_manifest_version: u64,
    pub accepted_manifest_digest: [u8; 32],
    pub accepted_signed_manifest_sha256: [u8; 32],
    pub election_core_sha256: [u8; 32],
    pub election_commitment: [u8; 32],
    pub election_bundle_sha256: [u8; 32],
    pub accepted_at_ms: u64,
}
/// Trusted PRESENT selection/permission read, never an echoed received proof.
#[derive(Clone)]
pub struct CurrentAuthority03 {
    pub profile: u8,
    pub manifest_profile: u8,
    pub account_id: [u8; 16],
    pub device_id: [u8; 16],
    pub line_id: [u8; 16],
    pub binding_id: [u8; 16],
    pub binding_generation: u64,
    pub selected_reader_key_id: [u8; 32],
    pub root_fingerprint: [u8; 32],
    pub vault_generation: u64,
    pub manifest_version: u64,
    pub manifest_digest: [u8; 32],
    pub election_commitment: [u8; 32],
    pub election_bundle_sha256: [u8; 32],
    pub compared_at_ms: u64,
    pub permission_expires_at_ms: u64,
}
pub struct VerifiedElection03 {
    accepted: DurableAcceptedElection03,
    root_point: [u8; 65],
}

pub struct AcceptedProofInput03<'a> {
    pub bundle: &'a [u8],
    pub expected_core: &'a [u8],
    pub accepted: &'a DurableAcceptedElection03,
    pub predecessor02: &'a VerifiedCheckpoint02,
    pub accepted_signed_manifest03: &'a [u8],
    pub device_signing_point_at_acceptance: &'a [u8; 65],
    pub owner_approval_point_at_acceptance: &'a [u8; 65],
}
fn nonzero(bytes: &[u8]) -> Check<()> {
    if bytes.iter().all(|b| *b == 0) {
        return Err("zero identity/digest");
    }
    Ok(())
}
fn accepted_shape(a: &DurableAcceptedElection03) -> Check<()> {
    for id in [
        &a.account_id,
        &a.device_id,
        &a.line_id,
        &a.old_binding_id,
        &a.new_binding_id,
    ] {
        nonzero(id)?;
    }
    for d in [
        &a.root_fingerprint,
        &a.old_binding_proof_digest,
        &a.selected_reader_key_id,
        &a.prior_manifest_digest,
        &a.prior_signed_manifest_sha256,
        &a.accepted_manifest_digest,
        &a.accepted_signed_manifest_sha256,
        &a.election_core_sha256,
        &a.election_commitment,
        &a.election_bundle_sha256,
    ] {
        nonzero(d)?;
    }
    for n in [
        a.vault_generation,
        a.old_binding_generation,
        a.new_binding_generation,
        a.prior_manifest_version,
        a.accepted_manifest_version,
        a.accepted_at_ms,
    ] {
        time(n)?;
    }
    Ok(())
}
/// Exact historical evidence and signatures only. Historical selected-reader
/// role and registry/session selection are trusted H2 acceptance obligations.
pub fn verify_accepted(input: &AcceptedProofInput03<'_>) -> Check<VerifiedElection03> {
    let a = input.accepted;
    accepted_shape(a)?;
    if input.bundle.len() != 628 || input.expected_core.len() != 500 {
        return Err("election size");
    }
    let core = &input.bundle[..500];
    if core != input.expected_core || &core[..8] != b"ZTPE\x03\x01\x02\x03" || core[496..] != [0; 4]
    {
        return Err("core framing/context");
    }
    nonzero(&core[56..72])?;
    nonzero(&core[352..384])?;
    for (at, expected) in [
        (8, a.account_id.as_slice()),
        (24, &a.device_id),
        (40, &a.line_id),
        (72, &a.old_binding_id),
        (104, &a.old_binding_proof_digest),
        (136, &a.root_fingerprint),
        (184, &a.prior_manifest_digest),
        (224, &a.accepted_manifest_digest),
        (256, &a.selected_reader_key_id),
    ] {
        if &core[at..at + expected.len()] != expected {
            return Err("accepted field mismatch");
        }
    }
    for (at, n) in [
        (88, a.old_binding_generation),
        (96, a.new_binding_generation),
        (168, a.vault_generation),
        (176, a.prior_manifest_version),
        (216, a.accepted_manifest_version),
    ] {
        if number(&core[at..at + 8])? != n {
            return Err("accepted integer mismatch");
        }
    }
    let issued = number(&core[384..392])?;
    let expires = number(&core[392..400])?;
    time(issued)?;
    time(expires)?;
    for at in [400, 432, 464] {
        nonzero(&core[at..at + 32])?;
    }
    if expires <= issued
        || expires - issued > 300_000
        || a.accepted_at_ms < issued
        || a.accepted_at_ms >= expires
        || a.accepted_at_ms < input.predecessor02.original_accepted_at()
        || a.new_binding_generation <= a.old_binding_generation
        || a.vault_generation != 1
        || a.prior_manifest_version == MAX
        || a.prior_manifest_version + 1 != a.accepted_manifest_version
    {
        return Err("acceptance time/generation");
    }
    if input.predecessor02.signed_sha256() != a.prior_signed_manifest_sha256
        || sha(input.accepted_signed_manifest03) != a.accepted_signed_manifest_sha256
        || sha(core) != a.election_core_sha256
        || sha(input.bundle) != a.election_bundle_sha256
        || sha(&framed(b"ZTSE/line/payload-profile/commitment/v1\0", core)?)
            != a.election_commitment
    {
        return Err("original evidence digest");
    }
    let manifest = verify_from_02(
        input.accepted_signed_manifest03,
        input.predecessor02,
        a.accepted_at_ms,
    )?;
    let id = manifest.identity_at(a.accepted_at_ms)?;
    if id.account_id != a.account_id
        || id.generation != a.vault_generation
        || id.version != a.accepted_manifest_version
        || id.digest != a.accepted_manifest_digest
        || manifest.signed_sha256() != a.accepted_signed_manifest_sha256
        || input.predecessor02.identity()? != (a.prior_manifest_version, a.prior_manifest_digest)
        || input.predecessor02.fingerprint() != a.root_fingerprint
    {
        return Err("manifest acceptance binding");
    }
    let device = input.device_signing_point_at_acceptance;
    let owner = input.owner_approval_point_at_acceptance;
    if sealed_manifest::key_id(4, device) != core[288..320]
        || sealed_manifest::key_id(4, owner) != core[320..352]
    {
        return Err("registry signing key id");
    }
    let device_sig = &input.bundle[500..564];
    signature(
        device,
        device_sig,
        &framed(b"ZTSE/line/payload-profile/device/v1\0", core)?,
    )?;
    let owner_payload = [core, &sha(device_sig)].concat();
    signature(
        owner,
        &input.bundle[564..],
        &framed(b"ZTSE/line/payload-profile/owner/v1\0", &owner_payload)?,
    )?;
    Ok(VerifiedElection03 {
        accepted: a.clone(),
        root_point: id.root_point,
    })
}

/// Validate a separately authenticated current tuple against historical proof
/// and genuine current manifest. This still does not prove live permission,
/// durable ancestry, session provenance or atomic fork selection by itself.
pub fn require_current(
    proof: &VerifiedElection03,
    manifest: &VerifiedManifest03,
    current: &CurrentAuthority03,
    now: u64,
) -> Check<CurrentAuthority03> {
    time(now)?;
    let a = &proof.accepted;
    let c = current;
    for n in [
        c.binding_generation,
        c.vault_generation,
        c.manifest_version,
        c.compared_at_ms,
        c.permission_expires_at_ms,
    ] {
        time(n)?;
    }
    if c.profile != 3
        || c.manifest_profile != 3
        || now < a.accepted_at_ms
        || now < c.compared_at_ms
        || now >= c.permission_expires_at_ms
    {
        return Err("current profile/time/permission");
    }
    if c.account_id != a.account_id
        || c.device_id != a.device_id
        || c.line_id != a.line_id
        || c.binding_id != a.new_binding_id
        || c.binding_generation != a.new_binding_generation
        || c.selected_reader_key_id != a.selected_reader_key_id
        || c.root_fingerprint != a.root_fingerprint
        || c.vault_generation != a.vault_generation
        || c.election_commitment != a.election_commitment
        || c.election_bundle_sha256 != a.election_bundle_sha256
        || c.manifest_version < a.accepted_manifest_version
    {
        return Err("current binding/election mismatch");
    }
    let id = manifest.identity_at(now)?;
    if id.account_id != c.account_id
        || id.root_point != proof.root_point
        || id.generation != c.vault_generation
        || id.version != c.manifest_version
        || id.digest != c.manifest_digest
        || c.manifest_version == a.accepted_manifest_version
            && c.manifest_digest != a.accepted_manifest_digest
    {
        return Err("current manifest binding");
    }
    Ok(c.clone())
}

#[cfg(test)]
pub(crate) mod tests;
