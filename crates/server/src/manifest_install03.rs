// SPDX-License-Identifier: AGPL-3.0-only
//! Exact public513 possession and narrow root-signed03 successor checks. A
//! cryptographic candidate does not establish cookie/MFA, durable ancestry,
//! current point reservation, physical custody or content permission.
use crate::sealed_manifest03::{self as crypto, Check, VerifiedManifest03};
use uuid::Uuid;
use zrotext_root_material::profile03_manifest as shared;
mod current;
pub(crate) mod live;
mod records;
mod selected;
mod verified_history;
pub(crate) use selected::{Physical03 as SelectedPhysical03, SelectedManifest03};
const DOMAIN: &[u8] = b"ZTSE/line/payload-profile/manifest-install03/v1\0";

/// Exact public evidence commitments. These bind cache/snapshot identity only,
/// never root authenticity, durable acceptance or current permission.
pub(crate) fn base_commitment(
    account: Uuid,
    election: Uuid,
    binding: Uuid,
    first_signed: &[u8],
    accepted_ms: u64,
    bundle_sha256: &[u8; 32],
) -> Check<[u8; 32]> {
    if account.is_nil()
        || election.is_nil()
        || binding.is_nil()
        || bundle_sha256 == &[0; 32]
        || !(366..=9753).contains(&first_signed.len())
    {
        return Err("manifest ancestry base shape");
    }
    crypto::time(accepted_ms)?;
    Ok(crypto::sha(&crypto::framed(
        b"ZTSE/line/payload-profile/manifest-ancestry-base03/v1\0",
        &[
            account.as_bytes().as_slice(),
            election.as_bytes(),
            binding.as_bytes(),
            &crypto::sha(first_signed),
            &accepted_ms.to_be_bytes(),
            bundle_sha256,
        ]
        .concat(),
    )?))
}
pub(crate) fn step_commitment(
    prior: &[u8; 32],
    statement: &Statement03,
    signature: &[u8; 64],
    successor: &[u8],
    accepted_ms: u64,
) -> Check<[u8; 32]> {
    crypto::time(accepted_ms)?;
    if prior == &[0; 32] || !(366..=9753).contains(&successor.len()) {
        return Err("manifest ancestry step shape");
    }
    Ok(crypto::sha(&crypto::framed(
        b"ZTSE/line/payload-profile/manifest-ancestry-step03/v1\0",
        &[
            prior.as_slice(),
            statement.opening().as_bytes(),
            &crypto::sha(statement.bytes()),
            &crypto::sha(signature),
            &crypto::sha(successor),
            &accepted_ms.to_be_bytes(),
        ]
        .concat(),
    )?))
}

pub(crate) struct Statement03 {
    bytes: [u8; 513],
    ids: [[u8; 16]; 8],
    numbers: [u64; 7],
    digests: [[u8; 32]; 8],
    point: [u8; 65],
}
impl Statement03 {
    pub(crate) fn decode(bytes: &[u8]) -> Check<Self> {
        let parsed = shared::PossessionStatement03::decode(bytes)?;
        Ok(Self {
            bytes: *parsed.bytes(),
            ids: parsed.identities(),
            numbers: parsed.counters_and_window(),
            digests: parsed.commitments(),
            point: parsed.browser_point(),
        })
    }
    pub(crate) fn bytes(&self) -> &[u8; 513] {
        &self.bytes
    }
    pub(crate) fn account(&self) -> Uuid {
        Uuid::from_bytes(self.ids[0])
    }
    pub(crate) fn line(&self) -> Uuid {
        Uuid::from_bytes(self.ids[4])
    }
    pub(crate) fn opening(&self) -> Uuid {
        Uuid::from_bytes(self.ids[7])
    }
    pub(crate) fn expires(&self) -> u64 {
        self.numbers[6]
    }
    pub(crate) fn transcript(&self) -> Vec<u8> {
        crypto::framed(DOMAIN, &self.bytes).expect("fixed possession")
    }
}

/// Internal expected scope must come from actual held owner/root/election and
/// locked current selection. A caller-created value supplies no such proof.
pub(crate) struct ExpectedInstall03<'a> {
    pub account: Uuid,
    pub user: Uuid,
    pub owner_session: Uuid,
    pub device: Uuid,
    pub line: Uuid,
    pub binding: Uuid,
    pub election_challenge: Uuid,
    pub binding_generation: u64,
    pub vault_generation: u64,
    pub selection_epoch: u64,
    pub root_fingerprint: [u8; 32],
    pub election_commitment: [u8; 32],
    pub election_bundle_sha256: [u8; 32],
    pub canonical_origin: &'a str,
}
pub(crate) use shared::Operation03;
pub(crate) struct VerifiedInstall03 {
    statement: Statement03,
    successor: VerifiedManifest03,
    signature: [u8; 64],
    operation: Operation03,
}
impl VerifiedInstall03 {
    pub(crate) fn statement(&self) -> &Statement03 {
        &self.statement
    }
    pub(crate) fn successor(&self) -> &VerifiedManifest03 {
        &self.successor
    }
    pub(crate) fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    pub(crate) fn operation(&self) -> Operation03 {
        self.operation
    }
}
fn records(bytes: &[u8]) -> Check<Vec<&[u8]>> {
    if bytes.len() < 366
        || bytes[..6] != *b"ZTMA\x03\x03"
        || bytes.len() != 217 + 149 * usize::from(bytes[152])
    {
        return Err("manifest policy framing");
    }
    Ok(bytes[153..bytes.len() - 64].chunks_exact(149).collect())
}
pub(crate) struct Predecessor03<'a> {
    pub signed: &'a [u8],
    pub verified: &'a VerifiedManifest03,
    pub accepted_ms: u64,
}
pub(crate) fn verify(
    statement: Statement03,
    signature: &[u8],
    successor: &[u8],
    prior: Predecessor03<'_>,
    expected: &ExpectedInstall03<'_>,
    now: u64,
) -> Check<VerifiedInstall03> {
    crypto::time(now)?;
    crypto::time(prior.accepted_ms)?;
    let p = prior.verified.identity_at(prior.accepted_ms)?;
    let owner = crate::sealed_payload_election03::adapter_contract::OwnerSessionIdentity03 {
        account_id: *expected.account.as_bytes(),
        user_id: *expected.user.as_bytes(),
        session_id: *expected.owner_session.as_bytes(),
    }
    .digest()?;
    if statement.ids[..7]
        != [
            *expected.account.as_bytes(),
            *expected.user.as_bytes(),
            *expected.owner_session.as_bytes(),
            *expected.device.as_bytes(),
            *expected.line.as_bytes(),
            *expected.binding.as_bytes(),
            *expected.election_challenge.as_bytes(),
        ]
        || statement.numbers[..5]
            != [
                expected.binding_generation,
                expected.vault_generation,
                expected.selection_epoch,
                p.version,
                p.version
                    .checked_add(1)
                    .ok_or("manifest version exhausted")?,
            ]
        || statement.digests[..7]
            != [
                expected.root_fingerprint,
                expected.election_commitment,
                expected.election_bundle_sha256,
                crate::sealed_payload_election03::adapter_contract::origin_digest(
                    expected.canonical_origin,
                )?,
                owner,
                p.digest,
                crypto::sha(successor),
            ]
        || p.account_id != *expected.account.as_bytes()
        || p.generation != expected.vault_generation
        || prior.verified.signed_sha256() != crypto::sha(prior.signed)
        || prior.accepted_ms > now
        || now < statement.numbers[5]
        || now >= statement.numbers[6]
    {
        return Err("manifest held scope/original predecessor");
    }
    let pin = [
        b"ZTRP\x02".as_slice(),
        expected.account.as_bytes(),
        &expected.vault_generation.to_be_bytes(),
        &p.root_point,
    ]
    .concat();
    if crypto::sha(&[b"ZTSE/root-pin/v2\0".as_slice(), &pin].concat()) != expected.root_fingerprint
    {
        return Err("manifest original root selection");
    }
    let next = crypto::verify_successor(successor, prior.verified, now)?;
    let id = next.identity_at(now)?;
    if id.issued_ms > now {
        return Err("manifest future issuance");
    }
    let historical = shared::verify_checkpoint(
        &pin,
        prior.signed,
        &shared::Checkpoint03 {
            account_id: p.account_id,
            root_fingerprint: expected.root_fingerprint,
            version: p.version,
            digest: p.digest,
            accepted_ms: prior.accepted_ms,
        },
        prior.accepted_ms,
    )?;
    let reviewed = shared::verify_successor(
        &historical,
        successor,
        expected.line.as_bytes(),
        &statement.point,
        now,
    )?;
    if reviewed.checkpoint().digest() != &id.digest {
        return Err("manifest shared verifier identity");
    }
    let operation = reviewed.operation();
    // The selected physical reader must remain genuine and currently live.
    // Enrolled/SEALED points and mutable known-point reservations are checked
    // independently by the actual held production adapter and narrow SQL call.
    let physical: Vec<_> = records(successor)?
        .into_iter()
        .filter(|r| {
            r[0] == 1
                && r[98..114] == *expected.device.as_bytes()
                && r[114..130] == *expected.line.as_bytes()
                && r[148] == 1
        })
        .collect();
    if physical.len() != 1
        || crypto::number(&physical[0][132..140])? > now
        || crypto::number(&physical[0][140..148])? <= now
    {
        return Err("manifest current selected physical reader");
    }
    shared::PossessionStatement03::decode(statement.bytes())?.verify_signature(signature)?;
    Ok(VerifiedInstall03 {
        statement,
        successor: next,
        signature: signature
            .try_into()
            .map_err(|_| "manifest possession signature width")?,
        operation,
    })
}

#[cfg(test)]
mod tests;
