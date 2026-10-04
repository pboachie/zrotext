// SPDX-License-Identifier: AGPL-3.0-only
//! Dormant candidate-02 manifest authority. No production route calls this module.
//!
//! Root fingerprints and chain positions must come from independently authenticated
//! owner trust and durable high-water state, never a relay directory. The caller
//! supplies trusted time and atomically persists advances before envelope effects.
//! This module does not enroll roots, accept transitions, perform CAS, validate
//! live session/line/grant state, or permit storage, decryption or SMS dispatch.

use crate::sealed_envelope::{ExpectedContext, ExpectedRecipient, Kind, Profile};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];
const DAY_MS: u64 = 86_400_000;
const MAX_ROLES: usize = 64;

fn u64_be(data: &[u8]) -> Result<u64, &'static str> {
    let value = u64::from_be_bytes(data.try_into().map_err(|_| "u64 width")?);
    if value > i64::MAX as u64 {
        return Err("signed storage range");
    }
    Ok(value)
}

fn key_id(role: u8, point: &[u8]) -> [u8; 32] {
    let algorithm = if role <= 3 { [0, 0x10] } else { [1, 1] };
    Sha256::digest([b"ZTSE/key/v1\0".as_slice(), &algorithm, point].concat()).into()
}

fn verify_signature(
    point: &[u8],
    signature: &[u8],
    label: &[u8],
    unsigned: &[u8],
) -> Result<(), &'static str> {
    let signature = Signature::from_slice(signature).map_err(|_| "signature scalar")?;
    if signature.to_bytes()[32..] > HALF_ORDER[..] {
        return Err("high-s signature");
    }
    let key = VerifyingKey::from_sec1_bytes(point).map_err(|_| "root point")?;
    let transcript = [label, &(unsigned.len() as u32).to_be_bytes(), unsigned].concat();
    key.verify(&transcript, &signature)
        .map_err(|_| "owner signature")
}

/// A precise chain position selected using durable authenticated state.
#[derive(Clone, Copy)]
pub enum ChainPosition {
    /// First manifest under an authenticated root. A rotation anchor must already
    /// have been independently verified; this does not authorize root rotation.
    /// Generation one requires the zero anchor; later generations require nonzero.
    Genesis { anchor_digest: [u8; 32] },
    /// Require exactly the next version linked to this accepted semantic digest.
    After { version: u64, digest: [u8; 32] },
    /// Reuse only the exact current semantic manifest, never a same-version fork.
    Current { version: u64, digest: [u8; 32] },
}

#[derive(Clone)]
pub struct ManifestTrust {
    pub account_id: [u8; 16],
    pub root_fingerprint: [u8; 32],
    pub generation: u64,
    pub position: ChainPosition,
}

struct RoleRecord {
    role: u8,
    id: [u8; 32],
    point: [u8; 65],
    device: [u8; 16],
    line: [u8; 16],
    scope: u16,
    from: u64,
    until: u64,
    state: u8,
}

/// Immutable authority constructed only after signature, pin and chain checks.
/// Debug deliberately omits identities, keys and unsigned bytes.
pub struct VerifiedManifest {
    digest: [u8; 32],
    account: [u8; 16],
    generation: u64,
    version: u64,
    issued: u64,
    expires: u64,
    roles: Vec<RoleRecord>,
}

pub(crate) struct AccountArchiveStatementRecords {
    pub account: [u8; 16],
    pub generation: u64,
    pub version: u64,
    pub digest: [u8; 32],
    pub issued: u64,
    pub expires: u64,
    pub root_point: [u8; 65],
    pub root_id: [u8; 32],
    pub root_from: u64,
    pub root_until: u64,
    pub reader_point: [u8; 65],
    pub reader_from: u64,
    pub reader_until: u64,
}

impl std::fmt::Debug for VerifiedManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedManifest").finish_non_exhaustive()
    }
}

/// Routing and explicit readers chosen by the caller, not inferred by the builder.
/// The subsequent envelope verifier compares these exact fields to signed bytes.
#[derive(Clone)]
pub struct EnvelopeAuthority<'a> {
    pub kind: Kind,
    pub account_id: [u8; 16],
    pub message_id: [u8; 16],
    pub device_id: [u8; 16],
    pub line_id: [u8; 16],
    pub signer_key_id: [u8; 32],
    pub peer: &'a [u8],
    pub recipients: &'a [ExpectedRecipient],
}

fn freshness(issued: u64, expires: u64, now: u64) -> Result<(), &'static str> {
    if now == 0
        || now > i64::MAX as u64
        || issued == 0
        || expires <= issued
        || expires - issued > DAY_MS
        || issued > now.saturating_add(300_000)
        || now >= expires
    {
        return Err("manifest freshness");
    }
    Ok(())
}

/// Verify exact bytes against caller-authenticated root and durable chain expectations.
/// This performs no root enrollment, transition acceptance or high-water persistence.
pub fn verify(
    pin: &[u8],
    manifest: &[u8],
    trusted: &ManifestTrust,
    now: u64,
) -> Result<VerifiedManifest, &'static str> {
    if now == 0 || now > i64::MAX as u64 || trusted.generation == 0 {
        return Err("trusted time/generation");
    }
    let fingerprint = &trusted.root_fingerprint;
    if pin.len() != 94 || &pin[..5] != b"ZTRP\x02" {
        return Err("pin shape");
    }
    if Sha256::digest([b"ZTSE/root-pin/v2\0".as_slice(), pin].concat()).as_slice() != fingerprint {
        return Err("pin fingerprint");
    }
    let account: [u8; 16] = pin[5..21].try_into().map_err(|_| "pin account")?;
    if account == [0; 16]
        || account != trusted.account_id
        || u64_be(&pin[21..29])? != trusted.generation
    {
        return Err("pin identity");
    }
    VerifyingKey::from_sec1_bytes(&pin[29..94]).map_err(|_| "pin curve")?;

    if !(364..=9751).contains(&manifest.len()) || &manifest[..5] != b"ZTMA\x02" {
        return Err("manifest shape");
    }
    let count = usize::from(manifest[150]);
    if !(1..=MAX_ROLES).contains(&count) || manifest.len() != 215 + 149 * count {
        return Err("manifest size/count");
    }
    if manifest[5..21] != account || manifest[85..150] != pin[29..94] {
        return Err("manifest pin");
    }
    let generation = u64_be(&manifest[21..29])?;
    let version = u64_be(&manifest[29..37])?;
    let issued = u64_be(&manifest[37..45])?;
    let expires = u64_be(&manifest[45..53])?;
    if generation != trusted.generation || version == 0 {
        return Err("manifest chain");
    }
    freshness(issued, expires, now)?;

    let mut roles: Vec<RoleRecord> = Vec::with_capacity(MAX_ROLES);
    let mut seen_points = HashSet::new();
    let mut owner_count = 0;
    let mut archive_count = 0;
    for index in 0..count {
        let at = 151 + 149 * index;
        let role = manifest[at];
        let id: [u8; 32] = manifest[at + 1..at + 33]
            .try_into()
            .map_err(|_| "key id width")?;
        let point = &manifest[at + 33..at + 98];
        let device: [u8; 16] = manifest[at + 98..at + 114]
            .try_into()
            .map_err(|_| "device width")?;
        let line: [u8; 16] = manifest[at + 114..at + 130]
            .try_into()
            .map_err(|_| "line width")?;
        let scope = u16::from_be_bytes(
            manifest[at + 130..at + 132]
                .try_into()
                .map_err(|_| "scope")?,
        );
        let from = u64_be(&manifest[at + 132..at + 140])?;
        let until = u64_be(&manifest[at + 140..at + 148])?;
        let state = manifest[at + 148];
        if !(1..=6).contains(&role)
            || !match role {
                1 => scope == 4 && device != [0; 16] && line != [0; 16],
                2 => scope == 12 && device == [0; 16] && line == [0; 16],
                3 => [4, 8, 12].contains(&scope) && device == [0; 16] && line == [0; 16],
                4 => scope == 2 && device != [0; 16] && line != [0; 16],
                5 => scope == 1 && device == [0; 16] && line != [0; 16],
                6 => scope == 0 && device == [0; 16] && line == [0; 16],
                _ => false,
            }
        {
            return Err("role/scope/subject");
        }
        if from > until || ![1, 2].contains(&state) {
            return Err("key interval/state");
        }
        if roles
            .last()
            .is_some_and(|previous| (role, id) <= (previous.role, previous.id))
        {
            return Err("record order");
        }
        VerifyingKey::from_sec1_bytes(point).map_err(|_| "record point")?;
        if id != key_id(role, point) || !seen_points.insert(point.to_vec()) {
            return Err("key identity or point reuse");
        }
        if role == 6 {
            owner_count += 1;
            if point != &pin[29..94] || state != 1 || from > issued || until < expires {
                return Err("owner root record");
            }
        }
        if role == 2 && state == 1 {
            archive_count += 1;
        }
        roles.push(RoleRecord {
            role,
            id,
            device,
            line,
            point: point.try_into().map_err(|_| "point width")?,
            scope,
            from,
            until,
            state,
        });
    }
    if owner_count != 1 || archive_count != 1 {
        return Err("root/archive cardinality");
    }
    let unsigned = &manifest[..manifest.len() - 64];
    verify_signature(
        &pin[29..94],
        &manifest[unsigned.len()..],
        b"ZTSE/manifest/v2\0",
        unsigned,
    )?;
    let digest = Sha256::digest(unsigned).into();
    let chain_matches = match trusted.position {
        ChainPosition::Genesis { anchor_digest } => {
            version == 1
                && if generation == 1 {
                    anchor_digest == [0; 32]
                } else {
                    anchor_digest != [0; 32]
                }
                && manifest[53..85] == anchor_digest
        }
        ChainPosition::After {
            version: previous_version,
            digest: previous_digest,
        } => {
            previous_version > 0
                && previous_version.checked_add(1) == Some(version)
                && manifest[53..85] == previous_digest
        }
        ChainPosition::Current {
            version: current_version,
            digest: current_digest,
        } => version == current_version && digest == current_digest,
    };
    if !chain_matches {
        return Err("manifest chain");
    }
    Ok(VerifiedManifest {
        digest,
        account,
        generation,
        version,
        issued,
        expires,
        roles,
    })
}

impl VerifiedManifest {
    /// Owned historical public records only; no installed contact permission.
    pub(crate) fn account_archive_statement_records(
        &self,
        reader_id: &[u8; 32],
        comparison_ms: u64,
    ) -> Result<AccountArchiveStatementRecords, &'static str> {
        freshness(self.issued, self.expires, comparison_ms)?;
        if self.generation != 1 {
            return Err("statement generation");
        }
        let reader = self
            .roles
            .iter()
            .find(|r| r.role == 2 && r.id == *reader_id && r.scope == 12 && r.active(comparison_ms))
            .ok_or("statement reader")?;
        let root = self
            .roles
            .iter()
            .find(|r| r.role == 6 && r.scope == 0 && r.active(comparison_ms))
            .ok_or("statement root")?;
        Ok(AccountArchiveStatementRecords {
            account: self.account,
            generation: self.generation,
            version: self.version,
            digest: self.digest,
            issued: self.issued,
            expires: self.expires,
            root_point: root.point,
            root_id: root.id,
            root_from: root.from,
            root_until: root.until,
            reader_point: reader.point,
            reader_from: reader.from,
            reader_until: reader.until,
        })
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn account_id(&self) -> &[u8; 16] {
        &self.account
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The single role-3 (integration) reader record for this exact public
    /// point when it is currently active: `(key_id, scope, until)`. Connector
    /// registration and authorization bind to exactly this record; no other
    /// role, wildcard or implicit reader can be selected through it.
    pub(crate) fn active_integration_reader(
        &self,
        point: &[u8],
        now: u64,
    ) -> Option<([u8; 32], u16, u64)> {
        self.roles
            .iter()
            .filter(|k| k.role == 3 && k.point.as_slice() == point && k.active(now))
            .map(|k| (k.id, k.scope, k.until.min(self.expires)))
            .next()
    }

    pub(crate) fn active_agent_signer(&self, line: &[u8; 16], signer: &[u8; 32], now: u64) -> bool {
        self.active_agent_signer_until(line, signer, now).is_some()
    }

    pub(crate) fn active_agent_signer_until(
        &self,
        line: &[u8; 16],
        signer: &[u8; 32],
        now: u64,
    ) -> Option<u64> {
        self.roles
            .iter()
            .find(|key| {
                key.role == 5
                    && key.scope == 1
                    && key.line == *line
                    && key.id == *signer
                    && key.active(now)
            })
            .map(|key| key.until.min(self.expires))
    }

    pub(crate) fn active_agent_reader(&self, key_id: &[u8; 32], directions: u16, now: u64) -> bool {
        [0, 4, 8, 12].contains(&directions)
            && self.roles.iter().any(|key| {
                key.role == 3
                    && key.id == *key_id
                    && key.scope & directions == directions
                    && key.active(now)
            })
    }

    pub(crate) fn conversation_keys(
        &self,
        device: &[u8; 16],
        line: &[u8; 16],
        now: u64,
    ) -> Result<([u8; 32], [u8; 32]), &'static str> {
        freshness(self.issued, self.expires, now)?;
        let reader = self
            .roles
            .iter()
            .find(|k| k.role == 2 && k.active(now))
            .ok_or("archive reader authority")?;
        let mut signers = self
            .roles
            .iter()
            .filter(|k| k.role == 4 && k.device == *device && k.line == *line && k.active(now));
        let signer = signers.next().ok_or("conversation signer authority")?;
        if signers.next().is_some() {
            return Err("ambiguous conversation signer");
        }
        Ok((reader.id, signer.id))
    }

    pub(crate) fn admission_deadline(
        &self,
        request: &EnvelopeAuthority<'_>,
        now: u64,
    ) -> Result<u64, &'static str> {
        self.envelope_context(request, now)?;
        let mut deadline = self.expires;
        for key in self.roles.iter().filter(|k| {
            k.id == request.signer_key_id
                || request
                    .recipients
                    .iter()
                    .any(|r| r.role == k.role && r.key_id == k.id)
        }) {
            deadline = deadline.min(key.until);
        }
        Ok(deadline)
    }

    /// Recheck freshness and key validity at use, then build strict candidate-02
    /// context. No wildcard readers or automatic reader expansion is performed.
    /// A returned context is only suitable for immediate signature verification;
    /// admission still needs current durable trust and transactional live checks.
    pub fn envelope_context<'a>(
        &'a self,
        request: &EnvelopeAuthority<'a>,
        now: u64,
    ) -> Result<ExpectedContext<'a>, &'static str> {
        freshness(self.issued, self.expires, now)?;
        if request.account_id != self.account
            || request.message_id == [0; 16]
            || request.device_id == [0; 16]
            || request.line_id == [0; 16]
        {
            return Err("envelope identity");
        }
        let inbound = request.kind == Kind::Inbound;
        let signer_role = if inbound { 4 } else { 5 };
        let signer = self
            .roles
            .iter()
            .find(|key| key.role == signer_role && key.id == request.signer_key_id)
            .ok_or("signer authority")?;
        if !signer.active(now)
            || signer.scope != if inbound { 2 } else { 1 }
            || signer.line != request.line_id
            || (inbound && signer.device != request.device_id)
        {
            return Err("signer authority");
        }
        if request.recipients.is_empty() || request.recipients.len() > if inbound { 7 } else { 8 } {
            return Err("reader set");
        }
        let mut devices = 0;
        let mut archives = 0;
        let mut integrations = 0;
        let mut previous = None;
        for reader in request.recipients {
            let identity = (reader.role, reader.key_id);
            if previous.is_some_and(|value| identity <= value) {
                return Err("reader order");
            }
            previous = Some(identity);
            let key = self
                .roles
                .iter()
                .find(|key| key.role == reader.role && key.id == reader.key_id)
                .ok_or("reader authority")?;
            if !key.active(now) || key.scope & if inbound { 8 } else { 4 } == 0 {
                return Err("reader authority");
            }
            match reader.role {
                1 if !inbound && key.device == request.device_id && key.line == request.line_id => {
                    devices += 1
                }
                2 => archives += 1,
                3 => integrations += 1,
                _ => return Err("reader role/subject"),
            }
        }
        if devices != usize::from(!inbound) || archives != 1 || integrations > 6 {
            return Err("reader set");
        }
        Ok(ExpectedContext {
            profile: Profile::Draft02Candidate,
            kind: request.kind,
            account_id: self.account,
            message_id: request.message_id,
            device_id: request.device_id,
            line_id: request.line_id,
            keyset_version: self.version,
            manifest_digest: self.digest,
            peer: request.peer,
            signer_public_point: &signer.point,
            recipients: request.recipients,
        })
    }
}
impl RoleRecord {
    fn active(&self, now: u64) -> bool {
        self.state == 1 && self.from <= now && now < self.until
    }
}

#[cfg(test)]
mod tests;
