// SPDX-License-Identifier: AGPL-3.0-only
//! First-origin protection proof bytes. These pure checks do not establish
//! enrollment, provider freshness, a current actor, pin installation or effects.

use crate::sealed_manifest03::{self as crypto, Check};
use p256::ecdsa::VerifyingKey;

const ASSOCIATION: &[u8; 8] = b"ZTPA\x01\x01\0\0";
const CORE: &[u8; 8] = b"ZTPR\x01\x01\0\0";
const DEVICE: &[u8] = b"ZT/protection/first-origin-device/v1\0";
const CANARY: &[u8] = b"ZT/protection/first-origin-canary/v1\0";

fn nonzero(bytes: &[u8]) -> Check<()> {
    if bytes.iter().all(|b| *b == 0) {
        Err("protection zero field")
    } else {
        Ok(())
    }
}

/// Immutable public provider-result claims, not independent custody evidence.
#[derive(Clone)]
pub struct Association {
    bytes: [u8; 329],
    ids: [[u8; 16]; 6],
    hashes: [[u8; 32]; 5],
    canary: [u8; 65],
}
impl Association {
    pub fn decode(raw: &[u8]) -> Check<Self> {
        let bytes: [u8; 329] = raw.try_into().map_err(|_| "protection association width")?;
        if &bytes[..8] != ASSOCIATION {
            return Err("protection association header");
        }
        let mut ids = [[0; 16]; 6];
        for (i, id) in ids.iter_mut().enumerate() {
            id.copy_from_slice(&bytes[8 + i * 16..24 + i * 16]);
            nonzero(id)?;
        }
        let mut hashes = [[0; 32]; 5];
        for (i, hash) in hashes.iter_mut().enumerate() {
            hash.copy_from_slice(&bytes[104 + i * 32..136 + i * 32]);
            nonzero(hash)?;
        }
        let canary: [u8; 65] = bytes[264..]
            .try_into()
            .map_err(|_| "protection canary width")?;
        if canary[0] != 4 || VerifyingKey::from_sec1_bytes(&canary).is_err() {
            return Err("protection canary point");
        }
        Ok(Self {
            bytes,
            ids,
            hashes,
            canary,
        })
    }
    pub fn bytes(&self) -> &[u8; 329] {
        &self.bytes
    }
    pub fn identities(&self) -> &[[u8; 16]; 6] {
        &self.ids
    }
    pub fn digests(&self) -> &[[u8; 32]; 5] {
        &self.hashes
    }
    pub fn canary_point(&self) -> &[u8; 65] {
        &self.canary
    }
    pub fn digest(&self) -> [u8; 32] {
        crypto::sha(&self.bytes)
    }
    pub fn matches_provider_claims(&self, opening_nonce: &[u8], aes_probe: &[u8]) -> Check<()> {
        if opening_nonce.len() != 32
            || aes_probe.len() != 120
            || crypto::sha(opening_nonce) != self.hashes[2]
            || crypto::sha(aes_probe) != self.hashes[4]
        {
            return Err("protection original provider claims");
        }
        Ok(())
    }
    /// Exact192-byte context for independently retained HMAC and both AES probes.
    pub fn probe_context(&self, opening_nonce: &[u8]) -> Check<[u8; 192]> {
        if opening_nonce.len() != 32 || crypto::sha(opening_nonce) != self.hashes[2] {
            return Err("protection original opening nonce");
        }
        let mut out = [0; 192];
        out[..160].copy_from_slice(&self.bytes[8..168]);
        out[160..].copy_from_slice(opening_nonce);
        Ok(out)
    }
    pub fn hmac_probe_transcript(&self, opening_nonce: &[u8]) -> Check<Vec<u8>> {
        crypto::framed(
            b"ZT/protection/hmac-probe/v1\0",
            &self.probe_context(opening_nonce)?,
        )
    }
}

/// An exact server-attempt projection, still requiring actual retained source.
pub struct ProofCore {
    bytes: [u8; 393],
    association: Association,
    attempt: [u8; 16],
    issued: u64,
    expires: u64,
    nonce_sha: [u8; 32],
}
impl ProofCore {
    pub fn decode(raw: &[u8]) -> Check<Self> {
        let bytes: [u8; 393] = raw.try_into().map_err(|_| "protection core width")?;
        if &bytes[..8] != CORE {
            return Err("protection core header");
        }
        let mut association = [0; 329];
        association[..8].copy_from_slice(ASSOCIATION);
        association[8..].copy_from_slice(&bytes[8..329]);
        let association = Association::decode(&association)?;
        let attempt = bytes[329..345]
            .try_into()
            .map_err(|_| "protection attempt width")?;
        nonzero(&attempt)?;
        let issued = crypto::number(&bytes[345..353])?;
        let expires = crypto::number(&bytes[353..361])?;
        crypto::time(issued)?;
        crypto::time(expires)?;
        if expires <= issued || expires - issued > 30_000 {
            return Err("protection proof window");
        }
        let nonce_sha = bytes[361..]
            .try_into()
            .map_err(|_| "protection nonce width")?;
        nonzero(&nonce_sha)?;
        Ok(Self {
            bytes,
            association,
            attempt,
            issued,
            expires,
            nonce_sha,
        })
    }
    pub fn bytes(&self) -> &[u8; 393] {
        &self.bytes
    }
    pub fn association(&self) -> &Association {
        &self.association
    }
    pub fn attempt_id(&self) -> &[u8; 16] {
        &self.attempt
    }
    pub fn issued_ms(&self) -> u64 {
        self.issued
    }
    pub fn expires_ms(&self) -> u64 {
        self.expires
    }
    pub fn matches_nonce(&self, nonce: &[u8]) -> Check<()> {
        if nonce.len() != 32 || crypto::sha(nonce) != self.nonce_sha {
            return Err("protection attempt nonce");
        }
        Ok(())
    }
    pub fn fresh(&self, now: u64) -> Check<()> {
        crypto::time(now)?;
        if now < self.issued || now >= self.expires {
            return Err("protection proof expired");
        }
        Ok(())
    }
}

/// Verified candidate signatures, without any storage or authenticated-actor brand.
pub struct CandidateProof {
    bytes: [u8; 521],
    core: ProofCore,
}
impl CandidateProof {
    pub fn verify(
        raw: &[u8],
        actual_enrolled_point: &[u8],
        expected_association: &Association,
    ) -> Check<Self> {
        let bytes: [u8; 521] = raw.try_into().map_err(|_| "protection bundle width")?;
        let core = ProofCore::decode(&bytes[..393])?;
        if core.association.bytes() != expected_association.bytes()
            || crate::sealed_manifest::key_id(4, actual_enrolled_point)
                != core.association.hashes[1]
            || actual_enrolled_point == core.association.canary.as_slice()
        {
            return Err("protection original actor/association");
        }
        crypto::signature(
            actual_enrolled_point,
            &bytes[393..457],
            &crypto::framed(DEVICE, &bytes[..393])?,
        )?;
        let mut second = bytes[..393].to_vec();
        second.extend(crypto::sha(&bytes[393..457]));
        crypto::signature(
            &core.association.canary,
            &bytes[457..],
            &crypto::framed(CANARY, &second)?,
        )?;
        Ok(Self { bytes, core })
    }
    pub fn bytes(&self) -> &[u8; 521] {
        &self.bytes
    }
    pub fn core(&self) -> &ProofCore {
        &self.core
    }
    pub fn digest(&self) -> [u8; 32] {
        crypto::sha(&self.bytes)
    }
}

#[cfg(test)]
mod tests;
