//! Accepted election evidence requires independent authenticated application records.
use crate::{
    Error,
    manifest::{Manifest, enroll_root, verify_manifest, window},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[derive(Clone, Default)]
pub struct ElectionRecord {
    pub bytes: BTreeMap<String, Vec<u8>>,
    pub numbers: BTreeMap<String, u64>,
}
pub struct ElectionProof {
    accepted: ElectionRecord,
    manifest: Manifest,
}
const AU: &[&str] = &[
    "accountId",
    "deviceId",
    "lineId",
    "oldBindingId",
    "newBindingId",
];
const AT: &[&str] = &[
    "vaultGeneration",
    "oldBindingGeneration",
    "newBindingGeneration",
    "priorManifestVersion",
    "acceptedManifestVersion",
    "acceptedAtMs",
];
const AD: &[&str] = &[
    "rootFingerprint",
    "oldBindingProofDigest",
    "selectedReaderKeyId",
    "priorManifestDigest",
    "priorSignedManifestSha256",
    "acceptedManifestDigest",
    "acceptedSignedManifestSha256",
    "electionCoreSha256",
    "electionCommitment",
    "electionBundleSha256",
];
const CU: &[&str] = &["accountId", "deviceId", "lineId", "bindingId"];
const CT: &[&str] = &[
    "bindingGeneration",
    "vaultGeneration",
    "manifestVersion",
    "comparedAtMs",
    "permissionExpiresAtMs",
    "profile",
    "manifestProfile",
];
const CD: &[&str] = &[
    "selectedReaderKeyId",
    "rootFingerprint",
    "manifestDigest",
    "electionCommitment",
    "electionBundleSha256",
];
fn need(value: bool) -> Result<(), Error> {
    if value {
        Ok(())
    } else {
        Err(Error::Authentication)
    }
}
impl ElectionRecord {
    pub(crate) fn b(&self, name: &str) -> &[u8] {
        &self.bytes[name]
    }
    pub(crate) fn n(&self, name: &str) -> u64 {
        self.numbers[name]
    }
    pub(crate) fn capture(&self, current: bool) -> Result<Self, Error> {
        let (uuids, times, digests) = if current { (CU, CT, CD) } else { (AU, AT, AD) };
        need(self.bytes.len() == uuids.len() + digests.len() && self.numbers.len() == times.len())?;
        for (names, size) in [(uuids, 16), (digests, 32)] {
            for name in names {
                let v = self.bytes.get(*name).ok_or(Error::Shape)?;
                need(v.len() == size && v.iter().any(|b| *b != 0))?;
            }
        }
        for name in times {
            let v = *self.numbers.get(*name).ok_or(Error::Shape)?;
            need(v > 0 && v <= i64::MAX as u64)?;
        }
        if current {
            need(
                self.n("profile") == 3
                    && self.n("manifestProfile") == 3
                    && self.n("permissionExpiresAtMs") > self.n("comparedAtMs"),
            )?;
        }
        Ok(self.clone())
    }
}
fn framed(domain: &str, payload: &[u8]) -> Vec<u8> {
    [
        domain.as_bytes(),
        b"\0",
        &(payload.len() as u32).to_be_bytes(),
        payload,
    ]
    .concat()
}
fn hash(value: &[u8]) -> Vec<u8> {
    Sha256::digest(value).to_vec()
}
fn number(b: &[u8], at: usize) -> Result<u64, Error> {
    let n = u64::from_be_bytes(b[at..at + 8].try_into().map_err(|_| Error::Shape)?);
    need(n > 0 && n <= i64::MAX as u64)?;
    Ok(n)
}
fn signature(point: &[u8], raw: &[u8], domain: &str, payload: &[u8]) -> Result<(), Error> {
    need(point.len() == 65 && point[0] == 4)?;
    let key = VerifyingKey::from_sec1_bytes(point).map_err(|_| Error::Shape)?;
    let sig = Signature::from_slice(raw).map_err(|_| Error::Shape)?;
    need(sig.normalize_s() == sig)?;
    key.verify(&framed(domain, payload), &sig)
        .map_err(|_| Error::Authentication)
}
/// Exact packet-independent expected core, accepted record and registry points are mandatory.
pub struct ElectionEvidence<'a> {
    pub bundle: &'a [u8],
    pub expected_core: &'a [u8],
    pub accepted: &'a ElectionRecord,
    pub predecessor: &'a Manifest,
    pub signed02: &'a [u8],
    pub signed03: &'a [u8],
    pub device_point: &'a [u8],
    pub owner_point: &'a [u8],
}
pub fn verify_accepted_election03(e: ElectionEvidence<'_>) -> Result<ElectionProof, Error> {
    let ElectionEvidence {
        bundle,
        expected_core,
        accepted,
        predecessor: prior,
        signed02,
        signed03,
        device_point,
        owner_point,
    } = e;
    need(bundle.len() == 628 && expected_core.len() == 500 && prior.profile == 2)?;
    let a = accepted.capture(false)?;
    let core = &bundle[..500];
    need(
        signed02 == prior.raw
            && a.n("acceptedAtMs") >= prior.comparison
            && window(prior.issued, prior.expires, a.n("acceptedAtMs")),
    )?;
    need(core == expected_core && &core[..8] == b"ZTPE\x03\x01\x02\x03" && core[496..] == [0; 4])?;
    for (start, end) in [(56, 72), (352, 384), (400, 432), (432, 464), (464, 496)] {
        need(core[start..end].iter().any(|v| *v != 0))?;
    }
    for (at, name) in [
        (8, "accountId"),
        (24, "deviceId"),
        (40, "lineId"),
        (72, "oldBindingId"),
        (104, "oldBindingProofDigest"),
        (136, "rootFingerprint"),
        (184, "priorManifestDigest"),
        (224, "acceptedManifestDigest"),
        (256, "selectedReaderKeyId"),
    ] {
        need(&core[at..at + a.b(name).len()] == a.b(name))?;
    }
    for (at, name) in [
        (88, "oldBindingGeneration"),
        (96, "newBindingGeneration"),
        (168, "vaultGeneration"),
        (176, "priorManifestVersion"),
        (216, "acceptedManifestVersion"),
    ] {
        need(number(core, at)? == a.n(name))?;
    }
    let issued = number(core, 384)?;
    let expires = number(core, 392)?;
    need(
        issued <= a.n("acceptedAtMs")
            && a.n("acceptedAtMs") < expires
            && expires - issued <= 300000
            && a.n("newBindingGeneration") > a.n("oldBindingGeneration")
            && a.n("vaultGeneration") == 1
            && a.n("priorManifestVersion") < i64::MAX as u64
            && a.n("acceptedManifestVersion") == a.n("priorManifestVersion") + 1,
    )?;
    let commitment = framed("ZTSE/line/payload-profile/commitment/v1", core);
    for (value, name) in [
        (signed02, "priorSignedManifestSha256"),
        (signed03, "acceptedSignedManifestSha256"),
        (core, "electionCoreSha256"),
        (bundle, "electionBundleSha256"),
        (commitment.as_slice(), "electionCommitment"),
    ] {
        need(hash(value) == a.b(name))?;
    }
    let pin = [
        b"ZTRP\x02".as_slice(),
        &prior.account,
        &1u64.to_be_bytes(),
        &prior.root,
    ]
    .concat();
    let root = enroll_root(&pin, a.b("rootFingerprint"))?;
    let m = verify_manifest(signed03, &root, Some(prior), 3, a.n("acceptedAtMs"))?;
    need(
        m.account == a.b("accountId")
            && m.version == a.n("acceptedManifestVersion")
            && m.digest == a.b("acceptedManifestDigest")
            && prior.version == a.n("priorManifestVersion")
            && prior.digest == a.b("priorManifestDigest"),
    )?;
    for (i, point) in [device_point, owner_point].iter().enumerate() {
        need(
            hash(&[b"ZTSE/key/v1\0\x01\x01".as_slice(), point].concat())
                == core[288 + i * 32..320 + i * 32],
        )?;
    }
    signature(
        device_point,
        &bundle[500..564],
        "ZTSE/line/payload-profile/device/v1",
        core,
    )?;
    signature(
        owner_point,
        &bundle[564..],
        "ZTSE/line/payload-profile/owner/v1",
        &[core, &hash(&bundle[500..564])].concat(),
    )?;
    Ok(ElectionProof {
        accepted: a,
        manifest: m,
    })
}
impl ElectionProof {
    pub fn accepted_manifest(&self) -> &Manifest {
        &self.manifest
    }
}
/// Present authenticated authority and exact verified lineage are required independently.
pub fn require_current_election03(
    proof: &ElectionProof,
    m: &Manifest,
    current: &ElectionRecord,
    now: u64,
) -> Result<ElectionRecord, Error> {
    let a = &proof.accepted;
    let c = current.capture(true)?;
    need(
        now >= a.n("acceptedAtMs")
            && now >= c.n("comparedAtMs")
            && now < c.n("permissionExpiresAtMs")
            && now >= m.comparison
            && window(m.issued, m.expires, now),
    )?;
    for (cn, an) in [
        ("accountId", "accountId"),
        ("deviceId", "deviceId"),
        ("lineId", "lineId"),
        ("bindingId", "newBindingId"),
        ("selectedReaderKeyId", "selectedReaderKeyId"),
        ("rootFingerprint", "rootFingerprint"),
        ("electionCommitment", "electionCommitment"),
        ("electionBundleSha256", "electionBundleSha256"),
    ] {
        need(c.b(cn) == a.b(an))?;
    }
    need(
        c.n("bindingGeneration") == a.n("newBindingGeneration")
            && c.n("vaultGeneration") == 1
            && c.n("manifestVersion") >= a.n("acceptedManifestVersion")
            && m.profile == 3
            && m.version == c.n("manifestVersion")
            && m.root == proof.manifest.root
            && m.account == proof.manifest.account
            && m.account == c.b("accountId")
            && m.digest == c.b("manifestDigest")
            && m.lineage.contains(&proof.manifest.digest),
    )?;
    Ok(c)
}
