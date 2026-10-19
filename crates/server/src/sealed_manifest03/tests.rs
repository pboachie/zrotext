// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use aes_gcm::aead::Generate;
use p256::ecdsa::{
    SigningKey,
    signature::{RandomizedSigner, Signer},
};
use serde_json::Value;

pub(crate) const NOW: u64 = 1_700_000_000_000;
pub(crate) fn sign(key: &SigningKey, label: &[u8], bytes: &[u8]) -> Vec<u8> {
    let sig: Signature = key.sign(&framed(label, bytes).unwrap());
    sig.normalize_s().to_bytes().to_vec()
}
pub(crate) fn hex(value: &Value) -> Vec<u8> {
    value
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
pub(crate) fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/sealed-profile03-contract-01.json"
    ))
    .unwrap()
}
pub(crate) struct Fixture {
    pub root: SigningKey,
    pub keys: Vec<SigningKey>,
    pub records: Vec<Vec<u8>>,
    pub account: [u8; 16],
    pub device: [u8; 16],
    pub line: [u8; 16],
    pub pin: Vec<u8>,
}
impl Fixture {
    pub fn new() -> Self {
        let root = SigningKey::generate_from_rng(&mut rand::rng());
        let account = [1; 16];
        let device = [2; 16];
        let line = [3; 16];
        let mut pin = b"ZTRP\x02".to_vec();
        pin.extend(account);
        pin.extend(1u64.to_be_bytes());
        pin.extend(root.verifying_key().to_sec1_point(false).as_bytes());
        let mut keys = Vec::new();
        let mut records = Vec::new();
        for role in 1..=6 {
            let key = SigningKey::generate_from_rng(&mut rand::rng());
            let point = if role == 6 {
                root.verifying_key().to_sec1_point(false)
            } else {
                key.verifying_key().to_sec1_point(false)
            };
            let mut r = vec![role];
            r.extend(sealed_manifest::key_id(role, point.as_bytes()));
            r.extend(point.as_bytes());
            r.extend(if [1, 4].contains(&role) {
                device
            } else {
                [0; 16]
            });
            r.extend(if [1, 4, 5].contains(&role) {
                line
            } else {
                [0; 16]
            });
            r.extend([0, 4u16, 12, 12, 2, 1, 0][usize::from(role)].to_be_bytes());
            r.extend((NOW - 1000).to_be_bytes());
            r.extend((NOW + 100_000).to_be_bytes());
            r.push(1);
            records.push(r);
            keys.push(key);
        }
        Self {
            root,
            keys,
            records,
            account,
            device,
            line,
            pin,
        }
    }
    pub fn manifest(
        &self,
        profile: u8,
        version: u64,
        predecessor: u8,
        previous: [u8; 32],
    ) -> Vec<u8> {
        let mut b = b"ZTMA".to_vec();
        b.push(profile);
        if profile == 3 {
            b.extend([3, predecessor]);
        }
        b.extend(self.account);
        b.extend(1u64.to_be_bytes());
        b.extend(version.to_be_bytes());
        b.extend((NOW - 1000).to_be_bytes());
        b.extend((NOW + 100_000).to_be_bytes());
        b.extend(previous);
        b.extend(self.root.verifying_key().to_sec1_point(false).as_bytes());
        b.push(self.records.len() as u8);
        let mut records = self.records.clone();
        records.sort_by(|a, b| a[..33].cmp(&b[..33]));
        for r in records {
            b.extend(r);
        }
        let label: &[u8] = if profile == 2 {
            b"ZTSE/manifest/v2\0"
        } else {
            b"ZTSE/manifest/v3\0"
        };
        b.extend(sign(&self.root, label, &b));
        b
    }
    pub fn checkpoint(&self, bytes: &[u8], now: u64) -> VerifiedCheckpoint02 {
        verify_checkpoint02(&self.pin, bytes, &self.context(bytes), now).unwrap()
    }
    pub fn context(&self, bytes: &[u8]) -> AuthenticatedCheckpoint02 {
        AuthenticatedCheckpoint02 {
            trust: ManifestTrust {
                account_id: self.account,
                generation: 1,
                root_fingerprint: sha(&[b"ZTSE/root-pin/v2\0".as_slice(), &self.pin].concat()),
                position: ChainPosition::Current {
                    version: number(&bytes[29..37]).unwrap(),
                    digest: sha(&bytes[..bytes.len() - 64]),
                },
            },
            anchor_digest: [0; 32],
            accepted_at_ms: NOW - 10,
            last_verified_ms: NOW,
        }
    }
    pub fn pair(&self) -> (VerifiedCheckpoint02, Vec<u8>, VerifiedManifest03) {
        let old = self.manifest(2, 1, 0, [0; 32]);
        let prior = self.checkpoint(&old, NOW);
        let first = self.manifest(3, 2, 2, sha(&old[..old.len() - 64]));
        let verified = verify_from_02(&first, &prior, NOW).unwrap();
        (prior, first, verified)
    }
    pub fn resign03(&self, bytes: &mut [u8]) {
        let end = bytes.len() - 64;
        let sig = sign(&self.root, b"ZTSE/manifest/v3\0", &bytes[..end]);
        bytes[end..].copy_from_slice(&sig);
    }
}

#[test]
fn exact_public_cross_profile_vectors_verify_in_rust() {
    let v = corpus();
    let pin = hex(&v["rootPinHex"]);
    let old = hex(&v["manifests"]["prior02"]["signedHex"]);
    let now = v["nowMs"].as_u64().unwrap();
    let context = AuthenticatedCheckpoint02 {
        trust: ManifestTrust {
            account_id: pin[5..21].try_into().unwrap(),
            root_fingerprint: hex(&v["rootFingerprintHex"]).try_into().unwrap(),
            generation: 1,
            position: ChainPosition::Current {
                version: 1,
                digest: hex(&v["manifests"]["prior02"]["semanticDigestHex"])
                    .try_into()
                    .unwrap(),
            },
        },
        anchor_digest: [0; 32],
        accepted_at_ms: now,
        last_verified_ms: now,
    };
    let prior = verify_checkpoint02(&pin, &old, &context, now).unwrap();
    let first = hex(&v["manifests"]["successor03"]["signedHex"]);
    let accepted = verify_from_02(&first, &prior, now).unwrap();
    assert_eq!(
        accepted.identity_at(now).unwrap().digest.as_slice(),
        hex(&v["manifests"]["successor03"]["semanticDigestHex"])
    );
    let after = verify_successor(
        &hex(&v["manifests"]["after03"]["signedHex"]),
        &accepted,
        now,
    )
    .unwrap();
    assert_eq!(after.identity_at(now).unwrap().version, 3);
    verify_current(&first, &accepted, now).unwrap();
    for name in ["genesis03ContractOnly", "sameVersionFork03"] {
        assert!(verify_current(&hex(&v["manifests"][name]["signedHex"]), &accepted, now).is_err());
    }
}

#[test]
fn election_selects_both_registered_signers_independently_of_conversation_roles() {
    let f = Fixture::new();
    let old = f.manifest(2, 1, 0, [0; 32]);
    let context = f.context(&old);
    let manifest02 = sealed_manifest::verify(&f.pin, &old, &context.trust, NOW).unwrap();
    let (_, _, manifest03) = f.pair();
    let enrolled = SigningKey::generate_from_rng(&mut rand::rng());
    let point: [u8; 65] = enrolled
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    let original_approval = SigningKey::generate_from_rng(&mut rand::rng());
    let owner: [u8; 65] = original_approval
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    assert_ne!(
        point.as_slice(),
        f.keys[3].verifying_key().to_sec1_point(false).as_bytes()
    );
    let a = manifest02
        .profile_election_keys(&f.device, &f.line, &point, &owner, NOW)
        .unwrap();
    let b = manifest03
        .profile_election_keys(&f.device, &f.line, &point, &owner, NOW)
        .unwrap();
    assert_eq!(a.device_signer_id, sealed_manifest::key_id(4, &point));
    assert_eq!(b.device_signer_id, a.device_signer_id);
    assert_eq!(b.reader_id, a.reader_id);
    assert_eq!(b.approval_id, a.approval_id);
    assert_eq!(b.approval_id, sealed_manifest::key_id(4, &owner));
    // Signing key IDs identify algorithm0101 plus point, not manifest role.
    assert_eq!(b.approval_id, sealed_manifest::key_id(5, &owner));
    for (device, line, signer, approval, now) in [
        ([9; 16], f.line, point, owner, NOW),
        (f.device, [9; 16], point, owner, NOW),
        (f.device, f.line, [0; 65], owner, NOW),
        (f.device, f.line, point, [0; 65], NOW),
        (f.device, f.line, point, point, NOW),
        (f.device, f.line, point, owner, NOW + 100_000),
    ] {
        assert!(
            manifest02
                .profile_election_keys(&device, &line, &signer, &approval, now)
                .is_err()
        );
        assert!(
            manifest03
                .profile_election_keys(&device, &line, &signer, &approval, now)
                .is_err()
        );
    }
}

#[test]
fn signed_manifests_without_outbound_role_still_select_election_but_cannot_send() {
    let mut f = Fixture::new();
    f.records.retain(|r| r[0] != 5);
    let old = f.manifest(2, 1, 0, [0; 32]);
    let old02 = sealed_manifest::verify(&f.pin, &old, &f.context(&old).trust, NOW).unwrap();
    let (_, _, new03) = f.pair();
    let device = SigningKey::generate_from_rng(&mut rand::rng());
    let owner = SigningKey::generate_from_rng(&mut rand::rng());
    let point = |key: &SigningKey| -> [u8; 65] {
        key.verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap()
    };
    let selection = old02
        .profile_election_keys(&f.device, &f.line, &point(&device), &point(&owner), NOW)
        .unwrap();
    let next = new03
        .profile_election_keys(&f.device, &f.line, &point(&device), &point(&owner), NOW)
        .unwrap();
    assert_eq!(selection.reader_id, next.reader_id);
    let archive =
        sealed_manifest::key_id(2, f.keys[1].verifying_key().to_sec1_point(false).as_bytes());
    assert!(
        new03
            .authorize(
                &Authorization03 {
                    kind: 1,
                    account: &f.account,
                    device: &f.device,
                    line: &f.line,
                    signer_id: &sealed_manifest::key_id(5, &point(&owner)),
                    readers: &[(1, next.reader_id), (2, archive)]
                },
                NOW
            )
            .is_err()
    );
}

#[test]
fn actual_anchor_checkpoint_and_original_comparison_are_not_invented() {
    let f = Fixture::new();
    let old = f.manifest(2, 17, 0, [7; 32]);
    let mut c = f.context(&old);
    let prior = verify_checkpoint02(&f.pin, &old, &c, NOW).unwrap();
    let next = f.manifest(3, 18, 2, sha(&old[..old.len() - 64]));
    let accepted = verify_from_02(&next, &prior, NOW).unwrap();
    assert_eq!(accepted.identity_at(NOW + 1).unwrap().comparison_ms, NOW);
    assert!(accepted.identity_at(NOW - 1).is_err());
    c.anchor_digest = [7; 32];
    assert!(verify_checkpoint02(&f.pin, &old, &c, NOW).is_err());
    c.anchor_digest = [0; 32];
    c.last_verified_ms = NOW + 1;
    assert!(verify_checkpoint02(&f.pin, &old, &c, NOW).is_err());
    c.last_verified_ms = NOW;
    c.accepted_at_ms = NOW + 1;
    assert!(verify_checkpoint02(&f.pin, &old, &c, NOW).is_err());
    let mut bad = old.clone();
    let end = bad.len() - 1;
    bad[end] ^= 1;
    assert!(verify_checkpoint02(&f.pin, &bad, &f.context(&old), NOW).is_err());
}

#[test]
fn outbound_authorization_deadline_includes_signer_lifetime() {
    let mut f = Fixture::new();
    let signer = f.records.iter_mut().find(|r| r[0] == 5).unwrap();
    signer[140..148].copy_from_slice(&(NOW + 250).to_be_bytes());
    let (_, _, manifest) = f.pair();
    let readers: Vec<_> = f
        .records
        .iter()
        .filter(|r| r[0] <= 3)
        .map(|r| (r[0], r[1..33].try_into().unwrap()))
        .collect();
    let signer = f.records.iter().find(|r| r[0] == 5).unwrap()[1..33]
        .try_into()
        .unwrap();
    let (_, _, deadline) = manifest
        .authorize(
            &Authorization03 {
                kind: 1,
                account: &f.account,
                device: &f.device,
                line: &f.line,
                signer_id: &signer,
                readers: &readers,
            },
            NOW,
        )
        .unwrap();
    assert_eq!(deadline, NOW + 250);
}

#[test]
fn root_signed_wrong_roles_scopes_subjects_and_chain_refuse() {
    let f = Fixture::new();
    let (prior, first, current) = f.pair();
    for (at, byte) in [
        (5, 2),
        (6, 0),
        (7, 0),
        (153, 7),
        (153 + 130, 1),
        (153 + 148, 0),
        (153 + 149 + 98, 1),
        (153 + 5 * 149 + 148, 2),
    ] {
        let mut changed = first.clone();
        changed[at] = byte;
        f.resign03(&mut changed);
        assert!(
            verify_from_02(&changed, &prior, NOW).is_err(),
            "offset {at}"
        );
    }
    for at in [23, 31, 39, 47, 153 + 132, 153 + 140] {
        let mut changed = first.clone();
        changed[at..at + 8].copy_from_slice(&(MAX + 1).to_be_bytes());
        f.resign03(&mut changed);
        assert!(verify_from_02(&changed, &prior, NOW).is_err());
    }
    let fork = f.manifest(3, 2, 2, [9; 32]);
    assert!(verify_current(&fork, &current, NOW).is_err());
    let gap = f.manifest(3, 4, 3, current.identity.digest);
    assert!(verify_successor(&gap, &current, NOW).is_err());
    let wrong_profile = f.manifest(3, 3, 2, current.identity.digest);
    assert!(verify_successor(&wrong_profile, &current, NOW).is_err());
}

#[test]
fn signatures_exact_sizes_and_old_history_are_separate_from_currentness() {
    let f = Fixture::new();
    let (_, first, current) = f.pair();
    let end = first.len() - 64;
    let alternate: Signature = f.root.sign_with_rng(
        &mut rand::rng(),
        &framed(b"ZTSE/manifest/v3\0", &first[..end]).unwrap(),
    );
    let mut alias = first.clone();
    alias[end..].copy_from_slice(&alternate.normalize_s().to_bytes());
    assert_ne!(alias, first);
    assert_eq!(
        verify_current(&alias, &current, NOW)
            .unwrap()
            .identity
            .digest,
        current.identity.digest
    );
    assert_ne!(sha(&alias), current.signed_sha256);
    for bytes in [
        vec![0; 365],
        vec![0; 9754],
        first[..first.len() - 1].to_vec(),
        [first.as_slice(), &[0]].concat(),
    ] {
        assert!(verify_current(&bytes, &current, NOW).is_err());
    }
    let mut zero = first.clone();
    let end = zero.len() - 64;
    zero[end..].fill(0);
    assert!(verify_current(&zero, &current, NOW).is_err());
    let mut corrupt = first.clone();
    corrupt[end + 1] ^= 1;
    assert!(verify_current(&corrupt, &current, NOW).is_err());
    let mut domain = first.clone();
    let raw = sign(&f.root, b"ZTSE/manifest/v2\0", &domain[..end]);
    domain[end..].copy_from_slice(&raw);
    assert!(verify_current(&domain, &current, NOW).is_err());
    assert!(current.identity_at(NOW + 100_000).is_err());
    let mut next = f.manifest(3, 3, 3, current.identity.digest);
    next[39..47].copy_from_slice(&(NOW + 100_000).to_be_bytes());
    next[47..55].copy_from_slice(&(NOW + 101_000).to_be_bytes());
    // Root record must cover this genuinely fresh next interval.
    for i in 0..6 {
        let at = 153 + 149 * i;
        next[at + 140..at + 148].copy_from_slice(&(NOW + 101_000).to_be_bytes());
    }
    f.resign03(&mut next);
    let after = verify_successor(&next, &current, NOW + 100_000).unwrap();
    assert_eq!(after.identity.version, 3);
    assert!(verify_current(&first, &current, NOW + 100_000).is_err());
    assert!(verify_successor(&next, &current, NOW - 1).is_err());
}

#[test]
fn scalar_twin_count_point_reuse_and_version_extremes_refuse() {
    let f = Fixture::new();
    let (prior, first, current) = f.pair();
    let order: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc,
        0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ];
    let mut twin = first.clone();
    let at = twin.len() - 32;
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(order[i]) - i16::from(twin[at + i]) - borrow;
        twin[at + i] = d as u8;
        borrow = i16::from(d < 0);
    }
    assert!(verify_current(&twin, &current, NOW).is_err());
    for count in [0, 65, 1] {
        let mut b = first.clone();
        b[152] = count;
        f.resign03(&mut b);
        assert!(verify_from_02(&b, &prior, NOW).is_err());
    }
    let mut reused = first.clone();
    let point = f.root.verifying_key().to_sec1_point(false);
    reused[154..186].copy_from_slice(&sealed_manifest::key_id(1, point.as_bytes()));
    reused[186..251].copy_from_slice(point.as_bytes());
    f.resign03(&mut reused);
    assert!(verify_from_02(&reused, &prior, NOW).is_err());
    for version in [MAX - 1, MAX] {
        let old = f.manifest(2, version, 0, [0; 32]);
        let prior = f.checkpoint(&old, NOW);
        let next = f.manifest(3, MAX, 2, sha(&old[..old.len() - 64]));
        if version == MAX - 1 {
            assert_eq!(
                verify_from_02(&next, &prior, NOW).unwrap().identity.version,
                MAX
            );
        } else {
            assert!(verify_from_02(&next, &prior, NOW).is_err());
        }
    }
    let mut changed = first.clone();
    changed[39..47].copy_from_slice(&(NOW - 999).to_be_bytes());
    f.resign03(&mut changed);
    assert!(verify_current(&changed, &current, NOW).is_err());
}
