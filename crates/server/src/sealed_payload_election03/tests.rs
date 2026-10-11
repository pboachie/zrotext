// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_manifest::{ChainPosition, ManifestTrust};
use crate::sealed_manifest03::tests::{Fixture, NOW, corpus, hex, sign};
use crate::sealed_manifest03::{AuthenticatedCheckpoint02, verify_checkpoint02, verify_successor};

fn accepted(core: &[u8], old: &[u8], next: &[u8], bundle: &[u8]) -> DurableAcceptedElection03 {
    let uuid = |at| core[at..at + 16].try_into().unwrap();
    let digest = |at| core[at..at + 32].try_into().unwrap();
    let integer = |at| number(&core[at..at + 8]).unwrap();
    DurableAcceptedElection03 {
        account_id: uuid(8),
        device_id: uuid(24),
        line_id: uuid(40),
        root_fingerprint: digest(136),
        vault_generation: integer(168),
        old_binding_id: uuid(72),
        old_binding_generation: integer(88),
        old_binding_proof_digest: digest(104),
        new_binding_id: [9; 16],
        new_binding_generation: integer(96),
        selected_reader_key_id: digest(256),
        prior_manifest_version: integer(176),
        prior_manifest_digest: digest(184),
        prior_signed_manifest_sha256: sha(old),
        accepted_manifest_version: integer(216),
        accepted_manifest_digest: digest(224),
        accepted_signed_manifest_sha256: sha(next),
        election_core_sha256: sha(core),
        election_commitment: sha(
            &framed(b"ZTSE/line/payload-profile/commitment/v1\0", core).unwrap()
        ),
        election_bundle_sha256: sha(bundle),
        accepted_at_ms: NOW,
    }
}
#[test]
fn exact_public_election_signatures_and_historical_current_boundary() {
    let v = corpus();
    let pin = hex(&v["rootPinHex"]);
    let old = hex(&v["manifests"]["prior02"]["signedHex"]);
    let next = hex(&v["manifests"]["successor03"]["signedHex"]);
    let core = hex(&v["election"]["coreHex"]);
    let bundle = hex(&v["election"]["bundleHex"]);
    let a = accepted(&core, &old, &next, &bundle);
    let prior = verify_checkpoint02(
        &pin,
        &old,
        &AuthenticatedCheckpoint02 {
            trust: ManifestTrust {
                account_id: a.account_id,
                root_fingerprint: a.root_fingerprint,
                generation: 1,
                position: ChainPosition::Current {
                    version: 1,
                    digest: a.prior_manifest_digest,
                },
            },
            anchor_digest: [0; 32],
            accepted_at_ms: NOW,
            last_verified_ms: NOW,
        },
        NOW,
    )
    .unwrap();
    let device = hex(&v["publicPointsHex"]["deviceEnrollment"])
        .try_into()
        .unwrap();
    let owner = hex(&v["publicPointsHex"]["ownerApproval"])
        .try_into()
        .unwrap();
    let input = AcceptedProofInput03 {
        bundle: &bundle,
        expected_core: &core,
        accepted: &a,
        predecessor02: &prior,
        accepted_signed_manifest03: &next,
        device_signing_point_at_acceptance: &device,
        owner_approval_point_at_acceptance: &owner,
    };
    let proof = verify_accepted(&input).unwrap();
    assert_eq!(
        proof.accepted.election_commitment.as_slice(),
        hex(&v["election"]["semanticCommitmentHex"])
    );
    let first = verify_from_02(&next, &prior, NOW).unwrap();
    let current = CurrentAuthority03 {
        profile: 3,
        manifest_profile: 3,
        account_id: a.account_id,
        device_id: a.device_id,
        line_id: a.line_id,
        binding_id: a.new_binding_id,
        binding_generation: a.new_binding_generation,
        selected_reader_key_id: a.selected_reader_key_id,
        root_fingerprint: a.root_fingerprint,
        vault_generation: 1,
        manifest_version: 2,
        manifest_digest: a.accepted_manifest_digest,
        election_commitment: a.election_commitment,
        election_bundle_sha256: a.election_bundle_sha256,
        compared_at_ms: NOW + 60_000,
        permission_expires_at_ms: NOW + 80_000,
    };
    // The original ceremony has expired, but separately authenticated present
    // permission and fresh manifest authority can still be compared.
    require_current(&proof, &first, &current, NOW + 60_000).unwrap();
    let after = verify_successor(
        &hex(&v["manifests"]["after03"]["signedHex"]),
        &first,
        NOW + 60_000,
    )
    .unwrap();
    let mut later = current.clone();
    let id = after.identity_at(NOW + 60_000).unwrap();
    later.manifest_version = id.version;
    later.manifest_digest = id.digest;
    require_current(&proof, &after, &later, NOW + 60_000).unwrap();
    for mutate in 0..16 {
        let mut c = current.clone();
        match mutate {
            0 => c.profile = 2,
            1 => c.manifest_profile = 2,
            2 => c.account_id[0] ^= 1,
            3 => c.device_id[0] ^= 1,
            4 => c.line_id[0] ^= 1,
            5 => c.binding_id[0] ^= 1,
            6 => c.binding_generation += 1,
            7 => c.selected_reader_key_id[0] ^= 1,
            8 => c.root_fingerprint[0] ^= 1,
            9 => c.vault_generation += 1,
            10 => c.manifest_version += 1,
            11 => c.manifest_digest[0] ^= 1,
            12 => c.election_commitment[0] ^= 1,
            13 => c.election_bundle_sha256[0] ^= 1,
            14 => c.compared_at_ms = NOW + 60_001,
            _ => c.permission_expires_at_ms = NOW + 60_000,
        }
        assert!(require_current(&proof, &first, &c, NOW + 60_000).is_err());
    }
    for at in [0, 56, 136, 288, 352, 400, 432, 464, 496, 500, 564, 627] {
        let mut changed = bundle.clone();
        changed[at] ^= 1;
        assert!(
            verify_accepted(&AcceptedProofInput03 {
                bundle: &changed,
                ..input
            })
            .is_err()
        );
    }
    for field in 0..21 {
        let mut changed = a.clone();
        match field {
            0 => changed.account_id[0] ^= 1,
            1 => changed.device_id[0] ^= 1,
            2 => changed.line_id[0] ^= 1,
            3 => changed.root_fingerprint[0] ^= 1,
            4 => changed.vault_generation += 1,
            5 => changed.old_binding_id[0] ^= 1,
            6 => changed.old_binding_generation += 1,
            7 => changed.old_binding_proof_digest[0] ^= 1,
            // New binding UUID is allocated by the trusted adapter, not encoded
            // in E500. Its nonzero shape is checked, not a fabricated wire link.
            8 => changed.new_binding_id = [0; 16],
            9 => changed.new_binding_generation += 1,
            10 => changed.selected_reader_key_id[0] ^= 1,
            11 => changed.prior_manifest_version += 1,
            12 => changed.prior_manifest_digest[0] ^= 1,
            13 => changed.prior_signed_manifest_sha256[0] ^= 1,
            14 => changed.accepted_manifest_version += 1,
            15 => changed.accepted_manifest_digest[0] ^= 1,
            16 => changed.accepted_signed_manifest_sha256[0] ^= 1,
            17 => changed.election_core_sha256[0] ^= 1,
            18 => changed.election_commitment[0] ^= 1,
            19 => changed.election_bundle_sha256[0] ^= 1,
            _ => changed.accepted_at_ms = NOW + 300_000,
        }
        assert!(
            verify_accepted(&AcceptedProofInput03 {
                accepted: &changed,
                ..input
            })
            .is_err()
        );
    }
}

#[test]
fn valid_owner_signature_over_wrong_device_proof_digest_refuses() {
    let f = Fixture::new();
    let old = f.manifest(2, 1, 0, [0; 32]);
    let prior = f.checkpoint(&old, NOW);
    let next = f.manifest(3, 2, 2, sha(&old[..old.len() - 64]));
    let mut core = hex(&corpus()["election"]["coreHex"]);
    core[8..24].copy_from_slice(&f.account);
    core[24..40].copy_from_slice(&f.device);
    core[40..56].copy_from_slice(&f.line);
    core[136..168].copy_from_slice(&f.context(&old).trust.root_fingerprint);
    core[184..216].copy_from_slice(&sha(&old[..old.len() - 64]));
    core[224..256].copy_from_slice(&sha(&next[..next.len() - 64]));
    core[256..288].copy_from_slice(&f.records[0][1..33]);
    core[288..320].copy_from_slice(&f.records[3][1..33]);
    core[320..352].copy_from_slice(&f.records[4][1..33]);
    let device = f.keys[3]
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    let owner = f.keys[4]
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    let ds = sign(&f.keys[3], b"ZTSE/line/payload-profile/device/v1\0", &core);
    let os = sign(
        &f.keys[4],
        b"ZTSE/line/payload-profile/owner/v1\0",
        &[core.as_slice(), &sha(&ds)].concat(),
    );
    let bundle = [core.as_slice(), &ds, &os].concat();
    let a = accepted(&core, &old, &next, &bundle);
    let input = AcceptedProofInput03 {
        bundle: &bundle,
        expected_core: &core,
        accepted: &a,
        predecessor02: &prior,
        accepted_signed_manifest03: &next,
        device_signing_point_at_acceptance: &device,
        owner_approval_point_at_acceptance: &owner,
    };
    verify_accepted(&input).unwrap();
    let wrong = sign(
        &f.keys[4],
        b"ZTSE/line/payload-profile/owner/v1\0",
        &[core.as_slice(), &[7; 32]].concat(),
    );
    let changed = [core.as_slice(), &ds, &wrong].concat();
    let mut altered = a.clone();
    altered.election_bundle_sha256 = sha(&changed);
    assert!(
        verify_accepted(&AcceptedProofInput03 {
            bundle: &changed,
            accepted: &altered,
            ..input
        })
        .is_err()
    );
}
