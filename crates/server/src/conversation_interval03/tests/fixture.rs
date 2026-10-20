// SPDX-License-Identifier: AGPL-3.0-only
//! Synthetic original election evidence for independent consent crypto tests.
use crate::sealed_manifest03::tests::{Fixture, NOW, corpus, hex, sign};
use crate::sealed_manifest03::{self as crypto, VerifiedManifest03};
use crate::sealed_payload_election03::{
    self as election, AcceptedProofInput03, CurrentAuthority03, VerifiedElection03,
};
pub(super) struct Packet {
    pub(super) f: Fixture,
    pub(super) manifest: VerifiedManifest03,
    pub(super) proof: VerifiedElection03,
    pub(super) current: CurrentAuthority03,
}
impl Packet {
    pub(super) fn new() -> Self {
        let f = Fixture::new();
        let old = f.manifest(2, 1, 0, [0; 32]);
        let prior = f.checkpoint(&old, NOW);
        let next = f.manifest(3, 2, 2, crypto::sha(&old[..old.len() - 64]));
        let manifest = crypto::verify_from_02(&next, &prior, NOW).unwrap();
        let mut core = hex(&corpus()["election"]["coreHex"]);
        for (at, bytes) in [
            (8, f.account.as_slice()),
            (24, &f.device),
            (40, &f.line),
            (136, &f.context(&old).trust.root_fingerprint),
            (184, &crypto::sha(&old[..old.len() - 64])),
            (224, &crypto::sha(&next[..next.len() - 64])),
            (256, &f.records[0][1..33]),
            (288, &f.records[3][1..33]),
            (320, &f.records[4][1..33]),
        ] {
            core[at..at + bytes.len()].copy_from_slice(bytes);
        }
        let ds = sign(&f.keys[3], b"ZTSE/line/payload-profile/device/v1\0", &core);
        let os = sign(
            &f.keys[4],
            b"ZTSE/line/payload-profile/owner/v1\0",
            &[core.as_slice(), &crypto::sha(&ds)].concat(),
        );
        let bundle = [core.as_slice(), &ds, &os].concat();
        let a = election::tests::accepted(&core, &old, &next, &bundle);
        let point = |i: usize| -> [u8; 65] {
            f.keys[i]
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .try_into()
                .unwrap()
        };
        let proof = election::verify_accepted(&AcceptedProofInput03 {
            bundle: &bundle,
            expected_core: &core,
            accepted: &a,
            predecessor02: &prior,
            accepted_signed_manifest03: &next,
            device_signing_point_at_acceptance: &point(3),
            owner_approval_point_at_acceptance: &point(4),
        })
        .unwrap();
        let current = CurrentAuthority03 {
            profile: 3,
            manifest_profile: 3,
            account_id: f.account,
            device_id: f.device,
            line_id: f.line,
            binding_id: a.new_binding_id,
            binding_generation: a.new_binding_generation,
            selected_reader_key_id: a.selected_reader_key_id,
            root_fingerprint: a.root_fingerprint,
            vault_generation: 1,
            manifest_version: 2,
            manifest_digest: a.accepted_manifest_digest,
            election_commitment: a.election_commitment,
            election_bundle_sha256: a.election_bundle_sha256,
            compared_at_ms: NOW,
            permission_expires_at_ms: NOW + 90_000,
        };
        Self {
            f,
            manifest,
            proof,
            current,
        }
    }
}
