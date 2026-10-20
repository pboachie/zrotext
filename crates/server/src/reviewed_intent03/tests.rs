// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_envelope03::tests::{envelope, readers};
use crate::sealed_manifest03::tests::{Fixture, NOW, corpus, hex, sign};
use election::{AcceptedProofInput03, adapter_contract::OwnerSessionIdentity03};
use p256::elliptic_curve::Generate;

pub(crate) struct Packet {
    pub(crate) f: Fixture,
    pub(crate) manifest: VerifiedManifest03,
    pub(crate) proof: VerifiedElection03,
    pub(crate) current: CurrentAuthority03,
    intent: Vec<u8>,
    signature: Vec<u8>,
    pub(super) envelope: Vec<u8>,
    readers: Vec<(u8, [u8; 32])>,
    signer: [u8; 32],
}
impl Packet {
    pub(crate) fn new() -> Self {
        let f = Fixture::new();
        let old = f.manifest(2, 1, 0, [0; 32]);
        let prior = f.checkpoint(&old, NOW);
        let next = f.manifest(3, 2, 2, crypto::sha(&old[..old.len() - 64]));
        let manifest = crypto::verify_from_02(&next, &prior, NOW).unwrap();
        // The historical registered SEALED approval key is deliberately
        // independent of the current browser outbound signer.
        let approval = p256::ecdsa::SigningKey::generate_from_rng(&mut rand::rng());
        let approval_point: [u8; 65] = approval
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        let approval_id = crate::sealed_manifest::key_id(4, &approval_point);
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
            (320, approval_id.as_slice()),
        ] {
            core[at..at + bytes.len()].copy_from_slice(bytes);
        }
        let ds = sign(&f.keys[3], b"ZTSE/line/payload-profile/device/v1\0", &core);
        let os = sign(
            &approval,
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
            owner_approval_point_at_acceptance: &approval_point,
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
        let envelope = envelope(&f, &manifest, 1, 17, b"+12");
        let readers = readers(&f, 1);
        let signer = f.records[4][1..33].try_into().unwrap();
        let owner = OwnerSessionIdentity03 {
            account_id: f.account,
            user_id: [7; 16],
            session_id: [8; 16],
        }
        .digest()
        .unwrap();
        let mut intent = HEADER.to_vec();
        for id in [
            f.account,
            f.device,
            f.line,
            current.binding_id,
            [7; 16],
            [8; 16],
            [10; 16],
            [4; 16],
        ] {
            intent.extend(id);
        }
        for n in [
            current.binding_generation,
            1,
            2,
            1,
            NOW,
            NOW + 500,
            NOW,
            NOW + 200,
        ] {
            intent.extend(n.to_be_bytes());
        }
        for digest in [
            current.selected_reader_key_id,
            current.root_fingerprint,
            current.manifest_digest,
            current.election_commitment,
            current.election_bundle_sha256,
            owner,
            election::adapter_contract::origin_digest("https://owner.example").unwrap(),
            signer,
            crypto::sha(&envelope),
            crypto::sha(&envelope[..envelope.len() - 64]),
            crypto::sha(b"synthetic opaque body"),
        ] {
            intent.extend(digest);
        }
        intent.push(3);
        intent.extend(b"+12");
        intent.push(readers.len() as u8);
        for (role, id) in &readers {
            intent.push(*role);
            intent.extend(id);
        }
        intent.push(1);
        let signature = sign(&f.keys[4], DOMAIN, &intent);
        Self {
            f,
            manifest,
            proof,
            current,
            intent,
            signature,
            envelope,
            readers,
            signer,
        }
    }
    pub(super) fn expected(&self) -> ExpectedReview03<'_> {
        ExpectedReview03 {
            current: &self.current,
            election: &self.proof,
            manifest: &self.manifest,
            selection_epoch: 1,
            user: Uuid::from_bytes([7; 16]),
            session: Uuid::from_bytes([8; 16]),
            canonical_origin: "https://owner.example",
            interval: Uuid::from_bytes([10; 16]),
            interval_starts_ms: NOW - 1000,
            interval_expires_ms: NOW + 90_000,
            peer: b"+12",
            signer: &self.signer,
            recipients: &self.readers,
        }
    }
    fn verify(&self) -> Check<VerifiedReview03> {
        verify(
            Intent03::decode(&self.intent)?,
            &self.signature,
            &self.envelope,
            &self.expected(),
            NOW,
        )
    }
}

#[test]
fn unsupported_public_epoch_keeps_exact_transcript_and_signature_without_runtime_acceptance() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/reviewed-intent03.json"
    ))
    .unwrap();
    for case in v["cases"].as_array().unwrap() {
        let bytes = hex(&case["intent_hex"]);
        // This independent public codec vector deliberately uses epoch9. Its
        // exact bytes/signature remain valid parity evidence, while this actual
        // runtime supports only epoch1. Genuine epoch1 parser/envelope tests
        // below exercise acceptance; do not relabel or rewrite the vector.
        assert_eq!(case["fields"]["accountSelectionEpoch"], "9");
        assert!(matches!(Intent03::decode(&bytes), Err("review lifetime")));
        assert_eq!(
            u64::from(*bytes.last().unwrap()),
            case["fields"]["smsCeiling"].as_u64().unwrap()
        );
        assert_eq!(crypto::sha(&bytes).as_slice(), hex(&case["intent_sha256"]));
        let transcript = crypto::framed(DOMAIN, &bytes).unwrap();
        assert_eq!(
            crypto::sha(&transcript).as_slice(),
            hex(&case["transcript_sha256"])
        );
        crypto::signature(
            &hex(&case["signer_point_hex"]),
            &hex(&case["signature_hex"]),
            &transcript,
        )
        .unwrap();
    }
}
#[test]
fn genuine_envelope_and_role_five_intent_verify_exact_ceiling_and_original_bytes() {
    let mut p = Packet::new();
    for ceiling in [1, 6] {
        *p.intent.last_mut().unwrap() = ceiling;
        p.signature = sign(&p.f.keys[4], DOMAIN, &p.intent);
        let valid = p.verify().unwrap();
        assert_eq!(valid.intent().sms_ceiling(), ceiling);
        assert_eq!(valid.signature(), p.signature.as_slice());
        assert_eq!(valid.envelope().bytes(), p.envelope);
        assert_eq!(valid.expires_ms(), NOW + 500);
        assert_eq!(valid.body_digest(), &crypto::sha(b"synthetic opaque body"));
    }
}
#[test]
fn current_selection_owner_session_interval_and_exact_ciphertext_cannot_be_substituted() {
    let p = Packet::new();
    for mode in 0..9 {
        let mut e = p.expected();
        let bad = [9; 32];
        match mode {
            0 => e.selection_epoch = 2,
            1 => e.user = Uuid::new_v4(),
            2 => e.session = Uuid::new_v4(),
            3 => e.canonical_origin = "https://other.example",
            4 => e.interval = Uuid::new_v4(),
            5 => e.peer = b"+34",
            6 => e.signer = &bad,
            7 => e.interval_starts_ms = NOW + 1,
            _ => e.interval_expires_ms = NOW + 499,
        }
        assert!(
            verify(
                Intent03::decode(&p.intent).unwrap(),
                &p.signature,
                &p.envelope,
                &e,
                NOW
            )
            .is_err()
        );
    }
    let mut envelope = p.envelope.clone();
    envelope[200] ^= 1;
    assert!(
        verify(
            Intent03::decode(&p.intent).unwrap(),
            &p.signature,
            &envelope,
            &p.expected(),
            NOW
        )
        .is_err()
    );
}
#[test]
fn signed_mutations_do_not_bypass_structural_identity_or_original_timing() {
    let p = Packet::new();
    for at in [
        8, 24, 40, 56, 72, 88, 104, 120, 136, 144, 152, 160, 168, 176, 184, 192, 200, 232, 264,
        296, 328, 360, 392, 424, 456, 488,
    ] {
        let mut bytes = p.intent.clone();
        bytes[at] ^= 1;
        let sig = sign(&p.f.keys[4], DOMAIN, &bytes);
        let result =
            Intent03::decode(&bytes).and_then(|i| verify(i, &sig, &p.envelope, &p.expected(), NOW));
        assert!(result.is_err(), "offset {at}");
    }
    for ceiling in [0, 7, 255] {
        let mut bytes = p.intent.clone();
        *bytes.last_mut().unwrap() = ceiling;
        assert!(Intent03::decode(&bytes).is_err());
    }
    for bytes in [
        &p.intent[..p.intent.len() - 1],
        &[p.intent.as_slice(), &[0]].concat(),
    ] {
        assert!(Intent03::decode(bytes).is_err());
    }
    assert!(
        verify(
            Intent03::decode(&p.intent).unwrap(),
            &p.signature,
            &p.envelope,
            &p.expected(),
            NOW + 200
        )
        .is_err()
    );
}
#[test]
fn wrong_key_domain_and_high_s_signatures_refuse() {
    let p = Packet::new();
    for sig in [
        sign(&p.f.keys[3], DOMAIN, &p.intent),
        sign(&p.f.keys[4], b"ZTSE/sign/v3\0", &p.intent),
    ] {
        assert!(
            verify(
                Intent03::decode(&p.intent).unwrap(),
                &sig,
                &p.envelope,
                &p.expected(),
                NOW
            )
            .is_err()
        );
    }
    let sig = p256::ecdsa::Signature::from_slice(&p.signature).unwrap();
    let (r, s) = sig.split_scalars();
    let high = p256::ecdsa::Signature::from_scalars(r.to_bytes(), (-s).to_bytes())
        .unwrap()
        .to_bytes();
    assert!(
        verify(
            Intent03::decode(&p.intent).unwrap(),
            &high,
            &p.envelope,
            &p.expected(),
            NOW
        )
        .is_err()
    );
}

#[test]
fn retained_review_uses_original_admission_window_and_present_grant_deadline_independently() {
    let mut p = Packet::new();
    let now = NOW + 250;
    p.current.compared_at_ms = now;
    // The current held lease covers this grant, even though the original
    // queued message has a later immutable expiry. Neither is renewed.
    p.current.permission_expires_at_ms = NOW + 450;
    assert!(
        verify(
            Intent03::decode(&p.intent).unwrap(),
            &p.signature,
            &p.envelope,
            &p.expected(),
            now
        )
        .is_err()
    );
    let retained = |admitted_ms, installed_ms, required_until_ms| RetainedTiming03 {
        admitted_ms,
        installed_ms,
        required_until_ms,
    };
    verify_retained(
        Intent03::decode(&p.intent).unwrap(),
        &p.signature,
        &p.envelope,
        &p.expected(),
        now,
        retained(NOW + 50, NOW, NOW + 400),
    )
    .unwrap();
    for original in [
        retained(NOW + 200, NOW, NOW + 400),
        retained(NOW + 50, NOW + 51, NOW + 400),
        retained(NOW + 251, NOW, NOW + 400),
        retained(NOW + 50, NOW, now),
        retained(NOW + 50, NOW, NOW + 451),
        retained(NOW + 50, NOW, NOW + 501),
    ] {
        assert!(
            verify_retained(
                Intent03::decode(&p.intent).unwrap(),
                &p.signature,
                &p.envelope,
                &p.expected(),
                now,
                original
            )
            .is_err()
        );
    }
}
