// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/device-protection-origin-v1.json"
    ))
    .unwrap()
}
fn raw(v: &serde_json::Value) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn independent_public_dual_signature_vector_has_exact_probes_and_historical_window() {
    let v = fixture();
    let p = &v["parameters"];
    let association = Association::decode(&raw(&v["association"])).unwrap();
    assert_eq!(association.bytes().len(), 329);
    association
        .matches_provider_claims(&raw(&p["opening_nonce"]), &raw(&p["aes_probe"]))
        .unwrap();
    let mut expected = Vec::new();
    for name in [
        "account_id",
        "device_id",
        "setup_id",
        "opening_id",
        "command_id",
        "source_pairing_id",
    ] {
        expected.extend(
            uuid::Uuid::parse_str(p[name].as_str().unwrap())
                .unwrap()
                .as_bytes(),
        );
    }
    expected.extend(raw(&p["origin_digest"]));
    expected.extend(raw(&p["enrolled_key_id"]));
    expected.extend(raw(&p["opening_nonce"]));
    assert_eq!(
        association
            .probe_context(&raw(&p["opening_nonce"]))
            .unwrap()
            .as_slice(),
        expected
    );
    assert_eq!(
        association.digest().as_slice(),
        raw(&v["sha256"]["association"])
    );
    let proof =
        CandidateProof::verify(&raw(&v["bundle"]), &raw(&p["enrolled_point"]), &association)
            .unwrap();
    assert_eq!(proof.bytes().len(), 521);
    assert_eq!(proof.core().bytes().len(), 393);
    assert_eq!(proof.digest().as_slice(), raw(&v["sha256"]["bundle"]));
    proof
        .core()
        .matches_nonce(&raw(&p["attempt_nonce"]))
        .unwrap();
    proof.core().fresh(3_000_000).unwrap();
    proof.core().fresh(3_029_999).unwrap();
    assert!(proof.core().fresh(2_999_999).is_err());
    assert!(proof.core().fresh(3_030_000).is_err());
    let mut reversed = raw(&p["withdrawal_aes_probe"]);
    reversed.extend(raw(&p["journal_aes_probe"]));
    assert!(
        association
            .matches_provider_claims(&raw(&p["opening_nonce"]), &reversed)
            .is_err()
    );
    assert!(proof.core().matches_nonce(&[1; 32]).is_err());
    assert!(
        CandidateProof::verify(&raw(&v["bundle"]), association.canary_point(), &association)
            .is_err()
    );
}

#[test]
fn every_packet_byte_is_bound_and_other_widths_domains_or_windows_refuse() {
    let v = fixture();
    let association = Association::decode(&raw(&v["association"])).unwrap();
    let original = raw(&v["bundle"]);
    let point = raw(&v["parameters"]["enrolled_point"]);
    for i in 0..original.len() {
        let mut changed = original.clone();
        changed[i] ^= 1;
        assert!(
            CandidateProof::verify(&changed, &point, &association).is_err(),
            "byte {i}"
        );
    }
    for n in [329, 393, 473, 520, 522, 601, 649] {
        assert!(CandidateProof::verify(&vec![1; n], &point, &association).is_err());
    }
    let mut changed = raw(&v["core"]);
    changed[353..361].copy_from_slice(&3_030_001_u64.to_be_bytes());
    assert!(ProofCore::decode(&changed).is_err());
    changed[353..361].copy_from_slice(&3_000_000_u64.to_be_bytes());
    assert!(ProofCore::decode(&changed).is_err());
    changed = raw(&v["core"]);
    changed[345..353].fill(0);
    assert!(ProofCore::decode(&changed).is_err());
    changed = raw(&v["core"]);
    changed[329..345].fill(0);
    assert!(ProofCore::decode(&changed).is_err());
    let mut association_bytes = raw(&v["association"]);
    association_bytes[..8].copy_from_slice(CORE);
    assert!(Association::decode(&association_bytes).is_err());
}
