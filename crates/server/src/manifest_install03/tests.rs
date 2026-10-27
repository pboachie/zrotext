// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::sealed_manifest::{ChainPosition, ManifestTrust};
use crate::sealed_manifest03::AuthenticatedCheckpoint02;
use serde_json::Value;
pub(super) fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/sealed-profile03-manifest-install-01.json"
    ))
    .unwrap()
}
pub(super) fn bytes(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    assert_eq!(s.len() % 2, 0);
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| chunk.as_slice())
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
pub(super) fn number(v: &Value) -> u64 {
    v.as_str().unwrap().parse().unwrap()
}
pub(super) fn id(v: &Value) -> Uuid {
    Uuid::parse_str(v.as_str().unwrap()).unwrap()
}
fn expected(v: &Value) -> ExpectedInstall03<'_> {
    ExpectedInstall03 {
        account: id(&v["account_id"]),
        user: id(&v["user_id"]),
        owner_session: id(&v["owner_session_id"]),
        device: id(&v["device_id"]),
        line: id(&v["line_id"]),
        binding: id(&v["binding_id"]),
        election_challenge: id(&v["election_challenge_id"]),
        binding_generation: number(&v["binding_generation"]),
        vault_generation: number(&v["vault_generation"]),
        selection_epoch: number(&v["selection_epoch"]),
        root_fingerprint: bytes(&v["root_fingerprint_hex"]).try_into().unwrap(),
        election_commitment: bytes(&v["election_commitment_hex"]).try_into().unwrap(),
        election_bundle_sha256: bytes(&v["election_bundle_sha256_hex"]).try_into().unwrap(),
        canonical_origin: v["canonical_origin"].as_str().unwrap(),
    }
}
pub(super) fn first(v: &Value) -> VerifiedManifest03 {
    let old = bytes(&v["prior02"]["signed_hex"]);
    let accepted = number(&v["first03"]["accepted_ms"]);
    let checkpoint = crypto::verify_checkpoint02(
        &bytes(&v["root_pin_hex"]),
        &old,
        &AuthenticatedCheckpoint02 {
            trust: ManifestTrust {
                account_id: *id(&v["account_id"]).as_bytes(),
                root_fingerprint: bytes(&v["root_fingerprint_hex"]).try_into().unwrap(),
                generation: 1,
                position: ChainPosition::Current {
                    version: 1,
                    digest: crypto::sha(&old[..old.len() - 64]),
                },
            },
            anchor_digest: [0; 32],
            accepted_at_ms: number(&v["prior02"]["accepted_ms"]),
            last_verified_ms: accepted,
        },
        accepted,
    )
    .unwrap();
    crypto::verify_from_02(&bytes(&v["first03"]["signed_hex"]), &checkpoint, accepted).unwrap()
}
#[test]
fn real_four_role_genesis_enrollment_expired_predecessor_renewal_and_lost_key_replacement() {
    let v = corpus();
    let mut prior = first(&v);
    let mut original = bytes(&v["first03"]["signed_hex"]);
    let mut accepted = number(&v["first03"]["accepted_ms"]);
    let e = expected(&v);
    assert_eq!(
        records(&original)
            .unwrap()
            .iter()
            .map(|r| r[0])
            .collect::<Vec<_>>(),
        vec![1, 2, 4, 6]
    );
    for row in v["successors"].as_array().unwrap() {
        let statement = Statement03::decode(&bytes(&row["statement_hex"])).unwrap();
        assert_eq!(statement.account(), e.account);
        assert_eq!(statement.line(), e.line);
        assert_eq!(statement.opening(), id(&row["opening_id"]));
        assert_eq!(
            crypto::sha(
                &shared::PossessionStatement03::decode(statement.bytes())
                    .unwrap()
                    .transcript()
            )
            .as_slice(),
            bytes(&row["transcript_sha256"])
        );
        let signature = bytes(&row["signature_hex"]);
        let next = bytes(&row["successor_signed_hex"]);
        let now = number(&row["accepted_ms"]);
        if row["operation"] == "renew" {
            assert!(now > prior.identity_at(accepted).unwrap().expires_ms);
        }
        let checked = verify(
            statement,
            &signature,
            &next,
            Predecessor03 {
                signed: &original,
                verified: &prior,
                accepted_ms: accepted,
            },
            &e,
            now,
        )
        .unwrap();
        assert_eq!(checked.operation().as_str(), row["operation"]);
        assert_eq!(checked.statement.bytes().len(), 513);
        assert_eq!(
            checked
                .successor
                .identity_at(now)
                .unwrap()
                .digest
                .as_slice(),
            bytes(&row["successor_semantic_sha256"])
        );
        prior = checked.successor;
        original = next;
        accepted = now;
    }
    let role5: Vec<_> = records(&original)
        .unwrap()
        .into_iter()
        .filter(|r| r[0] == 5)
        .collect();
    assert_eq!(role5.len(), 2);
    assert_eq!(role5.iter().filter(|r| r[148] == 1).count(), 1);
    assert_eq!(role5.iter().filter(|r| r[148] == 2).count(), 1);
}
#[test]
fn exact_owner_origin_election_packet_and_root_successor_are_all_required() {
    let v = corpus();
    let row = &v["successors"][0];
    let prior = first(&v);
    let original = bytes(&v["first03"]["signed_hex"]);
    let accepted = number(&v["first03"]["accepted_ms"]);
    let now = number(&row["accepted_ms"]);
    let e = expected(&v);
    let packet = bytes(&row["statement_hex"]);
    let signature = bytes(&row["signature_hex"]);
    let next = bytes(&row["successor_signed_hex"]);
    for at in 0..513 {
        let mut changed = packet.clone();
        changed[at] ^= 1;
        let result = Statement03::decode(&changed).and_then(|s| {
            verify(
                s,
                &signature,
                &next,
                Predecessor03 {
                    signed: &original,
                    verified: &prior,
                    accepted_ms: accepted,
                },
                &e,
                now,
            )
        });
        assert!(result.is_err(), "unbound offset {at}");
    }
    for at in [0, 6, 39, 47, 55, 153, next.len() - 1] {
        let mut bad = next.clone();
        bad[at] ^= 1;
        assert!(
            verify(
                Statement03::decode(&packet).unwrap(),
                &signature,
                &bad,
                Predecessor03 {
                    signed: &original,
                    verified: &prior,
                    accepted_ms: accepted
                },
                &e,
                now
            )
            .is_err()
        );
    }
    for time in [number(&row["issued_ms"]) - 1, number(&row["expires_ms"])] {
        assert!(
            verify(
                Statement03::decode(&packet).unwrap(),
                &signature,
                &next,
                Predecessor03 {
                    signed: &original,
                    verified: &prior,
                    accepted_ms: accepted
                },
                &e,
                time
            )
            .is_err()
        );
    }
    assert!(Statement03::decode(&packet[..512]).is_err());
    assert!(Statement03::decode(&[packet.as_slice(), &[0]].concat()).is_err());
}
#[test]
fn received_high_s_possession_is_rejected_without_normalizing_original_signature() {
    let v = corpus();
    let row = &v["successors"][0];
    let mut signature = bytes(&row["signature_hex"]);
    let order = [
        0xffu8, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc,
        0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ];
    let mut borrow = 0i16;
    for at in (0..32).rev() {
        let n = i16::from(order[at]) - i16::from(signature[32 + at]) - borrow;
        signature[32 + at] = n.rem_euclid(256) as u8;
        borrow = i16::from(n < 0);
    }
    let prior = first(&v);
    let original = bytes(&v["first03"]["signed_hex"]);
    assert!(
        verify(
            Statement03::decode(&bytes(&row["statement_hex"])).unwrap(),
            &signature,
            &bytes(&row["successor_signed_hex"]),
            Predecessor03 {
                signed: &original,
                verified: &prior,
                accepted_ms: number(&v["first03"]["accepted_ms"])
            },
            &expected(&v),
            number(&row["accepted_ms"])
        )
        .is_err()
    );
}

#[test]
fn exact_prefix_matches_independent_vector_and_commits_original_signatures_and_times() {
    let v = corpus();
    let mut prefix = base_commitment(
        id(&v["account_id"]),
        id(&v["election_challenge_id"]),
        id(&v["binding_id"]),
        &bytes(&v["first03"]["signed_hex"]),
        number(&v["first03"]["accepted_ms"]),
        &bytes(&v["election_bundle_sha256_hex"]).try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(prefix.as_slice(), bytes(&v["base_ancestry_sha256_hex"]));
    for row in v["successors"].as_array().unwrap() {
        assert_eq!(
            prefix.as_slice(),
            bytes(&row["predecessor_ancestry_sha256_hex"])
        );
        let statement = Statement03::decode(&bytes(&row["statement_hex"])).unwrap();
        let signature: [u8; 64] = bytes(&row["signature_hex"]).try_into().unwrap();
        let signed = bytes(&row["successor_signed_hex"]);
        let accepted = number(&row["accepted_ms"]);
        let next = step_commitment(&prefix, &statement, &signature, &signed, accepted).unwrap();
        assert_eq!(next.as_slice(), bytes(&row["ancestry_sha256_hex"]));
        let mut original_signature = signature;
        original_signature[0] ^= 1;
        assert_ne!(
            next,
            step_commitment(&prefix, &statement, &original_signature, &signed, accepted).unwrap()
        );
        let mut root_signature = signed.clone();
        let at = root_signature.len() - 1;
        root_signature[at] ^= 1;
        assert_eq!(
            crypto::sha(&signed[..signed.len() - 64]),
            crypto::sha(&root_signature[..root_signature.len() - 64])
        );
        assert_ne!(
            next,
            step_commitment(&prefix, &statement, &signature, &root_signature, accepted).unwrap()
        );
        assert_ne!(
            next,
            step_commitment(&prefix, &statement, &signature, &signed, accepted + 1).unwrap()
        );
        prefix = next;
    }
}
