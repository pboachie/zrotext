// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde_json::Value;
fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/sealed-profile03-manifest-install-01.json"
    ))
    .unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    v.as_str()
        .unwrap()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| chunk.as_slice())
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn time(v: &Value) -> u64 {
    v.as_str().unwrap().parse().unwrap()
}
fn first(v: &Value) -> VerifiedCheckpoint03 {
    let signed = bytes(&v["first03"]["signed_hex"]);
    let pin = bytes(&v["root_pin_hex"]);
    let accepted = time(&v["first03"]["accepted_ms"]);
    verify_checkpoint(
        &pin,
        &signed,
        &Checkpoint03 {
            account_id: pin[5..21].try_into().unwrap(),
            root_fingerprint: bytes(&v["root_fingerprint_hex"]).try_into().unwrap(),
            version: 2,
            digest: hash(&signed[..signed.len() - 64]),
            accepted_ms: accepted,
        },
        accepted,
    )
    .unwrap()
}
#[test]
fn actual_four_role_history_enrolls_then_renews_expired_history_and_replaces_lost_browser_key() {
    let v = corpus();
    let mut prior = first(&v);
    assert_eq!(
        records(&prior.signed[..prior.signed.len() - 64])
            .unwrap()
            .iter()
            .map(|r| r[0])
            .collect::<Vec<_>>(),
        vec![1, 2, 4, 6]
    );
    for row in v["successors"].as_array().unwrap() {
        let packet = PossessionStatement03::decode(&bytes(&row["statement_hex"])).unwrap();
        let signed = bytes(&row["successor_signed_hex"]);
        let now = time(&row["accepted_ms"]);
        packet
            .verify_signature(&bytes(&row["signature_hex"]))
            .unwrap();
        assert_eq!(
            hash(&packet.transcript()).as_slice(),
            bytes(&row["transcript_sha256"])
        );
        let review = inspect_unsigned_successor(
            &prior,
            &signed[..signed.len() - 64],
            &packet.identities()[4],
            &packet.browser_point(),
            now,
        )
        .unwrap();
        assert_eq!(review.operation().as_str(), row["operation"]);
        let checked = verify_successor(
            &prior,
            &signed,
            &packet.identities()[4],
            &packet.browser_point(),
            now,
        )
        .unwrap();
        assert_eq!(checked.operation(), review.operation());
        assert_eq!(checked.checkpoint().digest(), review.digest());
        if row["operation"] == "renew" {
            assert!(now > number(&prior.signed[47..55]).unwrap());
        }
        prior = checked.into_checkpoint();
    }
    let records = records(&prior.signed[..prior.signed.len() - 64]).unwrap();
    assert_eq!(
        records.iter().filter(|r| r[0] == 5 && r[148] == 1).count(),
        1
    );
    assert_eq!(
        records.iter().filter(|r| r[0] == 5 && r[148] == 2).count(),
        1
    );
}
#[test]
fn unsigned_review_never_supplies_a_root_signature_or_installation_proof() {
    let v = corpus();
    let prior = first(&v);
    let row = &v["successors"][0];
    let signed = bytes(&row["successor_signed_hex"]);
    let point: [u8; 65] = bytes(&row["role5_point_hex"]).try_into().unwrap();
    let now = time(&row["accepted_ms"]);
    let line: [u8; 16] = PossessionStatement03::decode(&bytes(&row["statement_hex"]))
        .unwrap()
        .identities()[4];
    let review =
        inspect_unsigned_successor(&prior, &signed[..signed.len() - 64], &line, &point, now)
            .unwrap();
    assert_eq!(review.unsigned(), &signed[..signed.len() - 64]);
    let mut invalid = signed.clone();
    let end = invalid.len();
    invalid[end - 64..].fill(0);
    assert!(verify_successor(&prior, &invalid, &line, &point, now).is_err());
    assert!(inspect_unsigned_successor(&prior, &signed, &line, &point, now).is_err());
}
#[test]
fn mutable_key_scope_and_unrelated_revocation_cannot_hide_in_an_unsigned_successor() {
    let v = corpus();
    let prior = first(&v);
    let row = &v["successors"][0];
    let signed = bytes(&row["successor_signed_hex"]);
    let packet = PossessionStatement03::decode(&bytes(&row["statement_hex"])).unwrap();
    let now = time(&row["accepted_ms"]);
    for mode in 0..4 {
        let mut unsigned = signed[..signed.len() - 64].to_vec();
        let at = 153; // Real selected role1 is first in the canonical record set.
        match mode {
            0 => unsigned[at + 114] ^= 1,
            1 => unsigned[at + 148] = 2,
            2 => {
                let until = number(&prior.signed[at + 140..at + 148]).unwrap() - 1;
                unsigned[at + 140..at + 148].copy_from_slice(&until.to_be_bytes());
            }
            _ => unsigned[at + 132..at + 140].copy_from_slice(&(now - 1).to_be_bytes()),
        }
        assert!(
            inspect_unsigned_successor(
                &prior,
                &unsigned,
                &packet.identities()[4],
                &packet.browser_point(),
                now
            )
            .is_err()
        );
    }
}
#[test]
fn candidate_packet_copies_bytes_and_requires_exact_curve_key_id_and_received_signature() {
    let v = corpus();
    let row = &v["successors"][0];
    let original = bytes(&row["statement_hex"]);
    let mut input = original.clone();
    let parsed = PossessionStatement03::decode(&input).unwrap();
    input.fill(0);
    assert_eq!(parsed.bytes().as_slice(), original);
    let signature = bytes(&row["signature_hex"]);
    parsed.verify_signature(&signature).unwrap();
    let mut changed = signature.clone();
    changed[0] ^= 1;
    assert!(parsed.verify_signature(&changed).is_err());
    for at in [0, 4, 5, 6, 7, 136, 168, 184, 416, 448] {
        let mut packet = original.clone();
        packet[at] ^= 1;
        let result =
            PossessionStatement03::decode(&packet).and_then(|p| p.verify_signature(&signature));
        assert!(result.is_err());
    }
    assert!(PossessionStatement03::decode(&original[..512]).is_err());
    assert!(PossessionStatement03::decode(&[original.as_slice(), &[0]].concat()).is_err());
}
#[test]
fn independently_selected_root_and_historical_checkpoint_cannot_come_from_downloaded_scope() {
    let v = corpus();
    let prior = first(&v);
    for mode in 0..5 {
        let mut selected = Checkpoint03 {
            account_id: prior.account,
            root_fingerprint: bytes(&v["root_fingerprint_hex"]).try_into().unwrap(),
            version: prior.version,
            digest: prior.digest,
            accepted_ms: prior.accepted,
        };
        match mode {
            0 => selected.account_id[0] ^= 1,
            1 => selected.root_fingerprint[0] ^= 1,
            2 => selected.version += 1,
            3 => selected.digest[0] ^= 1,
            _ => selected.accepted_ms = 1,
        };
        assert!(verify_checkpoint(&prior.pin, &prior.signed, &selected, prior.comparison).is_err());
    }
}

#[test]
fn cold_expired_predecessor_reconstructs_from_original_acceptance_before_renewal() {
    let v = corpus();
    let enrolled = &v["successors"][0];
    let renewal = &v["successors"][1];
    let pin = bytes(&v["root_pin_hex"]);
    let signed = bytes(&enrolled["successor_signed_hex"]);
    let now = time(&renewal["accepted_ms"]);
    assert!(now > number(&signed[47..55]).unwrap());
    let mut selected = Checkpoint03 {
        account_id: pin[5..21].try_into().unwrap(),
        root_fingerprint: bytes(&v["root_fingerprint_hex"]).try_into().unwrap(),
        version: 3,
        digest: hash(&signed[..signed.len() - 64]),
        accepted_ms: time(&enrolled["accepted_ms"]),
    };
    let prior = verify_checkpoint(&pin, &signed, &selected, now).unwrap();
    let packet = PossessionStatement03::decode(&bytes(&renewal["statement_hex"])).unwrap();
    let next = verify_successor(
        &prior,
        &bytes(&renewal["successor_signed_hex"]),
        &packet.identities()[4],
        &packet.browser_point(),
        now,
    )
    .unwrap();
    assert_eq!(next.operation(), Operation03::Renew);
    assert!(
        verify_successor(
            &prior,
            &bytes(&renewal["successor_signed_hex"]),
            &packet.identities()[4],
            &packet.browser_point(),
            now - 1
        )
        .is_err()
    );
    // Merely finding an expired signed packet cannot invent valid acceptance.
    selected.accepted_ms = number(&signed[47..55]).unwrap();
    assert!(verify_checkpoint(&pin, &signed, &selected, now).is_err());
}

#[test]
fn possession_grammar_requires_exact_supported_vault_and_election_epochs() {
    let v = corpus();
    let original = bytes(&v["successors"][0]["statement_hex"]);
    for offset in [144, 152] {
        for unsupported in [0u64, 2, u64::MAX] {
            let mut input = original.clone();
            input[offset..offset + 8].copy_from_slice(&unsupported.to_be_bytes());
            assert!(PossessionStatement03::decode(&input).is_err());
        }
    }
}
