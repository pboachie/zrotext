// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use serde_json::Value;
fn corpus() -> Value {
    serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/sealed-profile03-manifest-install-01.json"
    ))
    .unwrap()
}
fn bytes(value: &Value) -> Vec<u8> {
    value
        .as_str()
        .unwrap()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| chunk.as_slice())
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn num(value: &Value) -> u64 {
    value.as_str().unwrap().parse().unwrap()
}
fn wire(scope: &Scope, prior: &[u8], unsigned: &[u8]) -> Vec<u8> {
    let mut out = b"ZTMU\x01".to_vec();
    out.push(match scope.operation {
        Operation03::Enroll => 1,
        Operation03::Renew => 2,
        Operation03::Replace => 3,
    });
    for id in [scope.account, scope.device, scope.line] {
        out.extend(id);
    }
    out.extend((scope.origin.len() as u16).to_be_bytes());
    out.extend(scope.origin.as_bytes());
    out.extend(scope.fingerprint);
    out.extend(scope.predecessor_version.to_be_bytes());
    out.extend(scope.predecessor_digest);
    out.extend(scope.predecessor_accepted_ms.to_be_bytes());
    out.extend(scope.phone_reader);
    out.extend(scope.browser_point);
    out.extend(scope.browser_key);
    out.extend(scope.issued_ms.to_be_bytes());
    out.extend(scope.expires_ms.to_be_bytes());
    for field in [prior, unsigned] {
        out.extend((field.len() as u16).to_be_bytes());
        out.extend(field);
    }
    out
}
fn fixture(index: usize) -> (Proposal, Expected, Vec<u8>, u64) {
    let v = corpus();
    let row = &v["successors"][index];
    let prior = if index == 0 {
        bytes(&v["first03"]["signed_hex"])
    } else {
        bytes(&v["successors"][index - 1]["successor_signed_hex"])
    };
    let signed = bytes(&row["successor_signed_hex"]);
    let statement = policy::PossessionStatement03::decode(&bytes(&row["statement_hex"])).unwrap();
    let ids = statement.identities();
    let scope = Scope {
        operation: [
            Operation03::Enroll,
            Operation03::Renew,
            Operation03::Replace,
        ][index],
        account: ids[0],
        device: ids[3],
        line: ids[4],
        origin: v["canonical_origin"].as_str().unwrap().into(),
        fingerprint: bytes(&v["root_fingerprint_hex"]).try_into().unwrap(),
        predecessor_version: num(&row["predecessor_version"]),
        predecessor_digest: bytes(&row["predecessor_semantic_sha256"])
            .try_into()
            .unwrap(),
        predecessor_accepted_ms: num(&row["predecessor_accepted_ms"]),
        phone_reader: prior[154..186].try_into().unwrap(),
        browser_point: statement.browser_point(),
        browser_key: statement.commitments()[7],
        issued_ms: u64::from_be_bytes(signed[39..47].try_into().unwrap()),
        expires_ms: num(&row["manifest_expires_ms"]),
    };
    let expected = Expected {
        identity: ExpectedIdentity {
            account_id: scope.account,
            origin: scope.origin.clone(),
            root_fingerprint: scope.fingerprint,
        },
        root_pin: bytes(&v["root_pin_hex"]).try_into().unwrap(),
        scope: scope.clone(),
    };
    let public_packets: Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/sealed-profile03-manifest-proposal-01.json"
    ))
    .unwrap();
    let packet = bytes(&public_packets["cases"][index]["proposal_hex"]);
    assert_eq!(packet, wire(&scope, &prior, &signed[..signed.len() - 64]));
    assert_eq!(
        hash(&packet).as_slice(),
        bytes(&public_packets["cases"][index]["proposal_sha256"])
    );
    let proposal = decode(&packet).unwrap();
    (proposal, expected, signed, num(&row["accepted_ms"]))
}
#[test]
fn independently_signed_enrollment_expired_renewal_and_replacement_are_exact_public_proposals() {
    for index in 0..3 {
        let (proposal, expected, signed, now) = fixture(index);
        let mut reviewed = inspect(&proposal, &expected, now).unwrap();
        assert_eq!(reviewed.scope().operation, expected.scope.operation);
        assert_eq!(reviewed.unsigned(), &signed[..signed.len() - 64]);
        reviewed.recheck(now + 1).unwrap();
        verify_signed(&proposal, &expected, &signed, now).unwrap();
        if index == 1 {
            assert!(now > u64::from_be_bytes(proposal.predecessor()[47..55].try_into().unwrap()));
        }
    }
}
#[test]
fn downloaded_scope_does_not_supply_independent_root_highwater_phone_or_new_browser_intent() {
    let (proposal, expected, _, now) = fixture(0);
    for mode in 0..11 {
        let mut changed = expected.clone();
        match mode {
            0 => changed.identity.account_id[0] ^= 1,
            1 => changed.identity.origin = "https://other.example.invalid".into(),
            2 => changed.identity.root_fingerprint[0] ^= 1,
            3 => changed.scope.predecessor_version += 1,
            4 => changed.scope.predecessor_digest[0] ^= 1,
            5 => changed.scope.predecessor_accepted_ms += 1,
            6 => changed.scope.device[0] ^= 1,
            7 => changed.scope.phone_reader[0] ^= 1,
            8 => changed.scope.browser_point[1] ^= 1,
            9 => changed.scope.operation = Operation03::Replace,
            _ => changed.root_pin[40] ^= 1,
        }
        assert!(inspect(&proposal, &changed, now).is_err());
    }
}
#[test]
fn short_long_trailing_unknown_and_mutated_unsigned_candidates_refuse() {
    let (proposal, expected, _, now) = fixture(0);
    let original = wire(
        proposal.scope(),
        proposal.predecessor(),
        proposal.unsigned(),
    );
    for end in [0, 4, 5, 6, 54, original.len() - 1] {
        assert!(decode(&original[..end]).is_err());
    }
    assert!(decode(&[original.as_slice(), &[0]].concat()).is_err());
    assert!(decode(&vec![0; MAX_PACKET + 1]).is_err());
    let mut unknown = original.clone();
    unknown[5] = 4;
    assert!(decode(&unknown).is_err());
    for offset in [6, 31, 55, 87, 153 + 114, 153 + 148] {
        let mut unsigned = proposal.unsigned().to_vec();
        unsigned[offset] ^= 1;
        let changed = decode(&wire(proposal.scope(), proposal.predecessor(), &unsigned)).unwrap();
        assert!(inspect(&changed, &expected, now).is_err());
    }
}
#[test]
fn late_or_regressing_clock_and_changed_returned_unsigned_or_signature_cannot_publish() {
    let (proposal, expected, signed, now) = fixture(0);
    let mut reviewed = inspect(&proposal, &expected, now).unwrap();
    reviewed.recheck(now + 10).unwrap();
    assert!(reviewed.recheck(now + 5).is_err());
    assert!(reviewed.recheck(now - 1).is_err());
    assert!(
        reviewed
            .recheck(expected.scope.issued_ms + 300_000)
            .is_err()
    );
    assert!(inspect(&proposal, &expected, expected.scope.issued_ms - 1).is_err());
    assert!(inspect(&proposal, &expected, expected.scope.expires_ms).is_err());
    for offset in [6, 31, 153, signed.len() - 1] {
        let mut changed = signed.clone();
        changed[offset] ^= 1;
        assert!(verify_signed(&proposal, &expected, &changed, now).is_err());
    }
    let mut forged_prior = proposal.predecessor().to_vec();
    let end = forged_prior.len();
    forged_prior[end - 1] ^= 1;
    let changed = decode(&wire(proposal.scope(), &forged_prior, proposal.unsigned())).unwrap();
    assert!(inspect(&changed, &expected, now).is_err());
}

#[cfg(feature = "unlock")]
#[test]
fn typed_one_use_signing_requires_the_genuinely_matching_recovered_root_and_fresh_review() {
    use crate::root_backup::RootSecret;
    use p256::{
        SecretKey,
        ecdsa::{Signature, SigningKey, signature::Signer},
        elliptic_curve::Generate,
    };
    use rand::rngs::SysRng;
    use zeroize::Zeroizing;
    let (proposal, mut expected, _, now) = fixture(0);
    let secret = SecretKey::try_generate_from_rng(&mut SysRng).unwrap();
    let root = RootSecret::new(Zeroizing::new(secret.to_bytes().into())).unwrap();
    let signing = SigningKey::from(secret);
    let point = signing.verifying_key().to_sec1_point(false);
    let mut pin = expected.root_pin;
    pin[29..94].copy_from_slice(point.as_bytes());
    expected.root_pin = pin;
    expected.identity.root_fingerprint =
        crate::sealed_root_enrollment::root_fingerprint(&pin, &expected.scope.account).unwrap();
    expected.scope.fingerprint = expected.identity.root_fingerprint;
    let replace_root = |bytes: &mut [u8]| {
        bytes[87..152].copy_from_slice(point.as_bytes());
        let record = bytes[153..]
            .as_chunks_mut::<149>()
            .0
            .iter_mut()
            .map(|chunk| chunk.as_mut_slice())
            .find(|row| row[0] == 6)
            .unwrap();
        record[33..98].copy_from_slice(point.as_bytes());
        record[1..33].copy_from_slice(&hash(
            &[b"ZTSE/key/v1\0".as_slice(), &[1, 1], point.as_bytes()].concat(),
        ));
    };
    let mut old = proposal.predecessor()[..proposal.predecessor().len() - 64].to_vec();
    replace_root(&mut old);
    expected.scope.predecessor_digest = hash(&old);
    let transcript = [
        b"ZTSE/manifest/v3\0".as_slice(),
        &(old.len() as u32).to_be_bytes(),
        &old,
    ]
    .concat();
    let signature: Signature = signing.sign(&transcript);
    old.extend(signature.normalize_s().to_bytes());
    let mut unsigned = proposal.unsigned().to_vec();
    replace_root(&mut unsigned);
    unsigned[55..87].copy_from_slice(&expected.scope.predecessor_digest);
    let proposal = decode(&wire(&expected.scope, &old, &unsigned)).unwrap();
    let reviewed = inspect(&proposal, &expected, now).unwrap();
    let signed = sign(&root, reviewed, now).unwrap();
    verify_signed(&proposal, &expected, &signed, now).unwrap();
    let mut later = inspect(&proposal, &expected, now).unwrap();
    later.recheck(now + 10).unwrap();
    assert!(sign(&root, later, now + 5).is_err());
    let wrong = SecretKey::try_generate_from_rng(&mut SysRng).unwrap();
    let wrong = RootSecret::new(Zeroizing::new(wrong.to_bytes().into())).unwrap();
    assert!(sign(&wrong, inspect(&proposal, &expected, now).unwrap(), now).is_err());
    assert!(sign(&root, inspect(&proposal, &expected, now).unwrap(), now - 1).is_err());
    assert!(
        sign(
            &root,
            inspect(&proposal, &expected, now).unwrap(),
            expected.scope.issued_ms + 300_000
        )
        .is_err()
    );
}
