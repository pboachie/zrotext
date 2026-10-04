use super::*;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/preaccount-root-evidence-01.json"
    ))
    .unwrap()
}
fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn bytes(v: &Value, key: &str) -> Vec<u8> {
    hex(v[key].as_str().unwrap())
}
fn backup_vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/root-backup-01.json"
    ))
    .unwrap()
}
fn card_vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/recovery-kit-01.json"
    ))
    .unwrap()
}
// Independent fixture selections; never construct expectation from received I/C.
fn expected(index: usize) -> ExpectedStageRoot {
    let v = vectors();
    let backup = backup_vector();
    let card = card_vector();
    let origin = match index {
        0 => "https://example.test".into(),
        1 => "https://a".into(),
        2 => format!("https://{}", "a".repeat(504)),
        _ => panic!("unknown fixture case"),
    };
    let i = Intent {
        epoch: [8; 16],
        allocation: 1,
        account: [1; 16],
        user: [2; 16],
        approval: [3; 16],
        origin,
        root_pin: bytes(&backup, "rootPinHex").try_into().unwrap(),
        root_fingerprint: bytes(&backup, "fingerprintHex").try_into().unwrap(),
        backup: bytes(&card, "backupIdHex").try_into().unwrap(),
        backup_digest: Sha256::digest(bytes(&backup, "ciphertextHex")).into(),
        card_digest: Sha256::digest(bytes(&card, "cardHex")).into(),
        managed_plan_digest: Sha256::digest(b"ZROtext synthetic stage managed-plan commitment")
            .into(),
        policy_digest: Sha256::digest(b"ZROtext synthetic stage operator-policy commitment").into(),
        deadline_ms: 1_300_000,
    };
    let c = Challenge {
        epoch: [8; 16],
        allocation: 1,
        intent_digest: intent_digest(&encode_intent(&i).unwrap()).unwrap(),
        id: [4; 16],
        nonce: Sha256::digest(b"ZROtext synthetic stage root challenge nonce").into(),
        issued_ms: 1_000_000,
        expires_ms: 1_300_000,
    };
    assert_eq!(v["cases"][index]["origin"].as_str().unwrap(), i.origin);
    ExpectedStageRoot {
        intent: i,
        challenge: c,
    }
}
fn evidence(index: usize) -> Vec<u8> {
    bytes(&vectors()["cases"][index], "evidenceHex")
}

#[test]
fn genuine_shared_signatures_bind_full_independent_intents_and_copy_metadata() {
    let v = vectors();
    assert_eq!(INTENT_DOMAIN, bytes(&v, "intentDomainHex").as_slice());
    assert_eq!(ROOT_DOMAIN, bytes(&v, "rootDomainHex").as_slice());
    assert_eq!((EVIDENCE_MIN, EVIDENCE_MAX), (543, 1054));
    for n in 0..3 {
        let e = expected(n);
        let row = &v["cases"][n];
        let ib = bytes(row, "intentHex");
        let cb = bytes(row, "challengeHex");
        assert_eq!(encode_intent(&e.intent).unwrap(), ib);
        assert_eq!(decode_intent(&ib).unwrap(), e.intent);
        assert_eq!(encode_challenge(&e.challenge).unwrap(), cb);
        assert_eq!(decode_challenge(&cb).unwrap(), e.challenge);
        assert_eq!(
            intent_digest(&ib).unwrap().as_slice(),
            bytes(row, "intentDigestHex").as_slice()
        );
        assert_eq!(transcript(&ib, &cb), bytes(row, "transcriptHex"));
        let mut wire = evidence(n);
        let proof = verify(&wire, &e, 1_000_000).unwrap();
        assert_eq!(proof.kind(), "cryptographic_signed_evidence");
        let original = proof.identity();
        assert_eq!(original.account, [1; 16]);
        assert_eq!(original.intent_digest, e.challenge.intent_digest);
        wire.fill(0);
        let mut copy = proof.identity();
        copy.account.fill(0);
        assert_eq!(proof.identity(), original);
    }
    assert_eq!(evidence(2).len(), EVIDENCE_MAX);
    // N=1 is a framing floor, not an accepted canonical HTTPS origin.
    assert!(evidence(1).len() > EVIDENCE_MIN);
}

#[test]
fn every_expected_binding_and_freshly_signed_foreign_approval_remains_independent() {
    let original = expected(0);
    let mut intents = Vec::new();
    macro_rules! changed_intent {
        ($field:ident) => {{
            let mut i = original.intent.clone();
            i.$field[0] ^= 1;
            intents.push(i);
        }};
    }
    changed_intent!(epoch);
    changed_intent!(account);
    changed_intent!(user);
    changed_intent!(approval);
    changed_intent!(root_pin);
    changed_intent!(root_fingerprint);
    changed_intent!(backup);
    changed_intent!(backup_digest);
    changed_intent!(card_digest);
    changed_intent!(managed_plan_digest);
    changed_intent!(policy_digest);
    let mut i = original.intent.clone();
    i.allocation += 1;
    intents.push(i);
    let mut i = original.intent.clone();
    i.deadline_ms -= 1;
    intents.push(i);
    let mut i = original.intent.clone();
    i.origin = "https://other.invalid".into();
    intents.push(i);
    for i in intents {
        let mut e = original.clone();
        e.intent = i;
        assert!(verify(&evidence(0), &e, 1_000_000).is_err());
    }
    let mut challenges = Vec::new();
    macro_rules! changed_challenge {
        ($field:ident) => {{
            let mut c = original.challenge.clone();
            c.$field[0] ^= 1;
            challenges.push(c);
        }};
    }
    changed_challenge!(epoch);
    changed_challenge!(intent_digest);
    changed_challenge!(id);
    changed_challenge!(nonce);
    let mut c = original.challenge.clone();
    c.allocation += 1;
    challenges.push(c);
    let mut c = original.challenge.clone();
    c.issued_ms += 1;
    challenges.push(c);
    let mut c = original.challenge.clone();
    c.expires_ms -= 1;
    challenges.push(c);
    for c in challenges {
        let mut e = original.clone();
        e.challenge = c;
        assert!(verify(&evidence(0), &e, 1_000_000).is_err());
    }
    let foreign = bytes(&vectors(), "foreignValidApprovalEvidenceHex");
    assert!(verify(&foreign, &original, 1_000_000).is_err());
    // The fixture's altered approval really was signed: accepting a changed
    // expectation proves math only, never that a caller approved that change.
    let mut foreign_expectation = original.clone();
    foreign_expectation.intent.approval = [7; 16];
    foreign_expectation.challenge.intent_digest =
        intent_digest(&encode_intent(&foreign_expectation.intent).unwrap()).unwrap();
    assert_eq!(
        verify(&foreign, &foreign_expectation, 1_000_000)
            .unwrap()
            .kind(),
        "cryptographic_signed_evidence"
    );
}

#[test]
fn every_wire_bit_truncation_extra_byte_and_length_alias_refuses() {
    let wire = evidence(0);
    let e = expected(0);
    for n in 0..wire.len() {
        assert!(verify(&wire[..n], &e, 1_000_000).is_err());
        let mut changed = wire.clone();
        changed[n] ^= 1;
        assert!(verify(&changed, &e, 1_000_000).is_err());
    }
    let mut extra = wire.clone();
    extra.push(0);
    assert!(verify(&extra, &e, 1_000_000).is_err());
    let mut alias = wire;
    alias[..2].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(verify(&alias, &e, 1_000_000).is_err());
    assert!(verify(&vec![0; EVIDENCE_MAX + 1], &e, 1_000_000).is_err());
}

#[test]
fn purpose_curve_pin_origin_and_integer_shapes_refuse_before_signature_use() {
    let e = expected(0);
    for id in 0..5 {
        let mut i = e.intent.clone();
        match id {
            0 => i.epoch.fill(0),
            1 => i.account.fill(0),
            2 => i.user.fill(0),
            3 => i.approval.fill(0),
            _ => i.backup.fill(0),
        };
        assert!(encode_intent(&i).is_err());
    }
    for origin in [
        "https://example.test/",
        "https://EXAMPLE.test",
        "http://example.test",
        "https://example.test?x",
        "https://é.invalid",
        "https://example.test\n",
    ] {
        let mut i = e.intent.clone();
        i.origin = origin.into();
        assert!(encode_intent(&i).is_err());
    }
    let mut i = e.intent.clone();
    i.origin = format!("https://{}", "a".repeat(505));
    assert!(encode_intent(&i).is_err());
    for offset in [0, 5, 21, 29] {
        let mut i = e.intent.clone();
        i.root_pin[offset] ^= 1;
        assert!(encode_intent(&i).is_err());
    }
    let mut i = e.intent.clone();
    i.root_pin[30..].fill(0);
    assert!(encode_intent(&i).is_err());
    for value in [0, i64::MAX as u64 + 1, u64::MAX] {
        let mut i = e.intent.clone();
        i.allocation = value;
        assert!(encode_intent(&i).is_err());
        let mut i = e.intent.clone();
        i.deadline_ms = value;
        assert!(encode_intent(&i).is_err());
        let mut c = e.challenge.clone();
        c.allocation = value;
        assert!(encode_challenge(&c).is_err());
    }
    for tag in 0..2 {
        let mut ib = encode_intent(&e.intent).unwrap();
        ib[tag] = 2;
        assert!(decode_intent(&ib).is_err());
        let mut cb = encode_challenge(&e.challenge).unwrap();
        cb[tag] = 2;
        assert!(decode_challenge(&cb).is_err());
    }
}

#[test]
fn old_owner_session_domain_foreign_root_high_s_and_noncanonical_signatures_refuse() {
    let v = vectors();
    let e = expected(0);
    let old_unsigned = bytes(&v, "oldOwnerUnsignedHex");
    let old_signature = bytes(&v, "oldOwnerSignatureHex");
    let old_expected = crate::sealed_root_enrollment::parse(&old_unsigned).unwrap();
    assert!(
        crate::sealed_root_enrollment::verify(
            &e.intent.root_pin,
            &old_unsigned,
            &old_signature,
            &old_expected,
            1_000_000
        )
        .is_ok()
    );
    assert!(decode_intent(&old_unsigned).is_err());
    for name in [
        "oldOwnerSignatureHex",
        "wrongDomainSignatureHex",
        "wrongRootSignatureHex",
        "highSignatureHex",
    ] {
        let mut wire = evidence(0);
        let at = wire.len() - 64;
        wire[at..].copy_from_slice(&bytes(&v, name));
        assert!(verify(&wire, &e, 1_000_000).is_err());
    }
    let mut zero = evidence(0);
    let at = zero.len() - 64;
    zero[at..].fill(0);
    assert!(verify(&zero, &e, 1_000_000).is_err());
    let mut long = evidence(0);
    long.push(0);
    assert!(verify(&long, &e, 1_000_000).is_err());
}

#[test]
fn signed_intervals_require_trusted_fresh_time_and_bounded_intent_deadline() {
    let e = expected(0);
    for now in [0, 999_999, 1_300_000, i64::MAX as u64 + 1] {
        assert!(verify(&evidence(0), &e, now).is_err());
    }
    assert!(verify(&evidence(0), &e, 1_299_999).is_ok());
    for (issued, expires) in [
        (0, 1_300_000),
        (1_000_000, 1_000_000),
        (1_000_000, 1_300_001),
        (1_000_000, i64::MAX as u64 + 1),
    ] {
        let mut c = e.challenge.clone();
        c.issued_ms = issued;
        c.expires_ms = expires;
        assert!(encode_challenge(&c).is_err());
    }
    let mut c = e.challenge.clone();
    c.nonce.fill(0);
    assert!(encode_challenge(&c).is_err());
    let mut c = e.challenge.clone();
    c.id.fill(0);
    assert!(encode_challenge(&c).is_err());
    let mut c = e.challenge.clone();
    c.epoch.fill(0);
    assert!(encode_challenge(&c).is_err());
    let mut i = e.intent.clone();
    i.deadline_ms -= 1;
    let mut c = e.challenge.clone();
    c.intent_digest = intent_digest(&encode_intent(&i).unwrap()).unwrap();
    let raw: [u8; 64] = bytes(&vectors()["cases"][0], "signatureHex")
        .try_into()
        .unwrap();
    assert!(encode_evidence(&i, &c, &raw).is_err());
}

#[test]
fn decoded_public_snapshots_and_redacted_results_do_not_supply_authority() {
    let e = expected(0);
    let mut ib = encode_intent(&e.intent).unwrap();
    let decoded = decode_intent(&ib).unwrap();
    ib.fill(0);
    assert_eq!(decoded, e.intent);
    let proof = verify(&evidence(0), &e, 1_000_000).unwrap();
    assert_eq!(
        format!("{proof:?}"),
        "VerifiedStageRootEvidence([REDACTED])"
    );
    assert_eq!(
        format!("{:?}", proof.identity()),
        "EvidenceIdentity([REDACTED])"
    );
    assert_eq!(format!("{e:?}"), "ExpectedStageRoot([REDACTED])");
    // Width variants commit the old fixture's artifact hashes under a distinct
    // origin. Math succeeds; no artifact recovery/custody claim follows.
    assert_eq!(
        verify(&evidence(1), &expected(1), 1_000_000)
            .unwrap()
            .kind(),
        "cryptographic_signed_evidence"
    );
}

#[test]
fn closed_codecs_bound_individual_frames_and_canonical_encodings() {
    let e = expected(0);
    let ib = encode_intent(&e.intent).unwrap();
    let cb = encode_challenge(&e.challenge).unwrap();
    for n in 0..ib.len() {
        assert!(decode_intent(&ib[..n]).is_err());
    }
    for n in 0..cb.len() {
        assert!(decode_challenge(&cb[..n]).is_err());
    }
    let mut more = ib;
    more.push(0);
    assert!(decode_intent(&more).is_err());
    let mut more = cb;
    more.push(0);
    assert!(decode_challenge(&more).is_err());
    let mut alias = encode_intent(&e.intent).unwrap();
    alias[74..76].copy_from_slice(&1u16.to_be_bytes());
    assert!(decode_intent(&alias).is_err());
    assert!(decode_intent(&vec![0; INTENT_MAX + 1]).is_err());
}

#[cfg(feature = "unlock")]
fn synthetic_root(label: &[u8]) -> RootSecret {
    RootSecret::new(zeroize::Zeroizing::new(Sha256::digest(label).into())).unwrap()
}
#[cfg(feature = "unlock")]
fn reviewed(e: &ExpectedStageRoot, now: u64) -> ReviewedStageRoot {
    ReviewedStageRoot::inspect(
        &encode_intent(&e.intent).unwrap(),
        &encode_challenge(&e.challenge).unwrap(),
        e,
        now,
    )
    .unwrap()
}

#[cfg(feature = "unlock")]
#[test]
fn matched_unlock_producer_emits_genuine_signatures_for_all_bounded_cases() {
    let root = synthetic_root(b"ZROtext synthetic root-backup test root");
    for index in 0..3 {
        let e = expected(index);
        let wire = reviewed(&e, 1_000_000).sign(&root, 1_000_001).unwrap();
        assert_eq!(
            verify(&wire, &e, 1_000_001)
                .unwrap()
                .identity()
                .intent_digest,
            e.challenge.intent_digest
        );
        let signature = canonical_signature(&wire[wire.len() - 64..]).unwrap();
        let public = VerifyingKey::from_sec1_bytes(&e.intent.root_pin[29..]).unwrap();
        // Independent shared transcript verifies the produced signature too.
        public
            .verify(
                &bytes(&vectors()["cases"][index], "transcriptHex"),
                &signature,
            )
            .unwrap();
    }
}

#[cfg(feature = "unlock")]
#[test]
fn unlock_refuses_wrong_root_expiry_and_backwards_fresh_signing_time() {
    let e = expected(0);
    let root = synthetic_root(b"ZROtext synthetic root-backup test root");
    let other = synthetic_root(b"ZROtext synthetic unrelated stage root");
    assert!(reviewed(&e, 1_000_000).sign(&other, 1_000_001).is_err());
    assert!(reviewed(&e, 1_000_000).sign(&root, 1_300_000).is_err());
    assert!(reviewed(&e, 1_000_010).sign(&root, 1_000_009).is_err());
    assert!(reviewed(&e, 1_000_010).sign(&root, 1_000_010).is_ok());
}

#[cfg(feature = "unlock")]
#[test]
fn unlock_inspection_captures_owned_public_context_without_caller_mutation() {
    let mut e = expected(0);
    let original = e.clone();
    let mut ib = encode_intent(&e.intent).unwrap();
    let mut cb = encode_challenge(&e.challenge).unwrap();
    let snapshot = ReviewedStageRoot::inspect(&ib, &cb, &e, 1_000_000).unwrap();
    ib.fill(0);
    cb.fill(0);
    e.intent.approval.fill(0);
    e.challenge.nonce.fill(0);
    let root = synthetic_root(b"ZROtext synthetic root-backup test root");
    let wire = snapshot.sign(&root, 1_000_001).unwrap();
    assert!(verify(&wire, &original, 1_000_001).is_ok());
    assert!(verify(&wire, &e, 1_000_001).is_err());
}

#[cfg(feature = "unlock")]
#[test]
fn unlock_inspection_refuses_valid_foreign_intent_and_old_owner_session_purpose() {
    let e = expected(0);
    let wire = bytes(&vectors(), "foreignValidApprovalEvidenceHex");
    let n = u16::from_be_bytes(wire[..2].try_into().unwrap()) as usize;
    assert!(
        ReviewedStageRoot::inspect(
            &wire[2..2 + n],
            &wire[2 + n..2 + n + CHALLENGE_SIZE],
            &e,
            1_000_000
        )
        .is_err()
    );
    assert!(
        ReviewedStageRoot::inspect(
            &bytes(&vectors(), "oldOwnerUnsignedHex"),
            &encode_challenge(&e.challenge).unwrap(),
            &e,
            1_000_000
        )
        .is_err()
    );
}
