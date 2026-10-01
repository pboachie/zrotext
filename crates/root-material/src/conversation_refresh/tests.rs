// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use zeroize::Zeroizing;
fn signing(n: u8) -> SigningKey {
    let mut scalar = [0; 32];
    scalar[31] = n;
    SigningKey::from_slice(&scalar).unwrap()
}
fn point(n: u8) -> [u8; 65] {
    signing(n)
        .verifying_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap()
}
fn record(
    role: u8,
    n: u8,
    device: [u8; 16],
    line: [u8; 16],
    scope: u16,
    from: u64,
    until: u64,
) -> Vec<u8> {
    let p = point(n);
    [
        &[role],
        key_id(role, &p).as_slice(),
        &p,
        &device,
        &line,
        &scope.to_be_bytes(),
        &from.to_be_bytes(),
        &until.to_be_bytes(),
        &[1],
    ]
    .concat()
}
fn header(version: u64, issued: u64, previous: [u8; 32], count: u8) -> Vec<u8> {
    [
        b"ZTMA\x02".as_slice(),
        &[1; 16],
        &1u64.to_be_bytes(),
        &version.to_be_bytes(),
        &issued.to_be_bytes(),
        &3_600_000u64.to_be_bytes(),
        &previous,
        &point(1),
        &[count],
    ]
    .concat()
}
pub(super) fn fixture() -> (RootSecret, Proposal, Expected) {
    let before_records = vec![
        record(1, 2, [4; 16], [5; 16], 4, 1000, 3_600_000),
        record(2, 3, [0; 16], [0; 16], 12, 1000, 3_600_000),
        record(4, 4, [4; 16], [5; 16], 2, 1000, 3_600_000),
        record(6, 1, [0; 16], [0; 16], 0, 1000, 3_600_000),
    ];
    let mut predecessor = header(7, 1000, [9; 32], 4);
    for r in &before_records {
        predecessor.extend(r);
    }
    let digest = hash(&predecessor);
    let signature: Signature = signing(1).sign(&transcript(&predecessor));
    predecessor.extend(signature.normalize_s().to_bytes());
    let pin = [
        b"ZTRP\x02".as_slice(),
        &[1; 16],
        &1u64.to_be_bytes(),
        &point(1),
    ]
    .concat();
    let fingerprint = sealed_root_enrollment::root_fingerprint(&pin, &[1; 16]).unwrap();
    let scope = Scope {
        account: [1; 16],
        session: [2; 16],
        interval: [3; 16],
        device: [4; 16],
        line: [5; 16],
        line_generation: 1,
        peer: "+12".into(),
        origin: "https://owner.invalid".into(),
        fingerprint,
        predecessor_version: 7,
        predecessor_digest: digest,
        phone_reader: key_id(1, &point(2)),
        archive_reader: key_id(2, &point(3)),
        signer: key_id(5, &point(5)),
        point: point(5),
        until_ms: 1_000_000,
    };
    let mut records = before_records;
    records.push(record(5, 5, [0; 16], [5; 16], 1, 2000, scope.until_ms));
    records.sort_by(|a, b| a[..33].cmp(&b[..33]));
    let mut unsigned = header(8, 2000, digest, 5);
    for r in records {
        unsigned.extend(r);
    }
    let expected = Expected {
        identity: ExpectedIdentity {
            account_id: [1; 16],
            origin: scope.origin.clone(),
            root_fingerprint: fingerprint,
        },
        scope: scope.clone(),
    };
    let mut scalar = [0; 32];
    scalar[31] = 1;
    (
        RootSecret::new(Zeroizing::new(scalar)).unwrap(),
        Proposal {
            scope,
            predecessor,
            unsigned,
        },
        expected,
    )
}
fn encode(p: &Proposal) -> Vec<u8> {
    let s = &p.scope;
    let mut out = b"ZTCF\x01".to_vec();
    for id in [s.account, s.session, s.interval, s.device, s.line] {
        out.extend(id);
    }
    out.extend(s.line_generation.to_be_bytes());
    out.push(s.peer.len() as u8);
    out.extend(s.peer.as_bytes());
    out.extend((s.origin.len() as u16).to_be_bytes());
    out.extend(s.origin.as_bytes());
    out.extend(s.fingerprint);
    out.extend(s.predecessor_version.to_be_bytes());
    for id in [
        s.predecessor_digest,
        s.phone_reader,
        s.archive_reader,
        s.signer,
    ] {
        out.extend(id);
    }
    out.extend(s.point);
    out.extend(s.until_ms.to_be_bytes());
    for b in [&p.predecessor, &p.unsigned] {
        out.extend((b.len() as u16).to_be_bytes());
        out.extend(b);
    }
    out
}
#[test]
fn exact_refresh_signs_and_preserves_archive() {
    let (root, p, e) = fixture();
    let decoded = decode(&encode(&p)).unwrap();
    assert!(inspect(&decoded, &e, 2000).is_ok());
    let signed = sign(&root, &decoded, &e, 2100).unwrap();
    let accepted = manifest(&signed, true, &e.identity, 2100).unwrap();
    let old = manifest(&p.predecessor, true, &e.identity, 2100).unwrap();
    assert!(old.records.iter().all(|r| accepted.records.contains(r)));
    assert_eq!(&signed[..signed.len() - 64], p.unsigned);
    assert_eq!(accepted.records.len(), old.records.len() + 1);
}
#[test]
fn independently_expected_scope_substitution_is_rejected() {
    for field in 0..16 {
        let (_, p, mut e) = fixture();
        match field {
            0 => e.scope.account[0] ^= 1,
            1 => e.scope.session[0] ^= 1,
            2 => e.scope.interval[0] ^= 1,
            3 => e.scope.device[0] ^= 1,
            4 => e.scope.line[0] ^= 1,
            5 => e.scope.line_generation += 1,
            6 => e.scope.peer = "+13".into(),
            7 => e.scope.origin = "https://other.invalid".into(),
            8 => e.scope.fingerprint[0] ^= 1,
            9 => e.scope.predecessor_version += 1,
            10 => e.scope.predecessor_digest[0] ^= 1,
            11 => e.scope.phone_reader[0] ^= 1,
            12 => e.scope.archive_reader[0] ^= 1,
            13 => e.scope.signer[0] ^= 1,
            14 => e.scope.point = point(6),
            15 => e.scope.until_ms += 1,
            _ => unreachable!(),
        };
        assert!(inspect(&p, &e, 2000).is_err(), "field {field}");
    }
}
#[test]
fn signed_predecessor_tampering_and_high_s_are_refused() {
    let (_, mut p, e) = fixture();
    p.predecessor[60] ^= 1;
    assert!(inspect(&p, &e, 2000).is_err());
    let (_, mut p, e) = fixture();
    let at = p.predecessor.len() - 64;
    p.predecessor[at + 32..].fill(255);
    assert!(inspect(&p, &e, 2000).is_err());
}
#[test]
fn predecessor_link_and_version_cannot_be_changed() {
    for at in [29, 53] {
        let (_, mut p, e) = fixture();
        p.unsigned[at] ^= 1;
        assert!(inspect(&p, &e, 2000).is_err());
    }
}
#[test]
fn existing_archive_and_other_records_are_immutable() {
    for role in [1, 2, 4, 6] {
        let (_, mut p, e) = fixture();
        let at = HEADER
            + (0..5)
                .find(|n| p.unsigned[HEADER + n * RECORD] == role)
                .unwrap()
                * RECORD;
        p.unsigned[at + 140 + 7] ^= 1;
        assert!(inspect(&p, &e, 2000).is_err(), "role {role}");
    }
}
#[test]
fn extra_role_and_substituted_signer_are_rejected() {
    let (_, mut p, e) = fixture();
    p.unsigned[HEADER + 3 * RECORD] = 3;
    assert!(inspect(&p, &e, 2000).is_err());
    let (_, mut p, e) = fixture();
    let at = HEADER
        + (0..5)
            .find(|n| p.unsigned[HEADER + n * RECORD] == 5)
            .unwrap()
            * RECORD;
    p.unsigned[at + 33..at + 98].copy_from_slice(&point(6));
    p.unsigned[at + 1..at + 33].copy_from_slice(&key_id(5, &point(6)));
    assert!(inspect(&p, &e, 2000).is_err());
}
#[test]
fn expiry_and_future_issuance_are_rechecked_after_recovery() {
    let (root, p, e) = fixture();
    assert!(inspect(&p, &e, 1000).is_err());
    assert!(sign(&root, &p, &e, e.scope.until_ms).is_err());
    assert!(sign(&root, &p, &e, 3_600_000).is_err());
    assert!(sign(&root, &p, &e, 0).is_err());
}
#[test]
fn oversized_role5_lifetime_is_rejected() {
    let (_, mut p, mut e) = fixture();
    p.scope.until_ms = 2_000_001;
    e.scope.until_ms = p.scope.until_ms;
    let at = HEADER
        + (0..5)
            .find(|n| p.unsigned[HEADER + n * RECORD] == 5)
            .unwrap()
            * RECORD;
    p.unsigned[at + 140..at + 148].copy_from_slice(&p.scope.until_ms.to_be_bytes());
    assert!(inspect(&p, &e, 2000).is_err());
}
#[test]
fn wrong_recovered_root_cannot_sign() {
    let (_, p, e) = fixture();
    let mut scalar = [0; 32];
    scalar[31] = 7;
    let wrong = RootSecret::new(Zeroizing::new(scalar)).unwrap();
    assert!(sign(&wrong, &p, &e, 2000).is_err());
}
#[test]
fn canonical_framing_rejects_trailing_truncation_and_other_purposes() {
    let (_, p, _) = fixture();
    let bytes = encode(&p);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode(&trailing).is_err());
    assert!(decode(&bytes[..bytes.len() - 1]).is_err());
    let mut wrong = bytes;
    wrong[3] = b'X';
    assert!(decode(&wrong).is_err());
    assert!(decode(&vec![0; MAX_PROPOSAL + 1]).is_err());
}
#[test]
fn ambiguous_origins_and_peers_are_rejected() {
    for origin in [
        "https://name@owner.invalid",
        "https://owner.invalid/path",
        "https://owner.invalid?x",
        "https://owner.invalid#x",
        "http://owner.invalid",
    ] {
        let (_, mut p, _) = fixture();
        p.scope.origin = origin.into();
        assert!(decode(&encode(&p)).is_err());
    }
    for peer in ["+01", "+1", "12", "+1\n"] {
        let (_, mut p, _) = fixture();
        p.scope.peer = peer.into();
        assert!(decode(&encode(&p)).is_err());
    }
}

#[test]
fn zero_time_revoked_record_is_preserved_under_existing_grammar() {
    let (root, mut p, mut e) = fixture();
    let old_at = HEADER
        + (0..4)
            .find(|n| p.predecessor[HEADER + n * RECORD] == 4)
            .unwrap()
            * RECORD;
    p.predecessor[old_at + 132..old_at + 148].fill(0);
    p.predecessor[old_at + 148] = 2;
    let unsigned_len = p.predecessor.len() - 64;
    let signature: Signature = signing(1).sign(&transcript(&p.predecessor[..unsigned_len]));
    p.predecessor[unsigned_len..].copy_from_slice(&signature.normalize_s().to_bytes());
    let digest = hash(&p.predecessor[..unsigned_len]);
    p.scope.predecessor_digest = digest;
    e.scope.predecessor_digest = digest;
    p.unsigned[53..85].copy_from_slice(&digest);
    let new_at = HEADER
        + (0..5)
            .find(|n| p.unsigned[HEADER + n * RECORD] == 4)
            .unwrap()
            * RECORD;
    p.unsigned[new_at..new_at + RECORD].copy_from_slice(&p.predecessor[old_at..old_at + RECORD]);
    assert!(inspect(&p, &e, 2000).is_ok());
    assert!(sign(&root, &p, &e, 2000).is_ok());
}
