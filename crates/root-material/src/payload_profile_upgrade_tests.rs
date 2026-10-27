// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

fn fixture() -> (RootSecret, Proposal, Expected) {
    let (root, old, e) = super::super::tests::fixture();
    let before = manifest(old.predecessor(), true, &e.identity, 2000).unwrap();
    let selected = |role| {
        before.records.iter().find(|r| r[0] == role).unwrap()[1..33]
            .try_into()
            .unwrap()
    };
    let scope = Scope {
        account: old.scope.account,
        device: old.scope.device,
        line: old.scope.line,
        origin: old.scope.origin.clone(),
        fingerprint: old.scope.fingerprint,
        predecessor_version: before.version,
        predecessor_digest: hash(&old.predecessor()[..old.predecessor().len() - 64]),
        phone_reader: selected(1),
        // Independent enrollment identity, deliberately different from role4.
        phone_signer: key_id(
            4,
            SigningKey::from_slice(&[27; 32])
                .unwrap()
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes(),
        ),
        issued_ms: 2000,
    };
    let mut unsigned = b"ZTMA\x03\x03\x02".to_vec();
    unsigned.extend_from_slice(&old.predecessor()[5..old.predecessor().len() - 64]);
    unsigned[31..39].copy_from_slice(&(scope.predecessor_version + 1).to_be_bytes());
    unsigned[39..47].copy_from_slice(&scope.issued_ms.to_be_bytes());
    unsigned[55..87].copy_from_slice(&scope.predecessor_digest);
    let proposal = Proposal {
        scope: scope.clone(),
        predecessor: old.predecessor().to_vec(),
        unsigned,
    };
    (
        root,
        proposal,
        Expected {
            identity: e.identity,
            scope,
        },
    )
}
fn encode(p: &Proposal) -> Vec<u8> {
    let s = &p.scope;
    let sized = |b: &[u8]| [&(b.len() as u16).to_be_bytes(), b].concat();
    [
        b"ZTPU\x01".as_slice(),
        &s.account,
        &s.device,
        &s.line,
        &sized(s.origin.as_bytes()),
        &s.fingerprint,
        &s.predecessor_version.to_be_bytes(),
        &s.predecessor_digest,
        &s.phone_reader,
        &s.phone_signer,
        &s.issued_ms.to_be_bytes(),
        &sized(&p.predecessor),
        &sized(&p.unsigned),
    ]
    .concat()
}
#[test]
fn exact_same_root_upgrade_preserves_all_records_and_uses_only_manifest03_domain() {
    let (root, p, e) = fixture();
    let parsed = decode(&encode(&p)).unwrap();
    assert!(inspect(&parsed, &e, 2000).is_ok());
    let signed = sign(&root, &parsed, &e, 2000).unwrap();
    assert_eq!(
        &signed[153..signed.len() - 64],
        &p.predecessor[151..p.predecessor.len() - 64]
    );
    assert_eq!(&signed[47..55], &p.predecessor[45..53]);
    let signature = Signature::from_slice(&signed[signed.len() - 64..]).unwrap();
    assert_eq!(signature.normalize_s().to_bytes(), signature.to_bytes());
    let key = VerifyingKey::from_sec1_bytes(&signed[87..152]).unwrap();
    let unsigned = &signed[..signed.len() - 64];
    let framed = |label: &[u8]| [label, &(unsigned.len() as u32).to_be_bytes(), unsigned].concat();
    assert!(
        key.verify(&framed(b"ZTSE/manifest/v3\0"), &signature)
            .is_ok()
    );
    assert!(
        key.verify(&framed(b"ZTSE/manifest/v2\0"), &signature)
            .is_err()
    );
}
#[test]
fn changing_any_unsigned_byte_including_root_expiry_or_archive_refuses() {
    let (_, mut p, e) = fixture();
    for index in 0..p.unsigned.len() {
        p.unsigned[index] ^= 1;
        assert!(inspect(&p, &e, 2000).is_err(), "changed byte {index}");
        p.unsigned[index] ^= 1;
    }
}
#[test]
fn independent_root_scope_high_water_and_selected_keys_cannot_be_copied_from_proposal() {
    let (_, p, mut e) = fixture();
    let original = e.scope.clone();
    for field in 0..10 {
        e.scope = original.clone();
        match field {
            0 => e.scope.account[0] ^= 1,
            1 => e.scope.device[0] ^= 1,
            2 => e.scope.line[0] ^= 1,
            3 => e.scope.origin = "https://other.invalid".into(),
            4 => e.scope.fingerprint[0] ^= 1,
            5 => e.scope.predecessor_version += 1,
            6 => e.scope.predecessor_digest[0] ^= 1,
            7 => e.scope.phone_reader[0] ^= 1,
            8 => e.scope.phone_signer[0] ^= 1,
            _ => e.scope.issued_ms += 1,
        }
        assert!(inspect(&p, &e, 2000).is_err());
    }
}
#[test]
fn closed_framing_wrong_signing_root_and_expired_original_are_refused() {
    let (_, p, e) = fixture();
    let encoded = encode(&p);
    for size in 0..encoded.len() {
        assert!(decode(&encoded[..size]).is_err());
    }
    assert!(decode(&[encoded, vec![0]].concat()).is_err());
    assert!(decode(&vec![0; MAX_PROPOSAL + 1]).is_err());
    assert!(inspect(&p, &e, 1999).is_err());
    assert!(inspect(&p, &e, 3_600_000).is_err());
    let mut scalar = [0; 32];
    scalar[31] = 2;
    let wrong = RootSecret::new(zeroize::Zeroizing::new(scalar)).unwrap();
    assert!(sign(&wrong, &p, &e, 2000).is_err());
}
