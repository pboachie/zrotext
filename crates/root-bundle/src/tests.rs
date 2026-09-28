use super::*;

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

pub(crate) fn fixture() -> (Vec<u8>, Vec<u8>, root_backup::ExpectedIdentity) {
    let backup: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol/v1/vectors/root-backup-01.json"
    ))
    .unwrap();
    let kit: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol/v1/vectors/recovery-kit-01.json"
    ))
    .unwrap();
    let expected = root_backup::ExpectedIdentity {
        account_id: [1; 16],
        origin: "https://example.test".into(),
        root_fingerprint: hex(kit["fingerprintHex"].as_str().unwrap())
            .try_into()
            .unwrap(),
    };
    (
        hex(backup["ciphertextHex"].as_str().unwrap()),
        hex(kit["cardHex"].as_str().unwrap()),
        expected,
    )
}

#[cfg(windows)]
pub(crate) fn bundle() -> EncryptedBundle {
    let (backup, card, expected) = fixture();
    EncryptedBundle::new(&backup, &card, &expected).unwrap()
}

#[test]
fn public_bundle_requires_exact_bounded_framing_and_matching_card_digest() {
    let (backup, card, mut expected) = fixture();
    let good = EncryptedBundle::new(&backup, &card, &expected).unwrap();
    assert!(good.name().starts_with("bundle-"));
    assert_eq!(good.name().len(), 39);
    for length in 0..backup.len() {
        assert!(EncryptedBundle::new(&backup[..length], &card, &expected).is_err());
    }
    for length in 0..card.len() {
        assert!(EncryptedBundle::new(&backup, &card[..length], &expected).is_err());
    }
    let mut extra = backup.clone();
    extra.push(0);
    assert!(EncryptedBundle::new(&extra, &card, &expected).is_err());
    let mut changed = backup.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(EncryptedBundle::new(&changed, &card, &expected).is_err());
    expected.account_id = [2; 16];
    assert!(EncryptedBundle::new(&backup, &card, &expected).is_err());
}

#[test]
fn public_header_inspection_is_not_ciphertext_authentication() {
    let (mut backup, _, expected) = fixture();
    let id = root_backup::validate_public_header(&backup, &expected).unwrap();
    *backup.last_mut().unwrap() ^= 1;
    assert_eq!(
        root_backup::validate_public_header(&backup, &expected).unwrap(),
        id
    );
    backup[5] ^= 1;
    assert!(root_backup::validate_public_header(&backup, &expected).is_err());
}
