// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use crate::root_backup;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/recovery-kit-01.json"
    ))
    .unwrap()
}
fn bytes(value: &Value, field: &str) -> Vec<u8> {
    let hex = value[field].as_str().unwrap();
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
        .collect()
}
fn expected() -> ExpectedIdentity {
    ExpectedIdentity {
        account_id: [1; 16],
        origin: "https://example.test".into(),
        root_fingerprint: bytes(&fixture(), "fingerprintHex").try_into().unwrap(),
    }
}
fn context() -> KitContext {
    KitContext::new(
        expected(),
        &bytes(&fixture(), "rootPinHex"),
        bytes(&fixture(), "backupIdHex").try_into().unwrap(),
    )
    .unwrap()
}
fn secret() -> RecoverySecret {
    RecoverySecret::new(Zeroizing::new(
        Sha256::digest(b"ZROtext synthetic root-backup test recovery").into(),
    ))
}
fn backup() -> Vec<u8> {
    let value: Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/root-backup-01.json"
    ))
    .unwrap();
    bytes(&value, "ciphertextHex")
}

#[test]
fn independent_vectors_match_and_decoded_secret_opens_authenticated_backup() {
    let fixture = fixture();
    let context = context();
    let token = encode_token(&secret(), &context);
    assert_eq!(
        Sha256::digest(token.expose_ascii()).as_slice(),
        bytes(&fixture, "tokenSha256Hex")
    );
    let decoded = decode_token(token.expose_ascii(), &context).unwrap();
    let restored = root_backup::open(&backup(), &decoded, &expected()).unwrap();
    assert_eq!(
        restored.as_bytes().as_slice(),
        Sha256::digest(b"ZROtext synthetic root-backup test root").as_slice()
    );
    let digest = bytes(&fixture, "encryptedBackupSha256Hex")
        .try_into()
        .unwrap();
    let card = encode_public_card(&bytes(&fixture, "rootPinHex"), &expected(), &digest).unwrap();
    assert_eq!(card, bytes(&fixture, "cardHex"));
    let decoded = decode_public_card(&card, &expected(), &digest).unwrap();
    assert_eq!(decoded.origin(), "https://example.test");
    assert_eq!(decoded.root_pin().as_slice(), bytes(&fixture, "rootPinHex"));
    assert_eq!(decoded.encrypted_backup_sha256(), &digest);
}

#[test]
fn secret_wrappers_and_all_errors_are_redacted() {
    let secret = secret();
    let token = encode_token(&secret, &context());
    assert_eq!(format!("{secret:?}"), "RecoverySecret([REDACTED])");
    assert_eq!(format!("{token:?}"), "RecoveryToken([REDACTED])");
    for error in [
        KitError::InvalidContext,
        KitError::TokenRejected,
        KitError::CardRejected,
    ] {
        let rendered = format!("{error:?}: {error}");
        assert!(!rendered.contains("ZTRK1"));
        assert!(!rendered.contains(std::str::from_utf8(&token.expose_ascii()[6..10]).unwrap()));
    }
}

#[test]
fn every_token_byte_mutation_truncation_and_extra_byte_is_rejected() {
    let context = context();
    let token = encode_token(&secret(), &context);
    for at in 0..TOKEN_LEN {
        let mut changed = Zeroizing::new(*token.expose_ascii());
        changed[at] ^= 1;
        assert!(
            decode_token(changed.as_ref(), &context).is_err(),
            "offset {at}"
        );
        assert!(decode_token(&token.expose_ascii()[..at], &context).is_err());
    }
    for extra in [0, b' ', b'\n', b'='] {
        let mut changed = Zeroizing::new(token.expose_ascii().to_vec());
        changed.push(extra);
        assert!(decode_token(&changed, &context).is_err());
    }
    assert!(decode_token(&[b'A'; 4096], &context).is_err());
}

#[test]
fn noncanonical_pad_bits_case_alphabet_and_separators_are_rejected() {
    let context = context();
    let token = encode_token(&secret(), &context);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let last = alphabet
        .iter()
        .position(|&c| c == token.expose_ascii()[69])
        .unwrap();
    assert_eq!(last % 16, 0);
    for low_bits in 1..16 {
        let mut changed = Zeroizing::new(*token.expose_ascii());
        changed[69] = alphabet[last + low_bits];
        assert!(decode_token(changed.as_ref(), &context).is_err());
    }
    for replacement in [b'a', b'0', b'1', b'8', b'=', b' ', b'\n', b'\r', 0, 0xff] {
        let mut changed = Zeroizing::new(*token.expose_ascii());
        changed[6] = replacement;
        assert!(decode_token(changed.as_ref(), &context).is_err());
    }
    // The shared vector's checksum happens to contain only decimal digits.
    // Use a distinct synthetic secret so this check actually changes letter case.
    let case_token = encode_token(&RecoverySecret::new(Zeroizing::new([3; 32])), &context);
    assert!(
        case_token.expose_ascii()[71..]
            .iter()
            .any(u8::is_ascii_uppercase)
    );
    let mut lowercase = Zeroizing::new(*case_token.expose_ascii());
    lowercase[71..].make_ascii_lowercase();
    assert!(decode_token(lowercase.as_ref(), &context).is_err());
    let mut alias = Zeroizing::new(*token.expose_ascii());
    alias[10] = b' ';
    assert!(decode_token(alias.as_ref(), &context).is_err());
}

#[test]
fn valid_but_different_context_cannot_reuse_a_transcription_checksum() {
    let original = context();
    let token = encode_token(&secret(), &original);
    let pin = bytes(&fixture(), "rootPinHex");
    let mut other_account_pin = pin.clone();
    other_account_pin[5..21].fill(2);
    let other_account = ExpectedIdentity {
        account_id: [2; 16],
        origin: expected().origin,
        root_fingerprint: root_fingerprint(&other_account_pin, &[2; 16]).unwrap(),
    };
    let mut other_origin = expected();
    other_origin.origin = "https://other.example.test".into();
    let other_vector: Value = serde_json::from_str(include_str!(
        "../../../../protocol/v1/vectors/root-enrollment-01.json"
    ))
    .unwrap();
    let other_root_pin = bytes(&other_vector, "rootPinHex");
    let mut other_root = expected();
    other_root.root_fingerprint = root_fingerprint(&other_root_pin, &[1; 16]).unwrap();
    for changed in [
        KitContext::new(other_account, &other_account_pin, original.backup_id).unwrap(),
        KitContext::new(other_origin, &pin, original.backup_id).unwrap(),
        KitContext::new(other_root, &other_root_pin, original.backup_id).unwrap(),
        KitContext::new(expected(), &pin, [9; 16]).unwrap(),
    ] {
        assert!(decode_token(token.expose_ascii(), &changed).is_err());
    }
}

#[test]
fn checksum_success_never_substitutes_for_backup_authentication() {
    let different_secret = RecoverySecret::new(Zeroizing::new(
        Sha256::digest(b"ZROtext synthetic different recovery secret").into(),
    ));
    let context = context();
    let token = encode_token(&different_secret, &context);
    let decoded = decode_token(token.expose_ascii(), &context).unwrap();
    assert!(root_backup::open(&backup(), &decoded, &expected()).is_err());
}

#[test]
fn invalid_genesis_context_is_rejected_before_token_formatting() {
    let pin = bytes(&fixture(), "rootPinHex");
    let id = context().backup_id;
    for origin in [
        "https://example.test/",
        "https://EXAMPLE.test",
        "https://example.test:443",
        "http://example.test",
        "https://example.test?",
        "https://example.test#",
        "https://user@example.test",
        "https://bücher.example",
        "",
    ] {
        let mut identity = expected();
        identity.origin = origin.into();
        assert!(KitContext::new(identity.clone(), &pin, id).is_err());
        assert!(encode_public_card(&pin, &identity, &[0; 32]).is_err());
    }
    assert!(KitContext::new(expected(), &pin, [0; 16]).is_err());
    for at in [0, 4, 5, 21, 28, 29, 30, 93] {
        let mut changed = pin.clone();
        changed[at] ^= 1;
        assert!(KitContext::new(expected(), &changed, id).is_err());
    }
    let mut zero_account = expected();
    zero_account.account_id = [0; 16];
    assert!(KitContext::new(zero_account, &pin, id).is_err());
    let mut wrong_fingerprint = expected();
    wrong_fingerprint.root_fingerprint[0] ^= 1;
    assert!(KitContext::new(wrong_fingerprint, &pin, id).is_err());
}

#[test]
fn public_card_mutations_truncations_extra_bytes_and_wrong_expected_values_fail() {
    let fixture = fixture();
    let original = bytes(&fixture, "cardHex");
    let digest = bytes(&fixture, "encryptedBackupSha256Hex")
        .try_into()
        .unwrap();
    for at in 0..original.len() {
        let mut changed = original.clone();
        changed[at] ^= 1;
        assert!(
            decode_public_card(&changed, &expected(), &digest).is_err(),
            "offset {at}"
        );
        assert!(decode_public_card(&original[..at], &expected(), &digest).is_err());
    }
    assert!(
        decode_public_card(&[original.as_slice(), &[0]].concat(), &expected(), &digest).is_err()
    );
    assert!(decode_public_card(&[0; MAX_CARD + 1], &expected(), &digest).is_err());
    assert!(decode_public_card(&original, &expected(), &[0; 32]).is_err());
    let mut other_identity = expected();
    other_identity.account_id = [2; 16];
    assert!(decode_public_card(&original, &other_identity, &digest).is_err());
}

#[test]
fn maximum_origin_and_exact_card_bound_are_enforced() {
    let pin = bytes(&fixture(), "rootPinHex");
    let mut identity = expected();
    identity.origin = format!("https://{}.test", "a".repeat(499));
    assert_eq!(identity.origin.len(), 512);
    let card = encode_public_card(&pin, &identity, &[0; 32]).unwrap();
    assert_eq!(card.len(), 645);
    assert!(decode_public_card(&card, &identity, &[0; 32]).is_ok());
    assert!(KitContext::new(identity.clone(), &pin, [1; 16]).is_ok());
    identity.origin.insert(8, 'a');
    assert!(encode_public_card(&pin, &identity, &[0; 32]).is_err());
    assert!(KitContext::new(identity, &pin, [1; 16]).is_err());
}
