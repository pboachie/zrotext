//! Synthetic ZTMA draft-01 demonstration, not production manifest verification.
//!
//! Low-s signing and high-s rejection remove the public ECDSA signature twin,
//! but independently generated valid low-s signatures can still differ. Stable
//! manifest identity must hash verified canonical unsigned fields, not the
//! signature bytes. This fixture uses the public generator point as its
//! test-only owner key; never use the scalar in service.

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}

#[test]
fn a_public_high_s_twin_verifies_but_changes_complete_manifest_digest() {
    // Fixed, synthetic key from scalar 1. The unsigned bytes have the draft-01
    // field order and one owner-auth record, with a matching key identifier.
    let root = hex::<65>(
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    let key_id = hex::<32>("b0d8345f27248e9485b6ab3aeb3d458b6786ee54fa3650613829964e79446587");
    let mut unsigned = Vec::new();
    unsigned.extend_from_slice(b"ZTMA\x01");
    unsigned.extend(0_u8..16);
    for value in [1_u64, 1, 1, 2] {
        unsigned.extend_from_slice(&value.to_be_bytes());
    }
    unsigned.extend_from_slice(&[0_u8; 32]);
    unsigned.extend_from_slice(&root);
    unsigned.push(1); // one key record
    unsigned.push(6); // owner-auth role
    unsigned.extend_from_slice(&key_id);
    unsigned.extend_from_slice(&root);
    unsigned.extend_from_slice(&[0_u8; 32]); // zero device and line subjects
    unsigned.extend_from_slice(&0_u16.to_be_bytes()); // no message scope
    unsigned.extend_from_slice(&0_u64.to_be_bytes());
    unsigned.extend_from_slice(&100_000_u64.to_be_bytes());
    unsigned.push(1); // active
    assert_eq!(unsigned.len(), 300);

    let mut transcript = b"ZTSE/manifest/v1\0".to_vec();
    transcript.extend_from_slice(&(unsigned.len() as u32).to_be_bytes());
    transcript.extend_from_slice(&unsigned);

    let low = hex::<64>(
        "8721a2644c1c285ee40fb9d454e93af69eafb9d7f39fc7712e12e41f334a3d2a3a5fe75234fa7aecbfbf3e12eb857b6c46cdf4f50a8365cd3fb703a63822f1c4",
    );
    let high = hex::<64>(
        "8721a2644c1c285ee40fb9d454e93af69eafb9d7f39fc7712e12e41f334a3d2ac5a018accb0585144040c1ed147a8493761905b89c9438b7b402c71cc440338d",
    );
    let verifier = VerifyingKey::from_sec1_bytes(&root).unwrap();
    let low_signature = Signature::from_slice(&low).unwrap();
    let high_signature = Signature::from_slice(&high).unwrap();
    verifier.verify(&transcript, &low_signature).unwrap();
    verifier.verify(&transcript, &high_signature).unwrap();
    assert!(low_signature.normalize_s().is_none());
    assert!(high_signature.normalize_s().is_some());

    let low_manifest = [unsigned.as_slice(), low.as_slice()].concat();
    let high_manifest = [unsigned.as_slice(), high.as_slice()].concat();
    let low_digest = Sha256::digest(&low_manifest);
    let high_digest = Sha256::digest(&high_manifest);
    assert_eq!(
        &low_digest[..],
        &hex::<32>("86f21f6de8b169d170180212585be8411c6f839d056e90d9272486c699968f3c")
    );
    assert_eq!(
        &high_digest[..],
        &hex::<32>("0bd5da3cf33e50ca1487f7982c7739dcf169a5220aa7a1aaee74d16d1d823f95")
    );
    assert_ne!(low_digest, high_digest);
    // Hashing the unsigned manifest gives the same semantic identity for both
    // independently verified signatures; a versioned protocol would need to
    // define this as the chain/envelope digest instead of the complete bytes.
    assert_eq!(
        Sha256::digest(&low_manifest[..low_manifest.len() - 64]),
        Sha256::digest(&high_manifest[..high_manifest.len() - 64])
    );
}
