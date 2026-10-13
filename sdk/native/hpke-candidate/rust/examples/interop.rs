use serde_json::Value;
use std::io::{self, Read};
use zrotext_hpke_candidate::{Error, open_protected_cek, open_software_cek};
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn main() {
    let mut input = String::new();
    io::stdin()
        .take(1_000_000)
        .read_to_string(&mut input)
        .unwrap();
    let corpus: Value = serde_json::from_str(&input).unwrap();
    assert_eq!(corpus["format"], "zrotext-native-hpke-interop-v1");
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for c in cases {
        let args: [Vec<u8>; 6] = [
            "recipient_private_hex",
            "recipient_public_hex",
            "enc_hex",
            "info_hex",
            "aad_hex",
            "ciphertext_hex",
        ]
        .map(|f| hex(c[f].as_str().unwrap()));
        let open = |a: &[Vec<u8>; 6]| open_software_cek(&a[0], &a[1], &a[2], &a[3], &a[4], &a[5]);
        let plain = open(&args).expect("independent HPKE vector must authenticate");
        assert!(plain.as_slice() == hex(c["plaintext_hex"].as_str().unwrap()));
        for field in 0..6 {
            let mut bad = args.clone();
            if bad[field].is_empty() {
                bad[field].push(1);
            } else {
                let end = bad[field].len() - 1;
                bad[field][end] ^= 1;
            }
            assert!(open(&bad).is_err(), "altered HPKE context accepted");
        }
        for (field, len) in [(0, 31), (1, 64), (2, 64), (3, 36865), (4, 36865), (5, 47)] {
            let mut bad = args.clone();
            bad[field].resize(len, 0);
            assert!(open(&bad).is_err());
        }
        let mut bad = args.clone();
        bad[0].fill(0);
        assert!(open(&bad).is_err());
    }
    assert_eq!(
        open_protected_cek().unwrap_err(),
        Error::ProtectedUnavailable
    );
    println!("Rust: six independent HPKE cases plus context/shape/custody negatives passed");
}
