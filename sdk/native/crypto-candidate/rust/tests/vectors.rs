use serde_json::Value;
use zrotext_candidate_body::{BodyError, decode, open};
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn fixture() -> Value {
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../../protocol/v1/vectors/ztse-body-text-01.json"),
        )
        .unwrap(),
    )
    .unwrap()
}
#[test]
fn shared_text_and_authenticated_vectors_with_tamper_boundaries() {
    let v = fixture();
    assert_eq!(v["status"], "UNAPPROVED_TEST_ONLY");
    for c in v["textCases"].as_array().unwrap() {
        let raw = hex(c["hex"].as_str().unwrap());
        let result = decode(&raw);
        if c["verdict"] == "accept" {
            assert_eq!(result.unwrap().as_bytes(), raw);
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                c["reason"].as_str().unwrap()
            );
        }
    }
    assert_eq!(v["authenticatedCases"].as_array().unwrap().len(), 7);
    for c in v["authenticatedCases"].as_array().unwrap() {
        // Test-only extraction from an independently generated fixture, no production parser.
        let env = hex(c["envelopeHex"].as_str().unwrap());
        assert!(env[4] == 1 || env[4] == 2);
        let end = 10 + u16::from_be_bytes([env[8], env[9]]) as usize;
        let len = u32::from_be_bytes(env[end + 12..end + 16].try_into().unwrap()) as usize;
        let mut aad = format!("ZTSE/body/v{}\0", env[4]).into_bytes();
        aad.extend_from_slice(&env[..end]);
        let args = [
            hex(c["cekHex"].as_str().unwrap()),
            env[end..end + 12].to_vec(),
            aad,
            env[end + 16..end + 16 + len].to_vec(),
        ];
        let result = open(&args[0], &args[1], &args[2], &args[3]);
        if c["verdict"] != "accept" {
            assert_eq!(
                result.unwrap_err().to_string(),
                c["reason"].as_str().unwrap()
            );
            continue;
        }
        assert_eq!(result.unwrap().as_str(), c["text"].as_str().unwrap());
        for field in 0..4 {
            let mut bad = args.clone();
            let last = bad[field].len() - 1;
            bad[field][last] ^= 1;
            assert_eq!(
                open(&bad[0], &bad[1], &bad[2], &bad[3]).unwrap_err(),
                BodyError::Authentication
            );
            bad = args.clone();
            bad[field].clear();
            assert_eq!(
                open(&bad[0], &bad[1], &bad[2], &bad[3]).unwrap_err(),
                BodyError::Shape
            );
        }
        let mut bad = args.clone();
        bad[3][0] ^= 1;
        assert_eq!(
            open(&bad[0], &bad[1], &bad[2], &bad[3]).unwrap_err(),
            BodyError::Authentication
        );
        for (field, len) in [(0, 31), (1, 11), (2, 36865), (3, 32785)] {
            let mut bad = args.clone();
            bad[field].resize(len, 1);
            assert_eq!(
                open(&bad[0], &bad[1], &bad[2], &bad[3]).unwrap_err(),
                BodyError::Shape
            );
        }
    }
}

#[test]
fn authenticates_text_at_exact_boundaries() {
    use aes_gcm::{
        Aes256Gcm, KeyInit, Nonce,
        aead::{Aead, Payload},
    };
    let key = [7u8; 32];
    let nonce = Nonce::try_from(&[8u8; 12][..]).unwrap();
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let aad = vec![9; 36864];
    for (plain, expected) in [
        (vec![b'a'; 32768], None),
        (vec![0xff], Some(BodyError::Utf8)),
        (vec![0], Some(BodyError::Nul)),
        (vec![0xef, 0xbb, 0xbf], Some(BodyError::Bom)),
    ] {
        let encrypted = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .unwrap();
        let result = open(&key, &nonce, &aad, &encrypted);
        if let Some(error) = expected {
            assert_eq!(result.unwrap_err(), error);
        } else {
            assert_eq!(result.unwrap().as_bytes(), plain);
        }
        let mut tampered = encrypted;
        tampered[0] ^= 1;
        assert_eq!(
            open(&key, &nonce, &aad, &tampered).unwrap_err(),
            BodyError::Authentication
        );
    }
}
